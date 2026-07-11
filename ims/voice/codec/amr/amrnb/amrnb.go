package amrnb

import (
	"fmt"

	amrbitstream "github.com/damonto/ims-go/ims/voice/codec/amr/bitstream"
)

const (
	// SampleRate is the AMR-NB PCM sample rate in hertz.
	SampleRate = 8000
	// FrameSamples is the number of PCM samples in one 20 ms AMR-NB frame.
	FrameSamples = 160
)

// Mode identifies an AMR-NB bitrate mode.
type Mode int

const (
	Mode475 Mode = iota
	Mode515
	Mode590
	Mode670
	Mode740
	Mode795
	Mode1020
	Mode1220
	ModeDTX
	ModeNoData Mode = 15
)

var frameBits = [...]int{95, 103, 118, 134, 148, 159, 204, 244, 39}

// VADOption selects the AMR-NB encoder VAD variant used for DTX.
type VADOption int

const (
	// VAD1 is the default AMR-NB VAD from the OpenCORE encoder build.
	VAD1 VADOption = iota
	// VAD2 matches the alternate 3GPP conformance vectors built with VAD option 2.
	VAD2
)

// Config describes one AMR-NB encoder instance.
type Config struct {
	Mode Mode
	DTX  bool
	VAD  VADOption
}

// Encoder owns the AMR-NB encoder state.
//
// Encoder methods mutate internal history and are not safe for concurrent use.
type Encoder struct {
	mode       Mode
	dtx        bool
	preprocess encoderPreprocessState
	lpc        encoderLPCState
	lsp        encoderLSPState
	tonStab    tonStabState
	pitch      pitchFrState
	olPitch    pitchOLWeightState
	oldLags    [5]int16
	olGainFlag [2]int16
	memSyn     [lpcOrder]int16
	memW       [lpcOrder]int16
	memW0      [lpcOrder]int16
	memErr     [lpcOrder]int16
	oldSpeech  [speechHistorySamples]int16
	oldWsp     [pitchMax + FrameSamples]int16
	oldExc     [pitchMax + interpolationLen + FrameSamples]int16
	sharp      int16
	gain       encoderGainState
	vad        encoderVADState
	vad2       encoderVAD2State
	vadOption  VADOption
	serial     []byte
	params     []int16
	lastMode   Mode
	dtxState   encoderDTXState
}

// NewEncoder validates cfg and returns a stateful encoder.
func NewEncoder(cfg Config) (*Encoder, error) {
	if !ValidMode(cfg.Mode) {
		return nil, fmt.Errorf("creating AMR-NB encoder: invalid mode %d", cfg.Mode)
	}
	if cfg.VAD != VAD1 && cfg.VAD != VAD2 {
		return nil, fmt.Errorf("creating AMR-NB encoder: invalid VAD option %d", cfg.VAD)
	}
	encoder := &Encoder{
		mode:      cfg.Mode,
		dtx:       cfg.DTX,
		vadOption: cfg.VAD,
		lpc:       newEncoderLPCState(),
		lsp:       newEncoderLSPState(),
		sharp:     sharpMin,
	}
	encoder.gain.reset()
	encoder.olPitch.reset()
	for i := range encoder.oldLags {
		encoder.oldLags[i] = 40
	}
	encoder.lastMode = cfg.Mode
	encoder.dtxState.reset()
	return encoder, nil
}

// Mode returns the current encoder mode.
func (e *Encoder) Mode() Mode { return e.mode }

// FrameMode returns the frame type emitted by the most recent Encode call.
func (e *Encoder) FrameMode() Mode { return e.lastMode }

// DTX reports whether discontinuous transmission was requested.
func (e *Encoder) DTX() bool { return e.dtx }

// Encode encodes one 20 ms PCM frame into an AMR-NB frame.
//
// The returned Frame.Data aliases dst when dst has enough capacity.
func (e *Encoder) Encode(dst []byte, pcm []int16) (Frame, error) {
	if len(pcm) != FrameSamples {
		return Frame{}, fmt.Errorf("encoding AMR-NB frame: pcm sample count %d, want %d", len(pcm), FrameSamples)
	}
	homing := encoderHomingFrame(pcm)
	var (
		data []byte
		err  error
	)
	if e.dtx {
		data, err = e.encodeDTX(dst, pcm)
	} else if e.mode == ModeDTX {
		data, err = e.encodeSID(dst, pcm, e.dtxSIDMode(), true)
		e.lastMode = ModeDTX
	} else {
		e.lastMode = e.mode
		data, err = e.encodeSpeech(dst, pcm)
	}
	if err != nil {
		return Frame{}, err
	}
	if homing {
		lastMode := e.lastMode
		e.Reset()
		e.lastMode = lastMode
	}
	return Frame{Mode: e.lastMode, Quality: e.lastMode != ModeNoData, Data: data}, nil
}

// EncodeSerial packs one AMR-NB ETS serial bit vector into a frame.
func (e *Encoder) EncodeSerial(dst []byte, serial []byte) (Frame, error) {
	data, err := (Speech{Mode: e.mode, Serial: serial}).Pack(dst)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Mode: e.mode, Quality: true, Data: data}, nil
}

// Reset clears encoder history.
func (e *Encoder) Reset() {
	e.preprocess.reset()
	e.lpc.reset()
	e.lsp.reset()
	e.tonStab.reset()
	e.pitch.reset()
	e.olPitch.reset()
	for i := range e.oldLags {
		e.oldLags[i] = 40
	}
	clear(e.olGainFlag[:])
	e.gain.reset()
	e.vad.reset()
	e.vad2.reset()
	clear(e.memSyn[:])
	clear(e.memW[:])
	clear(e.memW0[:])
	clear(e.memErr[:])
	clear(e.oldSpeech[:])
	clear(e.oldWsp[:])
	clear(e.oldExc[:])
	e.sharp = sharpMin
	e.serial = e.serial[:0]
	e.params = e.params[:0]
	e.lastMode = e.mode
	e.dtxState.reset()
}

func (e *Encoder) encodeParams(pcm []int16) error {
	count, err := ParameterCount(e.mode)
	if err != nil {
		return err
	}
	if cap(e.params) < count {
		e.params = make([]int16, count)
	} else {
		e.params = e.params[:count]
		clear(e.params)
	}

	analysis, err := e.analyzeFrame(pcm)
	if err != nil {
		return err
	}
	if analysis.written != count {
		return fmt.Errorf(
			"encoding AMR-NB parameters: mode %d wrote %d parameters, want %d",
			e.mode,
			analysis.written,
			count,
		)
	}
	if e.dtx {
		if e.vadOption != VAD2 {
			e.vad.pitchDetection(analysis.tOp)
		}
		e.dtxState.buffer(analysis.lspNew[:], analysis.speech[:])
	}
	copy(e.params, analysis.params[:count])
	return nil
}

// Decoder owns the AMR-NB decoder state.
//
// Decoder methods mutate internal concealment and filter history and are not
// safe for concurrent use.
type Decoder struct {
	prevMode     Mode
	resetFlagOld bool
	core         decoderCoreState
	postFilter   postFilterState
	postProcess  postProcessState
	serial       []byte
	params       []int16
}

// NewDecoder returns a stateful decoder.
func NewDecoder() *Decoder {
	decoder := &Decoder{
		prevMode:     Mode475,
		resetFlagOld: true,
		core:         newDecoderCoreState(),
	}
	decoder.postFilter.reset()
	decoder.postProcess.reset()
	return decoder
}

// Decode validates and decodes one AMR-NB speech, SID, or lost frame.
//
// The returned PCM slice aliases dst when dst has enough capacity.
func (d *Decoder) Decode(dst []int16, frame Frame) ([]int16, error) {
	mode := frame.Mode
	if !validWireFrameType(mode) {
		return nil, fmt.Errorf("decoding AMR-NB frame: invalid mode %d", mode)
	}
	decoded, err := prepareDecoderFrame(d.serial, d.params, d.prevMode, mode, frame.Data, frame.Quality)
	if err != nil {
		return nil, err
	}
	return d.decodeFrame(dst, decoded)
}

// DecodeRX decodes one ETS serial frame with an explicit receive frame type.
func (d *Decoder) DecodeRX(dst []int16, mode Mode, serial []byte, rxType RXFrameType) ([]int16, error) {
	if rxType < RXSpeechGood || rxType > RXNoData {
		return nil, fmt.Errorf("decoding AMR-NB frame: invalid RX type %d", rxType)
	}
	if rxType == RXNoData {
		mode = d.prevMode
	} else if !ValidMode(mode) {
		return nil, fmt.Errorf("decoding AMR-NB frame: invalid mode %d", mode)
	}
	params, err := decoderFrameParams(d.params, mode, rxType, serial)
	if err != nil {
		return nil, err
	}
	if cap(d.serial) < len(serial) {
		d.serial = make([]byte, len(serial))
	} else {
		d.serial = d.serial[:len(serial)]
	}
	copy(d.serial, serial)
	d.params = params
	return d.decodeFrame(dst, decoderFrame{
		mode:   mode,
		rxType: rxType,
		serial: d.serial,
		params: params,
	})
}

func (d *Decoder) decodeFrame(dst []int16, frame decoderFrame) ([]int16, error) {
	d.serial = frame.serial
	d.params = frame.params
	d.prevMode = frame.mode

	resetFlag := false
	if d.resetFlagOld {
		resetFlag = decoderHomingFrameFirst(frame.serial, frame.mode)
	}
	var out []int16
	if resetFlag && d.resetFlagOld {
		if cap(dst) < FrameSamples {
			dst = make([]int16, 0, FrameSamples)
		}
		out = dst[:0]
		for range FrameSamples {
			out = append(out, encoderHomingFrameSample)
		}
	} else {
		var err error
		out, err = d.decodePreparedFrame(dst, frame)
		if err != nil {
			return nil, err
		}
	}
	if !d.resetFlagOld {
		resetFlag = decoderHomingFrame(frame.serial, frame.mode)
	}
	if resetFlag {
		d.Reset()
	}
	d.resetFlagOld = resetFlag
	return out, nil
}

func (d *Decoder) decodePreparedFrame(dst []int16, frame decoderFrame) ([]int16, error) {
	var err error
	d.params, err = d.core.beginFrame(frame.mode, frame.rxType, d.params)
	if err != nil {
		return nil, err
	}
	if cap(dst) < FrameSamples {
		dst = make([]int16, 0, FrameSamples)
	}
	dst = dst[:0]
	if d.core.lastDTXState != dtxStateSpeech {
		if err := d.core.dtx.updateSID(&d.core.lsfState, &d.core.predState, frame.mode, d.params); err != nil {
			return nil, err
		}
		decoded := d.core.synthesizeComfortNoise(dst)
		d.core.lspOld = lsfToLsp(d.core.lsfState.pastLSFQ[:])
		d.core.lspAvg.update(d.core.lsfState.pastLSFQ[:])
		d.core.dtx.finishSIDUpdate()
		d.core.dtx.globalState = d.core.lastDTXState
		return d.finishDecode(frame.mode, decoded)
	}
	if frame.mode < Mode475 || frame.mode > Mode1220 {
		return nil, fmt.Errorf("decoding AMR-NB frame: non-speech mode %d in speech state", frame.mode)
	}

	options, ok := speechOptionsForRX(frame.rxType)
	if !ok {
		return nil, fmt.Errorf("decoding AMR-NB frame: RX type %d is not valid for speech synthesis", frame.rxType)
	}
	_, decoded, err := d.core.decodeSpeechFrame(frame.mode, d.params, dst, options)
	if err != nil {
		return nil, err
	}
	d.core.dtx.globalState = d.core.lastDTXState
	return d.finishDecode(frame.mode, decoded.samples)
}

// DecodeSerial unpacks one AMR-NB frame into ETS serial bits.
func (d *Decoder) DecodeSerial(dst []byte, frame Frame) ([]byte, error) {
	speech := Speech{Mode: frame.Mode, Serial: dst}
	if err := speech.UnmarshalBinary(frame.Data); err != nil {
		return nil, err
	}
	return speech.Serial, nil
}

// DecodeSerialLost returns the ETS serial representation for a lost speech frame.
func (d *Decoder) DecodeSerialLost(dst []byte) ([]byte, error) {
	bits, err := FrameBitLen(ModeDTX)
	if err != nil {
		return nil, err
	}
	if cap(dst) < bits {
		dst = make([]byte, bits)
	} else {
		dst = dst[:bits]
		clear(dst)
	}
	return dst, nil
}

// DecodeLost synthesizes one missing AMR-NB frame using the decoder concealment state.
func (d *Decoder) DecodeLost(dst []int16) ([]int16, error) {
	return d.Decode(dst, Frame{Mode: ModeNoData})
}

// Reset clears decoder history once the algorithm port is available.
func (d *Decoder) Reset() {
	d.prevMode = Mode475
	d.resetFlagOld = true
	d.core.reset(Mode475)
	d.postFilter.reset()
	d.postProcess.reset()
}

func maskTo13Bits(pcm []int16) {
	for i := range pcm {
		pcm[i] &= ^int16(7)
	}
}

func (d *Decoder) finishDecode(mode Mode, pcm []int16) ([]int16, error) {
	filtered, err := d.postFilter.process(mode, pcm, d.core.az)
	if err != nil {
		return nil, err
	}
	copy(pcm, filtered[:])
	d.postProcess.process(pcm)
	maskTo13Bits(pcm)
	return pcm, nil
}

func speechOptionsForRX(rxType RXFrameType) (speechFrameOptions, bool) {
	switch rxType {
	case RXSpeechGood:
		return speechFrameOptions{}, true
	case RXSpeechDegraded:
		return speechFrameOptions{potentialDegrade: true}, true
	case RXSpeechBad, RXNoData, RXOnset:
		return speechFrameOptions{badFrame: true}, true
	default:
		return speechFrameOptions{}, false
	}
}

// ValidMode reports whether mode is defined by AMR-NB.
func ValidMode(mode Mode) bool {
	return mode >= Mode475 && mode <= ModeDTX
}

// FrameBytes returns the number of speech bytes for one encoded frame.
func FrameBytes(mode Mode) (int, error) {
	if mode == ModeNoData {
		return 0, nil
	}
	if !ValidMode(mode) {
		return 0, fmt.Errorf("AMR-NB frame mode %d is not supported", mode)
	}
	return amrbitstream.ByteLen(frameBits[mode]), nil
}
