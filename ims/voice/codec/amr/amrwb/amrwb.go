package amrwb

import (
	"fmt"

	amrbitstream "github.com/damonto/ims-go/ims/voice/codec/amr/bitstream"
)

const (
	// SampleRate is the AMR-WB PCM sample rate in hertz.
	SampleRate = 16000
	// FrameSamples is the number of PCM samples in one 20 ms AMR-WB frame.
	FrameSamples = 320

	encoderHomingFrameSample int16 = 0x0008
)

// Mode identifies an AMR-WB bitrate mode.
type Mode int

const (
	Mode660 Mode = iota
	Mode885
	Mode1265
	Mode1425
	Mode1585
	Mode1825
	Mode1985
	Mode2305
	Mode2385
	ModeSID        Mode = 9
	ModeSpeechLost Mode = 14
	ModeNoData     Mode = 15
)

var frameBits = [...]int{132, 177, 253, 285, 317, 365, 397, 461, 477, 40}

// Config describes one AMR-WB encoder instance.
type Config struct {
	Mode Mode
	DTX  bool
}

// Encoder owns the AMR-WB encoder state.
//
// Encoder methods mutate internal history and are not safe for concurrent use.
type Encoder struct {
	mode        Mode
	dtx         bool
	preprocess  encoderPreprocessState
	vad         encoderVADState
	vadActive   bool
	lpc         encoderLPCState
	isfQuant    encoderISFQuantState
	pitchClip   encoderPitchClipState
	gainQuant   encoderGainQuantState
	speech16k   [FrameSamples]int16
	speech12k8  [frameSamples12k8 + lpcLookahead12k8]int16
	vadSpeech   [frameSamples12k8]int16
	oldSpeech   [encoderOldSpeechSamples]int16
	oldWsp      [oldWspSamples]int16
	oldHPWsp    [oldWspSamples]int16
	oldWspMax   int16
	oldWspShift int16
	oldT0Med    int16
	oldOLLag    [5]int16
	olGain      int16
	adaW        int16
	olWghtFlg   int16
	oldExc      [pitchMax + interpolationLen]int16
	memSyn      [lpcOrder]int16
	memDecim2   [3]int16
	hpWspMem    [9]int16
	memWsp      int16
	memW0       int16
	tiltCode    int16
	scaleExp    int16
	serial      []byte
	params      []int16
	lastMode    Mode
	dtxState    encoderDTXState
	hb          encoderHighBandState
}

// NewEncoder validates cfg and returns a stateful encoder.
func NewEncoder(cfg Config) (*Encoder, error) {
	if !ValidMode(cfg.Mode) {
		return nil, fmt.Errorf("creating AMR-WB encoder: invalid mode %d", cfg.Mode)
	}
	encoder := &Encoder{mode: cfg.Mode, dtx: cfg.DTX}
	encoder.preprocess.reset()
	encoder.vad.reset()
	encoder.vadActive = true
	encoder.lpc.reset()
	encoder.isfQuant.reset()
	encoder.pitchClip.reset()
	encoder.gainQuant.reset()
	encoder.resetOpenLoopPitch()
	encoder.lastMode = cfg.Mode
	encoder.dtxState.reset()
	encoder.hb.reset()
	return encoder, nil
}

// Mode returns the current encoder mode.
func (e *Encoder) Mode() Mode { return e.mode }

// FrameMode returns the frame type emitted by the most recent Encode call.
func (e *Encoder) FrameMode() Mode { return e.lastMode }

// DTX reports whether discontinuous transmission was requested.
func (e *Encoder) DTX() bool { return e.dtx }

// Encode encodes one 20 ms PCM frame into an AMR-WB frame.
//
// The returned Frame.Data aliases dst when dst has enough capacity.
func (e *Encoder) Encode(dst []byte, pcm []int16) (Frame, error) {
	if len(pcm) != FrameSamples {
		return Frame{}, fmt.Errorf("encoding AMR-WB frame: pcm sample count %d, want %d", len(pcm), FrameSamples)
	}
	homing := encoderHomingFrame(pcm)
	var speech []byte
	var err error
	if e.dtx {
		speech, err = e.encodeDTX(dst, pcm)
	} else {
		e.lastMode = e.mode
		speech, err = e.encodeFrameSpeech(dst, pcm)
	}
	if err != nil {
		return Frame{}, err
	}
	if homing {
		lastMode := e.lastMode
		e.Reset()
		e.lastMode = lastMode
	}
	return Frame{Mode: e.lastMode, Quality: e.lastMode != ModeNoData, Data: speech}, nil
}

// EncodeSerial packs one AMR-WB serial bit vector into a frame.
func (e *Encoder) EncodeSerial(dst []byte, serial []byte) (Frame, error) {
	data, err := (Speech{Mode: e.mode, Serial: serial}).Pack(dst)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Mode: e.mode, Quality: true, Data: data}, nil
}

func (e *Encoder) encodeFrameParams(pcm []int16) ([]int16, error) {
	if _, err := e.prepareFrame(pcm); err != nil {
		return nil, err
	}
	if !e.dtx {
		active, err := e.vad.decide(e.vadSpeech[:])
		if err != nil {
			return nil, fmt.Errorf("encode AMR-WB frame: %w", err)
		}
		e.updateEncoderVADHistory(active)
	}
	return e.encodePreparedFrameParams(false)
}

func (e *Encoder) encodePreparedFrameParams(bufferDTX bool) ([]int16, error) {
	if err := e.encodeParams(); err != nil {
		return nil, err
	}
	analysis, err := e.analyzeSpeech(e.params)
	if err != nil {
		return nil, fmt.Errorf("encoding AMR-WB frame: %w", err)
	}
	if bufferDTX {
		logEnergy, err := e.dtxLogEnergyForQuantizedLPC(analysis.quantLPC.aq[:])
		if err != nil {
			return nil, fmt.Errorf("encode AMR-WB DTX frame: %w", err)
		}
		e.dtxState.bufferLogEnergy(analysis.quantLPC.isfQ[:], logEnergy)
	}
	if _, err := e.analyzePitchSubframes(analysis, e.params); err != nil {
		return nil, fmt.Errorf("encoding AMR-WB frame: %w", err)
	}
	if err := updateEncoderOldSpeech(e.oldSpeech[:], e.speech12k8[:]); err != nil {
		return nil, fmt.Errorf("encode AMR-WB frame: %w", err)
	}
	return e.params, nil
}

func (e *Encoder) encodeFrameSerial(pcm []int16) ([]byte, error) {
	params, err := e.encodeFrameParams(pcm)
	if err != nil {
		return nil, err
	}
	return e.encodePreparedSerial(params)
}

func (e *Encoder) encodePreparedFrameSerial(bufferDTX bool) ([]byte, error) {
	params, err := e.encodePreparedFrameParams(bufferDTX)
	if err != nil {
		return nil, err
	}
	return e.encodePreparedSerial(params)
}

func (e *Encoder) encodePreparedSerial(params []int16) ([]byte, error) {
	serial, err := (Params{Mode: e.mode, Values: params}).Pack(e.serial)
	if err != nil {
		return nil, err
	}
	e.serial = serial
	return serial, nil
}

func (e *Encoder) encodeFrameSpeech(dst []byte, pcm []int16) ([]byte, error) {
	serial, err := e.encodeFrameSerial(pcm)
	if err != nil {
		return nil, err
	}
	return (Speech{Mode: e.mode, Serial: serial}).Pack(dst)
}

func (e *Encoder) encodePreparedFrameSpeech(dst []byte, bufferDTX bool) ([]byte, error) {
	serial, err := e.encodePreparedFrameSerial(bufferDTX)
	if err != nil {
		return nil, err
	}
	return (Speech{Mode: e.mode, Serial: serial}).Pack(dst)
}

// Reset clears codec history.
func (e *Encoder) Reset() {
	e.preprocess.reset()
	e.vad.reset()
	e.vadActive = true
	e.lpc.reset()
	e.isfQuant.reset()
	e.pitchClip.reset()
	e.gainQuant.reset()
	clear(e.speech16k[:])
	clear(e.speech12k8[:])
	clear(e.vadSpeech[:])
	clear(e.oldSpeech[:])
	clear(e.oldWsp[:])
	clear(e.oldHPWsp[:])
	e.oldWspMax = 0
	e.oldWspShift = 0
	e.resetOpenLoopPitch()
	clear(e.oldExc[:])
	clear(e.memSyn[:])
	clear(e.memDecim2[:])
	clear(e.hpWspMem[:])
	e.memWsp = 0
	e.memW0 = 0
	e.tiltCode = 0
	e.scaleExp = 0
	e.serial = e.serial[:0]
	e.params = e.params[:0]
	e.lastMode = e.mode
	e.dtxState.reset()
	e.hb.reset()
}

func (e *Encoder) encodeParams() error {
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
	return nil
}

func (e *Encoder) prepareFrame(pcm []int16) (bool, error) {
	if len(pcm) != FrameSamples {
		return false, fmt.Errorf("preparing AMR-WB frame: pcm sample count %d, want %d", len(pcm), FrameSamples)
	}
	homing := encoderHomingFrame(pcm)
	copy(e.speech16k[:], pcm)
	maskEncoderInput(e.speech16k[:])
	qOld := e.preprocess.qOld
	speech := e.preprocess.processFrame(e.speech12k8[:0], e.speech16k[:])
	copy(e.speech12k8[:], speech)
	copy(e.vadSpeech[:], speech[:frameSamples12k8])
	scaleSignal(e.vadSpeech[:], 1-e.preprocess.qOld)
	e.scaleHistory(e.preprocess.qOld - qOld)
	return homing, nil
}

func (e *Encoder) scaleHistory(exp int16) {
	e.scaleExp = exp
	scaleSignal(e.oldSpeech[:], exp)
	scaleSignal(e.oldExc[:], exp)
	scaleSignal(e.memSyn[:], exp)
	scaleSignal(e.memDecim2[:], exp)
	memWsp := [1]int16{e.memWsp}
	scaleSignal(memWsp[:], exp)
	e.memWsp = memWsp[0]
	memW0 := [1]int16{e.memW0}
	scaleSignal(memW0[:], exp)
	e.memW0 = memW0[0]
}

// Decoder owns the AMR-WB decoder state.
//
// Decoder methods mutate internal concealment and synthesis history and are not
// safe for concurrent use.
type Decoder struct {
	modeOld      Mode
	resetFlagOld bool
	core         decoderCoreState
	serial       []byte
	params       []int16
}

// NewDecoder returns a stateful decoder.
func NewDecoder() *Decoder {
	return &Decoder{resetFlagOld: true, core: newDecoderCoreState()}
}

// Decode validates one speech frame and handles AMR-WB homing frames.
//
// The returned PCM slice aliases dst when dst has enough capacity.
func (d *Decoder) Decode(dst []int16, frame Frame) ([]int16, error) {
	mode := frame.Mode
	if !validWireFrameType(mode) {
		return nil, fmt.Errorf("decoding AMR-WB frame: invalid mode %d", mode)
	}
	if mode == ModeSpeechLost {
		return d.decodeRXFrame(dst, rxSpeechLost)
	}
	if mode == ModeNoData {
		return d.decodeRXFrame(dst, rxNoData)
	}
	speech := Speech{Mode: mode, Serial: d.serial}
	if err := speech.UnmarshalBinary(frame.Data); err != nil {
		return nil, err
	}
	serial := speech.Serial
	d.serial = serial
	packedParams := Params{Mode: mode, Values: d.params}
	if err := packedParams.UnmarshalBinary(serial); err != nil {
		return nil, err
	}
	params := packedParams.Values
	d.params = params
	if mode == ModeSID {
		frameType := rxSIDBad
		if frame.Quality {
			frameType = rxSIDFirst
			if serial[amrWBSIDRxTypeBitOffset] != 0 {
				frameType = rxSIDUpdate
			}
		}
		return d.decodeRXFrameWithParams(dst, d.modeOld, params, frameType)
	}
	resetFlag := false
	resetFlagOld := d.resetFlagOld
	if resetFlagOld {
		resetFlag = homingFrameTestFirst(serial, mode)
	}

	if cap(dst) < FrameSamples {
		dst = make([]int16, 0, FrameSamples)
	}
	dst = dst[:0]
	if !frame.Quality {
		d.resetFlagOld = false
		out, err := d.core.decodeCore(dst, mode, params, rxSpeechBad)
		if err != nil {
			return dst, err
		}
		d.modeOld = mode
		mask14BitOutput(out)
		return out, nil
	}

	if resetFlag && resetFlagOld {
		for range FrameSamples {
			dst = append(dst, encoderHomingFrameSample)
		}
		mask14BitOutput(dst)
		d.modeOld = mode
		d.resetFlagOld = true
		return dst, nil
	}
	out, err := d.core.decodeCore(dst, mode, params, rxSpeechGood)
	if err != nil {
		return dst, err
	}
	if !resetFlagOld {
		resetFlag = homingFrameTest(serial, mode)
	}
	if resetFlag {
		d.core.reset(true)
	}
	d.modeOld = mode
	d.resetFlagOld = resetFlag
	mask14BitOutput(out)
	return out, nil
}

// DecodeRX decodes one serial frame with an explicit receive frame type.
func (d *Decoder) DecodeRX(dst []int16, mode Mode, serial []byte, frameType RXFrameType) ([]int16, error) {
	if frameType < rxSpeechGood || frameType > rxNoData {
		return nil, fmt.Errorf("decoding AMR-WB frame: invalid RX type %d", frameType)
	}
	if frameType == rxSpeechLost || frameType == rxNoData {
		return d.decodeRXFrame(dst, frameType)
	}
	if !ValidMode(mode) {
		return nil, fmt.Errorf("decoding AMR-WB frame: invalid mode %d", mode)
	}
	paramMode := mode
	if frameType == rxSIDFirst || frameType == rxSIDUpdate || frameType == rxSIDBad {
		paramMode = ModeSID
	}
	if paramMode == ModeSID && len(serial) == 35 {
		padded := make([]byte, frameBits[ModeSID])
		copy(padded, serial)
		if frameType == rxSIDUpdate {
			padded[amrWBSIDRxTypeBitOffset] = 1
		}
		serial = padded
	}
	packedParams := Params{Mode: paramMode, Values: d.params}
	if err := packedParams.UnmarshalBinary(serial); err != nil {
		return nil, err
	}
	params := packedParams.Values
	d.params = params
	if cap(d.serial) < len(serial) {
		d.serial = make([]byte, len(serial))
	} else {
		d.serial = d.serial[:len(serial)]
	}
	copy(d.serial, serial)

	resetFlag := false
	resetFlagOld := d.resetFlagOld
	if paramMode == mode && resetFlagOld {
		resetFlag = homingFrameTestFirst(serial, mode)
	}
	if cap(dst) < FrameSamples {
		dst = make([]int16, 0, FrameSamples)
	}
	dst = dst[:0]
	if resetFlag && resetFlagOld {
		for range FrameSamples {
			dst = append(dst, encoderHomingFrameSample)
		}
		mask14BitOutput(dst)
		d.modeOld = mode
		d.resetFlagOld = true
		return dst, nil
	}

	out, err := d.core.decodeCore(dst, mode, params, frameType)
	if err != nil {
		return dst, err
	}
	if paramMode == mode && !resetFlagOld {
		resetFlag = homingFrameTest(serial, mode)
	}
	if resetFlag {
		d.core.reset(true)
	}
	d.modeOld = mode
	d.resetFlagOld = resetFlag
	mask14BitOutput(out)
	return out, nil
}

// DecodeSerial unpacks one AMR-WB frame into serial bits.
func (d *Decoder) DecodeSerial(dst []byte, frame Frame) ([]byte, error) {
	speech := Speech{Mode: frame.Mode, Serial: dst}
	if err := speech.UnmarshalBinary(frame.Data); err != nil {
		return nil, err
	}
	return speech.Serial, nil
}

// DecodeLost synthesizes one AMR-WB lost frame using the decoder state.
func (d *Decoder) DecodeLost(dst []int16) ([]int16, error) {
	return d.decodeRXFrame(dst, rxSpeechLost)
}

func (d *Decoder) decodeRXFrame(dst []int16, frameType RXFrameType) ([]int16, error) {
	count, err := ParameterCount(d.modeOld)
	if err != nil {
		return nil, err
	}
	if cap(d.params) < count {
		d.params = make([]int16, count)
	} else {
		d.params = d.params[:count]
		clear(d.params)
	}
	return d.decodeRXFrameWithParams(dst, d.modeOld, d.params, frameType)
}

func (d *Decoder) decodeRXFrameWithParams(
	dst []int16,
	mode Mode,
	params []int16,
	frameType RXFrameType,
) ([]int16, error) {
	if cap(dst) < FrameSamples {
		dst = make([]int16, 0, FrameSamples)
	}
	dst = dst[:0]
	out, err := d.core.decodeCore(dst, mode, params, frameType)
	if err != nil {
		return dst, err
	}
	mask14BitOutput(out)
	d.resetFlagOld = false
	return out, nil
}

// Reset returns the decoder wrapper state to the AMR-WB homed condition.
func (d *Decoder) Reset() {
	d.modeOld = Mode660
	d.resetFlagOld = true
	d.core.reset(true)
	d.serial = d.serial[:0]
	d.params = d.params[:0]
}

// ValidMode reports whether mode is defined by AMR-WB.
func ValidMode(mode Mode) bool {
	return mode >= Mode660 && mode <= Mode2385
}

func validWireFrameType(mode Mode) bool {
	return ValidMode(mode) || mode == ModeSID || mode == ModeSpeechLost || mode == ModeNoData
}

// FrameBytes returns the number of speech bytes for one encoded frame.
func FrameBytes(mode Mode) (int, error) {
	if mode == ModeSpeechLost || mode == ModeNoData {
		return 0, nil
	}
	if !ValidMode(mode) && mode != ModeSID {
		return 0, fmt.Errorf("AMR-WB frame mode %d is not supported", mode)
	}
	return amrbitstream.ByteLen(frameBits[mode]), nil
}
