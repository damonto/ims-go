package amrnb

import "testing"

func TestPrepareDecoderFrameSpeech(t *testing.T) {
	serial := make([]byte, 244)
	for i := range serial {
		serial[i] = byte((i >> 1) & 1)
	}
	speech, err := (Speech{Mode: Mode1220, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack() error = %v", err)
	}

	frame, err := prepareDecoderFrame(nil, nil, Mode475, Mode1220, speech, true)
	if err != nil {
		t.Fatalf("prepareDecoderFrame() error = %v", err)
	}
	if frame.mode != Mode1220 {
		t.Fatalf("mode = %d, want %d", frame.mode, Mode1220)
	}
	if frame.rxType != RXSpeechGood {
		t.Fatalf("rxType = %d, want %d", frame.rxType, RXSpeechGood)
	}
	decoded := Params{Mode: Mode1220}
	if err := decoded.UnmarshalBinary(serial); err != nil {
		t.Fatalf("Params.UnmarshalBinary() error = %v", err)
	}
	wantParams := decoded.Values
	if len(frame.params) != len(wantParams) {
		t.Fatalf("params = %d, want %d", len(frame.params), len(wantParams))
	}
	for i := range wantParams {
		if frame.params[i] != wantParams[i] {
			t.Fatalf("params[%d] = %d, want %d", i, frame.params[i], wantParams[i])
		}
	}

	badFrame, err := prepareDecoderFrame(nil, nil, Mode475, Mode1220, speech, false)
	if err != nil {
		t.Fatalf("prepareDecoderFrame(bad quality) error = %v", err)
	}
	if badFrame.rxType != RXSpeechBad {
		t.Fatalf("bad quality rxType = %d, want %d", badFrame.rxType, RXSpeechBad)
	}
}

func TestPrepareDecoderFrameSID(t *testing.T) {
	serial := make([]byte, 39)
	serial[amrSIDRxTypeBitOffset] = 1
	writeSIDMode(serial, Mode795)
	speech, err := (Speech{Mode: ModeDTX, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(SID) error = %v", err)
	}

	frame, err := prepareDecoderFrame(nil, nil, Mode475, ModeDTX, speech, true)
	if err != nil {
		t.Fatalf("prepareDecoderFrame(SID) error = %v", err)
	}
	if frame.mode != Mode795 {
		t.Fatalf("SID mode = %d, want %d", frame.mode, Mode795)
	}
	if frame.rxType != RXSIDUpdate {
		t.Fatalf("SID rxType = %d, want %d", frame.rxType, RXSIDUpdate)
	}
	if len(frame.params) != 5 {
		t.Fatalf("SID params = %d, want 5", len(frame.params))
	}

	first := make([]byte, 39)
	writeSIDMode(first, Mode670)
	speech, err = (Speech{Mode: ModeDTX, Serial: first}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(SID first) error = %v", err)
	}
	frame, err = prepareDecoderFrame(nil, nil, Mode475, ModeDTX, speech, true)
	if err != nil {
		t.Fatalf("prepareDecoderFrame(SID first) error = %v", err)
	}
	if frame.mode != Mode670 || frame.rxType != RXSIDFirst {
		t.Fatalf("SID first = mode %d rx %d, want mode %d rx %d", frame.mode, frame.rxType, Mode670, RXSIDFirst)
	}
	wantCount, err := ParameterCount(Mode670)
	if err != nil {
		t.Fatalf("ParameterCount() error = %v", err)
	}
	if len(frame.params) != wantCount {
		t.Fatalf("SID first params = %d, want speech-mode count %d", len(frame.params), wantCount)
	}

	frame, err = prepareDecoderFrame(nil, nil, Mode475, ModeDTX, speech, false)
	if err != nil {
		t.Fatalf("prepareDecoderFrame(SID bad) error = %v", err)
	}
	if frame.rxType != RXSIDBad {
		t.Fatalf("SID bad rxType = %d, want %d", frame.rxType, RXSIDBad)
	}
	if len(frame.params) != 5 {
		t.Fatalf("SID bad params = %d, want DTX count 5", len(frame.params))
	}
}

func TestPrepareDecoderFrameNoDataUsesPreviousMode(t *testing.T) {
	frame, err := prepareDecoderFrame(nil, nil, Mode1020, ModeNoData, nil, false)
	if err != nil {
		t.Fatalf("prepareDecoderFrame(no data) error = %v", err)
	}
	if frame.mode != Mode1020 {
		t.Fatalf("no-data mode = %d, want previous mode %d", frame.mode, Mode1020)
	}
	if frame.rxType != RXNoData {
		t.Fatalf("no-data rxType = %d, want %d", frame.rxType, RXNoData)
	}
}

func TestDecodeGoodFrameConsumesModeParameters(t *testing.T) {
	tests := []struct {
		name     string
		mode     Mode
		wantUsed int
	}{
		{name: "MR475", mode: Mode475, wantUsed: 17},
		{name: "MR515", mode: Mode515, wantUsed: 19},
		{name: "MR590", mode: Mode590, wantUsed: 19},
		{name: "MR670", mode: Mode670, wantUsed: 19},
		{name: "MR740", mode: Mode740, wantUsed: 19},
		{name: "MR795", mode: Mode795, wantUsed: 23},
		{name: "MR102", mode: Mode1020, wantUsed: 39},
		{name: "MR122", mode: Mode1220, wantUsed: 57},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newDecoderCoreState()
			params := goodSpeechFrameParams(tt.mode)

			used, got, err := state.decodeGoodFrame(tt.mode, params, nil)

			if err != nil {
				t.Fatalf("decodeGoodFrame error = %v", err)
			}
			if used != tt.wantUsed {
				t.Fatalf("used = %d, want %d", used, tt.wantUsed)
			}
			if len(got.samples) != FrameSamples {
				t.Fatalf("samples length = %d, want %d", len(got.samples), FrameSamples)
			}
			if len(params) != tt.wantUsed {
				t.Fatalf("test params length = %d, want %d", len(params), tt.wantUsed)
			}
			if state.ltpGainHistory[ltpGainHistoryLen-1] == 0 &&
				tt.mode != Mode795 && tt.mode != Mode1220 {
				t.Fatalf("ltp gain history tail stayed zero for mode %d", tt.mode)
			}
		})
	}
}

func TestDecodeGoodFrameRejectsShortParams(t *testing.T) {
	state := newDecoderCoreState()
	params := goodSpeechFrameParams(Mode1220)

	if _, _, err := state.decodeGoodFrame(Mode1220, params[:4], nil); err == nil {
		t.Fatal("decodeGoodFrame(short MR122 LPC params) error = nil, want error")
	}
}

func TestDecodeUpdatesPreviousModeBeforeAlgorithmPort(t *testing.T) {
	dec := NewDecoder()
	serial := make([]byte, 39)
	writeSIDMode(serial, Mode740)
	speech, err := (Speech{Mode: ModeDTX, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(SID) error = %v", err)
	}

	got, err := dec.Decode(nil, Frame{Mode: ModeDTX, Quality: true, Data: speech})
	if err != nil {
		t.Fatalf("Decode(SID) error = %v", err)
	}
	if len(got) != FrameSamples {
		t.Fatalf("Decode(SID) samples = %d, want %d", len(got), FrameSamples)
	}
	if dec.prevMode != Mode740 {
		t.Fatalf("prevMode after SID = %d, want %d", dec.prevMode, Mode740)
	}
	if dec.core.lastDTXState != dtxStateDTX {
		t.Fatalf("lastDTXState after SID = %d, want %d", dec.core.lastDTXState, dtxStateDTX)
	}
	if dec.core.dtx.sidFrame != 1 || dec.core.dtx.validData != 0 {
		t.Fatalf("DTX SID flags after SID_FIRST = %d/%d, want 1/0", dec.core.dtx.sidFrame, dec.core.dtx.validData)
	}
	got, err = dec.Decode(nil, Frame{Mode: ModeNoData})
	if err != nil {
		t.Fatalf("Decode(no data) error = %v", err)
	}
	if len(got) != FrameSamples {
		t.Fatalf("Decode(no data) samples = %d, want %d", len(got), FrameSamples)
	}
	if dec.prevMode != Mode740 {
		t.Fatalf("prevMode after no-data = %d, want %d", dec.prevMode, Mode740)
	}
	if dec.core.lastDTXState != dtxStateDTX {
		t.Fatalf("lastDTXState after no-data = %d, want %d", dec.core.lastDTXState, dtxStateDTX)
	}
	if dec.core.dtx.sinceLastSID != 1 {
		t.Fatalf("sinceLastSID after no-data = %d, want 1", dec.core.dtx.sinceLastSID)
	}
}

func TestDecodeSIDUpdateRefreshesDTXState(t *testing.T) {
	dec := NewDecoder()
	params := []int16{2, 1, 2, 3, 10}
	speech, err := sidSpeech(params, Mode740, true)
	if err != nil {
		t.Fatalf("sidSpeech() error = %v", err)
	}

	got, err := dec.Decode(nil, Frame{Mode: ModeDTX, Quality: true, Data: speech})
	if err != nil {
		t.Fatalf("Decode(SID_UPDATE) error = %v", err)
	}
	if len(got) != FrameSamples {
		t.Fatalf("Decode(SID_UPDATE) samples = %d, want %d", len(got), FrameSamples)
	}
	if dec.prevMode != Mode740 {
		t.Fatalf("prevMode = %d, want %d", dec.prevMode, Mode740)
	}
	if dec.core.dtx.dataUpdated != 1 || dec.core.dtx.validData != 1 {
		t.Fatalf("DTX updated flags = data %d valid %d, want 1/1", dec.core.dtx.dataUpdated, dec.core.dtx.validData)
	}
	if dec.core.dtx.logEnergy != 0 {
		t.Fatalf("DTX logEnergy = %d, want 0", dec.core.dtx.logEnergy)
	}
	if dec.core.predState.pastQuaEn[0] != -9000 {
		t.Fatalf("predictor pastQuaEn[0] = %d, want -9000", dec.core.predState.pastQuaEn[0])
	}
}

func TestDecodeSIDFrameRejectsInvalidBit(t *testing.T) {
	serial := make([]byte, 39)
	serial[amrSIDRxModeBitOffset] = 2
	if _, _, err := decodeSIDFrame(serial, true); err == nil {
		t.Fatal("decodeSIDFrame(invalid SID mode bit) error = nil")
	}
}

func TestDecoderFrameParamsAcceptsDefinedSerialLayouts(t *testing.T) {
	speechBits, err := ParameterSerialBits(Mode475)
	if err != nil {
		t.Fatalf("ParameterSerialBits() error = %v", err)
	}
	sidBits, err := FrameBitLen(ModeDTX)
	if err != nil {
		t.Fatalf("FrameBitLen(DTX) error = %v", err)
	}
	tests := []struct {
		name    string
		rxType  RXFrameType
		serial  []byte
		wantErr bool
	}{
		{name: "compact speech", rxType: RXSpeechGood, serial: make([]byte, speechBits)},
		{name: "fixed ETS speech", rxType: RXSpeechGood, serial: make([]byte, MaxSerialBits)},
		{name: "compact SID first", rxType: RXSIDFirst, serial: make([]byte, sidBits)},
		{name: "empty no data", rxType: RXNoData, serial: nil},
		{name: "short speech", rxType: RXSpeechGood, serial: make([]byte, speechBits-1), wantErr: true},
		{name: "extra speech", rxType: RXSpeechGood, serial: make([]byte, speechBits+1), wantErr: true},
		{name: "short SID update", rxType: RXSIDUpdate, serial: make([]byte, sidBits-1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decoderFrameParams(nil, Mode475, tt.rxType, tt.serial)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decoderFrameParams() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func sidSpeech(params []int16, mode Mode, update bool) ([]byte, error) {
	paramBits, err := (Params{Mode: ModeDTX, Values: params}).Pack(nil)
	if err != nil {
		return nil, err
	}
	serial := make([]byte, frameBits[ModeDTX])
	copy(serial, paramBits)
	if update {
		serial[amrSIDRxTypeBitOffset] = 1
	}
	writeSIDMode(serial, mode)
	return (Speech{Mode: ModeDTX, Serial: serial}).Pack(nil)
}

func writeSIDMode(serial []byte, mode Mode) {
	for i := range numAMRSIDRxModeBits {
		serial[amrSIDRxModeBitOffset+i] = byte((mode >> i) & 1)
	}
}

func goodSpeechFrameParams(mode Mode) []int16 {
	switch mode {
	case Mode475:
		return []int16{
			0, 0, 0,
			197, 0, 0, 0,
			4, 0, 0,
			4, 0, 0, 0,
			4, 0, 0,
		}
	case Mode515:
		return []int16{
			0, 0, 0,
			197, 0, 0, 0,
			4, 0, 0, 0,
			4, 0, 0, 0,
			4, 0, 0, 0,
		}
	case Mode590:
		return []int16{
			0, 0, 0,
			197, 0, 0, 0,
			20, 0, 0, 0,
			197, 0, 0, 0,
			20, 0, 0, 0,
		}
	case Mode670:
		return []int16{
			0, 0, 0,
			197, 0, 0, 0,
			20, 0, 0, 0,
			197, 0, 0, 0,
			20, 0, 0, 0,
		}
	case Mode740:
		return []int16{
			0, 0, 0,
			197, 0, 0, 0,
			20, 0, 0, 0,
			197, 0, 0, 0,
			20, 0, 0, 0,
		}
	case Mode795:
		return []int16{
			0, 0, 0,
			197, 0, 0, 0, 0,
			20, 0, 0, 0, 0,
			197, 0, 0, 0, 0,
			20, 0, 0, 0, 0,
		}
	case Mode1020:
		return []int16{
			0, 0, 0,
			197, 0, 0, 0, 0, 0, 0, 0, 0,
			20, 0, 0, 0, 0, 0, 0, 0, 0,
			197, 0, 0, 0, 0, 0, 0, 0, 0,
			20, 0, 0, 0, 0, 0, 0, 0, 0,
		}
	case Mode1220:
		return []int16{
			0, 0, 0, 0, 0,
			463, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			463, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		}
	default:
		return nil
	}
}
