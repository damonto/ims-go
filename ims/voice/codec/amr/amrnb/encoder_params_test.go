package amrnb

import "testing"

func TestEncodeParamsMode1220ProducesPackableSpeech(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode1220})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%59)*86 - 1700)
	}

	if err := encoder.encodeParams(pcm); err != nil {
		t.Fatalf("encodeParams(MR122) error = %v", err)
	}

	if len(encoder.params) != MaxParameters {
		t.Fatalf("parameter count = %d, want %d", len(encoder.params), MaxParameters)
	}
	serial, err := (Params{Mode: Mode1220, Values: encoder.params}).Pack(nil)
	if err != nil {
		t.Fatalf("Params.Pack() error = %v", err)
	}
	speech, err := (Speech{Mode: Mode1220, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack() error = %v", err)
	}
	if len(speech) != 31 {
		t.Fatalf("speech byte count = %d, want 31", len(speech))
	}
}

func TestEncodeParamsJointGainModesProducePackableSpeech(t *testing.T) {
	tests := []struct {
		name  string
		mode  Mode
		bytes int
	}{
		{name: "MR475", mode: Mode475, bytes: 12},
		{name: "MR515", mode: Mode515, bytes: 13},
		{name: "MR590", mode: Mode590, bytes: 15},
		{name: "MR670", mode: Mode670, bytes: 17},
		{name: "MR740", mode: Mode740, bytes: 19},
		{name: "MR795", mode: Mode795, bytes: 20},
		{name: "MR102", mode: Mode1020, bytes: 26},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder, err := NewEncoder(Config{Mode: tt.mode})
			if err != nil {
				t.Fatalf("NewEncoder() error = %v", err)
			}
			pcm := make([]int16, FrameSamples)
			for i := range pcm {
				pcm[i] = int16((i%61)*78 - 1500)
			}

			if err := encoder.encodeParams(pcm); err != nil {
				t.Fatalf("encodeParams() error = %v", err)
			}
			serial, err := (Params{Mode: tt.mode, Values: encoder.params}).Pack(nil)
			if err != nil {
				t.Fatalf("Params.Pack() error = %v", err)
			}
			speech, err := (Speech{Mode: tt.mode, Serial: serial}).Pack(nil)
			if err != nil {
				t.Fatalf("Speech.Pack() error = %v", err)
			}
			if len(speech) != tt.bytes {
				t.Fatalf("speech byte count = %d, want %d", len(speech), tt.bytes)
			}
		})
	}
}

func TestEncodeSpeechModesProduceSpeechBytes(t *testing.T) {
	tests := []struct {
		name  string
		mode  Mode
		bytes int
	}{
		{name: "MR475", mode: Mode475, bytes: 12},
		{name: "MR515", mode: Mode515, bytes: 13},
		{name: "MR590", mode: Mode590, bytes: 15},
		{name: "MR670", mode: Mode670, bytes: 17},
		{name: "MR740", mode: Mode740, bytes: 19},
		{name: "MR795", mode: Mode795, bytes: 20},
		{name: "MR102", mode: Mode1020, bytes: 26},
		{name: "MR122", mode: Mode1220, bytes: 31},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder, err := NewEncoder(Config{Mode: tt.mode})
			if err != nil {
				t.Fatalf("NewEncoder() error = %v", err)
			}
			pcm := make([]int16, FrameSamples)
			for i := range pcm {
				pcm[i] = int16((i%67)*64 - 1600)
			}

			frame, err := encoder.Encode(nil, pcm)

			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if frame.Mode != tt.mode || !frame.Quality {
				t.Fatalf("frame metadata = %d/%v, want %d/true", frame.Mode, frame.Quality, tt.mode)
			}
			if len(frame.Data) != tt.bytes {
				t.Fatalf("speech byte count = %d, want %d", len(frame.Data), tt.bytes)
			}
		})
	}
}

func TestEncodeExplicitDTXProducesSIDUpdate(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: ModeDTX})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%41)*32 - 640)
	}

	frame, err := encoder.Encode(nil, pcm)

	if err != nil {
		t.Fatalf("Encode(ModeDTX) error = %v", err)
	}
	if frame.Mode != ModeDTX || !frame.Quality {
		t.Fatalf("SID frame metadata = %d/%v, want %d/true", frame.Mode, frame.Quality, ModeDTX)
	}
	if len(frame.Data) != 5 {
		t.Fatalf("SID byte count = %d, want 5", len(frame.Data))
	}
	sidSpeech := Speech{Mode: ModeDTX}
	if err := sidSpeech.UnmarshalBinary(frame.Data); err != nil {
		t.Fatalf("Speech.UnmarshalBinary(SID) error = %v", err)
	}
	serial := sidSpeech.Serial
	if serial[amrSIDRxTypeBitOffset] != 1 {
		t.Fatalf("SID type bit = %d, want update", serial[amrSIDRxTypeBitOffset])
	}
	mode, rxType, err := decodeSIDFrame(serial, true)
	if err != nil {
		t.Fatalf("decodeSIDFrame() error = %v", err)
	}
	if mode != Mode1220 || rxType != RXSIDUpdate {
		t.Fatalf("SID mode/rx = %d/%d, want %d/%d", mode, rxType, Mode1220, RXSIDUpdate)
	}
	sidParams := Params{Mode: ModeDTX}
	if err := sidParams.UnmarshalBinary(serial[:35]); err != nil {
		t.Fatalf("Params.UnmarshalBinary(SID) error = %v", err)
	}
	params := sidParams.Values
	if len(params) != 5 {
		t.Fatalf("SID parameter count = %d, want 5", len(params))
	}
	if params[4] < 0 || params[4] > 63 {
		t.Fatalf("SID log energy index = %d outside 6-bit range", params[4])
	}

	decoder := NewDecoder()
	out, err := decoder.Decode(nil, frame)
	if err != nil {
		t.Fatalf("Decode(SID) error = %v", err)
	}
	if len(out) != FrameSamples {
		t.Fatalf("decoded samples = %d, want %d", len(out), FrameSamples)
	}
}

func TestEncodeDTXSequenceProducesSIDAndNoData(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode1220, DTX: true})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	decoder := NewDecoder()
	silence := make([]int16, FrameSamples)
	var modes []Mode
	var sizes []int
	for range 13 {
		frame, err := encoder.Encode(nil, silence)
		if err != nil {
			t.Fatalf("Encode(DTX silence) error = %v", err)
		}
		modes = append(modes, frame.Mode)
		sizes = append(sizes, len(frame.Data))
		if _, err := decoder.Decode(nil, frame); err != nil {
			t.Fatalf("Decode(DTX mode %d) error = %v", frame.Mode, err)
		}
	}

	if modes[7] != ModeDTX || sizes[7] != 5 {
		t.Fatalf("first DTX frame = mode %d size %d, want SID_FIRST", modes[7], sizes[7])
	}
	for _, index := range []int{8, 9} {
		if modes[index] != ModeNoData || sizes[index] != 0 {
			t.Fatalf("DTX frame %d = mode %d size %d, want no-data", index, modes[index], sizes[index])
		}
	}
	if modes[10] != ModeDTX || sizes[10] != 5 {
		t.Fatalf("DTX frame 10 = mode %d size %d, want SID_UPDATE", modes[10], sizes[10])
	}
}

func TestEncodeDTXKeepsActiveSpeechMode(t *testing.T) {
	encoder, err := NewEncoder(Config{Mode: Mode795, DTX: true})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	pcm := make([]int16, FrameSamples)
	for i := range pcm {
		pcm[i] = int16((i%23 + 1) * 16)
	}

	frame, err := encoder.Encode(nil, pcm)

	if err != nil {
		t.Fatalf("Encode(active DTX) error = %v", err)
	}
	if frame.Mode != Mode795 || len(frame.Data) != 20 {
		t.Fatalf("active DTX frame = mode %d size %d, want Mode795/20", frame.Mode, len(frame.Data))
	}
}
