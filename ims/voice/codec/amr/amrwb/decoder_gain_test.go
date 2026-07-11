package amrwb

import "testing"

func TestResetGainDecoder(t *testing.T) {
	mem := resetGainDecoder()
	for i, energy := range mem.pastQuantizedEnergy {
		if energy != -14336 {
			t.Fatalf("past quantized energy[%d] = %d, want -14336", i, energy)
		}
	}
	want := gainDecoderState{pastQuantizedEnergy: [gainPredOrder]int16{-14336, -14336, -14336, -14336}, randomSeed: randomInitialSeed}
	if mem != want {
		t.Fatalf("reset state = %+v, want %+v", mem, want)
	}
	if mem.randomSeed != randomInitialSeed {
		t.Fatalf("random seed = %d, want %d", mem.randomSeed, randomInitialSeed)
	}
}

func TestDecodeGainUsesSelectedQuantizerEntry(t *testing.T) {
	mem := resetGainDecoder()
	var code [subframeSamples]int16
	code[0] = 512

	decoded, err := decodeGain(mem, gainDecodeInput{
		index:          63,
		nbits:          6,
		code:           code[:],
		subframeLength: subframeSamples,
	})
	if err != nil {
		t.Fatalf("decodeGain() error = %v", err)
	}
	gain := decoded.gains
	mem = decoded.memory

	if gain.pitch != 20371 {
		t.Fatalf("pitch gain = %d, want 20371", gain.pitch)
	}
	if gain.code == 0 {
		t.Fatal("code gain = 0, want non-zero")
	}
	if mem.pastPitchGain != gain.pitch {
		t.Fatalf("past pitch gain = %d, want %d", mem.pastPitchGain, gain.pitch)
	}
	if mem.codeHistory[4] != mem.pastCodeGain {
		t.Fatalf("code history tail = %d, want past code gain %d", mem.codeHistory[4], mem.pastCodeGain)
	}
}

func TestDecodeGainSevenBitTable(t *testing.T) {
	mem := resetGainDecoder()
	var code [subframeSamples]int16
	code[0] = 512

	decoded, err := decodeGain(mem, gainDecodeInput{
		index:          127,
		nbits:          7,
		code:           code[:],
		subframeLength: subframeSamples,
	})
	if err != nil {
		t.Fatalf("decodeGain() error = %v", err)
	}
	gain := decoded.gains

	if gain.pitch != 21234 {
		t.Fatalf("pitch gain = %d, want 21234", gain.pitch)
	}
}

func TestDecodeGainRejectsInvalidInputWithoutStateChange(t *testing.T) {
	memory := resetGainDecoder()
	code := make([]int16, subframeSamples)
	tests := []struct {
		name  string
		input gainDecodeInput
	}{
		{name: "invalid width", input: gainDecodeInput{nbits: 5, code: code}},
		{name: "negative index", input: gainDecodeInput{index: -1, nbits: 6, code: code}},
		{name: "index above table", input: gainDecodeInput{index: 64, nbits: 6, code: code}},
		{name: "short code", input: gainDecodeInput{nbits: 6, code: code[:subframeSamples-1]}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeGain(memory, tt.input)
			if err == nil {
				t.Fatal("decodeGain() error = nil")
			}
			if got.memory != memory || got.gains != (decodedGains{}) {
				t.Fatalf("decodeGain() result = %+v, want unchanged memory and zero gains", got)
			}
		})
	}
}

func TestDecodeErasedGainUsesMedianHistory(t *testing.T) {
	mem := resetGainDecoder()
	copy(mem.pitchHistory[:], []int16{100, 400, 300, 500, 200})
	copy(mem.codeHistory[:], []int16{50, 90, 70, 110, 60})

	decoded, err := decodeGain(mem, gainDecodeInput{
		badFrame:       true,
		code:           make([]int16, subframeSamples),
		state:          1,
		subframeLength: subframeSamples,
	})
	if err != nil {
		t.Fatalf("decodeGain() error = %v", err)
	}
	gain := decoded.gains
	mem = decoded.memory

	if gain.pitch == 0 {
		t.Fatal("pitch gain = 0, want concealed gain from history")
	}
	if mem.pitchHistory[4] != mem.pastPitchGain {
		t.Fatalf("pitch history tail = %d, want past pitch gain %d", mem.pitchHistory[4], mem.pastPitchGain)
	}
	if mem.codeHistory[4] != mem.pastCodeGain {
		t.Fatalf("code history tail = %d, want past code gain %d", mem.codeHistory[4], mem.pastCodeGain)
	}
}
