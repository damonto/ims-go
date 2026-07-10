package amrwb

import "testing"

func TestResetGainDecoder(t *testing.T) {
	mem := resetGainDecoder()
	for i := range gainPredOrder {
		if mem[i] != -14336 {
			t.Fatalf("mem[%d] = %d, want -14336", i, mem[i])
		}
	}
	for i := gainPredOrder; i < len(mem)-1; i++ {
		if mem[i] != 0 {
			t.Fatalf("mem[%d] = %d, want 0", i, mem[i])
		}
	}
	if mem[22] != randomInitialSeed {
		t.Fatalf("mem[22] = %d, want %d", mem[22], randomInitialSeed)
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
	if mem[4] != gain.pitch {
		t.Fatalf("past pitch gain = %d, want %d", mem[4], gain.pitch)
	}
	if mem[12+4] != mem[5] {
		t.Fatalf("gbuf tail = %d, want past code gain %d", mem[12+4], mem[5])
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
	copy(mem[7:12], []int16{100, 400, 300, 500, 200})
	copy(mem[12:17], []int16{50, 90, 70, 110, 60})

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
	if mem[11] != mem[4] {
		t.Fatalf("pbuf tail = %d, want past pitch gain %d", mem[11], mem[4])
	}
	if mem[16] != mem[5] {
		t.Fatalf("gbuf tail = %d, want past code gain %d", mem[16], mem[5])
	}
}
