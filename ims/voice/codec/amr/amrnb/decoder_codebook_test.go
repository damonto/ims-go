package amrnb

import "testing"

func TestDecode2I40At9BitsKnownVector(t *testing.T) {
	code := decode2I40At9Bits(1, 2, 64|5|(3<<3))

	assertOnlyPulses(t, code[:], map[int]int16{
		27: -8192,
		19: 8191,
	})
}

func TestDecode2I40At11BitsKnownVector(t *testing.T) {
	index := int16(1 + (4 << 1) + (3 << 4) + (5 << 6))
	code := decode2I40At11Bits(1, index)

	assertOnlyPulses(t, code[:], map[int]int16{
		23: 8191,
		29: -8192,
	})
}

func TestDecode2I40At11BitsNonSpecialTrack(t *testing.T) {
	index := int16(0 + (2 << 1) + (2 << 4) + (6 << 6))
	code := decode2I40At11Bits(2, index)

	assertOnlyPulses(t, code[:], map[int]int16{
		11: -8192,
		32: 8191,
	})
}

func TestDecode3I40At14BitsKnownVector(t *testing.T) {
	index := int16(6 + (1 << 3) + (4 << 4) + (5 << 8))
	code := decode3I40At14Bits(5, index)

	assertOnlyPulses(t, code[:], map[int]int16{
		30: 8191,
		23: -8192,
		27: 8191,
	})
}

func TestDecode4I40At17BitsKnownVector(t *testing.T) {
	index := int16(6 + (4 << 3) + (3 << 6) + (1 << 9) + (5 << 10))
	code := decode4I40At17Bits(10, index)

	assertOnlyPulses(t, code[:], map[int]int16{
		20: -8192,
		26: 8191,
		12: -8192,
		34: 8191,
	})
}

func TestDecode8I40At31BitsDuplicatePulses(t *testing.T) {
	code := decode8I40At31Bits([]int16{0, 1, 0, 1, 0, 0, 0})

	assertOnlyPulses(t, code[:], map[int]int16{
		0: 16382,
		1: -16382,
		2: 16382,
		3: -16382,
	})
}

func TestDecode8I40At31BitsDecompressedPositions(t *testing.T) {
	code := decode8I40At31Bits([]int16{0, 1, 0, 1, 1000, 321, 87})

	assertOnlyPulses(t, code[:], map[int]int16{
		6:  8191,
		9:  8191,
		26: 8191,
		31: -16382,
		32: 16382,
		33: -8191,
	})
}

func TestDecode10I40At35BitsKnownVector(t *testing.T) {
	code := decode10I40At35Bits([]int16{14, 0, 12, 3, 13, 1, 7, 2, 3, 0})

	assertOnlyPulses(t, code[:], map[int]int16{
		1:  4096,
		4:  4096,
		5:  4096,
		13: 8192,
		17: 4096,
		20: -4096,
		27: -4096,
		34: -4096,
		36: 4096,
	})
}

func TestDecoderCoreFixedCodebookScratch(t *testing.T) {
	state := newDecoderCoreState()
	state.code[0] = 111

	code := state.decodeFixed2I40At9Bits(0, 3, 0)
	assertOnlyPulses(t, code[:], map[int]int16{
		0: 8191,
		2: 8191,
	})

	code = state.decodeFixed2I40At11Bits(0, 0)
	assertOnlyPulses(t, code[:], map[int]int16{
		1: -8192,
		0: -8192,
	})

	code = state.decodeFixed3I40At14Bits(0, 0)
	assertOnlyPulses(t, code[:], map[int]int16{
		0: -8192,
		1: -8192,
		2: -8192,
	})

	code = state.decodeFixed4I40At17Bits(0, 0)
	assertOnlyPulses(t, code[:], map[int]int16{
		0: -8192,
		1: -8192,
		2: -8192,
		3: -8192,
	})

	code = state.decodeFixed8I40At31Bits([]int16{0, 0, 0, 0, 0, 0, 0})
	assertOnlyPulses(t, code[:], map[int]int16{
		0: 16382,
		1: 16382,
		2: 16382,
		3: 16382,
	})

	code = state.decodeFixed10I40At35Bits([]int16{0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	assertOnlyPulses(t, code, map[int]int16{
		0: 8192,
		1: 8192,
		2: 8192,
		3: 8192,
		4: 8192,
	})
}

func assertOnlyPulses(t *testing.T, code []int16, pulses map[int]int16) {
	t.Helper()
	if len(code) < subframeSamples {
		t.Fatalf("code length = %d, want at least %d", len(code), subframeSamples)
	}
	for i := range subframeSamples {
		want := int16(0)
		if value, ok := pulses[i]; ok {
			want = value
		}
		if code[i] != want {
			t.Fatalf("code[%d] = %d, want %d", i, code[i], want)
		}
	}
}
