package amrwb

import "testing"

func TestDecodeAcelp2PIn64ZeroIndex(t *testing.T) {
	code, err := decodeAcelp2PIn64(0)
	if err != nil {
		t.Fatalf("decodeAcelp2PIn64() error = %v", err)
	}

	if code[0] != codePulseAmplitude || code[1] != codePulseAmplitude {
		t.Fatalf("code[0:2] = %d/%d, want %d/%d",
			code[0], code[1], codePulseAmplitude, codePulseAmplitude)
	}
	assertNonZeroCount(t, code[:], 2)
}

func TestDecodeAcelp2PIn64NegativeSigns(t *testing.T) {
	index := int16(32 | (32 << 6))

	code, err := decodeAcelp2PIn64(index)
	if err != nil {
		t.Fatalf("decodeAcelp2PIn64() error = %v", err)
	}

	if code[0] != -codePulseAmplitude || code[1] != -codePulseAmplitude {
		t.Fatalf("code[0:2] = %d/%d, want -%d/-%d",
			code[0], code[1], codePulseAmplitude, codePulseAmplitude)
	}
}

func TestDecodeAcelp4PIn64Zero20BitIndex(t *testing.T) {
	code, err := decodeAcelp4PIn64([]int16{0, 0, 0, 0}, 20)
	if err != nil {
		t.Fatalf("decodeAcelp4PIn64() error = %v", err)
	}
	for i := range codeTrackCount {
		if code[i] != codePulseAmplitude {
			t.Fatalf("code[%d] = %d, want %d", i, code[i], codePulseAmplitude)
		}
	}
	assertNonZeroCount(t, code[:], 4)
}

func TestDecodeAcelp4PIn64AllRatesProduceCode(t *testing.T) {
	tests := []struct {
		name  string
		nbits int16
		index []int16
	}{
		{name: "20", nbits: 20, index: []int16{1, 2, 3, 4}},
		{name: "36", nbits: 36, index: []int16{11, 22, 33, 44}},
		{name: "44", nbits: 44, index: []int16{111, 22, 333, 44}},
		{name: "52", nbits: 52, index: []int16{111, 222, 333, 444}},
		{name: "64", nbits: 64, index: []int16{0, 1, 2, 3, 111, 222, 333, 444}},
		{name: "72", nbits: 72, index: []int16{11, 22, 3, 0, 111, 222, 333, 444}},
		{name: "88", nbits: 88, index: []int16{11, 22, 33, 44, 111, 222, 333, 444}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := decodeAcelp4PIn64(tt.index, tt.nbits)
			if err != nil {
				t.Fatalf("decodeAcelp4PIn64() error = %v", err)
			}

			if countNonZero(code[:]) == 0 {
				t.Fatal("decoded codevector is all zero")
			}
		})
	}
}

func TestDecodeAcelpRejectsInvalidIndices(t *testing.T) {
	tests := []struct {
		name string
		run  func() ([subframeSamples]int16, error)
	}{
		{name: "negative 2-pulse index", run: func() ([subframeSamples]int16, error) {
			return decodeAcelp2PIn64(-1)
		}},
		{name: "large 2-pulse index", run: func() ([subframeSamples]int16, error) {
			return decodeAcelp2PIn64(1 << 12)
		}},
		{name: "unsupported width", run: func() ([subframeSamples]int16, error) {
			return decodeAcelp4PIn64(make([]int16, 8), 21)
		}},
		{name: "short index buffer", run: func() ([subframeSamples]int16, error) {
			return decodeAcelp4PIn64(make([]int16, 3), 20)
		}},
		{name: "negative track index", run: func() ([subframeSamples]int16, error) {
			return decodeAcelp4PIn64([]int16{-1, 0, 0, 0}, 20)
		}},
		{name: "track index above width", run: func() ([subframeSamples]int16, error) {
			return decodeAcelp4PIn64([]int16{32, 0, 0, 0}, 20)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, err := tt.run()
			if err == nil {
				t.Fatal("ACELP decode error = nil")
			}
			if code != ([subframeSamples]int16{}) {
				t.Fatalf("code = %v, want zero value", code)
			}
		})
	}
}

func assertNonZeroCount(t *testing.T, code []int16, want int) {
	t.Helper()
	if got := countNonZero(code); got != want {
		t.Fatalf("nonzero count = %d, want %d", got, want)
	}
}

func countNonZero(code []int16) int {
	count := 0
	for _, sample := range code {
		if sample != 0 {
			count++
		}
	}
	return count
}
