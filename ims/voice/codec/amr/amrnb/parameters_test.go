package amrnb

import "testing"

func TestParameterTablesMatchFrameBits(t *testing.T) {
	tests := []struct {
		mode       Mode
		parameters int
		frameBits  int
		paramBits  int
	}{
		{mode: Mode475, parameters: 17, frameBits: 95, paramBits: 95},
		{mode: Mode515, parameters: 19, frameBits: 103, paramBits: 103},
		{mode: Mode590, parameters: 19, frameBits: 118, paramBits: 118},
		{mode: Mode670, parameters: 19, frameBits: 134, paramBits: 134},
		{mode: Mode740, parameters: 19, frameBits: 148, paramBits: 148},
		{mode: Mode795, parameters: 23, frameBits: 159, paramBits: 159},
		{mode: Mode1020, parameters: 39, frameBits: 204, paramBits: 204},
		{mode: Mode1220, parameters: 57, frameBits: 244, paramBits: 244},
		{mode: ModeDTX, parameters: 5, frameBits: 39, paramBits: 35},
	}
	for _, tt := range tests {
		bits, err := ParameterBits(tt.mode)
		if err != nil {
			t.Fatalf("ParameterBits(%d) error = %v", tt.mode, err)
		}
		if len(bits) != tt.parameters {
			t.Fatalf("ParameterBits(%d) count = %d, want %d", tt.mode, len(bits), tt.parameters)
		}
		total := 0
		for _, width := range bits {
			total += width
		}
		if total != tt.paramBits {
			t.Fatalf("ParameterBits(%d) sum = %d, want %d", tt.mode, total, tt.paramBits)
		}
		gotTotal, err := ParameterSerialBits(tt.mode)
		if err != nil {
			t.Fatalf("ParameterSerialBits(%d) error = %v", tt.mode, err)
		}
		if gotTotal != tt.paramBits {
			t.Fatalf("ParameterSerialBits(%d) = %d, want %d", tt.mode, gotTotal, tt.paramBits)
		}
		if frameBits[tt.mode] != tt.frameBits {
			t.Fatalf("frameBits[%d] = %d, want %d", tt.mode, frameBits[tt.mode], tt.frameBits)
		}
	}
}

func TestParameterBitsReturnsCopy(t *testing.T) {
	bits, err := ParameterBits(Mode475)
	if err != nil {
		t.Fatalf("ParameterBits() error = %v", err)
	}
	bits[0] = 0

	got, err := ParameterBits(Mode475)
	if err != nil {
		t.Fatalf("ParameterBits() error = %v", err)
	}
	if got[0] != 8 {
		t.Fatalf("ParameterBits() reused mutable table, got first width %d, want 8", got[0])
	}
}

func TestParamsPackRoundTrip(t *testing.T) {
	for mode := Mode475; mode <= ModeDTX; mode++ {
		bits, err := ParameterBits(mode)
		if err != nil {
			t.Fatalf("ParameterBits(%d) error = %v", mode, err)
		}
		params := make([]int16, len(bits))
		for i, width := range bits {
			params[i] = int16((i*17 + int(mode)) & ((1 << width) - 1))
		}
		serial, err := (Params{Mode: mode, Values: params}).Pack(nil)
		if err != nil {
			t.Fatalf("Params.Pack(%d) error = %v", mode, err)
		}
		decoded := Params{Mode: mode}
		if err := decoded.UnmarshalBinary(serial); err != nil {
			t.Fatalf("Params.UnmarshalBinary(%d) error = %v", mode, err)
		}
		got := decoded.Values
		if len(got) != len(params) {
			t.Fatalf("mode %d got %d params, want %d", mode, len(got), len(params))
		}
		for i := range params {
			if got[i] != params[i] {
				t.Fatalf("mode %d param %d = %d, want %d", mode, i, got[i], params[i])
			}
		}
	}
}

func TestParamsPackRejectsInvalidInput(t *testing.T) {
	if _, err := (Params{Mode: Mode475, Values: make([]int16, 16)}).Pack(nil); err == nil {
		t.Fatal("Params.Pack(short params) error = nil")
	}
	params := make([]int16, 17)
	params[0] = 256
	if _, err := (Params{Mode: Mode475, Values: params}).Pack(nil); err == nil {
		t.Fatal("Params.Pack(overflow param) error = nil")
	}
	if err := (&Params{Mode: Mode475}).UnmarshalBinary(make([]byte, 94)); err == nil {
		t.Fatal("Params.UnmarshalBinary(short serial) error = nil")
	}
	serial := make([]byte, 95)
	serial[7] = 2
	if err := (&Params{Mode: Mode475}).UnmarshalBinary(serial); err == nil {
		t.Fatal("Params.UnmarshalBinary(invalid bit) error = nil")
	}
}
