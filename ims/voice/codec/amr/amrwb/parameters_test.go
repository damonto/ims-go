package amrwb

import (
	"bytes"
	"testing"
)

func TestParameterBitsMatchFrameBits(t *testing.T) {
	for mode := Mode660; mode <= Mode2385; mode++ {
		widths, err := ParameterBits(mode)
		if err != nil {
			t.Fatalf("ParameterBits(%d) error = %v", mode, err)
		}
		got := 0
		for _, width := range widths {
			got += width
		}
		want, err := FrameBitLen(mode)
		if err != nil {
			t.Fatalf("FrameBitLen(%d) error = %v", mode, err)
		}
		if got != want {
			t.Fatalf("mode %d parameter bit sum = %d, want %d", mode, got, want)
		}
	}
}

func TestParameterBitsReturnsCopy(t *testing.T) {
	widths, err := ParameterBits(Mode660)
	if err != nil {
		t.Fatalf("ParameterBits() error = %v", err)
	}
	widths[0] = 0

	got, err := ParameterBits(Mode660)
	if err != nil {
		t.Fatalf("ParameterBits() error = %v", err)
	}
	if got[0] != 1 {
		t.Fatalf("ParameterBits() reused mutable table, got first width %d, want 1", got[0])
	}
}

func TestSerialParamsRoundTrip(t *testing.T) {
	for mode := Mode660; mode <= Mode2385; mode++ {
		bits, err := FrameBitLen(mode)
		if err != nil {
			t.Fatalf("FrameBitLen(%d) error = %v", mode, err)
		}
		serial := make([]byte, bits)
		for i := range serial {
			serial[i] = byte((i*7 + int(mode)) & 1)
		}

		decoded := Params{Mode: mode}
		if err := decoded.UnmarshalBinary(serial); err != nil {
			t.Fatalf("Params.UnmarshalBinary(%d) error = %v", mode, err)
		}
		params := decoded.Values
		got, err := (Params{Mode: mode, Values: params}).Pack(nil)
		if err != nil {
			t.Fatalf("Params.Pack(%d) error = %v", mode, err)
		}
		if !bytes.Equal(got, serial) {
			t.Fatalf("mode %d serial/params round trip mismatch", mode)
		}
	}
}

func TestSIDSerialParamsUseFirst35Bits(t *testing.T) {
	serial := make([]byte, 40)
	serial[0] = 1
	serial[5] = 1
	serial[11] = 1
	serial[17] = 1
	serial[22] = 1
	serial[27] = 1
	serial[34] = 1
	serial[amrWBSIDRxTypeBitOffset] = 1

	decoded := Params{Mode: ModeSID}
	if err := decoded.UnmarshalBinary(serial); err != nil {
		t.Fatalf("Params.UnmarshalBinary(SID) error = %v", err)
	}
	params := decoded.Values
	if len(params) != 7 {
		t.Fatalf("SID parameter count = %d, want 7", len(params))
	}
	got, err := (Params{Mode: ModeSID, Values: params}).Pack(nil)
	if err != nil {
		t.Fatalf("Params.Pack(SID) error = %v", err)
	}
	if !bytes.Equal(got[:35], serial[:35]) {
		t.Fatal("SID parameter bits did not round trip")
	}
	for i, bit := range got[35:] {
		if bit != 0 {
			t.Fatalf("SID non-parameter bit %d = %d, want 0", 35+i, bit)
		}
	}
}

func TestParamsUnmarshalBinaryKnownMode660Vector(t *testing.T) {
	serial := make([]byte, 132)
	serial[0] = 1
	serial[1] = 1
	serial[8] = 1
	serial[24] = 1
	serial[37] = 1

	decoded := Params{Mode: Mode660}
	if err := decoded.UnmarshalBinary(serial); err != nil {
		t.Fatalf("Params.UnmarshalBinary() error = %v", err)
	}
	params := decoded.Values
	want := []int16{1, 129, 0, 64, 0}
	for i := range want {
		if params[i] != want[i] {
			t.Fatalf("params[%d] = %d, want %d", i, params[i], want[i])
		}
	}
}

func TestParamsPackRejectsInvalidParameter(t *testing.T) {
	count, err := ParameterCount(Mode660)
	if err != nil {
		t.Fatalf("ParameterCount() error = %v", err)
	}
	params := make([]int16, count)
	params[0] = 2

	if _, err := (Params{Mode: Mode660, Values: params}).Pack(nil); err == nil {
		t.Fatal("Params.Pack(invalid parameter) error = nil")
	}
}
