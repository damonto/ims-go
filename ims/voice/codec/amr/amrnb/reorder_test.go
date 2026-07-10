package amrnb

import (
	"bytes"
	"fmt"
	"testing"
)

func TestReorderTablesAreValidPermutations(t *testing.T) {
	for mode := Mode475; mode <= Mode1220; mode++ {
		table, err := ReorderBits(mode)
		if err != nil {
			t.Fatalf("ReorderBits(%d) error = %v", mode, err)
		}
		bits, err := FrameBitLen(mode)
		if err != nil {
			t.Fatalf("FrameBitLen(%d) error = %v", mode, err)
		}
		if len(table) != bits {
			t.Fatalf("ReorderBits(%d) length = %d, want %d", mode, len(table), bits)
		}
		seen := make([]bool, bits)
		for i, value := range table {
			if value < 0 || value >= bits {
				t.Fatalf("ReorderBits(%d)[%d] = %d outside 0..%d", mode, i, value, bits-1)
			}
			if seen[value] {
				t.Fatalf("ReorderBits(%d) duplicates %d", mode, value)
			}
			seen[value] = true
		}
	}
	table, err := ReorderBits(ModeDTX)
	if err != nil {
		t.Fatalf("ReorderBits(DTX) error = %v", err)
	}
	if table != nil {
		t.Fatalf("ReorderBits(DTX) = %v, want nil", table)
	}
	table, err = ReorderBits(ModeNoData)
	if err != nil {
		t.Fatalf("ReorderBits(NoData) error = %v", err)
	}
	if table != nil {
		t.Fatalf("ReorderBits(NoData) = %v, want nil", table)
	}
}

func TestReorderBitsReturnsCopy(t *testing.T) {
	table, err := ReorderBits(Mode475)
	if err != nil {
		t.Fatalf("ReorderBits() error = %v", err)
	}
	table[0] = -1

	got, err := ReorderBits(Mode475)
	if err != nil {
		t.Fatalf("ReorderBits() error = %v", err)
	}
	if got[0] == -1 {
		t.Fatal("ReorderBits() reused mutable table")
	}
}

func TestSpeechSerialRoundTrip(t *testing.T) {
	modes := []Mode{
		Mode475,
		Mode515,
		Mode590,
		Mode670,
		Mode740,
		Mode795,
		Mode1020,
		Mode1220,
		ModeDTX,
		ModeNoData,
	}
	for _, mode := range modes {
		t.Run(fmt.Sprintf("mode_%d", mode), func(t *testing.T) {
			bits, err := FrameBitLen(mode)
			if err != nil {
				t.Fatalf("FrameBitLen(%d) error = %v", mode, err)
			}
			serial := make([]byte, bits)
			for i := range serial {
				serial[i] = byte((i*7 + int(mode)) & 1)
			}
			speech, err := (Speech{Mode: mode, Serial: serial}).Pack(nil)
			if err != nil {
				t.Fatalf("Speech.Pack(%d) error = %v", mode, err)
			}
			decoded := Speech{Mode: mode}
			if err := decoded.UnmarshalBinary(speech); err != nil {
				t.Fatalf("Speech.UnmarshalBinary(%d) error = %v", mode, err)
			}
			got := decoded.Serial
			if !bytes.Equal(got, serial) {
				t.Fatalf("mode %d serial round trip mismatch", mode)
			}
		})
	}
}

func TestSpeechPackKnownMode475Vector(t *testing.T) {
	serial := make([]byte, 95)
	for _, index := range []int{0, 16, 22, 28, 36, 52, 67, 94} {
		serial[index] = 1
	}
	speech, err := (Speech{Mode: Mode475, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack() error = %v", err)
	}
	want := []byte{0x80, 0x00, 0x04, 0x00, 0x01, 0x00, 0x08, 0x00, 0x22, 0x08, 0x00, 0x08}
	if !bytes.Equal(speech, want) {
		t.Fatalf("speech = % X, want % X", speech, want)
	}
	decoded := Speech{Mode: Mode475}
	if err := decoded.UnmarshalBinary(want); err != nil {
		t.Fatalf("Speech.UnmarshalBinary() error = %v", err)
	}
	if !bytes.Equal(decoded.Serial, serial) {
		t.Fatal("known vector did not unpack to original serial bits")
	}
}

func TestSpeechSerialRejectsInvalidInput(t *testing.T) {
	if _, err := (Speech{Mode: Mode475, Serial: make([]byte, 94)}).Pack(nil); err == nil {
		t.Fatal("Speech.Pack(short serial) error = nil")
	}
	serial := make([]byte, 95)
	serial[3] = 2
	if _, err := (Speech{Mode: Mode475, Serial: serial}).Pack(nil); err == nil {
		t.Fatal("Speech.Pack(invalid bit) error = nil")
	}
	if err := (&Speech{Mode: Mode475}).UnmarshalBinary(make([]byte, 11)); err == nil {
		t.Fatal("Speech.UnmarshalBinary(short speech) error = nil")
	}
}
