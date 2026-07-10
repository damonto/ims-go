package amrwb

import (
	"bytes"
	"fmt"
	"testing"
)

func TestSortTablesAreValidPermutations(t *testing.T) {
	for mode := Mode660; mode <= Mode2385; mode++ {
		table, err := SortBits(mode)
		if err != nil {
			t.Fatalf("SortBits(%d) error = %v", mode, err)
		}
		bits, err := FrameBitLen(mode)
		if err != nil {
			t.Fatalf("FrameBitLen(%d) error = %v", mode, err)
		}
		if len(table) != bits {
			t.Fatalf("SortBits(%d) length = %d, want %d", mode, len(table), bits)
		}
		seen := make([]bool, bits)
		for i, value := range table {
			if value < 0 || value >= bits {
				t.Fatalf("SortBits(%d)[%d] = %d outside 0..%d", mode, i, value, bits-1)
			}
			if seen[value] {
				t.Fatalf("SortBits(%d) duplicates %d", mode, value)
			}
			seen[value] = true
		}
	}
	for _, mode := range []Mode{ModeSpeechLost, ModeNoData} {
		table, err := SortBits(mode)
		if err != nil {
			t.Fatalf("SortBits(%d) error = %v", mode, err)
		}
		if table != nil {
			t.Fatalf("SortBits(%d) = %v, want nil", mode, table)
		}
	}
}

func TestSortBitsReturnsCopy(t *testing.T) {
	table, err := SortBits(Mode660)
	if err != nil {
		t.Fatalf("SortBits() error = %v", err)
	}
	table[0] = -1

	got, err := SortBits(Mode660)
	if err != nil {
		t.Fatalf("SortBits() error = %v", err)
	}
	if got[0] == -1 {
		t.Fatal("SortBits() reused mutable table")
	}
}

func TestSpeechSerialRoundTrip(t *testing.T) {
	modes := []Mode{
		Mode660,
		Mode885,
		Mode1265,
		Mode1425,
		Mode1585,
		Mode1825,
		Mode1985,
		Mode2305,
		Mode2385,
		ModeSpeechLost,
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
				serial[i] = byte((i*5 + int(mode)) & 1)
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

func TestSIDSpeechSerialRoundTripPreservesTypeBit(t *testing.T) {
	serial := make([]byte, 40)
	for i := 0; i < 35; i += 3 {
		serial[i] = 1
	}
	serial[amrWBSIDRxTypeBitOffset] = 1

	speech, err := (Speech{Mode: ModeSID, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(SID) error = %v", err)
	}
	if len(speech) != 5 {
		t.Fatalf("SID speech bytes = %d, want 5", len(speech))
	}
	decoded := Speech{Mode: ModeSID}
	if err := decoded.UnmarshalBinary(speech); err != nil {
		t.Fatalf("Speech.UnmarshalBinary(SID) error = %v", err)
	}
	got := decoded.Serial
	if !bytes.Equal(got, serial) {
		t.Fatal("SID serial round trip mismatch")
	}
}

func TestSpeechPackKnownMode660Vector(t *testing.T) {
	serial := make([]byte, 132)
	for _, index := range []int{0, 7, 84, 130, 62, 4, 38, 40, 125} {
		serial[index] = 1
	}
	speech, err := (Speech{Mode: Mode660, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack() error = %v", err)
	}
	want := []byte{
		0x95, 0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10,
	}
	if !bytes.Equal(speech, want) {
		t.Fatalf("speech = % X, want % X", speech, want)
	}
	decoded := Speech{Mode: Mode660}
	if err := decoded.UnmarshalBinary(want); err != nil {
		t.Fatalf("Speech.UnmarshalBinary() error = %v", err)
	}
	if !bytes.Equal(decoded.Serial, serial) {
		t.Fatal("known vector did not unpack to original serial bits")
	}
}

func TestSpeechSerialRejectsInvalidInput(t *testing.T) {
	if _, err := (Speech{Mode: Mode660, Serial: make([]byte, 131)}).Pack(nil); err == nil {
		t.Fatal("Speech.Pack(short serial) error = nil")
	}
	serial := make([]byte, 132)
	serial[3] = 2
	if _, err := (Speech{Mode: Mode660, Serial: serial}).Pack(nil); err == nil {
		t.Fatal("Speech.Pack(invalid bit) error = nil")
	}
	if err := (&Speech{Mode: Mode660}).UnmarshalBinary(make([]byte, 16)); err == nil {
		t.Fatal("Speech.UnmarshalBinary(short speech) error = nil")
	}
}
