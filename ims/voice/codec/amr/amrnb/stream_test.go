package amrnb

import (
	"bytes"
	"encoding"
	"io"
	"slices"
	"testing"

	amrbitstream "github.com/damonto/ims-go/ims/voice/codec/amr/bitstream"
)

var (
	_ encoding.BinaryAppender    = Params{}
	_ encoding.BinaryMarshaler   = Params{}
	_ encoding.BinaryUnmarshaler = (*Params)(nil)
	_ io.WriterTo                = Params{}
	_ io.ReaderFrom              = (*Params)(nil)
	_ encoding.BinaryAppender    = Speech{}
	_ encoding.BinaryMarshaler   = Speech{}
	_ encoding.BinaryUnmarshaler = (*Speech)(nil)
	_ io.WriterTo                = Speech{}
	_ io.ReaderFrom              = (*Speech)(nil)
)

func TestParamsReadFromWriteTo(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
	}{
		{name: "speech", mode: Mode590},
		{name: "dtx", mode: ModeDTX},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			values := testParameterValues(t, tt.mode)
			wantBits, err := ParameterSerialBits(tt.mode)
			if err != nil {
				t.Fatalf("ParameterSerialBits() error = %v", err)
			}

			var buf bytes.Buffer
			n, err := (Params{Mode: tt.mode, Values: values}).WriteTo(&buf)
			if err != nil {
				t.Fatalf("Params.WriteTo() error = %v", err)
			}
			if n != int64(wantBits) {
				t.Fatalf("Params.WriteTo() wrote %d, want %d", n, wantBits)
			}

			decoded := Params{Mode: tt.mode}
			n, err = decoded.ReadFrom(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("Params.ReadFrom() error = %v", err)
			}
			if n != int64(wantBits) {
				t.Fatalf("Params.ReadFrom() read %d, want %d", n, wantBits)
			}
			if !slices.Equal(decoded.Values, values) {
				t.Fatalf("Params.ReadFrom() = %v, want %v", decoded.Values, values)
			}
		})
	}
}

func TestParamsAppendBinaryPreservesPrefix(t *testing.T) {
	prefix := []byte{9, 8}
	values := testParameterValues(t, Mode590)
	got, err := (Params{Mode: Mode590, Values: values}).AppendBinary(prefix)
	if err != nil {
		t.Fatalf("Params.AppendBinary() error = %v", err)
	}
	if !bytes.Equal(got[:len(prefix)], prefix) {
		t.Fatalf("Params.AppendBinary() prefix = %v, want %v", got[:len(prefix)], prefix)
	}
	if !bytes.Equal(prefix, []byte{9, 8}) {
		t.Fatalf("prefix = %v, want unchanged", prefix)
	}
}

func TestParamsReadFromRejectsShortInput(t *testing.T) {
	params := Params{Mode: Mode590}
	n, err := params.ReadFrom(bytes.NewReader([]byte{1, 0, 1}))
	if err == nil {
		t.Fatal("Params.ReadFrom() error = nil")
	}
	if n != 3 {
		t.Fatalf("Params.ReadFrom() read %d, want 3", n)
	}
}

func TestSpeechReadFromWriteTo(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
	}{
		{name: "speech", mode: Mode590},
		{name: "dtx", mode: ModeDTX},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serial := testSerialBits(t, tt.mode)
			wantBits, err := FrameBitLen(tt.mode)
			if err != nil {
				t.Fatalf("FrameBitLen() error = %v", err)
			}
			wantBytes := amrbitstream.ByteLen(wantBits)

			var buf bytes.Buffer
			n, err := (Speech{Mode: tt.mode, Serial: serial}).WriteTo(&buf)
			if err != nil {
				t.Fatalf("Speech.WriteTo() error = %v", err)
			}
			if n != int64(wantBytes) {
				t.Fatalf("Speech.WriteTo() wrote %d, want %d", n, wantBytes)
			}

			decoded := Speech{Mode: tt.mode}
			n, err = decoded.ReadFrom(bytes.NewReader(buf.Bytes()))
			if err != nil {
				t.Fatalf("Speech.ReadFrom() error = %v", err)
			}
			if n != int64(wantBytes) {
				t.Fatalf("Speech.ReadFrom() read %d, want %d", n, wantBytes)
			}
			if !slices.Equal(decoded.Serial, serial) {
				t.Fatalf("Speech.ReadFrom() = %v, want %v", decoded.Serial, serial)
			}
		})
	}
}

func TestSpeechAppendBinaryPreservesPrefix(t *testing.T) {
	prefix := []byte{9, 8}
	bits, err := FrameBitLen(Mode590)
	if err != nil {
		t.Fatalf("FrameBitLen() error = %v", err)
	}
	serial := make([]byte, bits)
	for i := range serial {
		serial[i] = byte(i & 1)
	}
	got, err := (Speech{Mode: Mode590, Serial: serial}).AppendBinary(prefix)
	if err != nil {
		t.Fatalf("Speech.AppendBinary() error = %v", err)
	}
	if !bytes.Equal(got[:len(prefix)], prefix) {
		t.Fatalf("Speech.AppendBinary() prefix = %v, want %v", got[:len(prefix)], prefix)
	}
	if !bytes.Equal(prefix, []byte{9, 8}) {
		t.Fatalf("prefix = %v, want unchanged", prefix)
	}
}

func TestSpeechReadFromRejectsShortInput(t *testing.T) {
	speech := Speech{Mode: Mode590}
	n, err := speech.ReadFrom(bytes.NewReader([]byte{0x80}))
	if err == nil {
		t.Fatal("Speech.ReadFrom() error = nil")
	}
	if n != 1 {
		t.Fatalf("Speech.ReadFrom() read %d, want 1", n)
	}
}

func testParameterValues(t *testing.T, mode Mode) []int16 {
	t.Helper()
	widths, err := ParameterBits(mode)
	if err != nil {
		t.Fatalf("ParameterBits() error = %v", err)
	}
	values := make([]int16, len(widths))
	for i, width := range widths {
		values[i] = int16((i*11 + int(mode)) & ((1 << width) - 1))
	}
	return values
}

func testSerialBits(t *testing.T, mode Mode) []byte {
	t.Helper()
	bits, err := FrameBitLen(mode)
	if err != nil {
		t.Fatalf("FrameBitLen() error = %v", err)
	}
	serial := make([]byte, bits)
	for i := range serial {
		serial[i] = byte((i*7 + int(mode)) & 1)
	}
	return serial
}
