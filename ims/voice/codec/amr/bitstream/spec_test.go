package bitstream

import (
	"bytes"
	"io"
	"slices"
	"testing"
)

func TestParamSpecReadFromWriteTo(t *testing.T) {
	tests := []struct {
		name       string
		spec       ParamSpec
		values     []int16
		wantSerial []byte
	}{
		{
			name: "default serial bits",
			spec: ParamSpec{
				Codec: "test",
				Widths: func(int) ([]int, error) {
					return []int{2, 3}, nil
				},
			},
			values:     []int16{2, 5},
			wantSerial: []byte{1, 0, 1, 0, 1},
		},
		{
			name: "padded serial bits",
			spec: ParamSpec{
				Codec: "test",
				Widths: func(int) ([]int, error) {
					return []int{2}, nil
				},
				SerialBits: func(int) (int, error) {
					return 5, nil
				},
			},
			values:     []int16{3},
			wantSerial: []byte{1, 1, 0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			n, err := tt.spec.WriteParamsTo(&buf, 0, tt.values)
			if err != nil {
				t.Fatalf("ParamSpec.WriteParamsTo() error = %v", err)
			}
			if n != int64(len(tt.wantSerial)) {
				t.Fatalf("ParamSpec.WriteParamsTo() wrote %d, want %d", n, len(tt.wantSerial))
			}
			if !bytes.Equal(buf.Bytes(), tt.wantSerial) {
				t.Fatalf("ParamSpec.WriteParamsTo() = %v, want %v", buf.Bytes(), tt.wantSerial)
			}

			got, n, err := tt.spec.ReadParamsFrom(bytes.NewReader(buf.Bytes()), nil, 0)
			if err != nil {
				t.Fatalf("ParamSpec.ReadParamsFrom() error = %v", err)
			}
			if n != int64(len(tt.wantSerial)) {
				t.Fatalf("ParamSpec.ReadParamsFrom() read %d, want %d", n, len(tt.wantSerial))
			}
			if !slices.Equal(got, tt.values) {
				t.Fatalf("ParamSpec.ReadParamsFrom() = %v, want %v", got, tt.values)
			}
		})
	}
}

func TestParamSpecAppendBinaryPreservesPrefix(t *testing.T) {
	prefix := []byte{9, 8}
	spec := ParamSpec{
		Codec: "test",
		Widths: func(int) ([]int, error) {
			return []int{1, 1}, nil
		},
	}
	got, err := spec.AppendParams(prefix, 0, []int16{1, 0})
	if err != nil {
		t.Fatalf("ParamSpec.AppendParams() error = %v", err)
	}
	want := []byte{9, 8, 1, 0}
	if !bytes.Equal(got, want) {
		t.Fatalf("ParamSpec.AppendParams() = %v, want %v", got, want)
	}
	if !bytes.Equal(prefix, []byte{9, 8}) {
		t.Fatalf("prefix = %v, want unchanged", prefix)
	}
}

func TestParamSpecUnmarshalBinaryRejectsLengthMismatch(t *testing.T) {
	spec := ParamSpec{
		Codec: "test",
		Widths: func(int) ([]int, error) {
			return []int{2}, nil
		},
		SerialBits: func(int) (int, error) {
			return 4, nil
		},
	}
	if _, err := spec.UnmarshalParams(nil, 0, []byte{1, 0}); err == nil {
		t.Fatal("ParamSpec.UnmarshalParams() error = nil")
	}
}

func TestParamSpecReadFromRejectsShortInput(t *testing.T) {
	spec := ParamSpec{
		Codec: "test",
		Widths: func(int) ([]int, error) {
			return []int{2, 2}, nil
		},
	}
	_, n, err := spec.ReadParamsFrom(bytes.NewReader([]byte{1, 0}), nil, 0)
	if err == nil {
		t.Fatal("ParamSpec.ReadParamsFrom() error = nil")
	}
	if n != 2 {
		t.Fatalf("ParamSpec.ReadParamsFrom() read %d, want 2", n)
	}
}

func TestParamSpecRejectsNegativeSerialBits(t *testing.T) {
	spec := ParamSpec{
		Codec: "test",
		Widths: func(int) ([]int, error) {
			return []int{1}, nil
		},
		SerialBits: func(int) (int, error) {
			return -1, nil
		},
	}
	if _, err := spec.ParameterSerialBits(0); err == nil {
		t.Fatal("ParamSpec.ParameterSerialBits() error = nil")
	}
}

func TestSpeechSpecReadFromWriteTo(t *testing.T) {
	spec := SpeechSpec{
		Codec: "test",
		Order: func(int) ([]int, error) {
			return []int{2, 0, 1, 3}, nil
		},
		BitLen: func(int) (int, error) {
			return 4, nil
		},
	}
	serial := []byte{1, 0, 1, 0}

	var buf bytes.Buffer
	n, err := spec.WriteSpeechTo(&buf, 0, serial)
	if err != nil {
		t.Fatalf("SpeechSpec.WriteSpeechTo() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("SpeechSpec.WriteSpeechTo() wrote %d, want 1", n)
	}
	if !bytes.Equal(buf.Bytes(), []byte{0xc0}) {
		t.Fatalf("SpeechSpec.WriteSpeechTo() = % X, want C0", buf.Bytes())
	}

	got, n, err := spec.ReadSpeechFrom(bytes.NewReader(buf.Bytes()), nil, 0)
	if err != nil {
		t.Fatalf("SpeechSpec.ReadSpeechFrom() error = %v", err)
	}
	if n != 1 {
		t.Fatalf("SpeechSpec.ReadSpeechFrom() read %d, want 1", n)
	}
	if !slices.Equal(got, serial) {
		t.Fatalf("SpeechSpec.ReadSpeechFrom() = %v, want %v", got, serial)
	}
}

func TestSpeechSpecAppendBinaryPreservesPrefix(t *testing.T) {
	prefix := []byte{9, 8}
	spec := SpeechSpec{
		Codec: "test",
		BitLen: func(int) (int, error) {
			return 2, nil
		},
	}
	got, err := spec.AppendSpeech(prefix, 0, []byte{1, 0})
	if err != nil {
		t.Fatalf("SpeechSpec.AppendSpeech() error = %v", err)
	}
	want := []byte{9, 8, 0x80}
	if !bytes.Equal(got, want) {
		t.Fatalf("SpeechSpec.AppendSpeech() = %v, want %v", got, want)
	}
	if !bytes.Equal(prefix, []byte{9, 8}) {
		t.Fatalf("prefix = %v, want unchanged", prefix)
	}
}

func TestSpeechSpecZeroBitLen(t *testing.T) {
	spec := SpeechSpec{
		Codec: "test",
		BitLen: func(int) (int, error) {
			return 0, nil
		},
	}
	data, err := spec.MarshalSpeech(0, nil)
	if err != nil {
		t.Fatalf("SpeechSpec.MarshalSpeech() error = %v", err)
	}
	if len(data) != 0 {
		t.Fatalf("SpeechSpec.MarshalSpeech() len = %d, want 0", len(data))
	}

	serial, n, err := spec.ReadSpeechFrom(bytes.NewReader(nil), nil, 0)
	if err != nil {
		t.Fatalf("SpeechSpec.ReadSpeechFrom() error = %v", err)
	}
	if n != 0 {
		t.Fatalf("SpeechSpec.ReadSpeechFrom() read %d, want 0", n)
	}
	if len(serial) != 0 {
		t.Fatalf("SpeechSpec.ReadSpeechFrom() len = %d, want 0", len(serial))
	}
}

func TestSpeechSpecRejectsNegativeBitLen(t *testing.T) {
	spec := SpeechSpec{
		Codec: "test",
		BitLen: func(int) (int, error) {
			return -1, nil
		},
	}
	if _, err := spec.MarshalSpeech(0, nil); err == nil {
		t.Fatal("SpeechSpec.MarshalSpeech() error = nil")
	}
}

func TestSpeechSpecReadFromRejectsShortInput(t *testing.T) {
	spec := SpeechSpec{
		Codec: "test",
		BitLen: func(int) (int, error) {
			return 9, nil
		},
	}
	_, n, err := spec.ReadSpeechFrom(bytes.NewReader([]byte{0x80}), nil, 0)
	if err == nil {
		t.Fatal("SpeechSpec.ReadSpeechFrom() error = nil")
	}
	if n != 1 {
		t.Fatalf("SpeechSpec.ReadSpeechFrom() read %d, want 1", n)
	}
	if err == io.EOF {
		t.Fatal("SpeechSpec.ReadSpeechFrom() error = EOF, want wrapped short read")
	}
}
