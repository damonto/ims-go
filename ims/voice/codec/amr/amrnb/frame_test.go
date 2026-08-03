package amrnb

import (
	"bytes"
	"encoding"
	"io"
	"testing"
)

var (
	_ encoding.BinaryAppender    = Frame{}
	_ encoding.BinaryMarshaler   = Frame{}
	_ encoding.BinaryUnmarshaler = (*Frame)(nil)
	_ encoding.BinaryAppender    = FrameHeader{}
	_ encoding.BinaryMarshaler   = FrameHeader{}
	_ encoding.BinaryUnmarshaler = (*FrameHeader)(nil)
	_ io.WriterTo                = Frame{}
	_ io.WriterTo                = FrameHeader{}
)

func TestFrameHeaderBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   FrameHeader
		want []byte
	}{
		{name: "speech", in: FrameHeader{Mode: Mode475, Quality: true}, want: []byte{0x04}},
		{name: "no data", in: FrameHeader{Mode: ModeNoData}, want: []byte{0x78}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.in.MarshalBinary()
			if err != nil {
				t.Fatalf("FrameHeader.MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(data, tt.want) {
				t.Fatalf("FrameHeader.MarshalBinary() = %x, want %x", data, tt.want)
			}
			var got FrameHeader
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("FrameHeader.UnmarshalBinary() error = %v", err)
			}
			if got != tt.in {
				t.Fatalf("FrameHeader.UnmarshalBinary() = %+v, want %+v", got, tt.in)
			}
		})
	}
}

func TestFrameHeaderReadHeaderFromWriteTo(t *testing.T) {
	header := FrameHeader{Mode: ModeDTX, Quality: true}
	var buf bytes.Buffer

	written, err := header.WriteTo(&buf)
	if err != nil {
		t.Fatalf("FrameHeader.WriteTo() error = %v", err)
	}
	if written != 1 {
		t.Fatalf("FrameHeader.WriteTo() bytes = %d, want 1", written)
	}
	var got FrameHeader
	read, err := got.ReadHeaderFrom(&buf)
	if err != nil {
		t.Fatalf("FrameHeader.ReadHeaderFrom() error = %v", err)
	}
	if read != written {
		t.Fatalf("FrameHeader.ReadHeaderFrom() bytes = %d, want %d", read, written)
	}
	if got != header {
		t.Fatalf("FrameHeader.ReadHeaderFrom() = %+v, want %+v", got, header)
	}
}

func TestFrameBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name:  "speech",
			frame: Frame{Mode: Mode475, Quality: true, Data: []byte{0x80, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}},
		},
		{
			name:  "no data",
			frame: Frame{Mode: ModeNoData},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.frame.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got Frame
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Mode != tt.frame.Mode || got.Quality != tt.frame.Quality || !bytes.Equal(got.Data, tt.frame.Data) {
				t.Fatalf("round trip = %d/%v/% X, want %d/%v/% X",
					got.Mode, got.Quality, got.Data, tt.frame.Mode, tt.frame.Quality, tt.frame.Data)
			}
		})
	}
}

func TestFrameReadFrameFromWriteTo(t *testing.T) {
	frame := Frame{Mode: ModeDTX, Quality: true, Data: []byte{0x01, 0x23, 0x45, 0x67, 0x80}}
	var buf bytes.Buffer

	written, err := frame.WriteTo(&buf)
	if err != nil {
		t.Fatalf("WriteTo() error = %v", err)
	}
	if written != 6 {
		t.Fatalf("WriteTo() bytes = %d, want 6", written)
	}
	var got Frame
	read, err := got.ReadFrameFrom(&buf)
	if err != nil {
		t.Fatalf("ReadFrameFrom() error = %v", err)
	}
	if read != written {
		t.Fatalf("ReadFrameFrom() bytes = %d, want %d", read, written)
	}
	if got.Mode != frame.Mode || got.Quality != frame.Quality || !bytes.Equal(got.Data, frame.Data) {
		t.Fatalf("ReadFrameFrom() = %d/%v/% X, want %d/%v/% X",
			got.Mode, got.Quality, got.Data, frame.Mode, frame.Quality, frame.Data)
	}
}

func TestFrameBinaryRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "marshal length",
			run: func() error {
				_, err := (Frame{Mode: Mode475, Quality: true, Data: make([]byte, 11)}).MarshalBinary()
				return err
			},
		},
		{
			name: "unmarshal empty",
			run: func() error {
				var frame Frame
				return frame.UnmarshalBinary(nil)
			},
		},
		{
			name: "unmarshal follow bit",
			run: func() error {
				var frame Frame
				return frame.UnmarshalBinary([]byte{0x80})
			},
		},
		{
			name: "unmarshal padding bits",
			run: func() error {
				var frame Frame
				return frame.UnmarshalBinary([]byte{0x01})
			},
		},
		{
			name: "unmarshal length",
			run: func() error {
				var frame Frame
				return frame.UnmarshalBinary(append([]byte{0x04}, make([]byte, 11)...))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err == nil {
				t.Fatal("error = nil")
			}
		})
	}
}
