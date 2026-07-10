package payload

import (
	"bytes"
	"testing"
)

var testSpec = Spec{
	Codec: "AMR-Test",
	ValidMode: func(mode int) bool {
		return mode == 0 || mode == 15
	},
	FrameBytes: func(mode int) (int, error) {
		if mode == 15 {
			return 0, nil
		}
		return 2, nil
	},
}

func TestHeaderBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Header
		want []byte
	}{
		{name: "speech", in: Header{Mode: 0, Quality: true}, want: []byte{0x04}},
		{name: "no data", in: Header{Mode: 15}, want: []byte{0x78}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := testSpec.MarshalHeader(tt.in)
			if err != nil {
				t.Fatalf("MarshalHeader() error = %v", err)
			}
			if !bytes.Equal(data, tt.want) {
				t.Fatalf("MarshalHeader() = %x, want %x", data, tt.want)
			}
			var got Header
			if err := testSpec.UnmarshalHeader(&got, data); err != nil {
				t.Fatalf("UnmarshalHeader() error = %v", err)
			}
			if got != tt.in {
				t.Fatalf("UnmarshalHeader() = %+v, want %+v", got, tt.in)
			}
		})
	}
}

func TestFrameBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   Frame
		want []byte
	}{
		{name: "speech", in: Frame{Mode: 0, Quality: true, Data: []byte{0xaa, 0xbb}}, want: []byte{0x04, 0xaa, 0xbb}},
		{name: "empty", in: Frame{Mode: 15}, want: []byte{0x78}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := testSpec.MarshalFrame(tt.in)
			if err != nil {
				t.Fatalf("MarshalFrame() error = %v", err)
			}
			if !bytes.Equal(data, tt.want) {
				t.Fatalf("MarshalFrame() = %x, want %x", data, tt.want)
			}
			var got Frame
			if err := testSpec.UnmarshalFrame(&got, data); err != nil {
				t.Fatalf("UnmarshalFrame() error = %v", err)
			}
			if got.Mode != tt.in.Mode || got.Quality != tt.in.Quality || !bytes.Equal(got.Data, tt.in.Data) {
				t.Fatalf("UnmarshalFrame() = %+v/%x, want %+v/%x", got, got.Data, tt.in, tt.in.Data)
			}
		})
	}
}

func TestFrameReadFromWriteTo(t *testing.T) {
	var buf bytes.Buffer
	frame := Frame{Mode: 0, Quality: true, Data: []byte{0x10, 0x20}}
	written, err := testSpec.WriteFrame(&buf, frame)
	if err != nil {
		t.Fatalf("WriteFrame() error = %v", err)
	}
	if written != 3 {
		t.Fatalf("WriteFrame() bytes = %d, want 3", written)
	}
	var got Frame
	read, err := testSpec.ReadFrame(&buf, &got)
	if err != nil {
		t.Fatalf("ReadFrame() error = %v", err)
	}
	if read != written {
		t.Fatalf("ReadFrame() bytes = %d, want %d", read, written)
	}
	if got.Mode != frame.Mode || got.Quality != frame.Quality || !bytes.Equal(got.Data, frame.Data) {
		t.Fatalf("ReadFrame() = %+v/%x, want %+v/%x", got, got.Data, frame, frame.Data)
	}
}

func TestFrameBinaryRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "marshal invalid mode",
			run: func() error {
				_, err := testSpec.MarshalFrame(Frame{Mode: 1, Quality: true, Data: []byte{0xaa, 0xbb}})
				return err
			},
		},
		{
			name: "marshal bad payload length",
			run: func() error {
				_, err := testSpec.MarshalFrame(Frame{Mode: 0, Quality: true, Data: []byte{0xaa}})
				return err
			},
		},
		{
			name: "unmarshal empty",
			run: func() error {
				var frame Frame
				return testSpec.UnmarshalFrame(&frame, nil)
			},
		},
		{
			name: "unmarshal follow bit",
			run: func() error {
				var frame Frame
				return testSpec.UnmarshalFrame(&frame, []byte{headerFollowFlag})
			},
		},
		{
			name: "unmarshal padding bits",
			run: func() error {
				var frame Frame
				return testSpec.UnmarshalFrame(&frame, []byte{0x01})
			},
		},
		{
			name: "unmarshal bad payload length",
			run: func() error {
				var frame Frame
				return testSpec.UnmarshalFrame(&frame, []byte{0x04, 0xaa})
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
