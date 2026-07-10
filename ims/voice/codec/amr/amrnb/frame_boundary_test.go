package amrnb

import (
	"bytes"
	"testing"
)

func TestEncoderDecoderSerialBoundary(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode1220})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	dec := NewDecoder()
	bits, err := FrameBitLen(Mode1220)
	if err != nil {
		t.Fatalf("FrameBitLen() error = %v", err)
	}
	serial := make([]byte, bits)
	for i := range serial {
		serial[i] = byte((i >> 1) & 1)
	}
	frame, err := enc.EncodeSerial(nil, serial)
	if err != nil {
		t.Fatalf("EncodeSerial() error = %v", err)
	}
	got, err := dec.DecodeSerial(nil, frame)
	if err != nil {
		t.Fatalf("DecodeSerial() error = %v", err)
	}
	if !bytes.Equal(got, serial) {
		t.Fatal("DecodeSerial() did not recover the encoder serial bits")
	}
}

func TestDecodeValidatesSpeechBeforeAlgorithmPort(t *testing.T) {
	dec := NewDecoder()
	if _, err := dec.Decode(nil, Frame{Mode: Mode1220, Quality: true, Data: make([]byte, 30)}); err == nil {
		t.Fatal("Decode(short speech) error = nil")
	}
}

func TestDecodeGoodSpeechReturnsMaskedPCM(t *testing.T) {
	dec := NewDecoder()
	size, err := FrameBytes(Mode475)
	if err != nil {
		t.Fatalf("FrameBytes() error = %v", err)
	}
	pcm, err := dec.Decode(nil, Frame{Mode: Mode475, Quality: true, Data: make([]byte, size)})
	if err != nil {
		t.Fatalf("Decode(good speech) error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("len(pcm) = %d, want %d", len(pcm), FrameSamples)
	}
	for i, sample := range pcm {
		if sample&7 != 0 {
			t.Fatalf("pcm[%d] = %d, want 13-bit masked sample", i, sample)
		}
	}
}
