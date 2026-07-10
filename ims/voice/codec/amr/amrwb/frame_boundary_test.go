package amrwb

import (
	"bytes"
	"testing"
)

func TestEncoderDecoderSerialBoundary(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode2385})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	dec := NewDecoder()
	bits, err := FrameBitLen(Mode2385)
	if err != nil {
		t.Fatalf("FrameBitLen() error = %v", err)
	}
	serial := make([]byte, bits)
	for i := range serial {
		serial[i] = byte((i >> 2) & 1)
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
	if _, err := dec.Decode(nil, Frame{Mode: Mode2385, Quality: true, Data: make([]byte, 59)}); err == nil {
		t.Fatal("Decode(short speech) error = nil")
	}
}

func TestDecodeRXErrorPreservesDecoderBuffers(t *testing.T) {
	invalidBit := make([]byte, frameBits[Mode2385])
	invalidBit[len(invalidBit)-1] = 2
	tests := []struct {
		name   string
		serial []byte
	}{
		{name: "short serial", serial: []byte{0}},
		{name: "invalid serial bit", serial: invalidBit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := NewDecoder()
			beforeMode := dec.modeOld

			if _, err := dec.DecodeRX(nil, Mode2385, tt.serial, RXSpeechGood); err == nil {
				t.Fatal("DecodeRX() error = nil")
			}
			if dec.modeOld != beforeMode {
				t.Fatalf("modeOld = %d, want unchanged %d", dec.modeOld, beforeMode)
			}
			if len(dec.serial) != 0 || len(dec.params) != 0 {
				t.Fatalf("decoder buffers = serial %d params %d, want 0/0", len(dec.serial), len(dec.params))
			}
		})
	}
}

func TestDecodeInitialHomingFrame(t *testing.T) {
	dec := NewDecoder()
	serial := homingSerial(Mode660, frameBits[Mode660])
	speech, err := (Speech{Mode: Mode660, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(homing) error = %v", err)
	}

	pcm, err := dec.Decode(nil, Frame{Mode: Mode660, Quality: true, Data: speech})

	if err != nil {
		t.Fatalf("Decode(initial homing) error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("pcm length = %d, want %d", len(pcm), FrameSamples)
	}
	if len(dec.params) == 0 {
		t.Fatal("decoder params were not prepared")
	}
	for i, sample := range pcm {
		if sample != encoderHomingFrameSample {
			t.Fatalf("pcm[%d] = %d, want EHF sample %d", i, sample, encoderHomingFrameSample)
		}
	}
	if !dec.resetFlagOld {
		t.Fatal("resetFlagOld = false, want homed state")
	}
}

func TestDecodeBadQualityDoesNotTriggerHoming(t *testing.T) {
	dec := NewDecoder()
	serial := homingSerial(Mode660, frameBits[Mode660])
	speech, err := (Speech{Mode: Mode660, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(homing) error = %v", err)
	}

	pcm, err := dec.Decode(nil, Frame{Mode: Mode660, Data: speech})

	if err != nil {
		t.Fatalf("Decode(bad quality homing) error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("pcm length = %d, want %d", len(pcm), FrameSamples)
	}
	if dec.resetFlagOld {
		t.Fatal("resetFlagOld = true after bad quality frame, want false")
	}
}

func TestDecodeLostInitialDTXComfortNoise(t *testing.T) {
	dec := NewDecoder()

	pcm, err := dec.DecodeLost(nil)

	if err != nil {
		t.Fatalf("DecodeLost() error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("pcm length = %d, want %d", len(pcm), FrameSamples)
	}
	if dec.core.dtx.globalState != dtxStateSpeech {
		t.Fatalf("dtx state = %d, want speech", dec.core.dtx.globalState)
	}
}

func TestDecodeSIDUpdateThenNoData(t *testing.T) {
	dec := NewDecoder()
	serial := make([]byte, 40)
	serial[amrWBSIDRxTypeBitOffset] = 1
	speech, err := (Speech{Mode: ModeSID, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(SID) error = %v", err)
	}

	pcm, err := dec.Decode(nil, Frame{Mode: ModeSID, Quality: true, Data: speech})
	if err != nil {
		t.Fatalf("Decode(SID update) error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("SID pcm length = %d, want %d", len(pcm), FrameSamples)
	}
	if dec.core.dtx.globalState != dtxStateDTX {
		t.Fatalf("dtx state after SID = %d, want DTX", dec.core.dtx.globalState)
	}

	pcm, err = dec.Decode(nil, Frame{Mode: ModeNoData})
	if err != nil {
		t.Fatalf("Decode(no-data) error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("no-data pcm length = %d, want %d", len(pcm), FrameSamples)
	}
	if dec.core.dtx.globalState != dtxStateDTX {
		t.Fatalf("dtx state after no-data = %d, want DTX", dec.core.dtx.globalState)
	}
}

func TestDecodeHomingStateTransitionsBeforeCorePort(t *testing.T) {
	dec := NewDecoder()
	serial := homingSerial(Mode885, frameBits[Mode885])
	serial[0] ^= 1
	speech, err := (Speech{Mode: Mode885, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(non-homing) error = %v", err)
	}

	pcm, err := dec.Decode(nil, Frame{Mode: Mode885, Quality: true, Data: speech})
	if err != nil {
		t.Fatalf("Decode(non-homing) error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("pcm length = %d, want %d", len(pcm), FrameSamples)
	}
	if dec.resetFlagOld {
		t.Fatal("resetFlagOld = true after non-homing frame, want false")
	}
	dec.core.seed = 123

	serial = homingSerial(Mode885, frameBits[Mode885])
	speech, err = (Speech{Mode: Mode885, Serial: serial}).Pack(nil)
	if err != nil {
		t.Fatalf("Speech.Pack(homing) error = %v", err)
	}
	pcm, err = dec.Decode(nil, Frame{Mode: Mode885, Quality: true, Data: speech})
	if err != nil {
		t.Fatalf("Decode(non-homed homing) error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("pcm length = %d, want %d", len(pcm), FrameSamples)
	}
	if !dec.resetFlagOld {
		t.Fatal("resetFlagOld = false after full homing frame, want true")
	}
	if dec.core.seed != randomInitialSeed {
		t.Fatalf("core seed after homing reset = %d, want %d", dec.core.seed, randomInitialSeed)
	}

	dec.Reset()
	if !dec.resetFlagOld || dec.modeOld != Mode660 || len(dec.serial) != 0 || len(dec.params) != 0 {
		t.Fatalf("Reset state = mode %d reset %v serial %d params %d, want Mode660/true/0/0",
			dec.modeOld, dec.resetFlagOld, len(dec.serial), len(dec.params))
	}
}
