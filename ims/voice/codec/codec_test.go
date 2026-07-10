package codec_test

import (
	"bytes"
	"encoding"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/damonto/ims-go/ims/voice"
	"github.com/damonto/ims-go/ims/voice/codec"
)

var (
	_ encoding.BinaryMarshaler   = codec.Frame{}
	_ encoding.BinaryUnmarshaler = (*codec.Frame)(nil)
	_ io.WriterTo                = codec.Frame{}
	_ io.ReaderFrom              = (*codec.Frame)(nil)
)

func TestFrameBytes(t *testing.T) {
	tests := []struct {
		name  codec.Name
		mode  codec.Mode
		bytes int
	}{
		{name: codec.AMR, mode: codec.AMRMode475, bytes: 12},
		{name: codec.AMR, mode: codec.AMRMode515, bytes: 13},
		{name: codec.AMR, mode: codec.AMRMode590, bytes: 15},
		{name: codec.AMR, mode: codec.AMRMode670, bytes: 17},
		{name: codec.AMR, mode: codec.AMRMode740, bytes: 19},
		{name: codec.AMR, mode: codec.AMRMode795, bytes: 20},
		{name: codec.AMR, mode: codec.AMRMode1020, bytes: 26},
		{name: codec.AMR, mode: codec.AMRMode1220, bytes: 31},
		{name: codec.AMR, mode: codec.AMRModeDTX, bytes: 5},
		{name: codec.AMR, mode: codec.AMRModeNoData, bytes: 0},
		{name: codec.AMRWB, mode: codec.AMRWBMode660, bytes: 17},
		{name: codec.AMRWB, mode: codec.AMRWBMode885, bytes: 23},
		{name: codec.AMRWB, mode: codec.AMRWBMode1265, bytes: 32},
		{name: codec.AMRWB, mode: codec.AMRWBMode1425, bytes: 36},
		{name: codec.AMRWB, mode: codec.AMRWBMode1585, bytes: 40},
		{name: codec.AMRWB, mode: codec.AMRWBMode1825, bytes: 46},
		{name: codec.AMRWB, mode: codec.AMRWBMode1985, bytes: 50},
		{name: codec.AMRWB, mode: codec.AMRWBMode2305, bytes: 58},
		{name: codec.AMRWB, mode: codec.AMRWBMode2385, bytes: 60},
		{name: codec.AMRWB, mode: codec.AMRWBModeSID, bytes: 5},
		{name: codec.AMRWB, mode: codec.AMRWBModeSpeechLost, bytes: 0},
		{name: codec.AMRWB, mode: codec.AMRWBModeNoData, bytes: 0},
	}
	for _, tt := range tests {
		got, err := codec.FrameBytes(tt.name, tt.mode)
		if err != nil {
			t.Fatalf("FrameBytes(%s, %d) error = %v", tt.name, tt.mode, err)
		}
		if got != tt.bytes {
			t.Fatalf("FrameBytes(%s, %d) = %d, want %d", tt.name, tt.mode, got, tt.bytes)
		}
	}
}

func TestFrameBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		frame codec.Frame
	}{
		{
			name: "amr speech",
			frame: codec.Frame{
				Name:    codec.AMR,
				Mode:    codec.AMRMode475,
				Quality: true,
				Data:    testFrameData(t, codec.AMR, codec.AMRMode475, 0x11),
			},
		},
		{
			name: "amr no data",
			frame: codec.Frame{
				Name:    codec.AMR,
				Mode:    codec.AMRModeNoData,
				Quality: false,
			},
		},
		{
			name: "amr-wb speech",
			frame: codec.Frame{
				Name:    codec.AMRWB,
				Mode:    codec.AMRWBMode660,
				Quality: true,
				Data:    testFrameData(t, codec.AMRWB, codec.AMRWBMode660, 0x22),
			},
		},
		{
			name: "amr-wb sid",
			frame: codec.Frame{
				Name:    codec.AMRWB,
				Mode:    codec.AMRWBModeSID,
				Quality: true,
				Data:    testFrameData(t, codec.AMRWB, codec.AMRWBModeSID, 0x33),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.frame.MarshalBinary()
			if err != nil {
				t.Fatalf("Frame.MarshalBinary() error = %v", err)
			}
			if len(wire) != len(tt.frame.Data)+1 {
				t.Fatalf("binary frame length = %d, want %d", len(wire), len(tt.frame.Data)+1)
			}

			got := codec.Frame{Name: tt.frame.Name}
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("Frame.UnmarshalBinary() error = %v", err)
			}
			assertFrameEqual(t, got, tt.frame)
		})
	}
}

func TestFrameReadFromWriteTo(t *testing.T) {
	tests := []struct {
		name  string
		frame codec.Frame
	}{
		{
			name: "amr",
			frame: codec.Frame{
				Name:    codec.AMR,
				Mode:    codec.AMRMode590,
				Quality: true,
				Data:    testFrameData(t, codec.AMR, codec.AMRMode590, 0x44),
			},
		},
		{
			name: "amr-wb",
			frame: codec.Frame{
				Name:    codec.AMRWB,
				Mode:    codec.AMRWBMode885,
				Quality: true,
				Data:    testFrameData(t, codec.AMRWB, codec.AMRWBMode885, 0x55),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			written, err := tt.frame.WriteTo(&buf)
			if err != nil {
				t.Fatalf("Frame.WriteTo() error = %v", err)
			}
			if written != int64(len(tt.frame.Data)+1) {
				t.Fatalf("Frame.WriteTo() wrote %d, want %d", written, len(tt.frame.Data)+1)
			}

			got := codec.Frame{Name: tt.frame.Name}
			read, err := got.ReadFrom(&buf)
			if err != nil {
				t.Fatalf("Frame.ReadFrom() error = %v", err)
			}
			if read != written {
				t.Fatalf("Frame.ReadFrom() read %d, want %d", read, written)
			}
			assertFrameEqual(t, got, tt.frame)
		})
	}
}

func TestFrameStreamReadWrite(t *testing.T) {
	tests := []struct {
		name   string
		codec  codec.Name
		frames []codec.Frame
	}{
		{
			name:  "amr",
			codec: codec.AMR,
			frames: []codec.Frame{
				{
					Name:    codec.AMR,
					Mode:    codec.AMRMode475,
					Quality: true,
					Data:    testFrameData(t, codec.AMR, codec.AMRMode475, 0x66),
				},
				{Name: codec.AMR, Mode: codec.AMRModeNoData},
			},
		},
		{
			name:  "amr-wb",
			codec: codec.AMRWB,
			frames: []codec.Frame{
				{
					Name:    codec.AMRWB,
					Mode:    codec.AMRWBMode660,
					Quality: true,
					Data:    testFrameData(t, codec.AMRWB, codec.AMRWBMode660, 0x77),
				},
				{
					Name:    codec.AMRWB,
					Mode:    codec.AMRWBModeSID,
					Quality: true,
					Data:    testFrameData(t, codec.AMRWB, codec.AMRWBModeSID, 0x88),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			writer := codec.NewFrameWriter(&buf)
			for _, frame := range tt.frames {
				if _, err := writer.WriteFrame(frame); err != nil {
					t.Fatalf("FrameWriter.WriteFrame() error = %v", err)
				}
			}

			reader := codec.NewFrameReader(&buf, tt.codec)
			for i, want := range tt.frames {
				got, err := reader.ReadFrame()
				if err != nil {
					t.Fatalf("FrameReader.ReadFrame(%d) error = %v", i, err)
				}
				assertFrameEqual(t, got, want)
			}
			if _, err := reader.ReadFrame(); !errors.Is(err, io.EOF) {
				t.Fatalf("FrameReader.ReadFrame() error = %v, want io.EOF", err)
			}
		})
	}
}

func TestFrameBinaryRejectsUnsupportedCodec(t *testing.T) {
	tests := []struct {
		name  string
		frame codec.Frame
	}{
		{
			name:  "unknown",
			frame: codec.Frame{Name: codec.Name("bogus")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.frame.MarshalBinary(); !errors.Is(err, codec.ErrUnsupportedCodec) {
				t.Fatalf("Frame.MarshalBinary() error = %v, want ErrUnsupportedCodec", err)
			}
			got := codec.Frame{Name: tt.frame.Name}
			if err := got.UnmarshalBinary([]byte{0}); !errors.Is(err, codec.ErrUnsupportedCodec) {
				t.Fatalf("Frame.UnmarshalBinary() error = %v, want ErrUnsupportedCodec", err)
			}
		})
	}
}

func TestFactoriesExposeMetadata(t *testing.T) {
	tests := []struct {
		name         codec.Name
		mode         codec.Mode
		sampleRate   int
		frameSamples int
	}{
		{name: codec.AMR, mode: codec.AMRMode1220, sampleRate: 8000, frameSamples: 160},
		{name: codec.AMRWB, mode: codec.AMRWBMode2385, sampleRate: 16000, frameSamples: 320},
	}
	for _, tt := range tests {
		cfg := codec.Config{Name: tt.name, Mode: tt.mode}
		enc, err := codec.NewEncoder(cfg)
		if err != nil {
			t.Fatalf("NewEncoder(%s) error = %v", tt.name, err)
		}
		if enc.Name() != tt.name || enc.SampleRate() != tt.sampleRate || enc.FrameSamples() != tt.frameSamples {
			t.Fatalf("encoder metadata = %s/%d/%d", enc.Name(), enc.SampleRate(), enc.FrameSamples())
		}
		dec, err := codec.NewDecoder(tt.name)
		if err != nil {
			t.Fatalf("NewDecoder(%s) error = %v", tt.name, err)
		}
		if dec.Name() != tt.name || dec.SampleRate() != tt.sampleRate || dec.FrameSamples() != tt.frameSamples {
			t.Fatalf("decoder metadata = %s/%d/%d", dec.Name(), dec.SampleRate(), dec.FrameSamples())
		}
	}
}

func TestAMRSpeechModesEncodeDecodeThroughPublicAPI(t *testing.T) {
	tests := []struct {
		name         codec.Name
		modes        []codec.Mode
		sampleRate   int
		frameSamples int
	}{
		{
			name: codec.AMR,
			modes: []codec.Mode{
				codec.AMRMode475,
				codec.AMRMode515,
				codec.AMRMode590,
				codec.AMRMode670,
				codec.AMRMode740,
				codec.AMRMode795,
				codec.AMRMode1020,
				codec.AMRMode1220,
			},
			sampleRate:   8000,
			frameSamples: 160,
		},
		{
			name: codec.AMRWB,
			modes: []codec.Mode{
				codec.AMRWBMode660,
				codec.AMRWBMode885,
				codec.AMRWBMode1265,
				codec.AMRWBMode1425,
				codec.AMRWBMode1585,
				codec.AMRWBMode1825,
				codec.AMRWBMode1985,
				codec.AMRWBMode2305,
				codec.AMRWBMode2385,
			},
			sampleRate:   16000,
			frameSamples: 320,
		},
	}

	for _, tt := range tests {
		for _, mode := range tt.modes {
			t.Run(fmt.Sprintf("%s/mode-%d", tt.name, mode), func(t *testing.T) {
				enc, err := codec.NewEncoder(codec.Config{Name: tt.name, Mode: mode})
				if err != nil {
					t.Fatalf("NewEncoder() error = %v", err)
				}
				if enc.Name() != tt.name ||
					enc.SampleRate() != tt.sampleRate ||
					enc.FrameSamples() != tt.frameSamples {
					t.Fatalf("encoder metadata = %s/%d/%d",
						enc.Name(), enc.SampleRate(), enc.FrameSamples())
				}

				frame, err := enc.Encode(nil, publicAPISpeechPCM(enc.FrameSamples(), int(mode)))
				if err != nil {
					t.Fatalf("Encode() error = %v", err)
				}
				if frame.Name != tt.name || frame.Mode != mode || !frame.Quality {
					t.Fatalf("frame metadata = %s/%d/%v", frame.Name, frame.Mode, frame.Quality)
				}
				wantBytes, err := codec.FrameBytes(tt.name, mode)
				if err != nil {
					t.Fatalf("FrameBytes() error = %v", err)
				}
				if len(frame.Data) != wantBytes {
					t.Fatalf("encoded bytes = %d, want %d", len(frame.Data), wantBytes)
				}

				dec, err := codec.NewDecoder(tt.name)
				if err != nil {
					t.Fatalf("NewDecoder() error = %v", err)
				}
				pcm, err := dec.Decode(nil, frame)
				if err != nil {
					t.Fatalf("Decode() error = %v", err)
				}
				if len(pcm) != tt.frameSamples {
					t.Fatalf("decoded samples = %d, want %d", len(pcm), tt.frameSamples)
				}
			})
		}
	}
}

func publicAPISpeechPCM(samples int, seed int) []int16 {
	pcm := make([]int16, samples)
	for i := range pcm {
		value := ((i*37 + seed*101) % 4096) - 2048
		pcm[i] = int16(value * 4)
	}
	return pcm
}

func TestAMRNBEncoderProducesFrame(t *testing.T) {
	enc, err := codec.NewEncoder(codec.Config{Name: codec.AMR, Mode: codec.AMRMode1220})
	if err != nil {
		t.Fatalf("NewEncoder(AMR) error = %v", err)
	}
	if _, err := enc.Encode(nil, make([]int16, enc.FrameSamples()-1)); err == nil {
		t.Fatal("AMR Encode() error = nil, want bad sample count")
	}

	frame, err := enc.Encode(nil, make([]int16, enc.FrameSamples()))

	if err != nil {
		t.Fatalf("AMR Encode() error = %v", err)
	}
	if frame.Name != codec.AMR || frame.Mode != codec.AMRMode1220 || !frame.Quality {
		t.Fatalf("AMR frame metadata = %s/%d/%v", frame.Name, frame.Mode, frame.Quality)
	}
	if len(frame.Data) != 31 {
		t.Fatalf("AMR frame byte count = %d, want 31", len(frame.Data))
	}
}

func TestAMRNBEncoderProducesDTXFrame(t *testing.T) {
	enc, err := codec.NewEncoder(codec.Config{Name: codec.AMR, Mode: codec.AMRModeDTX})
	if err != nil {
		t.Fatalf("NewEncoder(AMR DTX) error = %v", err)
	}

	frame, err := enc.Encode(nil, make([]int16, enc.FrameSamples()))

	if err != nil {
		t.Fatalf("AMR DTX Encode() error = %v", err)
	}
	if frame.Name != codec.AMR || frame.Mode != codec.AMRModeDTX || !frame.Quality {
		t.Fatalf("AMR DTX frame metadata = %s/%d/%v", frame.Name, frame.Mode, frame.Quality)
	}
	if len(frame.Data) != 5 {
		t.Fatalf("AMR DTX frame byte count = %d, want 5", len(frame.Data))
	}
	dec, err := codec.NewDecoder(codec.AMR)
	if err != nil {
		t.Fatalf("NewDecoder(AMR) error = %v", err)
	}
	pcm, err := dec.Decode(nil, frame)
	if err != nil {
		t.Fatalf("Decode(AMR DTX frame) error = %v", err)
	}
	if len(pcm) != dec.FrameSamples() {
		t.Fatalf("decoded samples = %d, want %d", len(pcm), dec.FrameSamples())
	}
}

func TestAMRNBEncoderDTXSequence(t *testing.T) {
	enc, err := codec.NewEncoder(codec.Config{Name: codec.AMR, Mode: codec.AMRMode1220, DTX: true})
	if err != nil {
		t.Fatalf("NewEncoder(AMR DTX) error = %v", err)
	}
	dec, err := codec.NewDecoder(codec.AMR)
	if err != nil {
		t.Fatalf("NewDecoder(AMR) error = %v", err)
	}
	silence := make([]int16, enc.FrameSamples())
	var frames []codec.Frame
	for range 13 {
		frame, err := enc.Encode(nil, silence)
		if err != nil {
			t.Fatalf("Encode(DTX silence) error = %v", err)
		}
		if _, err := dec.Decode(nil, frame); err != nil {
			t.Fatalf("Decode(DTX frame mode %d) error = %v", frame.Mode, err)
		}
		frames = append(frames, frame)
	}

	if frames[7].Mode != codec.AMRModeDTX || len(frames[7].Data) != 5 || !frames[7].Quality {
		t.Fatalf("first DTX frame = mode %d bytes %d quality %v, want SID_FIRST",
			frames[7].Mode, len(frames[7].Data), frames[7].Quality)
	}
	for _, index := range []int{8, 9} {
		if frames[index].Mode != codec.AMRModeNoData || len(frames[index].Data) != 0 || frames[index].Quality {
			t.Fatalf("DTX frame %d = mode %d bytes %d quality %v, want no-data",
				index, frames[index].Mode, len(frames[index].Data), frames[index].Quality)
		}
	}
	if frames[10].Mode != codec.AMRModeDTX || len(frames[10].Data) != 5 {
		t.Fatalf("DTX frame 10 = mode %d bytes %d, want SID_UPDATE", frames[10].Mode, len(frames[10].Data))
	}
}

func TestAMRWBEncoderProducesDecodableFrame(t *testing.T) {
	enc, err := codec.NewEncoder(codec.Config{Name: codec.AMRWB, Mode: codec.AMRWBMode2385})
	if err != nil {
		t.Fatalf("NewEncoder(AMR-WB) error = %v", err)
	}
	pcm := make([]int16, enc.FrameSamples())
	for i := range pcm {
		pcm[i] = int16((i%113 - 56) * 96)
	}
	if _, err := enc.Encode(nil, pcm[:enc.FrameSamples()-1]); err == nil {
		t.Fatal("AMR-WB Encode() error = nil, want bad sample count")
	}

	frame, err := enc.Encode(nil, pcm)

	if err != nil {
		t.Fatalf("AMR-WB Encode() error = %v", err)
	}
	if frame.Name != codec.AMRWB || frame.Mode != codec.AMRWBMode2385 || !frame.Quality {
		t.Fatalf("AMR-WB frame metadata = %s/%d/%v", frame.Name, frame.Mode, frame.Quality)
	}
	if len(frame.Data) != 60 {
		t.Fatalf("AMR-WB frame byte count = %d, want 60", len(frame.Data))
	}
	dec, err := codec.NewDecoder(codec.AMRWB)
	if err != nil {
		t.Fatalf("NewDecoder(AMR-WB) error = %v", err)
	}
	out, err := dec.Decode(nil, frame)
	if err != nil {
		t.Fatalf("Decode(AMR-WB encoded frame) error = %v", err)
	}
	if len(out) != dec.FrameSamples() {
		t.Fatalf("decoded samples = %d, want %d", len(out), dec.FrameSamples())
	}
}

func TestAMRWBEncoderHomingFrame(t *testing.T) {
	enc, err := codec.NewEncoder(codec.Config{Name: codec.AMRWB, Mode: codec.AMRWBMode660})
	if err != nil {
		t.Fatalf("NewEncoder(AMR-WB) error = %v", err)
	}
	pcm := make([]int16, enc.FrameSamples())
	for i := range pcm {
		pcm[i] = 0x0008
	}

	frame, err := enc.Encode(nil, pcm)

	if err != nil {
		t.Fatalf("AMR-WB Encode(homing) error = %v", err)
	}
	if frame.Name != codec.AMRWB || frame.Mode != codec.AMRWBMode660 || len(frame.Data) != 17 {
		t.Fatalf("AMR-WB homing frame = %s/%d/%d bytes", frame.Name, frame.Mode, len(frame.Data))
	}
	dec, err := codec.NewDecoder(codec.AMRWB)
	if err != nil {
		t.Fatalf("NewDecoder(AMR-WB) error = %v", err)
	}
	out, err := dec.Decode(nil, frame)
	if err != nil {
		t.Fatalf("Decode(AMR-WB homing frame) error = %v", err)
	}
	for i, sample := range out {
		if sample != 0x0008 {
			t.Fatalf("homing sample %d = %d, want 8", i, sample)
		}
	}
}

func TestDecoderValidatesFrameSize(t *testing.T) {
	dec, err := codec.NewDecoder(codec.AMRWB)
	if err != nil {
		t.Fatalf("NewDecoder() error = %v", err)
	}
	frame := codec.Frame{Name: codec.AMRWB, Mode: codec.AMRWBMode2385, Quality: true, Data: make([]byte, 59)}
	if _, err := dec.Decode(nil, frame); err == nil {
		t.Fatal("Decode() error = nil, want bad frame size")
	}
	frame.Data = append(frame.Data, 0)
	pcm, err := dec.Decode(nil, frame)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if len(pcm) != dec.FrameSamples() {
		t.Fatalf("len(pcm) = %d, want %d", len(pcm), dec.FrameSamples())
	}
}

func TestAMRWBEncoderDTXSequence(t *testing.T) {
	enc, err := codec.NewEncoder(codec.Config{Name: codec.AMRWB, Mode: codec.AMRWBMode2385, DTX: true})
	if err != nil {
		t.Fatalf("NewEncoder(AMR-WB DTX) error = %v", err)
	}
	dec, err := codec.NewDecoder(codec.AMRWB)
	if err != nil {
		t.Fatalf("NewDecoder(AMR-WB) error = %v", err)
	}
	silence := make([]int16, enc.FrameSamples())
	var frames []codec.Frame
	for range 13 {
		frame, err := enc.Encode(nil, silence)
		if err != nil {
			t.Fatalf("Encode(AMR-WB DTX silence) error = %v", err)
		}
		if _, err := dec.Decode(nil, frame); err != nil {
			t.Fatalf("Decode(AMR-WB DTX mode %d) error = %v", frame.Mode, err)
		}
		frames = append(frames, frame)
	}

	if frames[7].Mode != codec.AMRWBModeSID || len(frames[7].Data) != 5 || !frames[7].Quality {
		t.Fatalf("first AMR-WB DTX frame = mode %d bytes %d quality %v, want SID_FIRST",
			frames[7].Mode, len(frames[7].Data), frames[7].Quality)
	}
	for _, index := range []int{8, 9} {
		if frames[index].Mode != codec.AMRWBModeNoData || len(frames[index].Data) != 0 || frames[index].Quality {
			t.Fatalf("AMR-WB DTX frame %d = mode %d bytes %d quality %v, want no-data",
				index, frames[index].Mode, len(frames[index].Data), frames[index].Quality)
		}
	}
	if frames[10].Mode != codec.AMRWBModeSID || len(frames[10].Data) != 5 {
		t.Fatalf("AMR-WB DTX frame 10 = mode %d bytes %d, want SID_UPDATE",
			frames[10].Mode, len(frames[10].Data))
	}
}

func TestAMRWBDecoderHandlesSIDAndNoData(t *testing.T) {
	dec, err := codec.NewDecoder(codec.AMRWB)
	if err != nil {
		t.Fatalf("NewDecoder(AMR-WB) error = %v", err)
	}
	frame := codec.Frame{
		Name:    codec.AMRWB,
		Mode:    codec.AMRWBModeSID,
		Quality: true,
		Data:    []byte{0, 0, 0, 0, 0x10},
	}
	pcm, err := dec.Decode(nil, frame)
	if err != nil {
		t.Fatalf("Decode(AMR-WB SID) error = %v", err)
	}
	if len(pcm) != dec.FrameSamples() {
		t.Fatalf("SID decoded samples = %d, want %d", len(pcm), dec.FrameSamples())
	}

	frame = codec.Frame{Name: codec.AMRWB, Mode: codec.AMRWBModeNoData, Quality: false}
	pcm, err = dec.Decode(nil, frame)
	if err != nil {
		t.Fatalf("Decode(AMR-WB no-data) error = %v", err)
	}
	if len(pcm) != dec.FrameSamples() {
		t.Fatalf("no-data decoded samples = %d, want %d", len(pcm), dec.FrameSamples())
	}
}

func TestDecoderDecodesAMRGoodSpeechFrame(t *testing.T) {
	dec, err := codec.NewDecoder(codec.AMR)
	if err != nil {
		t.Fatalf("NewDecoder() error = %v", err)
	}
	frameBytes, err := codec.FrameBytes(codec.AMR, codec.AMRMode475)
	if err != nil {
		t.Fatalf("FrameBytes() error = %v", err)
	}
	pcm, err := dec.Decode(nil, codec.Frame{
		Name:    codec.AMR,
		Mode:    codec.AMRMode475,
		Quality: true,
		Data:    make([]byte, frameBytes),
	})
	if err != nil {
		t.Fatalf("Decode(AMR good speech) error = %v", err)
	}
	if len(pcm) != dec.FrameSamples() {
		t.Fatalf("len(pcm) = %d, want %d", len(pcm), dec.FrameSamples())
	}
}

func TestDecoderConcealsAMRLostFrame(t *testing.T) {
	dec, err := codec.NewDecoder(codec.AMR)
	if err != nil {
		t.Fatalf("NewDecoder() error = %v", err)
	}
	frameBytes, err := codec.FrameBytes(codec.AMR, codec.AMRMode590)
	if err != nil {
		t.Fatalf("FrameBytes() error = %v", err)
	}
	if _, err := dec.Decode(nil, codec.Frame{
		Name:    codec.AMR,
		Mode:    codec.AMRMode590,
		Quality: true,
		Data:    make([]byte, frameBytes),
	}); err != nil {
		t.Fatalf("Decode(AMR good speech) error = %v", err)
	}

	pcm, err := dec.DecodeLost(nil)

	if err != nil {
		t.Fatalf("DecodeLost() error = %v", err)
	}
	if len(pcm) != dec.FrameSamples() {
		t.Fatalf("len(pcm) = %d, want %d", len(pcm), dec.FrameSamples())
	}
}

func TestUnsupportedCodec(t *testing.T) {
	if _, err := codec.NewEncoder(codec.Config{Name: codec.AVS}); !errors.Is(err, codec.ErrUnsupportedCodec) {
		t.Fatalf("NewEncoder(AVS) error = %v, want ErrUnsupportedCodec", err)
	}
	if _, err := codec.NewDecoder(codec.Name("bogus")); !errors.Is(err, codec.ErrUnsupportedCodec) {
		t.Fatalf("NewDecoder(bogus) error = %v, want ErrUnsupportedCodec", err)
	}
}

func TestFrameCanUseVoiceAMRPayloadCodec(t *testing.T) {
	frameBytes, err := codec.FrameBytes(codec.AMRWB, codec.AMRWBMode2385)
	if err != nil {
		t.Fatalf("FrameBytes() error = %v", err)
	}
	frame := codec.Frame{
		Name:    codec.AMRWB,
		Mode:    codec.AMRWBMode2385,
		Quality: true,
		Data:    make([]byte, frameBytes),
	}
	media := voice.NegotiatedMedia{Codec: voice.CodecAMRWB, OctetAlign: true}
	payloadCodec := voice.AMRPayloadCodec{Media: media}
	payload, err := payloadCodec.Marshal(voice.AMRPayload{
		CMR: voice.AMRNoModeRequest,
		Frames: []voice.AMRFrame{{
			FrameType: int(frame.Mode),
			Quality:   frame.Quality,
			Data:      frame.Data,
		}},
	})
	if err != nil {
		t.Fatalf("AMRPayloadCodec.Marshal() error = %v", err)
	}
	got, err := payloadCodec.Unmarshal(payload)
	if err != nil {
		t.Fatalf("AMRPayloadCodec.Unmarshal() error = %v", err)
	}
	if len(got.Frames) != 1 {
		t.Fatalf("parsed frame count = %d, want 1", len(got.Frames))
	}
	roundTrip := codec.Frame{
		Name:    codec.AMRWB,
		Mode:    codec.Mode(got.Frames[0].FrameType),
		Quality: got.Frames[0].Quality,
		Data:    got.Frames[0].Data,
	}
	if roundTrip.Name != frame.Name || roundTrip.Mode != frame.Mode || !roundTrip.Quality || len(roundTrip.Data) != len(frame.Data) {
		t.Fatalf("round trip frame = %+v, want mode %d and %d bytes", roundTrip, frame.Mode, len(frame.Data))
	}
}

func TestAMRWBSIDFrameCanUseVoicePayloadCodec(t *testing.T) {
	frame := codec.Frame{
		Mode:    codec.AMRWBModeSID,
		Quality: true,
		Data:    []byte{0, 0, 0, 0, 0x10},
	}
	media := voice.NegotiatedMedia{Codec: voice.CodecAMRWB, OctetAlign: true}
	payloadCodec := voice.AMRPayloadCodec{Media: media}
	payload, err := payloadCodec.Marshal(voice.AMRPayload{
		CMR: voice.AMRNoModeRequest,
		Frames: []voice.AMRFrame{{
			FrameType: int(frame.Mode),
			Quality:   frame.Quality,
			Data:      frame.Data,
		}},
	})
	if err != nil {
		t.Fatalf("AMRPayloadCodec.Marshal(SID) error = %v", err)
	}
	got, err := payloadCodec.Unmarshal(payload)
	if err != nil {
		t.Fatalf("AMRPayloadCodec.Unmarshal(SID) error = %v", err)
	}
	if len(got.Frames) != 1 {
		t.Fatalf("parsed SID frame count = %d, want 1", len(got.Frames))
	}
	if got.Frames[0].FrameType != int(codec.AMRWBModeSID) ||
		!got.Frames[0].Quality ||
		len(got.Frames[0].Data) != len(frame.Data) {
		t.Fatalf("parsed SID frame = %+v", got.Frames[0])
	}
}

func testFrameData(t *testing.T, name codec.Name, mode codec.Mode, fill byte) []byte {
	t.Helper()
	n, err := codec.FrameBytes(name, mode)
	if err != nil {
		t.Fatalf("FrameBytes(%s, %d) error = %v", name, mode, err)
	}
	return bytes.Repeat([]byte{fill}, n)
}

func assertFrameEqual(t *testing.T, got, want codec.Frame) {
	t.Helper()
	if got.Name != want.Name ||
		got.Mode != want.Mode ||
		got.Quality != want.Quality ||
		!bytes.Equal(got.Data, want.Data) {
		t.Fatalf("frame = %+v, want %+v", got, want)
	}
}
