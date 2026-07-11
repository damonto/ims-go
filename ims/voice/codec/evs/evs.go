// Package evs runs the 3GPP EVS reference codec in a wazero WebAssembly sandbox.
//
// Engine hides the WebAssembly runtime and compilation lifecycle. A Codec owns
// one isolated module instance and both encoder and decoder state. Codec methods
// mutate history and must be called serially.
package evs

import (
	"errors"
	"fmt"
)

const (
	ABIVersion = 2

	SampleRateNB  = 8000
	SampleRateWB  = 16000
	SampleRateSWB = 32000
	SampleRateFB  = 48000

	maxFrameBits = 2560
)

// Format identifies the codec mode carried by an EVS RTP payload frame.
type Format uint8

const (
	Native Format = iota
	AMRWBIO
)

func (f Format) String() string {
	switch f {
	case Native:
		return "EVS Native"
	case AMRWBIO:
		return "AMR-WB IO"
	default:
		return fmt.Sprintf("Format(%d)", f)
	}
}

// Bandwidth limits the encoded audio bandwidth.
type Bandwidth uint8

const (
	BandwidthNB Bandwidth = iota
	BandwidthWB
	BandwidthSWB
	BandwidthFB
)

// RFConfig enables channel-aware partial-copy encoding. It is valid only for
// native EVS at 13.2 kbit/s, non-NB input and non-NB bandwidth.
type RFConfig struct {
	Offset    int
	Indicator int
}

// EncoderConfig configures the stateful encoder. Configure may change these
// values between frames without resetting codec history.
type EncoderConfig struct {
	Bitrate   int
	Bandwidth Bandwidth
	DTX       bool
	RF        RFConfig
}

// Config describes one module instance containing an encoder and decoder.
type Config struct {
	SampleRate int
	Encoder    EncoderConfig
}

// Frame is one codec access unit extracted from an EVS RTP payload. It does not
// include the RTP payload header or compact/full-header mode framing.
//
// Bits is the number of codec-core bits. AMR-WB IO SID frames have 35 core
// bits and five auxiliary STI/CMI bits, so Data contains five bytes.
type Frame struct {
	Format        Format
	FrameType     int
	Quality       bool
	Bits          int
	Data          []byte
	Partial       bool
	NextCoderType int
}

// ErrClosed reports use after Codec.Close.
var ErrClosed = errors.New("EVS codec is closed")

// ErrEngineClosed reports codec creation after Engine.Close.
var ErrEngineClosed = errors.New("EVS engine is closed")

// FrameBits returns the codec-core bit count for format and frameType.
func FrameBits(format Format, frameType int) (int, error) {
	var bits int
	var ok bool
	switch format {
	case Native:
		bits, ok = nativeFrameBits[frameType]
	case AMRWBIO:
		bits, ok = amrwbIOFrameBits[frameType]
	default:
		return 0, fmt.Errorf("looking up EVS frame bits: invalid format %d", format)
	}
	if !ok {
		return 0, fmt.Errorf("looking up EVS frame bits: frame type %d is invalid for %s", frameType, format)
	}
	return bits, nil
}

// FrameBytes returns the number of bytes occupied by one access unit.
func FrameBytes(format Format, frameType int) (int, error) {
	bits, err := FrameBits(format, frameType)
	if err != nil {
		return 0, err
	}
	if format == AMRWBIO && frameType == 9 {
		return 5, nil
	}
	return (bits + 7) / 8, nil
}

func (f Frame) validate() error {
	bits, err := FrameBits(f.Format, f.FrameType)
	if err != nil {
		return err
	}
	if f.Bits == 0 {
		f.Bits = bits
	}
	if f.Bits != bits {
		return fmt.Errorf("validating EVS frame: bit count %d, want %d for %s FT=%d", f.Bits, bits, f.Format, f.FrameType)
	}
	bytes, err := FrameBytes(f.Format, f.FrameType)
	if err != nil {
		return err
	}
	if len(f.Data) != bytes {
		return fmt.Errorf("validating EVS frame: byte count %d, want %d for %s FT=%d", len(f.Data), bytes, f.Format, f.FrameType)
	}
	if f.Format == Native && f.FrameType == 14 && f.Quality {
		return errors.New("validating EVS frame: native speech-lost frame cannot have good quality")
	}
	if f.Partial && f.Format != Native {
		return errors.New("validating EVS frame: partial copy requires EVS Native")
	}
	return nil
}

func validSampleRate(sampleRate int) bool {
	return sampleRate == SampleRateNB || sampleRate == SampleRateWB ||
		sampleRate == SampleRateSWB || sampleRate == SampleRateFB
}

var nativeFrameBits = map[int]int{
	0: 56, 1: 144, 2: 160, 3: 192, 4: 264, 5: 328,
	6: 488, 7: 640, 8: 960, 9: 1280, 10: 1920, 11: 2560,
	12: 48, 14: 0, 15: 0,
}

var amrwbIOFrameBits = map[int]int{
	0: 132, 1: 177, 2: 253, 3: 285, 4: 317,
	5: 365, 6: 397, 7: 461, 8: 477, 9: 35,
	14: 0, 15: 0,
}
