package codec

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/ims-go/ims/voice/codec/amr/amrnb"
	"github.com/damonto/ims-go/ims/voice/codec/amr/amrwb"
	"github.com/damonto/ims-go/ims/voice/codec/evs"
)

// Name identifies a speech codec family.
type Name string

const (
	// AMR identifies AMR narrowband, 8 kHz, 20 ms frames.
	AMR Name = "AMR"
	// AMRWB identifies AMR wideband, 16 kHz, 20 ms frames.
	AMRWB Name = "AMR-WB"
	// EVS identifies EVS Native and AMR-WB IO, 20 ms frames.
	EVS Name = "EVS"
	// AVS is reserved for a future AVS implementation.
	AVS Name = "AVS"
)

// Mode identifies a codec-specific bitrate or comfort-noise mode.
type Mode int

const (
	// AMRMode475 is AMR-NB 4.75 kbit/s.
	AMRMode475 Mode = Mode(amrnb.Mode475)
	// AMRMode515 is AMR-NB 5.15 kbit/s.
	AMRMode515 Mode = Mode(amrnb.Mode515)
	// AMRMode590 is AMR-NB 5.90 kbit/s.
	AMRMode590 Mode = Mode(amrnb.Mode590)
	// AMRMode670 is AMR-NB 6.70 kbit/s.
	AMRMode670 Mode = Mode(amrnb.Mode670)
	// AMRMode740 is AMR-NB 7.40 kbit/s.
	AMRMode740 Mode = Mode(amrnb.Mode740)
	// AMRMode795 is AMR-NB 7.95 kbit/s.
	AMRMode795 Mode = Mode(amrnb.Mode795)
	// AMRMode1020 is AMR-NB 10.2 kbit/s.
	AMRMode1020 Mode = Mode(amrnb.Mode1020)
	// AMRMode1220 is AMR-NB 12.2 kbit/s.
	AMRMode1220 Mode = Mode(amrnb.Mode1220)
	// AMRModeDTX is AMR-NB discontinuous transmission.
	AMRModeDTX Mode = Mode(amrnb.ModeDTX)
	// AMRModeNoData marks an AMR-NB no-data frame.
	AMRModeNoData Mode = Mode(amrnb.ModeNoData)
)

const (
	EVSMode2800       Mode = 0
	EVSMode7200       Mode = 1
	EVSMode8000       Mode = 2
	EVSMode9600       Mode = 3
	EVSMode13200      Mode = 4
	EVSMode16400      Mode = 5
	EVSMode24400      Mode = 6
	EVSMode32000      Mode = 7
	EVSMode48000      Mode = 8
	EVSMode64000      Mode = 9
	EVSMode96000      Mode = 10
	EVSMode128000     Mode = 11
	EVSModeSID        Mode = 12
	EVSModeSpeechLost Mode = 14
	EVSModeNoData     Mode = 15
)

const (
	// AMRWBMode660 is AMR-WB 6.60 kbit/s.
	AMRWBMode660 Mode = Mode(amrwb.Mode660)
	// AMRWBMode885 is AMR-WB 8.85 kbit/s.
	AMRWBMode885 Mode = Mode(amrwb.Mode885)
	// AMRWBMode1265 is AMR-WB 12.65 kbit/s.
	AMRWBMode1265 Mode = Mode(amrwb.Mode1265)
	// AMRWBMode1425 is AMR-WB 14.25 kbit/s.
	AMRWBMode1425 Mode = Mode(amrwb.Mode1425)
	// AMRWBMode1585 is AMR-WB 15.85 kbit/s.
	AMRWBMode1585 Mode = Mode(amrwb.Mode1585)
	// AMRWBMode1825 is AMR-WB 18.25 kbit/s.
	AMRWBMode1825 Mode = Mode(amrwb.Mode1825)
	// AMRWBMode1985 is AMR-WB 19.85 kbit/s.
	AMRWBMode1985 Mode = Mode(amrwb.Mode1985)
	// AMRWBMode2305 is AMR-WB 23.05 kbit/s.
	AMRWBMode2305 Mode = Mode(amrwb.Mode2305)
	// AMRWBMode2385 is AMR-WB 23.85 kbit/s.
	AMRWBMode2385 Mode = Mode(amrwb.Mode2385)
	// AMRWBModeSID is AMR-WB silence descriptor FT=9.
	AMRWBModeSID Mode = Mode(amrwb.ModeSID)
	// AMRWBModeSpeechLost marks an AMR-WB erased speech frame.
	AMRWBModeSpeechLost Mode = Mode(amrwb.ModeSpeechLost)
	// AMRWBModeNoData marks an AMR-WB no-data frame.
	AMRWBModeNoData Mode = Mode(amrwb.ModeNoData)
)

// ErrUnsupportedCodec reports a codec name that this package does not implement.
var ErrUnsupportedCodec = errors.New("unsupported codec")

// ErrSessionRequired reports codecs whose encoder and decoder state must share
// one call-scoped Session.
var ErrSessionRequired = errors.New("codec session is required")

// Config describes one codec instance.
type Config struct {
	Name Name
	Mode Mode
	DTX  bool
	EVS  EVSConfig
}

// Frame contains one encoded speech frame without RTP CMR or ToC bytes. EVS
// data is an access unit extracted from an EVS RTP payload, not a G.192 frame.
type Frame struct {
	Name    Name
	Mode    Mode
	Quality bool
	Data    []byte
	EVS     EVSFrame
}

// Encoder converts exactly one 20 ms PCM16 frame into one encoded speech frame.
type Encoder interface {
	Name() Name
	SampleRate() int
	FrameSamples() int
	Encode(ctx context.Context, dst []byte, pcm []int16) (Frame, error)
	Reset(ctx context.Context) error
	Close(ctx context.Context) error
}

// Decoder converts exactly one encoded speech frame into one 20 ms PCM16 frame.
type Decoder interface {
	Name() Name
	SampleRate() int
	FrameSamples() int
	Decode(ctx context.Context, dst []int16, frame Frame) ([]int16, error)
	DecodeLost(ctx context.Context, dst []int16) ([]int16, error)
	Reset(ctx context.Context) error
	Close(ctx context.Context) error
}

// NewEncoder creates an AMR or AMR-WB encoder. EVS requires a call-scoped
// Session so both directions preserve one continuous codec state.
func NewEncoder(ctx context.Context, cfg Config) (Encoder, error) {
	name := NormalizeName(cfg.Name)
	switch name {
	case AMR:
		enc, err := amrnb.NewEncoder(amrnb.Config{Mode: amrnb.Mode(cfg.Mode), DTX: cfg.DTX})
		if err != nil {
			return nil, err
		}
		return nbEncoder{enc: enc}, nil
	case AMRWB:
		enc, err := amrwb.NewEncoder(amrwb.Config{Mode: amrwb.Mode(cfg.Mode), DTX: cfg.DTX})
		if err != nil {
			return nil, err
		}
		return wbEncoder{enc: enc}, nil
	case EVS:
		return nil, fmt.Errorf("%w: %s", ErrSessionRequired, EVS)
	case AVS:
		return nil, fmt.Errorf("%w: %s implementation is not available", ErrUnsupportedCodec, AVS)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCodec, cfg.Name)
	}
}

// NewDecoder creates an AMR or AMR-WB decoder. EVS requires a call-scoped
// Session so both directions preserve one continuous codec state.
func NewDecoder(_ context.Context, name Name) (Decoder, error) {
	switch NormalizeName(name) {
	case AMR:
		return nbDecoder{dec: amrnb.NewDecoder()}, nil
	case AMRWB:
		return wbDecoder{dec: amrwb.NewDecoder()}, nil
	case EVS:
		return nil, fmt.Errorf("%w: %s", ErrSessionRequired, EVS)
	case AVS:
		return nil, fmt.Errorf("%w: %s implementation is not available", ErrUnsupportedCodec, AVS)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCodec, name)
	}
}

// NormalizeName maps common wire spellings onto the package codec names.
func NormalizeName(name Name) Name {
	switch strings.ToUpper(strings.TrimSpace(string(name))) {
	case "AMR":
		return AMR
	case "AMR-WB", "AMRWB":
		return AMRWB
	case "EVS":
		return EVS
	case "AVS":
		return AVS
	default:
		return name
	}
}

// FrameBytes returns the encoded speech byte count for one frame mode. EVS
// modes are interpreted as EVS Native; use EVSFrameBytes for AMR-WB IO.
func FrameBytes(name Name, mode Mode) (int, error) {
	switch NormalizeName(name) {
	case AMR:
		return amrnb.FrameBytes(amrnb.Mode(mode))
	case AMRWB:
		return amrwb.FrameBytes(amrwb.Mode(mode))
	case EVS:
		return evs.FrameBytes(evs.Native, int(mode))
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedCodec, name)
	}
}

type nbEncoder struct {
	enc *amrnb.Encoder
}

func (e nbEncoder) Name() Name { return AMR }

func (e nbEncoder) SampleRate() int { return amrnb.SampleRate }

func (e nbEncoder) FrameSamples() int { return amrnb.FrameSamples }

func (e nbEncoder) Encode(_ context.Context, dst []byte, pcm []int16) (Frame, error) {
	frame, err := e.enc.Encode(dst, pcm)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Name: AMR, Mode: Mode(frame.Mode), Quality: frame.Quality, Data: frame.Data}, nil
}

func (e nbEncoder) Reset(context.Context) error {
	e.enc.Reset()
	return nil
}

func (nbEncoder) Close(context.Context) error { return nil }

type nbDecoder struct {
	dec *amrnb.Decoder
}

func (d nbDecoder) Name() Name { return AMR }

func (d nbDecoder) SampleRate() int { return amrnb.SampleRate }

func (d nbDecoder) FrameSamples() int { return amrnb.FrameSamples }

func (d nbDecoder) Decode(_ context.Context, dst []int16, frame Frame) ([]int16, error) {
	if name := NormalizeName(frame.Name); name != "" && name != AMR {
		return nil, fmt.Errorf("decoding AMR frame: frame codec is %s", frame.Name)
	}
	pcm, err := d.dec.Decode(dst, amrnb.Frame{
		Mode:    amrnb.Mode(frame.Mode),
		Quality: frame.Quality,
		Data:    frame.Data,
	})
	if err != nil {
		return nil, err
	}
	return pcm, nil
}

func (d nbDecoder) DecodeLost(_ context.Context, dst []int16) ([]int16, error) {
	pcm, err := d.dec.DecodeLost(dst)
	if err != nil {
		return nil, err
	}
	return pcm, nil
}

func (d nbDecoder) Reset(context.Context) error {
	d.dec.Reset()
	return nil
}

func (nbDecoder) Close(context.Context) error { return nil }

type wbEncoder struct {
	enc *amrwb.Encoder
}

func (e wbEncoder) Name() Name { return AMRWB }

func (e wbEncoder) SampleRate() int { return amrwb.SampleRate }

func (e wbEncoder) FrameSamples() int { return amrwb.FrameSamples }

func (e wbEncoder) Encode(_ context.Context, dst []byte, pcm []int16) (Frame, error) {
	frame, err := e.enc.Encode(dst, pcm)
	if err != nil {
		return Frame{}, err
	}
	return Frame{Name: AMRWB, Mode: Mode(frame.Mode), Quality: frame.Quality, Data: frame.Data}, nil
}

func (e wbEncoder) Reset(context.Context) error {
	e.enc.Reset()
	return nil
}

func (wbEncoder) Close(context.Context) error { return nil }

type wbDecoder struct {
	dec *amrwb.Decoder
}

func (d wbDecoder) Name() Name { return AMRWB }

func (d wbDecoder) SampleRate() int { return amrwb.SampleRate }

func (d wbDecoder) FrameSamples() int { return amrwb.FrameSamples }

func (d wbDecoder) Decode(_ context.Context, dst []int16, frame Frame) ([]int16, error) {
	if name := NormalizeName(frame.Name); name != "" && name != AMRWB {
		return nil, fmt.Errorf("decoding AMR-WB frame: frame codec is %s", frame.Name)
	}
	pcm, err := d.dec.Decode(dst, amrwb.Frame{
		Mode:    amrwb.Mode(frame.Mode),
		Quality: frame.Quality,
		Data:    frame.Data,
	})
	if err != nil {
		return nil, err
	}
	return pcm, nil
}

func (d wbDecoder) DecodeLost(_ context.Context, dst []int16) ([]int16, error) {
	pcm, err := d.dec.DecodeLost(dst)
	if err != nil {
		return nil, err
	}
	return pcm, nil
}

func (d wbDecoder) Reset(context.Context) error {
	d.dec.Reset()
	return nil
}

func (wbDecoder) Close(context.Context) error { return nil }
