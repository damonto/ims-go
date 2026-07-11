package codec

import (
	"context"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/evs"
)

// EVSFormat identifies the EVS codec mode carried by a frame.
type EVSFormat uint8

const (
	EVSNative EVSFormat = iota
	EVSAMRWBIO
)

// EVSBandwidth limits the encoded audio bandwidth. The zero value selects the
// natural bandwidth for the configured sample rate.
type EVSBandwidth uint8

const (
	EVSBandwidthDefault EVSBandwidth = iota
	EVSBandwidthNB
	EVSBandwidthWB
	EVSBandwidthSWB
	EVSBandwidthFB
)

// EVSConfig contains setup used only when Config.Name is EVS.
type EVSConfig struct {
	Format EVSFormat
	// SampleRate accepts 8000, 16000, 32000 or 48000. Zero selects 16000.
	SampleRate  int
	Bandwidth   EVSBandwidth
	RFOffset    int
	RFIndicator int
}

// EVSFrame contains metadata used only when Frame.Name is EVS.
type EVSFrame struct {
	Format        EVSFormat
	Bits          int
	Partial       bool
	NextCoderType int
}

// EVSFrameBits returns the codec-core bit count for an EVS frame.
func EVSFrameBits(format EVSFormat, mode Mode) (int, error) {
	evsFormat, err := toEVSFormat(format)
	if err != nil {
		return 0, err
	}
	return evs.FrameBits(evsFormat, int(mode))
}

// EVSFrameBytes returns the access-unit byte count for an EVS frame.
func EVSFrameBytes(format EVSFormat, mode Mode) (int, error) {
	evsFormat, err := toEVSFormat(format)
	if err != nil {
		return 0, err
	}
	return evs.FrameBytes(evsFormat, int(mode))
}

type evsSession struct {
	codec        *evs.Codec
	decodeFormat evs.Format
}

func (s *evsSession) Name() Name { return EVS }

func (s *evsSession) SampleRate() int { return s.codec.SampleRate() }

func (s *evsSession) FrameSamples() int { return s.codec.FrameSamples() }

func (s *evsSession) Encode(ctx context.Context, dst []byte, pcm []int16) (Frame, error) {
	frame, err := s.codec.Encode(ctx, dst, pcm)
	if err != nil {
		return Frame{}, err
	}
	return Frame{
		Name:    EVS,
		Mode:    Mode(frame.FrameType),
		Quality: frame.Quality,
		Data:    frame.Data,
		EVS: EVSFrame{
			Format:        fromEVSFormat(frame.Format),
			Bits:          frame.Bits,
			Partial:       frame.Partial,
			NextCoderType: frame.NextCoderType,
		},
	}, nil
}

func (s *evsSession) Decode(ctx context.Context, dst []int16, frame Frame) ([]int16, error) {
	if name := NormalizeName(frame.Name); name != "" && name != EVS {
		return nil, fmt.Errorf("decoding EVS frame: frame codec is %s", frame.Name)
	}
	format, err := toEVSFormat(frame.EVS.Format)
	if err != nil {
		return nil, fmt.Errorf("decoding EVS frame: %w", err)
	}
	pcm, err := s.codec.Decode(ctx, dst, evs.Frame{
		Format:        format,
		FrameType:     int(frame.Mode),
		Quality:       frame.Quality,
		Bits:          frame.EVS.Bits,
		Data:          frame.Data,
		Partial:       frame.EVS.Partial,
		NextCoderType: frame.EVS.NextCoderType,
	})
	if err != nil {
		return nil, err
	}
	s.decodeFormat = format
	return pcm, nil
}

func (s *evsSession) DecodeLost(ctx context.Context, dst []int16) ([]int16, error) {
	return s.codec.DecodeLost(ctx, dst, s.decodeFormat)
}

func (s *evsSession) Configure(ctx context.Context, cfg Config) error {
	if name := NormalizeName(cfg.Name); name != "" && name != EVS {
		return fmt.Errorf("configuring EVS session: codec is %s", cfg.Name)
	}
	if cfg.EVS.SampleRate == 0 {
		cfg.EVS.SampleRate = s.SampleRate()
	}
	evsConfig, _, err := makeEVSConfig(cfg)
	if err != nil {
		return err
	}
	if evsConfig.SampleRate != s.SampleRate() {
		return fmt.Errorf("configuring EVS session: sample rate %d cannot change to %d", s.SampleRate(), evsConfig.SampleRate)
	}
	if err := s.codec.Configure(ctx, evsConfig.Encoder); err != nil {
		return err
	}
	return nil
}

func (s *evsSession) Reset(ctx context.Context) error { return s.codec.Reset(ctx) }

func (s *evsSession) Close(ctx context.Context) error { return s.codec.Close(ctx) }

func makeEVSConfig(cfg Config) (evs.Config, evs.Format, error) {
	format, err := toEVSFormat(cfg.EVS.Format)
	if err != nil {
		return evs.Config{}, 0, fmt.Errorf("creating EVS codec: %w", err)
	}
	sampleRate := cfg.EVS.SampleRate
	if sampleRate == 0 {
		sampleRate = evs.SampleRateWB
	}
	bandwidth, err := toEVSBandwidth(cfg.EVS.Bandwidth, sampleRate)
	if err != nil {
		return evs.Config{}, 0, err
	}
	bitrate, err := evsEncoderBitrate(format, cfg.Mode)
	if err != nil {
		return evs.Config{}, 0, err
	}
	return evs.Config{
		SampleRate: sampleRate,
		Encoder: evs.EncoderConfig{
			Bitrate:   bitrate,
			Bandwidth: bandwidth,
			DTX:       cfg.DTX,
			RF: evs.RFConfig{
				Offset:    cfg.EVS.RFOffset,
				Indicator: cfg.EVS.RFIndicator,
			},
		},
	}, format, nil
}

func evsEncoderBitrate(format evs.Format, mode Mode) (int, error) {
	frameType := int(mode)
	switch format {
	case evs.Native:
		if frameType < 0 || frameType > 11 {
			return 0, fmt.Errorf("creating EVS encoder: native mode %d is not a speech mode", mode)
		}
	case evs.AMRWBIO:
		if frameType < 0 || frameType > 8 {
			return 0, fmt.Errorf("creating EVS encoder: AMR-WB IO mode %d is not a speech mode", mode)
		}
	}
	bits, err := evs.FrameBits(format, frameType)
	if err != nil {
		return 0, fmt.Errorf("creating EVS encoder: %w", err)
	}
	return bits * 50, nil
}

func toEVSFormat(format EVSFormat) (evs.Format, error) {
	switch format {
	case EVSNative:
		return evs.Native, nil
	case EVSAMRWBIO:
		return evs.AMRWBIO, nil
	default:
		return 0, fmt.Errorf("invalid EVS format %d", format)
	}
}

func fromEVSFormat(format evs.Format) EVSFormat {
	if format == evs.AMRWBIO {
		return EVSAMRWBIO
	}
	return EVSNative
}

func toEVSBandwidth(bandwidth EVSBandwidth, sampleRate int) (evs.Bandwidth, error) {
	if bandwidth == EVSBandwidthDefault {
		switch sampleRate {
		case evs.SampleRateNB:
			return evs.BandwidthNB, nil
		case evs.SampleRateWB:
			return evs.BandwidthWB, nil
		case evs.SampleRateSWB:
			return evs.BandwidthSWB, nil
		case evs.SampleRateFB:
			return evs.BandwidthFB, nil
		default:
			return 0, fmt.Errorf("creating EVS codec: unsupported sample rate %d", sampleRate)
		}
	}
	switch bandwidth {
	case EVSBandwidthNB:
		return evs.BandwidthNB, nil
	case EVSBandwidthWB:
		return evs.BandwidthWB, nil
	case EVSBandwidthSWB:
		return evs.BandwidthSWB, nil
	case EVSBandwidthFB:
		return evs.BandwidthFB, nil
	default:
		return 0, fmt.Errorf("creating EVS codec: invalid bandwidth %d", bandwidth)
	}
}
