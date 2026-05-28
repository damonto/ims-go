package call

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

type AudioCodec string

const (
	CodecAMR            AudioCodec = "AMR"
	CodecAMRWB          AudioCodec = "AMR-WB"
	CodecEVS            AudioCodec = "EVS"
	CodecPCMU           AudioCodec = "PCMU"
	CodecTelephoneEvent AudioCodec = "telephone-event"
)

type Config struct {
	Codecs                 []AudioCodecConfig
	RTPProfile             string
	PTime                  time.Duration
	MaxPTime               time.Duration
	IncludeGeolocationPIDF bool
	GeolocationCountry     string
	Preconditions          bool
	ReliableProvisional    bool
	SessionTimer           bool
	SessionExpires         time.Duration
	MinSessionExpires      time.Duration
	MOCallRequestTimeout   time.Duration
	RingbackTimeout        time.Duration
	RingingTimeout         time.Duration
	AudioASBandwidthKbps   int
	RTPInactivityTimeout   time.Duration
	RTCPInactivityTimeout  time.Duration
	RTCPSendInterval       time.Duration
	LocalRTPPortMin        int
	LocalRTPPortMax        int
	PrepareMedia           func(ctx context.Context, cfg MediaConfig) (MediaTransport, error)
	OpenMedia              func(ctx context.Context, cfg MediaConfig) (MediaTransport, error)
	OnIncoming             func(Incoming)
	OnEvent                func(Event)
	OnError                func(error)
}

type AudioCodecConfig struct {
	Name         AudioCodec
	PayloadTypes []int
	ClockRate    int
	Channels     int
	OctetAlign   bool
	ModeSet      string
	Bitrate      string
	Bandwidth    string
	ChAwRecv     *int
}

type MediaConfig struct {
	LocalPort  int
	RemoteIP   net.IP
	RemotePort int
	Media      NegotiatedMedia
	OnPacket   func(MediaPacket)
}

type MediaPacket struct {
	RTCP    bool
	RTCPBye bool
}

type MediaTransport interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	WritePacket(ctx context.Context, data []byte) error
	ReadPacket(ctx context.Context) ([]byte, net.Addr, error)
	Close() error
}

type RTCPMediaTransport interface {
	ReadRTCP(ctx context.Context) ([]byte, net.Addr, error)
	WriteRTCP(ctx context.Context, data []byte) error
}

const (
	defaultRTPProfile      = "RTP/AVP"
	defaultPTime           = 20 * time.Millisecond
	defaultMaxPTime        = 240 * time.Millisecond
	defaultSessionExpires  = 1800 * time.Second
	defaultRTPInactivity   = 20 * time.Second
	defaultRTCPInactivity  = 20 * time.Second
	defaultRTCPSend        = 5 * time.Second
	defaultLocalRTPPortMin = 40000
	defaultLocalRTPPortMax = 40100
)

func (cfg Config) Normalized() (Config, error) {
	if cfg.Preconditions {
		return Config{}, errors.New("normalizing call config: sip preconditions are not supported")
	}
	cfg.RTPProfile = strings.TrimSpace(cfg.RTPProfile)
	if cfg.RTPProfile == "" {
		cfg.RTPProfile = defaultRTPProfile
	}
	cfg.GeolocationCountry = strings.ToUpper(strings.TrimSpace(cfg.GeolocationCountry))
	if cfg.IncludeGeolocationPIDF && cfg.GeolocationCountry == "" {
		cfg.GeolocationCountry = "US"
	}
	if cfg.GeolocationCountry != "" && len(cfg.GeolocationCountry) != 2 {
		return Config{}, errors.New("normalizing call config: geolocation country must be two letters")
	}
	if !strings.EqualFold(cfg.RTPProfile, "RTP/AVP") {
		return Config{}, fmt.Errorf("normalizing call config: unsupported rtp profile %q", cfg.RTPProfile)
	}
	if cfg.PTime < 0 {
		return Config{}, errors.New("normalizing call config: ptime must be >= 0")
	}
	if cfg.PTime == 0 {
		cfg.PTime = defaultPTime
	}
	if cfg.MaxPTime < 0 {
		return Config{}, errors.New("normalizing call config: maxptime must be >= 0")
	}
	if cfg.MaxPTime == 0 {
		cfg.MaxPTime = defaultMaxPTime
	}
	if cfg.MaxPTime < cfg.PTime {
		return Config{}, errors.New("normalizing call config: maxptime must be >= ptime")
	}
	if cfg.AudioASBandwidthKbps < 0 {
		return Config{}, errors.New("normalizing call config: audio AS bandwidth must be >= 0")
	}
	if cfg.SessionExpires < 0 {
		return Config{}, errors.New("normalizing call config: session expires must be >= 0")
	}
	if cfg.SessionExpires > 0 && cfg.SessionExpires < time.Second {
		return Config{}, errors.New("normalizing call config: session expires must be at least 1s")
	}
	if cfg.MinSessionExpires < 0 {
		return Config{}, errors.New("normalizing call config: min session expires must be >= 0")
	}
	if cfg.MinSessionExpires > 0 && cfg.MinSessionExpires < time.Second {
		return Config{}, errors.New("normalizing call config: min session expires must be at least 1s")
	}
	if cfg.SessionExpires > 0 && cfg.MinSessionExpires > cfg.SessionExpires {
		return Config{}, errors.New("normalizing call config: session expires must be >= min session expires")
	}
	if cfg.MOCallRequestTimeout < 0 {
		return Config{}, errors.New("normalizing call config: mo call request timeout must be >= 0")
	}
	if cfg.RingbackTimeout < 0 {
		return Config{}, errors.New("normalizing call config: ringback timeout must be >= 0")
	}
	if cfg.RingingTimeout < 0 {
		return Config{}, errors.New("normalizing call config: ringing timeout must be >= 0")
	}
	if cfg.RTPInactivityTimeout < 0 {
		return Config{}, errors.New("normalizing call config: rtp inactivity timeout must be >= 0")
	}
	if cfg.RTPInactivityTimeout == 0 {
		cfg.RTPInactivityTimeout = defaultRTPInactivity
	}
	if cfg.RTCPInactivityTimeout < 0 {
		return Config{}, errors.New("normalizing call config: rtcp inactivity timeout must be >= 0")
	}
	if cfg.RTCPInactivityTimeout == 0 {
		cfg.RTCPInactivityTimeout = defaultRTCPInactivity
	}
	if cfg.RTCPSendInterval < 0 {
		return Config{}, errors.New("normalizing call config: rtcp send interval must be >= 0")
	}
	if cfg.RTCPSendInterval == 0 {
		cfg.RTCPSendInterval = defaultRTCPSend
	}
	if cfg.LocalRTPPortMin == 0 {
		cfg.LocalRTPPortMin = defaultLocalRTPPortMin
	}
	if cfg.LocalRTPPortMax == 0 {
		cfg.LocalRTPPortMax = defaultLocalRTPPortMax
	}
	if cfg.LocalRTPPortMin < 1 || cfg.LocalRTPPortMin > 65535 || cfg.LocalRTPPortMax < 1 || cfg.LocalRTPPortMax > 65535 {
		return Config{}, errors.New("normalizing call config: local rtp port range must be between 1 and 65535")
	}
	if cfg.LocalRTPPortMin > cfg.LocalRTPPortMax {
		return Config{}, errors.New("normalizing call config: local rtp port min must be <= max")
	}
	codecs, err := normalizeCodecs(cfg.Codecs)
	if err != nil {
		return Config{}, err
	}
	cfg.Codecs = codecs
	return cfg, nil
}

func normalizeCodecs(codecs []AudioCodecConfig) ([]AudioCodecConfig, error) {
	if len(codecs) == 0 {
		codecs = []AudioCodecConfig{
			{Name: CodecAMRWB, PayloadTypes: []int{104}, ClockRate: 16000},
			{Name: CodecAMR, PayloadTypes: []int{102}, ClockRate: 8000, ModeSet: "0,2,4,7"},
			{Name: CodecPCMU, PayloadTypes: []int{0}, ClockRate: 8000},
			{Name: CodecTelephoneEvent, PayloadTypes: []int{101}, ClockRate: 8000},
		}
	}
	normalized := make([]AudioCodecConfig, 0, len(codecs))
	seenPayload := make(map[int]struct{})
	for _, codec := range codecs {
		codec.Name = AudioCodec(strings.TrimSpace(string(codec.Name)))
		switch strings.ToUpper(string(codec.Name)) {
		case "AMR":
			codec.Name = CodecAMR
			if codec.ClockRate == 0 {
				codec.ClockRate = 8000
			}
		case "AMR-WB", "AMRWB":
			codec.Name = CodecAMRWB
			if codec.ClockRate == 0 {
				codec.ClockRate = 16000
			}
		case "EVS":
			codec.Name = CodecEVS
			if codec.ClockRate == 0 {
				codec.ClockRate = 16000
			}
		case "PCMU":
			codec.Name = CodecPCMU
			if codec.ClockRate == 0 {
				codec.ClockRate = 8000
			}
		case "TELEPHONE-EVENT":
			codec.Name = CodecTelephoneEvent
			if codec.ClockRate == 0 {
				codec.ClockRate = 8000
			}
		default:
			return nil, fmt.Errorf("normalizing call config: unsupported codec %q", codec.Name)
		}
		if codec.ClockRate <= 0 {
			return nil, fmt.Errorf("normalizing call config: codec %s clock rate must be > 0", codec.Name)
		}
		if codec.Channels < 0 {
			return nil, fmt.Errorf("normalizing call config: codec %s channels must be >= 0", codec.Name)
		}
		if len(codec.PayloadTypes) == 0 {
			return nil, fmt.Errorf("normalizing call config: codec %s has no payload types", codec.Name)
		}
		payloadTypes := make([]int, 0, len(codec.PayloadTypes))
		for _, payloadType := range codec.PayloadTypes {
			if payloadType < 0 || payloadType > 127 {
				return nil, fmt.Errorf("normalizing call config: codec %s payload type %d is outside 0..127", codec.Name, payloadType)
			}
			if _, ok := seenPayload[payloadType]; ok {
				return nil, fmt.Errorf("normalizing call config: duplicate payload type %d", payloadType)
			}
			seenPayload[payloadType] = struct{}{}
			payloadTypes = append(payloadTypes, payloadType)
		}
		codec.PayloadTypes = payloadTypes
		codec.ModeSet = strings.TrimSpace(codec.ModeSet)
		codec.Bitrate = strings.TrimSpace(codec.Bitrate)
		codec.Bandwidth = strings.TrimSpace(codec.Bandwidth)
		normalized = append(normalized, codec)
	}
	return normalized, nil
}
