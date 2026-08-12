package voice

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/pidf"
)

type AudioCodec string

type RequestURIFormat string

const (
	CodecAMR            AudioCodec = "AMR"
	CodecAMRWB          AudioCodec = "AMR-WB"
	CodecEVS            AudioCodec = "EVS"
	CodecPCMU           AudioCodec = "PCMU"
	CodecTelephoneEvent AudioCodec = "telephone-event"
)

const (
	RequestURIFormatSIP RequestURIFormat = "sip"
	RequestURIFormatTEL RequestURIFormat = "tel"
)

type Config struct {
	Codecs                []AudioCodecConfig
	RTPProfile            string
	PTime                 time.Duration
	MaxPTime              time.Duration
	GeolocationPIDFInvite []int
	GeolocationCountry    string
	PIDFShortCodes        []string
	UseTelURIForPIDFXML   bool
	RequestURIFormat      RequestURIFormat
	PhoneContextDomain    string
	Preconditions         bool
	ReliableProvisional   bool
	SessionTimer          bool
	SessionExpires        time.Duration
	MinSessionExpires     time.Duration
	SessionRefresher      string
	MOCallRequestTimeout  time.Duration
	RingbackTimeout       time.Duration
	RingingTimeout        time.Duration
	// IncomingPreconditionTimeout bounds how long an early incoming call
	// waits for mandatory peer preconditions. Zero uses the 30-second default.
	IncomingPreconditionTimeout   time.Duration
	AllowHoldDuringEmergency      bool
	AudioASBandwidthKbps          int
	RTPInactivityTimeout          *time.Duration
	RTCPInactivityTimeout         *time.Duration
	AudioInactivityCallEndReasons []AudioInactivityCallEndReason
	LocalRTPPortMin               int
	LocalRTPPortMax               int
	PrepareMedia                  func(ctx context.Context, c MediaConfig) (MediaTransport, error)
	OpenMedia                     func(ctx context.Context, c MediaConfig) (MediaTransport, error)
	// WaitMediaReady confirms that the network resources for the negotiated
	// media are available. A successful packet transport alone does not satisfy
	// IMS QoS preconditions. When nil, local QoS preconditions remain unmet.
	WaitMediaReady func(ctx context.Context, c MediaConfig) error
	OnIncomingCall func(IncomingCall)
	OnCallEvent    func(CallEvent)
	OnMedia        func(MediaEvent)
	OnError        func(error)
	Logger         *slog.Logger
}

type AudioCodecConfig struct {
	Name          AudioCodec
	PayloadTypes  []int
	ClockRate     int
	Channels      int
	DTMFEventMask uint16
	OctetAlign    bool
	ModeSet       string
	Bitrate       string
	Bandwidth     string
	ChAwRecv      *int
	HFOnly        bool
}

type AudioInactivityCallEndReason int

const (
	AudioInactivityRTCPOnHold      AudioInactivityCallEndReason = 0
	AudioInactivityRTCPOnConnected AudioInactivityCallEndReason = 1
	AudioInactivityRTPOnConnected  AudioInactivityCallEndReason = 2
	AudioInactivityE911RTCP        AudioInactivityCallEndReason = 3
	AudioInactivityE911RTP         AudioInactivityCallEndReason = 4
)

type MediaConfig struct {
	LocalPort        int
	LocalDescription MediaDescription
	RemoteIP         net.IP
	RemotePort       int
	RemoteRTCPIP     net.IP
	RemoteRTCPPort   int
	RTCPMux          bool
	Media            NegotiatedMedia
	OnPacket         func(MediaPacket)
}

type MediaPacket struct {
	RTCP              bool
	RTCPBye           bool
	RTPSequenceNumber uint16
	RTPTimestamp      uint32
	RTPSSRC           uint32
	RTPPayloadBytes   int
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

type rtcpReader interface {
	ReadRTCP(ctx context.Context) ([]byte, net.Addr, error)
}

type rtcpWriter interface {
	WriteRTCP(ctx context.Context, data []byte) error
}

// MediaTransportConfigurer updates an existing transport after SDP negotiation
// or renegotiation changes the remote media description.
type MediaTransportConfigurer interface {
	ConfigureRemote(ctx context.Context, c MediaConfig) error
}

const (
	defaultRTPProfile                  = "RTP/AVP"
	defaultPTime                       = 20 * time.Millisecond
	defaultMaxPTime                    = 240 * time.Millisecond
	defaultSessionExpires              = 1800 * time.Second
	defaultMinSessionExpires           = 90 * time.Second
	defaultRTPInactivity               = 10 * time.Second
	defaultRTCPInactivity              = 30 * time.Second
	defaultIncomingPreconditionTimeout = 30 * time.Second
	defaultLocalRTPPortMin             = 40000
	defaultLocalRTPPortMax             = 40100
)

var defaultAudioInactivityCallEndReasons = []AudioInactivityCallEndReason{
	AudioInactivityRTCPOnHold,
	AudioInactivityRTPOnConnected,
	AudioInactivityE911RTP,
}

const (
	GeolocationPIDFNonEmergencyWiFi = pidf.GeolocationPIDFNonEmergencyWiFi
	GeolocationPIDFEmergencyWiFi    = pidf.GeolocationPIDFEmergencyWiFi
	GeolocationPIDFNonEmergencyCell = pidf.GeolocationPIDFNonEmergencyCell
	GeolocationPIDFEmergencyCell    = pidf.GeolocationPIDFEmergencyCell
)

func (c Config) Normalized() (Config, error) {
	c.RequestURIFormat = RequestURIFormat(strings.ToLower(strings.TrimSpace(string(c.RequestURIFormat))))
	c.PhoneContextDomain = strings.TrimSpace(c.PhoneContextDomain)
	if c.RequestURIFormat == "" {
		c.RequestURIFormat = RequestURIFormatSIP
	}
	switch c.RequestURIFormat {
	case RequestURIFormatSIP, RequestURIFormatTEL:
	default:
		return Config{}, fmt.Errorf("normalizing voice config: unsupported request URI format %q", c.RequestURIFormat)
	}
	c.RTPProfile = strings.TrimSpace(c.RTPProfile)
	if c.RTPProfile == "" {
		c.RTPProfile = defaultRTPProfile
	}
	if c.Preconditions {
		c.ReliableProvisional = true
	}
	c.GeolocationPIDFInvite = pidf.NormalizeTypes(c.GeolocationPIDFInvite)
	c.GeolocationCountry = strings.ToUpper(strings.TrimSpace(c.GeolocationCountry))
	c.PIDFShortCodes = normalizeShortCodes(c.PIDFShortCodes)
	if (len(c.GeolocationPIDFInvite) > 0 || len(c.PIDFShortCodes) > 0) && c.GeolocationCountry == "" {
		c.GeolocationCountry = "US"
	}
	if c.GeolocationCountry != "" && len(c.GeolocationCountry) != 2 {
		return Config{}, errors.New("normalizing voice config: geolocation country must be two letters")
	}
	if !strings.EqualFold(c.RTPProfile, "RTP/AVP") {
		return Config{}, fmt.Errorf("normalizing voice config: unsupported rtp profile %q", c.RTPProfile)
	}
	if c.PTime < 0 {
		return Config{}, errors.New("normalizing voice config: ptime must be >= 0")
	}
	if c.PTime == 0 {
		c.PTime = defaultPTime
	}
	if c.MaxPTime < 0 {
		return Config{}, errors.New("normalizing voice config: maxptime must be >= 0")
	}
	if c.MaxPTime == 0 {
		c.MaxPTime = defaultMaxPTime
	}
	if c.MaxPTime < c.PTime {
		return Config{}, errors.New("normalizing voice config: maxptime must be >= ptime")
	}
	if c.AudioASBandwidthKbps < 0 {
		return Config{}, errors.New("normalizing voice config: audio AS bandwidth must be >= 0")
	}
	if c.SessionExpires < 0 {
		return Config{}, errors.New("normalizing voice config: session expires must be >= 0")
	}
	if c.SessionExpires > 0 && c.SessionExpires < time.Second {
		return Config{}, errors.New("normalizing voice config: session expires must be at least 1s")
	}
	if c.MinSessionExpires < 0 {
		return Config{}, errors.New("normalizing voice config: min session expires must be >= 0")
	}
	if c.MinSessionExpires > 0 && c.MinSessionExpires < time.Second {
		return Config{}, errors.New("normalizing voice config: min session expires must be at least 1s")
	}
	if c.SessionExpires > 0 && c.MinSessionExpires > c.SessionExpires {
		c.SessionExpires = c.MinSessionExpires
	}
	c.SessionRefresher = strings.ToLower(strings.TrimSpace(c.SessionRefresher))
	if c.SessionRefresher == "" {
		c.SessionRefresher = sessionRefresherNone
	}
	switch c.SessionRefresher {
	case sessionRefresherNone, sessionRefresherUAC, sessionRefresherUAS:
	default:
		return Config{}, fmt.Errorf("normalizing voice config: unsupported session refresher %q", c.SessionRefresher)
	}
	if c.MOCallRequestTimeout < 0 {
		return Config{}, errors.New("normalizing voice config: mo call request timeout must be >= 0")
	}
	if c.RingbackTimeout < 0 {
		return Config{}, errors.New("normalizing voice config: ringback timeout must be >= 0")
	}
	if c.RingingTimeout < 0 {
		return Config{}, errors.New("normalizing voice config: ringing timeout must be >= 0")
	}
	if c.IncomingPreconditionTimeout < 0 {
		return Config{}, errors.New("normalizing voice config: incoming precondition timeout must be >= 0")
	}
	if c.IncomingPreconditionTimeout == 0 {
		c.IncomingPreconditionTimeout = defaultIncomingPreconditionTimeout
	}
	var err error
	if c.RTPInactivityTimeout, err = normalizeDurationSetting(c.RTPInactivityTimeout, defaultRTPInactivity, durationSettingRTPInactivityTimeout); err != nil {
		return Config{}, err
	}
	if c.RTCPInactivityTimeout, err = normalizeDurationSetting(c.RTCPInactivityTimeout, defaultRTCPInactivity, durationSettingRTCPInactivityTimeout); err != nil {
		return Config{}, err
	}
	if c.AudioInactivityCallEndReasons == nil {
		c.AudioInactivityCallEndReasons = append([]AudioInactivityCallEndReason(nil), defaultAudioInactivityCallEndReasons...)
	}
	for _, reason := range c.AudioInactivityCallEndReasons {
		switch reason {
		case AudioInactivityRTCPOnHold, AudioInactivityRTCPOnConnected, AudioInactivityRTPOnConnected, AudioInactivityE911RTCP, AudioInactivityE911RTP:
		default:
			return Config{}, fmt.Errorf("normalizing voice config: unsupported audio inactivity call end reason %d", reason)
		}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	if c.LocalRTPPortMin == 0 {
		c.LocalRTPPortMin = defaultLocalRTPPortMin
	}
	if c.LocalRTPPortMax == 0 {
		c.LocalRTPPortMax = defaultLocalRTPPortMax
	}
	if c.LocalRTPPortMin < 1 || c.LocalRTPPortMin > 65535 || c.LocalRTPPortMax < 1 || c.LocalRTPPortMax > 65535 {
		return Config{}, errors.New("normalizing voice config: local rtp port range must be between 1 and 65535")
	}
	if c.LocalRTPPortMin > c.LocalRTPPortMax {
		return Config{}, errors.New("normalizing voice config: local rtp port min must be <= max")
	}
	codecs, err := normalizeCodecs(c.Codecs)
	if err != nil {
		return Config{}, err
	}
	c.Codecs = codecs
	return c, nil
}

// Duration returns a configured duration value. Passing zero explicitly disables timers that use nil for defaults.
func Duration(value time.Duration) *time.Duration {
	return &value
}

type durationSetting uint8

const (
	durationSettingRTPInactivityTimeout durationSetting = iota
	durationSettingRTCPInactivityTimeout
)

func (s durationSetting) String() string {
	switch s {
	case durationSettingRTPInactivityTimeout:
		return "rtp inactivity timeout"
	case durationSettingRTCPInactivityTimeout:
		return "rtcp inactivity timeout"
	default:
		return "duration setting"
	}
}

func normalizeDurationSetting(value *time.Duration, fallback time.Duration, setting durationSetting) (*time.Duration, error) {
	if value == nil {
		value = Duration(fallback)
	}
	if *value < 0 {
		return nil, fmt.Errorf("normalizing voice config: %s must be >= 0", setting)
	}
	return Duration(*value), nil
}

func (c Config) endsCallOnAudioInactivity(reason AudioInactivityCallEndReason) bool {
	return slices.Contains(c.AudioInactivityCallEndReasons, reason)
}

func normalizeShortCodes(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = normalizeDialString(value)
		if value == "" || slices.Contains(out, value) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func normalizeCodecs(codecs []AudioCodecConfig) ([]AudioCodecConfig, error) {
	if len(codecs) == 0 {
		codecs = []AudioCodecConfig{
			{Name: CodecAMRWB, PayloadTypes: []int{104}, ClockRate: 16000},
			{Name: CodecAMR, PayloadTypes: []int{102}, ClockRate: 8000, ModeSet: "0,2,4,7"},
			{Name: CodecPCMU, PayloadTypes: []int{0}, ClockRate: 8000},
			{Name: CodecTelephoneEvent, PayloadTypes: []int{101}, ClockRate: 8000},
			{Name: CodecTelephoneEvent, PayloadTypes: []int{110}, ClockRate: 16000},
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
			if codec.DTMFEventMask == 0 {
				codec.DTMFEventMask = dtmfAllEventsMask
			}
		default:
			return nil, fmt.Errorf("normalizing voice config: unsupported codec %q", codec.Name)
		}
		if codec.ClockRate <= 0 {
			return nil, fmt.Errorf("normalizing voice config: codec %s clock rate must be > 0", codec.Name)
		}
		if codec.Channels < 0 {
			return nil, fmt.Errorf("normalizing voice config: codec %s channels must be >= 0", codec.Name)
		}
		if len(codec.PayloadTypes) == 0 {
			return nil, fmt.Errorf("normalizing voice config: codec %s has no payload types", codec.Name)
		}
		payloadTypes := make([]int, 0, len(codec.PayloadTypes))
		for _, payloadType := range codec.PayloadTypes {
			if payloadType < 0 || payloadType > 127 {
				return nil, fmt.Errorf("normalizing voice config: codec %s payload type %d is outside 0..127", codec.Name, payloadType)
			}
			if _, ok := seenPayload[payloadType]; ok {
				return nil, fmt.Errorf("normalizing voice config: duplicate payload type %d", payloadType)
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
