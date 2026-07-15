package voice

import (
	"net"
	"time"
)

type MediaOffer struct {
	Codecs       []AudioCodec
	PayloadTypes []int
	PTime        time.Duration
}

// AudioFormat describes one RTP payload format.
type AudioFormat struct {
	Codec         AudioCodec
	PayloadType   int
	ClockRate     int
	Channels      int
	FMTP          string
	DTMFEventMask uint16
	OctetAlign    bool
	ModeSet       string
	Bitrate       string
	Bandwidth     string
	ChAwRecv      *int
	HFOnly        bool
}

// MediaDescription is the audio media description carried by SDP.
type MediaDescription struct {
	Formats      []AudioFormat
	Profile      string
	PTime        time.Duration
	MaxPTime     time.Duration
	Direction    MediaDirection
	IP           net.IP
	Port         int
	RTCPIP       net.IP
	RTCPPort     int
	RTCPMux      bool
	RTCPDisabled bool
	RawSDP       []byte
}

// NegotiatedMedia describes the selected local and remote RTP format.
type NegotiatedMedia struct {
	AudioFormat
	RemoteFormat   AudioFormat
	DTMF           *AudioFormat
	Negotiated     bool
	Profile        string
	PTime          time.Duration
	MaxPTime       time.Duration
	Direction      MediaDirection
	RemoteIP       net.IP
	RemotePort     int
	RemoteRTCPIP   net.IP
	RemoteRTCPPort int
	RTCPMux        bool
	RTCPDisabled   bool
}

type MediaDirection string

const (
	MediaDirectionSendRecv MediaDirection = "sendrecv"
	MediaDirectionSendOnly MediaDirection = "sendonly"
	MediaDirectionRecvOnly MediaDirection = "recvonly"
	MediaDirectionInactive MediaDirection = "inactive"
)

type sdpOffer struct {
	RawSDP                []byte
	RemoteIP              net.IP
	RemotePort            int
	RemoteRTCPIP          net.IP
	RemoteRTCPPort        int
	RTCPMux               bool
	Preconditions         bool
	LocalQoSStatus        string
	RemoteQoSConfirmation bool
	TimeDescriptions      []string
	Profile               string
	Payloads              []int
	Codecs                map[int]AudioCodecConfig
	FMTP                  map[int]string
	PTime                 time.Duration
	MaxPTime              time.Duration
	RTCPSenderBandwidth   *int
	RTCPReceiverBandwidth *int
	Direction             MediaDirection
	Media                 []sdpMediaLine
	AudioIndex            int
}

type sdpMediaLine struct {
	Media     string
	Port      int
	PortCount int
	Protocol  string
	Formats   []string
}

type sdpAudioLine struct {
	Port      int
	PortCount int
	Protocol  string
	Payloads  []int
}

type sdpConnectionLine struct {
	Network     string
	AddressType string
	IP          net.IP
}

const (
	rtcpSenderBandwidth   = 0
	rtcpReceiverBandwidth = 2500

	amrModeChangeCapability = 2
	amrMaxRedMillis         = 220
	dtmfAllEventsMask       = 0xffff

	sdpNetworkIN      = "IN"
	sdpAddressTypeIP4 = "IP4"
	sdpAddressTypeIP6 = "IP6"
)
