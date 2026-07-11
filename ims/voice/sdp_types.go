package voice

import (
	"net"
	"time"
)

type MediaOffer struct {
	Codecs []AudioCodec
	PTime  time.Duration
}

type NegotiatedMedia struct {
	Codec           AudioCodec
	PayloadType     int
	ClockRate       int
	Channels        int
	OctetAlign      bool
	HFOnly          bool
	HasDTMF         bool
	DTMFPayloadType int
	DTMFClockRate   int
	DTMFEventMask   uint16
	PTime           time.Duration
	Direction       mediaDirection
	RemoteIP        net.IP
	RemotePort      int
	RemoteRTCPIP    net.IP
	RemoteRTCPPort  int
	RTCPMux         bool
	RTCPDisabled    bool
}

type mediaDirection string

const (
	mediaDirectionSendRecv mediaDirection = "sendrecv"
	mediaDirectionSendOnly mediaDirection = "sendonly"
	mediaDirectionRecvOnly mediaDirection = "recvonly"
	mediaDirectionInactive mediaDirection = "inactive"
)

type sdpOffer struct {
	RemoteIP              net.IP
	RemotePort            int
	RemoteRTCPIP          net.IP
	RemoteRTCPPort        int
	RTCPMux               bool
	Preconditions         bool
	LocalQoSStatus        string
	RemoteQoSConfirmation bool
	Profile               string
	Payloads              []int
	Codecs                map[int]AudioCodecConfig
	PTime                 time.Duration
	RTCPSenderBandwidth   *int
	RTCPReceiverBandwidth *int
	Direction             mediaDirection
	UnsupportedMedia      []sdpMediaLine
}

type sdpMediaLine struct {
	Media    string
	Protocol string
	Formats  []string
}

type sdpAudioLine struct {
	Port     int
	Protocol string
	Payloads []int
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
