package handshake

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"time"

	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/swu/ike"
)

var ErrIKETimeout = errors.New("ike timeout")

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type Config struct {
	LocalAddr                string
	RemoteAddr               string
	APN                      string
	PDNType                  PDNType
	InitialPort              int
	NATTPort                 int
	LocalSIPPort             int
	SIPPort                  int
	DHGroups                 []uint16
	IKEEncryptionKeyLens     []uint16
	IKEIntegrity             []uint16
	IKEPRF                   []uint16
	ChildEncryptionKeyLens   []uint16
	ChildIntegrity           []uint16
	PCSCFIPv4ConfigAttribute uint16
	PCSCFIPv6ConfigAttribute uint16
	PCSCFRestoration         bool
	PDUSessionID             byte
	IPMSIndication           bool
	NATKeepaliveInterval     time.Duration
	LivenessTimeout          time.Duration
	IKERetransmitDelays      []time.Duration
}

type IPAddress struct {
	IP        net.IP
	PrefixLen int
}

func (a IPAddress) IsZero() bool {
	return len(a.IP) == 0
}

type IPPrefix struct {
	IP        net.IP
	PrefixLen int
}

func (p IPPrefix) IsZero() bool {
	return len(p.IP) == 0
}

type Info struct {
	InnerIPv4                 net.IP
	InnerIPv6                 IPAddress
	InnerIPv6Prefix           IPPrefix
	PDNTypeRestriction        PDNType
	PCSCFIPs                  []net.IP
	ESPInitiatorSPI           uint32
	ESPResponderSPI           uint32
	Encryption                uint16
	EncryptionKeyLen          uint16
	Integrity                 uint16
	InitiatorTrafficSelectors []ike.TrafficSelector
	ResponderTrafficSelectors []ike.TrafficSelector
	PDUSessionID              byte
	SNSSAI                    []byte
	SNSSAIPlmnID              []byte
}

type PDNType uint8

const (
	PDNTypeUnspecified PDNType = iota
	PDNTypeIPv4
	PDNTypeIPv6
	PDNTypeIPv4v6
)

type ESPKeys struct {
	EncryptionInitiator []byte
	IntegrityInitiator  []byte
	EncryptionResponder []byte
	IntegrityResponder  []byte
}

type ConnectInput struct {
	IMEI        string
	Card        Card
	OuterLocal  *net.UDPAddr
	OuterRemote *net.UDPAddr
	Logger      *slog.Logger
	Config      Config
}

type SAInitState struct {
	InitiatorSPI      uint64
	ResponderSPI      uint64
	DHGroup           uint16
	NonceI            []byte
	ResponderNonce    []byte
	IKEInitRequest    []byte
	ChildInitiatorSPI uint32
}

type AuthState struct {
	Identity         string
	Realm            string
	CurrentMessageID uint32
	PendingEAPType   byte
	ChallengeData    [][]byte
	FinalPayloads    [][]byte
}

type Established struct {
	Info            Info
	ESPKeys         ESPKeys
	NextMessageID   uint32
	LivenessTimeout time.Duration
	DeviceIdentity  string
}

func (in ConnectInput) Validate() error {
	switch {
	case in.Card == nil:
		return errors.New("validating connect input: card is nil")
	case in.IMEI == "":
		return errors.New("validating connect input: imei is empty")
	case in.OuterRemote == nil:
		return errors.New("validating connect input: outer remote is nil")
	default:
		return nil
	}
}
