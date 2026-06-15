package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/handshake"
	"github.com/damonto/vowifi-go/swu/ike"
)

type Config struct {
	LocalAddr                        string
	RemoteAddr                       string
	APN                              string
	PDNType                          PDNType
	AKAPrimeNetworkName              string
	AllowAKAPrimeNetworkNameMismatch bool
	PacketConn                       net.PacketConn
	InitialPort                      int
	NATTPort                         int
	LocalSIPPort                     int
	SIPPort                          int
	DHGroups                         []uint16
	IKEEncryptionKeyLens             []uint16
	IKEIntegrity                     []uint16
	IKEPRF                           []uint16
	ChildEncryptionKeyLens           []uint16
	ChildIntegrity                   []uint16
	PCSCFIPv4ConfigAttribute         uint16
	PCSCFIPv6ConfigAttribute         uint16
	DisablePCSCFRestoration          bool
	PDUSessionID                     byte
	EnableIPMSIndication             bool
	NATKeepaliveInterval             time.Duration
	LivenessTimeout                  time.Duration
	IKERetransmitDelays              []time.Duration
	IKESALifetime                    time.Duration
	IKESARekeyMargin                 time.Duration
	IKESAByteLifetime                uint64
	IKESAByteRekeyMargin             uint64
	ChildSALifetime                  time.Duration
	ChildSARekeyMargin               time.Duration
	ChildSAByteLifetime              uint64
	ChildSAByteRekeyMargin           uint64
	AddKEToChildSARekey              bool
	Logger                           *slog.Logger
}

type IPAddress = handshake.IPAddress
type IPPrefix = handshake.IPPrefix
type PDNType = handshake.PDNType

const (
	PDNTypeUnspecified = handshake.PDNTypeUnspecified
	PDNTypeIPv4        = handshake.PDNTypeIPv4
	PDNTypeIPv6        = handshake.PDNTypeIPv6
	PDNTypeIPv4v6      = handshake.PDNTypeIPv4v6
)

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
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

type Session struct {
	conn                      net.PacketConn
	owned                     bool
	outerRemote               *net.UDPAddr
	outerNAT                  *net.UDPAddr
	useNATT                   bool
	ikeFragmentationSupported bool
	cfg                       Config
	logger                    *slog.Logger

	mu                   sync.RWMutex
	connected            bool
	connecting           bool
	innerLocal           *net.UDPAddr
	innerRemote          *net.UDPAddr
	tunnel               Info
	outboundESP          esp.Codec
	inboundESP           esp.Codec
	espSeq               uint32
	inboundReplay        esp.ReplayWindow
	retiredChildSAs      []retiredChildSA
	pendingChildSA       pendingChildSA
	ike                  *ikeCrypto
	pendingIKESA         ikeSARekeyResult
	pendingIKESAReady    bool
	retiredIKESAs        []retiredIKESA
	ikeLocalInitiator    bool
	tunnelErr            error
	initiatorSPI         uint64
	responderSPI         uint64
	deviceIdentity       string
	nextMessageID        uint32
	nextPeerMessageID    uint32
	lastInvalidMessageID time.Time
	lastProtectedRx      time.Time
	lastProtectedTx      time.Time
	ikeSAExpiresAt       time.Time
	ikeSARekeyAt         time.Time
	ikeSAByteRekeyAt     uint64
	ikeSAByteExpiresAt   uint64
	ikeSAInboundBytes    uint64
	ikeSAOutboundBytes   uint64
	ikeSARekeying        bool
	simultaneousIKESA    simultaneousIKESARekey
	childSAExpiresAt     time.Time
	childSARekeyAt       time.Time
	childSAByteRekeyAt   uint64
	childSAByteExpiresAt uint64
	childSAInboundBytes  uint64
	childSAOutboundBytes uint64
	childSARekeying      bool
	simultaneousChildSA  simultaneousChildSARekey
	livenessTimeout      time.Duration
	natKeepaliveInterval time.Duration
	informWaiters        map[ikeMessageKey]chan inboundIKE
	informResponses      map[uint32][][]byte
	informResponseReqs   map[uint32][]byte
	ikeFragments         map[ikeMessageKey]*ikeFragmentReassembly
	ikeRequestGate       chan struct{}
	rekeyWake            chan struct{}

	attachmentsMu sync.RWMutex
	attachments   []*sessionAttachment

	closeCh       chan struct{}
	closeOnce     sync.Once
	wg            sync.WaitGroup
	readCh        chan inboundPacket
	dataPlaneDone chan struct{}
}

type inboundPacket struct {
	data []byte
	addr net.Addr
	err  error
}

type inboundIKE struct {
	data     []byte
	payloads []ike.Payload
	addr     *net.UDPAddr
	err      error
}

type retiredChildSA struct {
	inbound        esp.Codec
	info           Info
	outboundSPI    uint32
	replay         esp.ReplayWindow
	expiresAt      time.Time
	protectedBytes uint64
	byteExpiresAt  uint64
}

type retiredIKESA struct {
	ike               *ikeCrypto
	localInitiator    bool
	initiatorSPI      uint64
	responderSPI      uint64
	peer              *net.UDPAddr
	useNATT           bool
	nextPeerMessageID uint32
	responses         map[uint32][][]byte
	responseReqs      map[uint32][]byte
	expiresAt         time.Time
}

type pendingChildSA struct {
	ready      bool
	info       Info
	outbound   esp.Codec
	oldInbound uint32
}

type ikeSAState uint8

const (
	ikeSAStateNone ikeSAState = iota
	ikeSAStateActive
	ikeSAStateRekeying
	ikeSAStatePendingInstall
)

type childSAState uint8

const (
	childSAStateNone childSAState = iota
	childSAStateActive
	childSAStateRekeying
	childSAStatePendingOutbound
)

type simultaneousChildSARekey struct {
	ready bool
	peer  childSARekeyResult
}

type simultaneousIKESARekey struct {
	ready bool
	peer  ikeSARekeyResult
}

const (
	defaultCloseTimeout = 5 * time.Second
	outerReadPollDelay  = 250 * time.Millisecond
	maxUDPPacketSize    = 64 * 1024
	childSADrainWindow  = 2 * time.Minute
	ikeSADrainWindow    = 2 * time.Minute
)

func Dial(ctx context.Context, cfg Config) (*Session, error) {
	cfg, err := cfg.Normalized()
	if err != nil {
		return nil, fmt.Errorf("normalizing session config: %w", err)
	}
	remote, err := resolveDialRemote(cfg)
	if err != nil {
		return nil, err
	}
	conn, owned, err := openSessionPacketConn(cfg)
	if err != nil {
		return nil, err
	}
	if err := ensureDialContext(ctx, conn, owned); err != nil {
		return nil, err
	}
	return newSession(cfg, conn, owned, remote), nil
}

func handshakeConfig(cfg Config) handshake.Config {
	return handshake.Config{
		LocalAddr:                cfg.LocalAddr,
		RemoteAddr:               cfg.RemoteAddr,
		APN:                      cfg.APN,
		PDNType:                  cfg.PDNType,
		InitialPort:              cfg.InitialPort,
		NATTPort:                 cfg.NATTPort,
		LocalSIPPort:             cfg.LocalSIPPort,
		SIPPort:                  cfg.SIPPort,
		DHGroups:                 append([]uint16(nil), cfg.DHGroups...),
		IKEEncryptionKeyLens:     append([]uint16(nil), cfg.IKEEncryptionKeyLens...),
		IKEIntegrity:             append([]uint16(nil), cfg.IKEIntegrity...),
		IKEPRF:                   append([]uint16(nil), cfg.IKEPRF...),
		ChildEncryptionKeyLens:   append([]uint16(nil), cfg.ChildEncryptionKeyLens...),
		ChildIntegrity:           append([]uint16(nil), cfg.ChildIntegrity...),
		PCSCFIPv4ConfigAttribute: cfg.PCSCFIPv4ConfigAttribute,
		PCSCFIPv6ConfigAttribute: cfg.PCSCFIPv6ConfigAttribute,
		PCSCFRestoration:         !cfg.DisablePCSCFRestoration,
		PDUSessionID:             cfg.PDUSessionID,
		IPMSIndication:           cfg.EnableIPMSIndication,
		NATKeepaliveInterval:     cfg.NATKeepaliveInterval,
		LivenessTimeout:          cfg.LivenessTimeout,
		IKERetransmitDelays:      append([]time.Duration(nil), cfg.IKERetransmitDelays...),
	}
}

func handshakeInfo(info Info) handshake.Info {
	return handshake.Info{
		InnerIPv4:                 append(net.IP(nil), info.InnerIPv4...),
		InnerIPv6:                 cloneIPAddress(info.InnerIPv6),
		InnerIPv6Prefix:           cloneIPPrefix(info.InnerIPv6Prefix),
		PDNTypeRestriction:        info.PDNTypeRestriction,
		PCSCFIPs:                  cloneIPList(info.PCSCFIPs),
		ESPInitiatorSPI:           info.ESPInitiatorSPI,
		ESPResponderSPI:           info.ESPResponderSPI,
		Encryption:                info.Encryption,
		EncryptionKeyLen:          info.EncryptionKeyLen,
		Integrity:                 info.Integrity,
		InitiatorTrafficSelectors: cloneTrafficSelectors(info.InitiatorTrafficSelectors),
		ResponderTrafficSelectors: cloneTrafficSelectors(info.ResponderTrafficSelectors),
		PDUSessionID:              info.PDUSessionID,
		SNSSAI:                    append([]byte(nil), info.SNSSAI...),
		SNSSAIPlmnID:              append([]byte(nil), info.SNSSAIPlmnID...),
	}
}

func infoFromHandshake(info handshake.Info) Info {
	return Info{
		InnerIPv4:                 append(net.IP(nil), info.InnerIPv4...),
		InnerIPv6:                 cloneIPAddress(info.InnerIPv6),
		InnerIPv6Prefix:           cloneIPPrefix(info.InnerIPv6Prefix),
		PDNTypeRestriction:        info.PDNTypeRestriction,
		PCSCFIPs:                  cloneIPList(info.PCSCFIPs),
		ESPInitiatorSPI:           info.ESPInitiatorSPI,
		ESPResponderSPI:           info.ESPResponderSPI,
		Encryption:                info.Encryption,
		EncryptionKeyLen:          info.EncryptionKeyLen,
		Integrity:                 info.Integrity,
		InitiatorTrafficSelectors: cloneTrafficSelectors(info.InitiatorTrafficSelectors),
		ResponderTrafficSelectors: cloneTrafficSelectors(info.ResponderTrafficSelectors),
		PDUSessionID:              info.PDUSessionID,
		SNSSAI:                    append([]byte(nil), info.SNSSAI...),
		SNSSAIPlmnID:              append([]byte(nil), info.SNSSAIPlmnID...),
	}
}

func cloneIPAddress(address IPAddress) IPAddress {
	return IPAddress{
		IP:        append(net.IP(nil), address.IP...),
		PrefixLen: address.PrefixLen,
	}
}

func cloneIPPrefix(prefix IPPrefix) IPPrefix {
	return IPPrefix{
		IP:        append(net.IP(nil), prefix.IP...),
		PrefixLen: prefix.PrefixLen,
	}
}

func cloneIPList(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	cloned := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		cloned = append(cloned, append(net.IP(nil), ip...))
	}
	return cloned
}

func handshakeESPKeys(keys ESPKeys) handshake.ESPKeys {
	return handshake.ESPKeys{
		EncryptionInitiator: append([]byte(nil), keys.EncryptionInitiator...),
		IntegrityInitiator:  append([]byte(nil), keys.IntegrityInitiator...),
		EncryptionResponder: append([]byte(nil), keys.EncryptionResponder...),
		IntegrityResponder:  append([]byte(nil), keys.IntegrityResponder...),
	}
}

func resolveDialRemote(cfg Config) (*net.UDPAddr, error) {
	return resolveUDPAddr(cfg.RemoteAddr, defaultValue(cfg.InitialPort, defaultIKEPort))
}

func openSessionPacketConn(cfg Config) (net.PacketConn, bool, error) {
	if cfg.PacketConn != nil {
		return cfg.PacketConn, false, nil
	}
	listenAddr := cfg.LocalAddr
	if listenAddr == "" {
		listenAddr = ":0"
	}
	conn, err := net.ListenPacket("udp", listenAddr)
	if err != nil {
		return nil, false, fmt.Errorf("listening on %s: %w", listenAddr, err)
	}
	return conn, true, nil
}

func ensureDialContext(ctx context.Context, conn net.PacketConn, owned bool) error {
	select {
	case <-ctx.Done():
		if owned && conn != nil {
			_ = conn.Close()
		}
		return ctx.Err()
	default:
		return nil
	}
}

func newSession(cfg Config, conn net.PacketConn, owned bool, remote *net.UDPAddr) *Session {
	useNATT := remote.Port == cfg.NATTPort
	return &Session{
		conn:           conn,
		owned:          owned,
		outerRemote:    remote,
		outerNAT:       &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: cfg.NATTPort, Zone: remote.Zone},
		useNATT:        useNATT,
		cfg:            cfg,
		logger:         cfg.Logger.With("component", "swu"),
		closeCh:        make(chan struct{}),
		readCh:         make(chan inboundPacket, 16),
		ikeRequestGate: make(chan struct{}, 1),
		rekeyWake:      make(chan struct{}, 1),
	}
}

func resolveUDPAddr(value string, defaultPort int) (*net.UDPAddr, error) {
	if strings.TrimSpace(value) == "" {
		return nil, errors.New("dialing session: remote address is empty")
	}
	if _, _, err := net.SplitHostPort(value); err != nil {
		if addrErr, ok := err.(*net.AddrError); ok && strings.Contains(addrErr.Err, "missing port") {
			value = net.JoinHostPort(value, strconv.Itoa(defaultPort))
		}
	}
	remote, err := net.ResolveUDPAddr("udp", value)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", value, err)
	}
	return remote, nil
}

func defaultValue(value, fallback int) int {
	if value != 0 {
		return value
	}
	return fallback
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}
