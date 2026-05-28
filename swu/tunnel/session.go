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

	"github.com/damonto/ims-client/swu/esp"
	"github.com/damonto/ims-client/swu/handshake"
	"github.com/damonto/ims-client/usim"
)

type Config struct {
	LocalAddr                string
	RemoteAddr               string
	PacketConn               net.PacketConn
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
	NATKeepaliveInterval     time.Duration
	IKERetransmitDelays      []time.Duration
	Logger                   *slog.Logger
}

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type Info struct {
	InnerIP          net.IP
	PCSCFIP          net.IP
	ESPInitiatorSPI  uint32
	ESPResponderSPI  uint32
	Encryption       uint16
	EncryptionKeyLen uint16
	Integrity        uint16
}

type Session struct {
	conn        net.PacketConn
	owned       bool
	outerRemote *net.UDPAddr
	outerNAT    *net.UDPAddr
	cfg         Config
	logger      *slog.Logger

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
	ike                  *ikeCrypto
	tunnelErr            error
	initiatorSPI         uint64
	responderSPI         uint64
	deviceIdentity       string
	nextMessageID        uint32
	lastProtectedRx      time.Time
	lastProtectedTx      time.Time
	livenessTimeout      time.Duration
	natKeepaliveInterval time.Duration
	informWaiters        map[uint32]chan inboundIKE
	informResponses      map[uint32][]byte

	attachmentsMu sync.RWMutex
	attachments   []*sessionAttachment

	closeCtx      context.Context
	closeCancel   context.CancelFunc
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
	data []byte
	addr *net.UDPAddr
}

const (
	defaultCloseTimeout = 5 * time.Second
	outerReadPollDelay  = 250 * time.Millisecond
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
		NATKeepaliveInterval:     cfg.NATKeepaliveInterval,
		IKERetransmitDelays:      append([]time.Duration(nil), cfg.IKERetransmitDelays...),
	}
}

func handshakeInfo(info Info) handshake.Info {
	return handshake.Info{
		InnerIP:          append(net.IP(nil), info.InnerIP...),
		PCSCFIP:          append(net.IP(nil), info.PCSCFIP...),
		ESPInitiatorSPI:  info.ESPInitiatorSPI,
		ESPResponderSPI:  info.ESPResponderSPI,
		Encryption:       info.Encryption,
		EncryptionKeyLen: info.EncryptionKeyLen,
		Integrity:        info.Integrity,
	}
}

func infoFromHandshake(info handshake.Info) Info {
	return Info{
		InnerIP:          append(net.IP(nil), info.InnerIP...),
		PCSCFIP:          append(net.IP(nil), info.PCSCFIP...),
		ESPInitiatorSPI:  info.ESPInitiatorSPI,
		ESPResponderSPI:  info.ESPResponderSPI,
		Encryption:       info.Encryption,
		EncryptionKeyLen: info.EncryptionKeyLen,
		Integrity:        info.Integrity,
	}
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
	return resolveUDPAddr(cfg.RemoteAddr, defaultValue(cfg.InitialPort, 500))
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
	closeCtx, closeCancel := context.WithCancel(context.Background())
	return &Session{
		conn:        conn,
		owned:       owned,
		outerRemote: remote,
		outerNAT:    &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: cfg.NATTPort, Zone: remote.Zone},
		cfg:         cfg,
		logger:      cfg.Logger.With("component", "swu"),
		closeCtx:    closeCtx,
		closeCancel: closeCancel,
		readCh:      make(chan inboundPacket, 16),
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
