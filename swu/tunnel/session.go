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

	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
)

type Session struct {
	conn                      net.PacketConn
	owned                     bool
	outerRemote               *net.UDPAddr
	outerNAT                  *net.UDPAddr
	useNATT                   bool
	ikeFragmentationSupported bool
	cfg                       Config
	logger                    *slog.Logger
	outerWriteMu              sync.Mutex

	mu sync.RWMutex
	tunnelConnection
	ikeAssociation
	childAssociation
	saLifetime
	ikeMessageIDs
	ikeExchangeState

	attachmentsMu sync.RWMutex
	attachments   []*sessionAttachment

	closeCh   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

type inboundIKE struct {
	data     []byte
	payloads []ike.Payload
	addr     *net.UDPAddr
	err      error
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
		conn:        conn,
		owned:       owned,
		outerRemote: remote,
		outerNAT:    &net.UDPAddr{IP: append(net.IP(nil), remote.IP...), Port: cfg.NATTPort, Zone: remote.Zone},
		useNATT:     useNATT,
		cfg:         cfg,
		logger:      cfg.Logger.With("component", "swu"),
		closeCh:     make(chan struct{}),
		ikeExchangeState: ikeExchangeState{
			ikeRequestGate: make(chan struct{}, 1),
			rekeyWake:      make(chan struct{}, 1),
		},
	}
}

func (s *Session) commitConnect(state *connectState) {
	if state.established.LivenessTimeout <= 0 {
		state.established.LivenessTimeout = state.sessionLivenessTimeout()
	}
	s.mu.Lock()
	s.connected = true
	s.connecting = false
	s.useNATT = state.useNATT
	s.ikeFragmentationSupported = state.ikeFragmentationSupported
	s.tunnel = infoFromHandshake(state.established.Info)
	s.ike = state.crypto
	s.pendingIKESA = ikeSARekeyResult{}
	s.pendingIKESAReady = false
	s.retiredIKESAs = nil
	s.ikeLocalInitiator = true
	s.tunnelErr = nil
	s.initiatorSPI = state.initiatorSPI
	s.responderSPI = state.responderSPI
	s.nextMessageID = state.established.NextMessageID
	s.nextPeerMessageID = 0
	s.deviceIdentity = state.established.DeviceIdentity
	s.espSeq = 0
	s.inboundReplay.Reset()
	now := time.Now()
	s.lastProtectedRx = now
	s.lastProtectedTx = now
	s.ikeSAExpiresAt = childSAExpiry(now, s.cfg.IKESALifetime)
	s.ikeSARekeyAt = childSARekeyTime(now, s.cfg.IKESALifetime, s.cfg.IKESARekeyMargin)
	s.ikeSAByteExpiresAt = saByteExpiry(s.cfg.IKESAByteLifetime)
	s.ikeSAByteRekeyAt = saByteRekeyLimit(s.cfg.IKESAByteLifetime, s.cfg.IKESAByteRekeyMargin)
	s.ikeSAInboundBytes = 0
	s.ikeSAOutboundBytes = 0
	s.ikeSARekeying = false
	s.simultaneousIKESA = simultaneousIKESARekey{}
	s.childSAExpiresAt = childSAExpiry(now, s.cfg.ChildSALifetime)
	s.childSARekeyAt = childSARekeyTime(now, s.cfg.ChildSALifetime, s.cfg.ChildSARekeyMargin)
	s.childSAByteExpiresAt = saByteExpiry(s.cfg.ChildSAByteLifetime)
	s.childSAByteRekeyAt = saByteRekeyLimit(s.cfg.ChildSAByteLifetime, s.cfg.ChildSAByteRekeyMargin)
	s.childSAInboundBytes = 0
	s.childSAOutboundBytes = 0
	s.childSARekeying = false
	s.simultaneousChildSA = simultaneousChildSARekey{}
	s.livenessTimeout = state.established.LivenessTimeout
	if state.useNATT {
		s.natKeepaliveInterval = s.cfg.NATKeepaliveInterval
	} else {
		s.natKeepaliveInterval = 0
	}
	s.informWaiters = make(map[ikeMessageKey]chan inboundIKE)
	s.informResponses = make(map[uint32][][]byte)
	s.informResponseReqs = make(map[uint32][]byte)
	s.ikeFragments = make(map[ikeMessageKey]*ikeFragmentReassembly)
	s.outboundESP = state.outboundESPCodec()
	s.inboundESP = state.inboundESPCodec()
	s.retiredChildSAs = nil
	s.pendingChildSA = pendingChildSA{}
	s.mu.Unlock()
}

func (s *Session) startBackgroundLoops() {
	s.startBackgroundLoop(s.readLoop)
	s.startBackgroundLoop(s.livenessLoop)
	s.startBackgroundLoop(s.natKeepaliveLoop)
	s.startBackgroundLoop(s.ikeSARekeyLoop)
	s.startBackgroundLoop(s.childSARekeyLoop)
}

func (s *Session) startBackgroundLoop(run func()) {
	s.wg.Add(1)
	go run()
}

func (s *Session) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	if err := s.sendDeleteRequest(ctx); err != nil {
		s.logger.Debug("sending IKE delete request failed", "err", err)
	}
	s.closeSession()
	s.wg.Wait()
	s.discardSecurityAssociations(nil)
	if !s.owned {
		return nil
	}
	closeErr := s.conn.Close()
	if errors.Is(closeErr, net.ErrClosed) {
		return nil
	}
	return closeErr
}

func (s *Session) isClosed() bool {
	select {
	case <-s.closeCh:
		return true
	default:
		return false
	}
}

func (s *Session) closeSession() {
	s.closeOnce.Do(func() {
		close(s.closeCh)
	})
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
