package swu

import (
	"context"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damonto/ims-client/usim"
)

type Config struct {
	LocalAddr    string
	RemoteAddr   string
	PacketConn   net.PacketConn
	InitialPort  int
	NATTPort     int
	LocalSIPPort int
	SIPPort      int
	Logger       *slog.Logger
}

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type TunnelInfo struct {
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
	innerLocal           *net.UDPAddr
	innerRemote          *net.UDPAddr
	tunnel               TunnelInfo
	outboundESP          ESPCodec
	inboundESP           ESPCodec
	espSeq               uint32
	inboundReplay        replayWindow
	ike                  *ikeCrypto
	initiatorSPI         uint64
	responderSPI         uint64
	deviceIdentity       string
	nextMessageID        uint32
	lastProtectedRx      time.Time
	lastProtectedTx      time.Time
	livenessTimeout      time.Duration
	natKeepaliveInterval time.Duration
	informWaiters        map[uint32]chan inboundIKE

	tcpMu     sync.RWMutex
	tcp       *TCPTransport
	tcpServer *TCPTransport
	udpMu     sync.RWMutex
	udpServer *SecureUDPTransport

	closeCtx    context.Context
	closeCancel context.CancelFunc
	wg          sync.WaitGroup
	readCh      chan inboundPacket
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

type connectState struct {
	card            Card
	imei            string
	identity        string
	realm           string
	initialAKAState usim.AKAIdentityState
	crypto          *ikeCrypto
	initiatorSPI    uint64
	responderSPI    uint64
	espInitiatorSPI uint32
	nonceI          []byte
	ikeInitRequest  []byte
	responderNonce  []byte
	nextMessageID   uint32
	finalPayloads   []Payload
	tunnel          TunnelInfo
	espKeys         ESPKeys
}

type innerWriteState struct {
	connected bool
	codec     ESPCodec
	outer     *net.UDPAddr
	seq       uint32
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

func (s *Session) Connect(ctx context.Context, imei string, card Card) error {
	state, err := s.prepareConnect(imei, card)
	if err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	if err := s.exchangeIKESAInit(ctx, state); err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	if err := s.exchangeIKEAuth(ctx, state); err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	s.commitConnect(state)
	s.startBackgroundLoops()
	return nil
}

func (s *Session) prepareConnect(imei string, card Card) (*connectState, error) {
	if err := validateConnectInput(imei, card); err != nil {
		return nil, err
	}
	if err := s.ensureConnectable(); err != nil {
		return nil, err
	}
	return newConnectState(imei, card)
}

func validateConnectInput(imei string, card Card) error {
	if card == nil {
		return fmt.Errorf("card is nil")
	}
	if imei == "" {
		return fmt.Errorf("imei is empty")
	}
	return nil
}

func (s *Session) ensureConnectable() error {
	if s.isClosed() {
		return fmt.Errorf("session is closed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.connected {
		return fmt.Errorf("already connected")
	}
	return nil
}

func newConnectState(imei string, card Card) (*connectState, error) {
	identity, realm, initialAKAState := initialAKAIdentity(card)
	crypto, initiatorSPI, espInitiatorSPI, nonceI, err := newConnectCryptoState()
	if err != nil {
		return nil, err
	}
	return &connectState{
		card:            card,
		imei:            imei,
		identity:        identity,
		realm:           realm,
		initialAKAState: initialAKAState,
		crypto:          crypto,
		initiatorSPI:    initiatorSPI,
		espInitiatorSPI: espInitiatorSPI,
		nonceI:          nonceI,
	}, nil
}

func newConnectCryptoState() (*ikeCrypto, uint64, uint32, []byte, error) {
	crypto, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	initiatorSPI, err := randomUint64()
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating initiator spi: %w", err)
	}
	espInitiatorSPI, err := randomUint32()
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating child spi: %w", err)
	}
	nonceI, err := randomBytes(16)
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating nonce: %w", err)
	}
	crypto.SetSPIs(initiatorSPI, 0)
	crypto.SetNonces(nonceI, nil)
	return crypto, initiatorSPI, espInitiatorSPI, nonceI, nil
}

func (state *connectState) buildIKESAInitRequest(outerLocal, outerRemote *net.UDPAddr) ([]byte, error) {
	payloads := defaultIKESAInitPayloads(state.crypto, outerLocal, outerRemote)
	header := IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeIKESAInit,
		Flags:        flagInitiator,
		MessageID:    0,
	}
	request, err := (IKEPacket{Header: header, Payloads: payloads}).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("building ike_sa_init request: %w", err)
	}
	return request, nil
}

func decodeIKESAInitPacket(raw []byte) (IKEPacket, error) {
	var packet IKEPacket
	if err := packet.UnmarshalBinary(raw); err != nil {
		return IKEPacket{}, fmt.Errorf("parsing ike_sa_init response: %w", err)
	}
	return packet, nil
}

func (state *connectState) applyIKESAInitResponse(response IKEPacket, request []byte) error {
	if response.Header.ResponderSPI == 0 {
		return fmt.Errorf("responder spi is empty")
	}
	proposal, responderNonce, responderKE, err := negotiatedIKESAFromPayloads(response.Payloads, transformDH1024MODP)
	if err != nil {
		return err
	}
	state.crypto.SetProposal(proposal.Encryption, proposal.EncryptionKeyLen, proposal.Integrity, proposal.PRF)
	state.crypto.SetSPIs(state.initiatorSPI, response.Header.ResponderSPI)
	state.crypto.SetNonces(state.nonceI, responderNonce)
	if err := state.crypto.DeriveIKEKeys(responderKE); err != nil {
		return fmt.Errorf("deriving ike keys: %w", err)
	}
	state.responderSPI = response.Header.ResponderSPI
	state.ikeInitRequest = append([]byte(nil), request...)
	state.responderNonce = append([]byte(nil), responderNonce...)
	return nil
}

func (s *Session) exchangeIKESAInit(ctx context.Context, state *connectState) error {
	outerLocal, err := resolveOuterLocalAddr(s.conn, s.outerRemote)
	if err != nil {
		s.logger.Debug("resolving local outer address failed", "err", err)
	}
	request, err := state.buildIKESAInitRequest(outerLocal, s.outerRemote)
	if err != nil {
		return err
	}
	responseRaw, _, err := s.exchangeIKE(ctx, s.outerRemote, request, false, 0)
	if err != nil {
		return err
	}
	response, err := decodeIKESAInitPacket(responseRaw)
	if err != nil {
		return err
	}
	return state.applyIKESAInitResponse(response, request)
}

func (s *Session) exchangeIKEAuth(ctx context.Context, state *connectState) error {
	request, idiData, err := buildIKEAuthRequest(state)
	if err != nil {
		return err
	}
	challengePayloads, err := s.readIKEAuthChallenge(ctx, state, request)
	if err != nil {
		return err
	}
	finalPayloads, nextMessageID, err := s.authenticateEAPAKA(ctx, state.card, state.imei, state.identity, state.realm, state.initialAKAState, state.crypto, state.initiatorSPI, state.responderSPI, state.ikeInitRequest, state.responderNonce, idiData, challengePayloads)
	if err != nil {
		return err
	}
	return finalizeIKEAuthState(state, finalPayloads, nextMessageID)
}

func buildIKEAuthRequest(state *connectState) ([]byte, []byte, error) {
	idi := (&IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte(state.identity)}).RawData()
	payloads, err := defaultIKEAuthInitPayloads(state.identity, state.espInitiatorSPI)
	if err != nil {
		return nil, nil, fmt.Errorf("building ike_auth request: %w", err)
	}
	header := IKEHeader{InitiatorSPI: state.initiatorSPI, ResponderSPI: state.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: 1}
	request, err := state.crypto.SealIKE(header, payloads, true)
	if err != nil {
		return nil, nil, fmt.Errorf("sealing ike_auth request: %w", err)
	}
	return request, idi, nil
}

func (s *Session) readIKEAuthChallenge(ctx context.Context, state *connectState, request []byte) ([]Payload, error) {
	challengeRaw, _, err := s.exchangeIKE(ctx, s.outerNAT, request, true, 1)
	if err != nil {
		return nil, err
	}
	var challengePacket IKEPacket
	if err := challengePacket.UnmarshalBinary(challengeRaw); err != nil {
		return nil, fmt.Errorf("parsing ike_auth challenge: %w", err)
	}
	challengePayloads, err := state.crypto.OpenIKE(challengePacket, false)
	if err != nil {
		return nil, fmt.Errorf("opening ike_auth challenge: %w", err)
	}
	return challengePayloads, nil
}

func finalizeIKEAuthState(state *connectState, finalPayloads []Payload, nextMessageID uint32) error {
	tunnel, err := tunnelInfoFromChildSA(finalPayloads)
	if err != nil {
		return err
	}
	tunnel.ESPInitiatorSPI = state.espInitiatorSPI
	espKeys, err := state.crypto.DeriveESPKeys(tunnel.EncryptionKeyLen, tunnel.Integrity)
	if err != nil {
		return fmt.Errorf("deriving esp keys: %w", err)
	}
	state.finalPayloads = finalPayloads
	state.nextMessageID = nextMessageID
	state.tunnel = tunnel
	state.espKeys = espKeys
	return nil
}

func (state *connectState) outboundESPCodec() ESPCodec {
	return ESPCodec{
		SPI:           state.tunnel.ESPResponderSPI,
		Encryption:    EncryptionAESCBC,
		Integrity:     integrityName(state.tunnel.Integrity),
		EncryptionKey: append([]byte(nil), state.espKeys.EncryptionInitiator...),
		IntegrityKey:  append([]byte(nil), state.espKeys.IntegrityInitiator...),
	}
}

func (state *connectState) inboundESPCodec() ESPCodec {
	return ESPCodec{
		SPI:           state.tunnel.ESPInitiatorSPI,
		Encryption:    EncryptionAESCBC,
		Integrity:     integrityName(state.tunnel.Integrity),
		EncryptionKey: append([]byte(nil), state.espKeys.EncryptionResponder...),
		IntegrityKey:  append([]byte(nil), state.espKeys.IntegrityResponder...),
	}
}

func (state *connectState) innerLocalAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), state.tunnel.InnerIP...), Port: port}
}

func (state *connectState) innerRemoteAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), state.tunnel.PCSCFIP...), Port: port}
}

func (state *connectState) sessionLivenessTimeout() time.Duration {
	timeout := livenessTimeout(state.finalPayloads)
	if timeout <= 0 {
		return 60 * time.Second
	}
	return timeout
}

func (s *Session) commitConnect(state *connectState) {
	s.mu.Lock()
	s.connected = true
	s.innerLocal = state.innerLocalAddr(s.cfg.LocalSIPPort)
	s.innerRemote = state.innerRemoteAddr(s.cfg.SIPPort)
	s.tunnel = state.tunnel
	s.ike = state.crypto
	s.initiatorSPI = state.initiatorSPI
	s.responderSPI = state.responderSPI
	s.nextMessageID = state.nextMessageID
	s.deviceIdentity = state.imei
	s.espSeq = 0
	s.inboundReplay.Reset()
	s.lastProtectedRx = time.Now()
	s.lastProtectedTx = time.Now()
	s.livenessTimeout = state.sessionLivenessTimeout()
	s.natKeepaliveInterval = 20 * time.Second
	s.informWaiters = make(map[uint32]chan inboundIKE)
	s.outboundESP = state.outboundESPCodec()
	s.inboundESP = state.inboundESPCodec()
	s.mu.Unlock()
}

func (s *Session) startBackgroundLoops() {
	s.wg.Add(3)
	go s.readLoop()
	go s.livenessLoop()
	go s.natKeepaliveLoop()
}

func (s *Session) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), defaultCloseTimeout)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *Session) CloseContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.closeCancel != nil {
		s.closeCancel()
	}
	s.wg.Wait()
	_ = s.sendDeleteRequest(ctx)
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
	return s.conn == nil || (s.closeCtx != nil && s.closeCtx.Err() != nil)
}

func (s *Session) discardSecurityAssociations(cause error) {
	s.clearInformationalWaiters()
	s.mu.Lock()
	s.connected = false
	s.innerLocal = nil
	s.innerRemote = nil
	s.tunnel = TunnelInfo{}
	s.outboundESP = ESPCodec{}
	s.inboundESP = ESPCodec{}
	s.espSeq = 0
	s.inboundReplay.Reset()
	s.ike = nil
	s.initiatorSPI = 0
	s.responderSPI = 0
	s.deviceIdentity = ""
	s.nextMessageID = 0
	s.lastProtectedRx = time.Time{}
	s.lastProtectedTx = time.Time{}
	s.livenessTimeout = 0
	s.natKeepaliveInterval = 0
	s.mu.Unlock()

	s.tcpMu.Lock()
	tcp := s.tcp
	tcpServer := s.tcpServer
	s.tcp = nil
	s.tcpServer = nil
	s.tcpMu.Unlock()

	s.udpMu.Lock()
	udpServer := s.udpServer
	s.udpServer = nil
	s.udpMu.Unlock()

	s.notifyDetachedTransports(tcp, tcpServer, udpServer, cause)
}

func (s *Session) failSecurityAssociations(cause error) {
	s.discardSecurityAssociations(cause)
	if s.closeCancel != nil {
		s.closeCancel()
	}
	if s.owned && s.conn != nil {
		_ = s.conn.Close()
	}
}

func (s *Session) notifyDetachedTransports(tcp, tcpServer *TCPTransport, udpServer *SecureUDPTransport, cause error) {
	if cause == nil {
		if tcp != nil {
			_ = tcp.Close()
		}
		if tcpServer != nil {
			_ = tcpServer.Close()
		}
		if udpServer != nil {
			_ = udpServer.Close()
		}
		return
	}
	if tcp != nil {
		tcp.fail(fmt.Errorf("reading tcp packet: %w", cause))
	}
	if tcpServer != nil {
		tcpServer.fail(fmt.Errorf("reading tcp packet: %w", cause))
	}
	if udpServer != nil {
		udpServer.fail(fmt.Errorf("reading secure udp packet: %w", cause))
	}
}

func (s *Session) acceptInboundESPSequence(sequence uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.connected {
		return false
	}
	return s.inboundReplay.Accept(sequence)
}

func (s *Session) LocalAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connected && s.innerLocal != nil {
		return cloneUDPAddr(s.innerLocal)
	}
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connected && s.innerRemote != nil {
		return cloneUDPAddr(s.innerRemote)
	}
	return cloneUDPAddr(s.outerRemote)
}

func (s *Session) Tunnel() TunnelInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return TunnelInfo{
		InnerIP:          append(net.IP(nil), s.tunnel.InnerIP...),
		PCSCFIP:          append(net.IP(nil), s.tunnel.PCSCFIP...),
		ESPInitiatorSPI:  s.tunnel.ESPInitiatorSPI,
		ESPResponderSPI:  s.tunnel.ESPResponderSPI,
		Encryption:       s.tunnel.Encryption,
		EncryptionKeyLen: s.tunnel.EncryptionKeyLen,
		Integrity:        s.tunnel.Integrity,
	}
}

func (s *Session) WritePacket(ctx context.Context, data []byte) error {
	if s.isClosed() {
		return errors.New("writing packet: session is closed")
	}
	s.mu.RLock()
	connected := s.connected
	innerLocal := cloneUDPAddr(s.innerLocal)
	innerRemote := cloneUDPAddr(s.innerRemote)
	outerRemote := cloneUDPAddr(s.outerRemote)
	s.mu.RUnlock()
	if !connected {
		if outerRemote == nil {
			return errors.New("writing packet: remote address is nil")
		}
		return s.writeOuter(ctx, data, outerRemote)
	}
	innerPacket, nextHeader, err := buildInnerUDPPacket(innerLocal, innerRemote, data)
	if err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}
	return s.writeInner(ctx, innerPacket, nextHeader)
}

func (s *Session) prepareInnerWrite() (innerWriteState, error) {
	if s.isClosed() {
		return innerWriteState{}, errors.New("writing packet: session is closed")
	}
	s.mu.Lock()
	if !s.connected {
		outer := cloneUDPAddr(s.outerRemote)
		s.mu.Unlock()
		if outer == nil {
			return innerWriteState{}, errors.New("writing packet: remote address is nil")
		}
		return innerWriteState{outer: outer}, nil
	}
	codec := s.outboundESP
	outer := cloneUDPAddr(s.outerNAT)
	seq, ok := nextESPSequence(&s.espSeq)
	s.mu.Unlock()
	if !ok {
		s.failSecurityAssociations(errors.New("esp sequence number overflow"))
		return innerWriteState{}, errors.New("writing packet: esp sequence number overflow")
	}
	return innerWriteState{connected: true, codec: codec, outer: outer, seq: seq}, nil
}

func sealInnerPacket(state innerWriteState, innerPacket []byte, nextHeader byte) ([]byte, error) {
	return state.codec.Encode(ESPPacket{SPI: state.codec.SPI, Sequence: state.seq, NextHeader: nextHeader, Payload: innerPacket})
}

func (s *Session) writeInner(ctx context.Context, innerPacket []byte, nextHeader byte) error {
	state, err := s.prepareInnerWrite()
	if err != nil {
		return err
	}
	if !state.connected {
		s.logger.Debug("writing outer plain packet", "remote_addr", state.outer, "packet_len", len(innerPacket))
		return s.writeOuter(ctx, innerPacket, state.outer)
	}
	sealed, err := sealInnerPacket(state, innerPacket, nextHeader)
	if err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}
	s.logger.Debug("writing outer ESP packet", "remote_addr", state.outer, "packet_len", len(sealed))
	if err := s.writeOuter(ctx, sealed, state.outer); err != nil {
		return err
	}
	s.markProtectedTx(time.Now())
	return nil
}

func (s *Session) readConnectedPacket(ctx context.Context) ([]byte, net.Addr, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-s.closeCtx.Done():
			return nil, nil, errors.New("reading packet: session is closed")
		case inbound, ok := <-s.readCh:
			if !ok {
				return nil, nil, errors.New("reading packet: session is closed")
			}
			if inbound.err != nil {
				return nil, nil, inbound.err
			}
			return inbound.data, inbound.addr, nil
		}
	}
}

func (s *Session) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	if s.isClosed() {
		return nil, nil, errors.New("reading packet: session is closed")
	}
	s.mu.RLock()
	connected := s.connected
	s.mu.RUnlock()
	if !connected {
		return s.readOuterPacket(ctx)
	}
	return s.readConnectedPacket(ctx)
}

func (s *Session) readLoop() {
	defer s.wg.Done()
	defer close(s.readCh)
	buf := make([]byte, 64*1024)
	for {
		packet, addr, ok := s.readLoopPacket(buf)
		if !ok {
			return
		}
		if packet == nil {
			continue
		}
		s.handleOuterPacket(packet, addr)
	}
}

func (s *Session) readLoopPacket(buf []byte) ([]byte, net.Addr, bool) {
	if s.closeCtx != nil && s.closeCtx.Err() != nil {
		return nil, nil, false
	}
	if err := s.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		s.tryDeliverError(fmt.Errorf("reading packet: setting read deadline: %w", err))
		return nil, nil, false
	}
	n, addr, err := s.conn.ReadFrom(buf)
	if err != nil {
		if errors.Is(err, net.ErrClosed) || s.closeCtx.Err() != nil {
			return nil, nil, false
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if s.closeCtx != nil && s.closeCtx.Err() != nil {
				return nil, nil, false
			}
			return nil, nil, true
		}
		s.tryDeliverError(fmt.Errorf("reading packet: %w", err))
		return nil, nil, false
	}
	return append([]byte(nil), buf[:n]...), addr, true
}

func (s *Session) handleOuterPacket(packet []byte, addr net.Addr) {
	s.logger.Debug("read outer packet", "packet_len", len(packet))
	if isNATKeepalive(packet) {
		s.logger.Debug("ignoring NAT keepalive")
		return
	}
	if hasNonESPMarker(packet) {
		s.handleNonESPPacket(packet[4:], addr)
		return
	}
	s.handleESPPacket(packet)
}

func (s *Session) handleNonESPPacket(packet []byte, addr net.Addr) {
	handled, err := s.handleIKEPacket(packet, addr)
	if err != nil {
		s.logger.Debug("handling IKE packet failed", "err", err)
	}
	if handled {
		return
	}
	s.logger.Debug("ignoring unexpected non-ESP marker packet")
}

func (s *Session) inboundPacketContext() (ESPCodec, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inboundESP, s.cfg.LocalSIPPort
}

func (s *Session) handleESPPacket(packet []byte) {
	codec, localUDPPort := s.inboundPacketContext()
	espPacket, err := codec.Decode(packet)
	if err != nil {
		if len(packet) <= 16 {
			s.logger.Debug("decoding ESP packet failed", "err", err, "packet_hex", shortPacketHex(packet))
		} else {
			s.logger.Debug("decoding ESP packet failed", "err", err)
		}
		return
	}
	if !s.acceptInboundESPSequence(espPacket.Sequence) {
		s.logger.Debug("dropping replayed ESP packet", "esp_sequence", espPacket.Sequence)
		return
	}
	s.markProtectedRx(time.Now())
	proto, srcIP, dstIP, innerPayload, err := decodeInnerIPPacket(espPacket.Payload, espPacket.NextHeader)
	if err != nil {
		s.logger.Debug("parsing inner IP packet failed", "err", err)
		return
	}
	s.handleInnerPacket(proto, srcIP, dstIP, innerPayload, localUDPPort)
}

func (s *Session) handleInnerPacket(proto byte, srcIP, dstIP net.IP, innerPayload []byte, localUDPPort int) {
	switch proto {
	case 17:
		s.handleInnerUDPPacket(srcIP, dstIP, innerPayload, localUDPPort)
	case 6:
		s.handleInnerTCPPacket(srcIP, dstIP, innerPayload)
	case 50:
		s.handleInnerSecurePacket(srcIP, dstIP, innerPayload)
	default:
		s.logger.Debug("dropping unsupported inner protocol", "inner_proto", proto)
	}
}

func (s *Session) handleInnerUDPPacket(srcIP, dstIP net.IP, innerPayload []byte, localUDPPort int) {
	payload, peer, err := decodeUDPDatagram(srcIP, dstIP, innerPayload, localUDPPort)
	if err != nil {
		s.logger.Debug("parsing inner UDP packet failed", "err", err)
		return
	}
	s.logger.Debug("read inner UDP packet", "peer_addr", peer, "payload_len", len(payload))
	select {
	case s.readCh <- inboundPacket{data: payload, addr: peer}:
	case <-s.closeCtx.Done():
	}
}

func (s *Session) handleInnerTCPPacket(srcIP, dstIP net.IP, innerPayload []byte) {
	segment, err := decodeTCPSegment(srcIP, dstIP, innerPayload)
	if err != nil {
		s.logger.Debug("parsing inner TCP segment failed", "err", err)
		return
	}
	s.tcpMu.RLock()
	tcp := s.tcp
	s.tcpMu.RUnlock()
	if tcp == nil || tcp.secure {
		s.logger.Debug("dropping TCP segment without plain transport")
		return
	}
	if segment.dst.Port != tcp.local.Port || !segment.src.IP.Equal(tcp.remote.IP) || segment.src.Port != tcp.remote.Port {
		s.logger.Debug("dropping TCP segment for unexpected flow", "src_addr", segment.src, "dst_addr", segment.dst)
		return
	}
	tcp.handleSegment(segment)
}

func (s *Session) handleInnerSecurePacket(srcIP, dstIP net.IP, innerPayload []byte) {
	s.tcpMu.RLock()
	tcp := s.tcp
	tcpServer := s.tcpServer
	s.tcpMu.RUnlock()
	s.udpMu.RLock()
	udpServer := s.udpServer
	s.udpMu.RUnlock()
	spi := innerPacketSPI(innerPayload)
	if s.handleSecureTCPPacket(srcIP, dstIP, innerPayload, spi, tcp) {
		return
	}
	if s.handleSecureTCPPacket(srcIP, dstIP, innerPayload, spi, tcpServer) {
		return
	}
	if s.handleSecureUDPPacket(srcIP, dstIP, innerPayload, spi, udpServer) {
		return
	}
	s.logger.Debug("dropping secure packet", "spi", spi, "src_ip", srcIP, "dst_ip", dstIP)
}

func innerPacketSPI(packet []byte) uint32 {
	if len(packet) < 4 {
		return 0
	}
	return binary.BigEndian.Uint32(packet[:4])
}

func (s *Session) handleSecureTCPPacket(srcIP, dstIP net.IP, innerPayload []byte, spi uint32, candidate *TCPTransport) bool {
	if candidate == nil || !candidate.secure {
		return false
	}
	espPacket, err := candidate.inboundESP.Decode(innerPayload)
	if err != nil || espPacket.SPI != candidate.inboundESP.SPI {
		return false
	}
	if !candidate.acceptInboundESP(espPacket.Sequence) {
		s.logger.Debug("dropping replayed secure TCP packet", "spi", spi, "esp_sequence", espPacket.Sequence)
		return false
	}
	if espPacket.NextHeader != 6 {
		return false
	}
	segment, err := decodeTCPSegment(srcIP, dstIP, espPacket.Payload)
	if err != nil {
		s.logger.Debug("parsing secure TCP packet failed", "spi", spi, "local_addr", candidate.local, "remote_addr", candidate.remote, "err", err)
		return false
	}
	if segment.dst.Port != candidate.local.Port || !segment.src.IP.Equal(candidate.remote.IP) || segment.src.Port != candidate.remote.Port {
		s.logger.Debug("secure TCP flow mismatch", "spi", spi, "src_addr", segment.src, "dst_addr", segment.dst, "expected_remote_addr", candidate.remote, "expected_local_addr", candidate.local)
		return false
	}
	candidate.handleSegment(segment)
	return true
}

func (s *Session) handleSecureUDPPacket(srcIP, dstIP net.IP, innerPayload []byte, spi uint32, candidate *SecureUDPTransport) bool {
	if candidate == nil {
		return false
	}
	espPacket, err := candidate.inboundESP.Decode(innerPayload)
	if err != nil || espPacket.SPI != candidate.inboundESP.SPI {
		return false
	}
	if !candidate.acceptInboundESP(espPacket.Sequence) {
		s.logger.Debug("dropping replayed secure UDP packet", "spi", spi, "esp_sequence", espPacket.Sequence)
		return false
	}
	if espPacket.NextHeader != 17 {
		s.logger.Debug("secure ESP packet", "next_header", espPacket.NextHeader, "spi", spi, "local_addr", candidate.local, "remote_addr", candidate.remote)
		return false
	}
	payload, peer, err := decodeUDPDatagram(srcIP, dstIP, espPacket.Payload, candidate.local.Port)
	if err != nil {
		s.logger.Debug("parsing secure UDP packet failed", "spi", spi, "local_addr", candidate.local, "remote_addr", candidate.remote, "err", err)
		return false
	}
	udpPeer, _ := peer.(*net.UDPAddr)
	if udpPeer == nil || !udpPeer.IP.Equal(candidate.remote.IP) || udpPeer.Port != candidate.remote.Port {
		s.logger.Debug("secure UDP flow mismatch", "spi", spi, "peer_addr", peer, "expected_remote_addr", candidate.remote, "expected_local_addr", candidate.local)
		return false
	}
	s.logger.Debug("received secure UDP packet", "peer_addr", udpPeer, "local_addr", candidate.local, "payload_len", len(payload))
	candidate.deliver(payload, peer)
	return true
}

func (s *Session) tryDeliverError(err error) {
	select {
	case s.readCh <- inboundPacket{err: err}:
	case <-s.closeCtx.Done():
	}
}

func buildIKEWire(request []byte, nat bool) []byte {
	if !nat {
		return request
	}
	return append([]byte{0x00, 0x00, 0x00, 0x00}, request...)
}

func (s *Session) writeIKERequest(ctx context.Context, addr *net.UDPAddr, request []byte, nat bool, messageID uint32) error {
	wire := buildIKEWire(request, nat)
	if err := s.writeOuter(ctx, wire, addr); err != nil {
		return fmt.Errorf("connecting swu session: sending message %d: %w", messageID, err)
	}
	return nil
}

func (s *Session) awaitIKEAttempt(ctx context.Context, messageID uint32, attempt int) ([]byte, *net.UDPAddr, error) {
	response, peer, err := s.readIKEMessage(ctx, messageID, ikeRetransmitDelay(attempt))
	if err == nil {
		s.logger.Debug("received IKE message", "message_id", messageID, "peer_addr", peer, "response_len", len(response))
		return response, peer, nil
	}
	s.logger.Debug("waiting for IKE message", "message_id", messageID, "attempt", attempt+1, "err", err)
	return nil, nil, err
}

func (s *Session) exchangeIKE(ctx context.Context, addr *net.UDPAddr, request []byte, nat bool, messageID uint32) ([]byte, *net.UDPAddr, error) {
	s.logger.Debug("sending IKE message", "message_id", messageID, "use_natt", nat, "remote_addr", addr, "request_len", len(request))
	for attempt := range ikeRetransmitAttempts {
		if err := s.writeIKERequest(ctx, addr, request, nat, messageID); err != nil {
			return nil, nil, err
		}
		response, peer, err := s.awaitIKEAttempt(ctx, messageID, attempt)
		if err == nil {
			return response, peer, nil
		}
		if !errors.Is(err, errIKETimeout) {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("connecting swu session: waiting message %d: timeout", messageID)
}

var errIKETimeout = errors.New("ike timeout")

const ikeRetransmitAttempts = 6

func ikeRetransmitDelay(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	delay := 500 * time.Millisecond
	for range attempt {
		delay *= 2
		if delay >= 8*time.Second {
			return 8 * time.Second
		}
	}
	return delay
}

func (s *Session) readIKEMessage(ctx context.Context, messageID uint32, timeout time.Duration) ([]byte, *net.UDPAddr, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if ikeReadTimedOut(deadline) {
			return nil, nil, errIKETimeout
		}
		packet, udpAddr, err := s.readIKECandidate(deadline, buf)
		if err != nil {
			if errors.Is(err, errIKETimeout) {
				continue
			}
			return nil, nil, err
		}
		if !matchesIKEMessage(packet, messageID) {
			continue
		}
		return packet, udpAddr, nil
	}
}

func ikeReadTimedOut(deadline time.Time) bool {
	return time.Now().After(deadline)
}

func nextIKEReadDeadline(deadline time.Time) time.Time {
	readDeadline := time.Now().Add(250 * time.Millisecond)
	if readDeadline.After(deadline) {
		return deadline
	}
	return readDeadline
}

func (s *Session) readIKECandidate(deadline time.Time, buf []byte) ([]byte, *net.UDPAddr, error) {
	if err := s.conn.SetReadDeadline(nextIKEReadDeadline(deadline)); err != nil {
		return nil, nil, fmt.Errorf("connecting swu session: setting read deadline: %w", err)
	}
	n, addr, err := s.conn.ReadFrom(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, nil, errIKETimeout
		}
		return nil, nil, fmt.Errorf("connecting swu session: reading ike response: %w", err)
	}
	packet := normalizeIKEPacket(buf[:n])
	udpAddr, _ := addr.(*net.UDPAddr)
	return packet, cloneUDPAddr(udpAddr), nil
}

func normalizeIKEPacket(packet []byte) []byte {
	packet = append([]byte(nil), packet...)
	if hasNonESPMarker(packet) {
		return packet[4:]
	}
	return packet
}

func matchesIKEMessage(packet []byte, messageID uint32) bool {
	var header IKEHeader
	if err := header.UnmarshalBinary(packet); err != nil {
		return false
	}
	return header.MessageID == messageID
}

func (s *Session) writeOuter(ctx context.Context, data []byte, addr net.Addr) error {
	if deadline, ok := ctx.Deadline(); ok {
		if err := s.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("setting write deadline: %w", err)
		}
	} else {
		_ = s.conn.SetWriteDeadline(time.Time{})
	}
	if _, err := s.conn.WriteTo(data, addr); err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}
	return nil
}

func (s *Session) readOuterClosed() error {
	if s.closeCtx != nil && s.closeCtx.Err() != nil {
		return errors.New("reading packet: session is closed")
	}
	return nil
}

func (s *Session) readOuterCandidate(buf []byte) ([]byte, net.Addr, error) {
	if err := s.conn.SetReadDeadline(time.Now().Add(outerReadPollDelay)); err != nil {
		return nil, nil, fmt.Errorf("setting read deadline: %w", err)
	}
	n, addr, err := s.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), buf[:n]...), addr, nil
}

func (s *Session) readOuterPacket(ctx context.Context) ([]byte, net.Addr, error) {
	buf := make([]byte, 64*1024)
	for {
		if err := s.readOuterClosed(); err != nil {
			return nil, nil, err
		}
		packet, addr, err := s.readOuterCandidate(buf)
		if err == nil {
			return packet, addr, nil
		}
		if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
			return nil, nil, fmt.Errorf("reading packet: %w", err)
		}
		if err := s.readOuterClosed(); err != nil {
			return nil, nil, err
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}
	}
}

func (s *Session) markProtectedRx(now time.Time) {
	s.mu.Lock()
	if now.After(s.lastProtectedRx) {
		s.lastProtectedRx = now
	}
	s.mu.Unlock()
}

func (s *Session) markProtectedTx(now time.Time) {
	s.mu.Lock()
	if now.After(s.lastProtectedTx) {
		s.lastProtectedTx = now
	}
	s.mu.Unlock()
}

func (s *Session) allocateMessageID() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	messageID := s.nextMessageID
	if messageID == 0 {
		messageID = 1
	}
	s.nextMessageID = messageID + 1
	return messageID
}

func (s *Session) registerInformationalWaiter(messageID uint32) chan inboundIKE {
	ch := make(chan inboundIKE, 1)
	s.mu.Lock()
	if s.informWaiters == nil {
		s.informWaiters = make(map[uint32]chan inboundIKE)
	}
	s.informWaiters[messageID] = ch
	s.mu.Unlock()
	return ch
}

func (s *Session) unregisterInformationalWaiter(messageID uint32, ch chan inboundIKE) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.informWaiters[messageID]; ok && current == ch {
		delete(s.informWaiters, messageID)
	}
}

func (s *Session) deliverInformationalWaiter(messageID uint32, packet inboundIKE) bool {
	s.mu.Lock()
	ch, ok := s.informWaiters[messageID]
	if ok {
		delete(s.informWaiters, messageID)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- packet:
	default:
	}
	return true
}

func (s *Session) clearInformationalWaiters() {
	s.mu.Lock()
	s.informWaiters = nil
	s.mu.Unlock()
}

func (state informationalState) canSendDelete() bool {
	return state.connected && state.available()
}

func (state informationalState) sealDeleteRequest(messageID uint32) ([]byte, error) {
	return state.sealInitiatorRequest(messageID, []Payload{&DeletePayload{ProtocolID: protocolIDIKE}})
}

func (s *Session) sendDeleteRequest(ctx context.Context) error {
	state := s.currentInformationalState()
	if !state.canSendDelete() {
		return nil
	}
	wire, err := state.sealDeleteRequest(s.allocateMessageID())
	if err != nil {
		return fmt.Errorf("closing swu session: sealing delete request: %w", err)
	}
	if err := s.writeOuter(ctx, append([]byte{0x00, 0x00, 0x00, 0x00}, wire...), state.peer); err != nil {
		return fmt.Errorf("closing swu session: sending delete request: %w", err)
	}
	s.markProtectedTx(time.Now())
	return nil
}

func (s *Session) closeDone() <-chan struct{} {
	if s != nil && s.closeCtx != nil {
		return s.closeCtx.Done()
	}
	return nil
}

func (state informationalState) available() bool {
	return state.ike != nil && state.peer != nil
}

func (state informationalState) initiatorHeader(messageID uint32) IKEHeader {
	return IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		ResponderSPI: state.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        flagInitiator,
		MessageID:    messageID,
	}
}

func (state informationalState) sealInitiatorRequest(messageID uint32, payloads []Payload) ([]byte, error) {
	return state.ike.SealIKE(state.initiatorHeader(messageID), payloads, true)
}

func (s *Session) sendInformational(ctx context.Context, payloads []Payload) ([]Payload, error) {
	if s.isClosed() {
		return nil, errors.New("sending informational: session is closed")
	}
	state := s.currentInformationalState()
	if !state.available() {
		return nil, errors.New("sending informational: ike state is unavailable")
	}
	messageID := s.allocateMessageID()
	waiter := s.registerInformationalWaiter(messageID)
	defer s.unregisterInformationalWaiter(messageID, waiter)
	wire, err := state.sealInitiatorRequest(messageID, payloads)
	if err != nil {
		return nil, fmt.Errorf("sending informational: sealing request: %w", err)
	}
	return s.exchangeInformational(ctx, state, messageID, wire, waiter)
}

func (s *Session) exchangeInformational(ctx context.Context, state informationalState, messageID uint32, wire []byte, waiter <-chan inboundIKE) ([]Payload, error) {
	for attempt := range ikeRetransmitAttempts {
		if err := s.writeInformationalRequest(ctx, state.peer, wire); err != nil {
			return nil, err
		}
		payloads, received, err := s.awaitInformationalResponse(ctx, state.ike, waiter, attempt)
		if err != nil {
			return nil, err
		}
		if received {
			return payloads, nil
		}
		s.logger.Debug("retransmitting informational message", "message_id", messageID, "attempt", attempt+1)
	}
	return nil, fmt.Errorf("sending informational: waiting message %d: timeout", messageID)
}

func (s *Session) writeInformationalRequest(ctx context.Context, peer *net.UDPAddr, wire []byte) error {
	if err := s.writeOuter(ctx, append([]byte{0x00, 0x00, 0x00, 0x00}, wire...), peer); err != nil {
		return fmt.Errorf("sending informational: writing request: %w", err)
	}
	s.markProtectedTx(time.Now())
	return nil
}

func (s *Session) awaitInformationalResponse(ctx context.Context, ike *ikeCrypto, waiter <-chan inboundIKE, attempt int) ([]Payload, bool, error) {
	timer := time.NewTimer(ikeRetransmitDelay(attempt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case <-s.closeDone():
		return nil, false, errors.New("sending informational: session is closed")
	case response := <-waiter:
		payloads, err := s.openInformationalResponse(ike, response.data)
		if err != nil {
			return nil, false, err
		}
		return payloads, true, nil
	case <-timer.C:
		return nil, false, nil
	}
}

func (s *Session) openInformationalResponse(ike *ikeCrypto, data []byte) ([]Payload, error) {
	var packet IKEPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("sending informational: parsing response: %w", err)
	}
	payloads, err := ike.OpenIKE(packet, false)
	if err != nil {
		return nil, fmt.Errorf("sending informational: opening response: %w", err)
	}
	return payloads, nil
}

func (s *Session) livenessLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeCtx.Done():
			return
		case <-ticker.C:
		}
		s.mu.RLock()
		timeout := s.livenessTimeout
		lastRx := s.lastProtectedRx
		s.mu.RUnlock()
		if timeout <= 0 || lastRx.IsZero() || time.Since(lastRx) < timeout {
			continue
		}
		_, err := s.sendInformational(s.closeCtx, nil)
		if err == nil {
			s.markProtectedRx(time.Now())
			continue
		}
		cause := fmt.Errorf("liveness check: %w", err)
		s.tryDeliverError(cause)
		s.failSecurityAssociations(cause)
		return
	}
}

func (s *Session) natKeepaliveLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeCtx.Done():
			return
		case <-ticker.C:
		}
		s.mu.RLock()
		interval := s.natKeepaliveInterval
		lastTx := s.lastProtectedTx
		peer := cloneUDPAddr(s.outerNAT)
		s.mu.RUnlock()
		if interval <= 0 || peer == nil || lastTx.IsZero() || time.Since(lastTx) < interval {
			continue
		}
		ctx, cancel := context.WithTimeout(s.closeCtx, 2*time.Second)
		err := s.writeOuter(ctx, []byte{0xff}, peer)
		cancel()
		if err != nil {
			if s.closeCtx.Err() == nil {
				s.logger.Debug("sending NAT keepalive failed", "err", err)
			}
			continue
		}
		s.markProtectedTx(time.Now())
	}
}

func livenessTimeout(payloads []Payload) time.Duration {
	config := findConfigPayload(payloads)
	if config == nil {
		return 0
	}
	for _, attr := range config.Attributes {
		if attr.Type != configAttrTimeoutPeriodForLivenessCheck {
			continue
		}
		if attr.Format != attributeFormatTLV || len(attr.Value) != 4 {
			return 0
		}
		seconds := binary.BigEndian.Uint32(attr.Value)
		if seconds == 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	return 0
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

func hasNonESPMarker(data []byte) bool {
	return len(data) >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0
}

func isNATKeepalive(data []byte) bool {
	return len(data) == 1 && data[0] == 0xff
}

func shortPacketHex(packet []byte) string {
	const maxBytes = 16
	if len(packet) <= maxBytes {
		return hex.EncodeToString(packet)
	}
	return hex.EncodeToString(packet[:maxBytes]) + "..."
}

func resolveOuterLocalAddr(conn net.PacketConn, remote *net.UDPAddr) (*net.UDPAddr, error) {
	if conn == nil {
		return nil, fmt.Errorf("resolving outer local addr: conn is nil")
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("resolving outer local addr: local addr has type %T", conn.LocalAddr())
	}
	resolved := cloneUDPAddr(local)
	if resolved != nil && resolved.IP != nil && !resolved.IP.IsUnspecified() {
		return resolved, nil
	}
	if remote == nil {
		return resolved, nil
	}
	discovered, err := discoverOutboundIP(remote)
	if err != nil {
		return resolved, fmt.Errorf("resolving outer local addr: discovering outbound ip: %w", err)
	}
	if len(discovered) == 0 {
		return resolved, nil
	}
	resolved.IP = discovered
	return resolved, nil
}

func discoverOutboundIP(remote *net.UDPAddr) (net.IP, error) {
	if remote == nil {
		return nil, nil
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil, nil
	}
	return append(net.IP(nil), local.IP...), nil
}

func natDetectionHash(initiatorSPI, responderSPI uint64, addr *net.UDPAddr) [20]byte {
	seed := make([]byte, 16)
	binary.BigEndian.PutUint64(seed[0:8], initiatorSPI)
	binary.BigEndian.PutUint64(seed[8:16], responderSPI)
	if addr != nil {
		ip := addr.IP
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		} else {
			ip = ip.To16()
		}
		if len(ip) != 0 {
			seed = append(seed, ip...)
			seed = append(seed, byte(addr.Port>>8), byte(addr.Port))
		}
	}
	return sha1.Sum(seed)
}

func buildDeviceIdentityResponsePayload(payloads []Payload, identity string) (*NotifyPayload, bool, error) {
	notify := findNotifyPayload(payloads, notifyTypeDeviceIdentity)
	if notify == nil {
		return nil, false, nil
	}
	requestedType, requestedValue, err := decodeDeviceIdentity(notify.Data)
	if err != nil {
		return nil, false, err
	}
	if len(requestedValue) != 0 {
		return nil, false, nil
	}
	data, err := encodeDeviceIdentityForType(identity, requestedType)
	if err != nil {
		return nil, false, err
	}
	return &NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeDeviceIdentity, Data: data}, true, nil
}

func buildInformationalConfigReply(payloads []Payload) *ConfigPayload {
	request := findConfigPayload(payloads)
	if request == nil || request.ConfigType != configTypeRequest {
		return nil
	}
	attrs := make([]Attribute, 0, len(request.Attributes))
	for _, attr := range request.Attributes {
		switch attr.Type {
		case configAttrPCSCFIPv4Address, configAttrPCSCFIPv6Address, configAttrTimeoutPeriodForLivenessCheck:
			attrs = append(attrs, NewTLVAttribute(attr.Type, nil))
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return &ConfigPayload{ConfigType: configTypeReply, Attributes: attrs}
}

type informationalState struct {
	connected    bool
	ike          *ikeCrypto
	initiatorSPI uint64
	responderSPI uint64
	identity     string
	peer         *net.UDPAddr
}

func (s *Session) currentInformationalState() informationalState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return informationalState{
		connected:    s.connected,
		ike:          s.ike,
		initiatorSPI: s.initiatorSPI,
		responderSPI: s.responderSPI,
		identity:     s.deviceIdentity,
		peer:         cloneUDPAddr(s.outerNAT),
	}
}

func (state informationalState) matches(packet IKEPacket) bool {
	if state.ike == nil {
		return false
	}
	return packet.Header.InitiatorSPI == state.initiatorSPI && packet.Header.ResponderSPI == state.responderSPI
}

func buildInformationalResponsePayloads(payloads []Payload, identity string) ([]Payload, bool, error) {
	deleteRequest := findDeletePayload(payloads) != nil
	responsePayloads := make([]Payload, 0, 2)
	if deleteRequest {
		return responsePayloads, true, nil
	}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(payloads, identity)
	if err != nil {
		return nil, false, fmt.Errorf("building informational device identity: %w", err)
	}
	if ok {
		responsePayloads = append(responsePayloads, deviceIdentityPayload)
	}
	if configReply := buildInformationalConfigReply(payloads); configReply != nil {
		responsePayloads = append(responsePayloads, configReply)
	}
	return responsePayloads, false, nil
}

func (s *Session) informationalResponsePeer(addr net.Addr, fallback *net.UDPAddr) *net.UDPAddr {
	udpAddr, _ := addr.(*net.UDPAddr)
	if udpAddr != nil {
		return cloneUDPAddr(udpAddr)
	}
	return cloneUDPAddr(fallback)
}

func (s *Session) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if s != nil && s.closeCtx != nil {
		return context.WithTimeout(s.closeCtx, timeout)
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (s *Session) handleInformationalResponse(ike *ikeCrypto, packet IKEPacket, data []byte, addr net.Addr) (bool, error) {
	if _, err := ike.OpenIKE(packet, false); err != nil {
		return true, fmt.Errorf("opening informational response: %w", err)
	}
	s.markProtectedRx(time.Now())
	udpAddr, _ := addr.(*net.UDPAddr)
	if s.deliverInformationalWaiter(packet.Header.MessageID, inboundIKE{data: append([]byte(nil), data...), addr: cloneUDPAddr(udpAddr)}) {
		s.logger.Debug("matched informational response", "message_id", packet.Header.MessageID)
	}
	return true, nil
}

func (s *Session) writeInformationalResponse(state informationalState, messageID uint32, payloads []Payload, addr net.Addr) error {
	responseHeader := IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		ResponderSPI: state.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        flagResponse,
		MessageID:    messageID,
	}
	wire, err := state.ike.SealIKE(responseHeader, payloads, true)
	if err != nil {
		return fmt.Errorf("sealing informational response: %w", err)
	}
	ctx, cancel := s.timeoutContext(2 * time.Second)
	defer cancel()
	peer := s.informationalResponsePeer(addr, state.peer)
	if err := s.writeOuter(ctx, append([]byte{0x00, 0x00, 0x00, 0x00}, wire...), peer); err != nil {
		return fmt.Errorf("writing informational response: %w", err)
	}
	s.markProtectedTx(time.Now())
	s.logger.Debug("replied to informational request", "message_id", messageID, "payload_count", len(payloads))
	return nil
}

func (s *Session) handleInformationalRequest(state informationalState, packet IKEPacket, addr net.Addr) (bool, error) {
	payloads, err := state.ike.OpenIKE(packet, false)
	if err != nil {
		return true, fmt.Errorf("opening informational request: %w", err)
	}
	s.markProtectedRx(time.Now())
	responsePayloads, deleteRequest, err := buildInformationalResponsePayloads(payloads, state.identity)
	if err != nil {
		return true, err
	}
	if err := s.writeInformationalResponse(state, packet.Header.MessageID, responsePayloads, addr); err != nil {
		return true, err
	}
	if deleteRequest {
		s.logger.Debug("received IKE delete request", "message_id", packet.Header.MessageID)
		s.failSecurityAssociations(errors.New("peer deleted IKE SA"))
	}
	return true, nil
}

func (s *Session) handleIKEPacket(data []byte, addr net.Addr) (bool, error) {
	var packet IKEPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return false, nil
	}
	state := s.currentInformationalState()
	if !state.matches(packet) {
		return false, nil
	}
	if packet.Header.ExchangeType != exchangeTypeInformational {
		return false, nil
	}
	if packet.Header.Flags&flagResponse != 0 {
		return s.handleInformationalResponse(state.ike, packet, data, addr)
	}
	return s.handleInformationalRequest(state, packet, addr)
}

type negotiatedIKESA struct {
	Encryption       uint16
	EncryptionKeyLen uint16
	Integrity        uint16
	PRF              uint16
}

func negotiatedIKESAFromPayloads(payloads []Payload, dhGroup uint16) (negotiatedIKESA, []byte, []byte, error) {
	nonce := findNoncePayload(payloads)
	sa := findSAPayload(payloads)
	ke := findKEPayload(payloads, dhGroup)
	if nonce == nil || sa == nil || ke == nil {
		return negotiatedIKESA{}, nil, nil, fmt.Errorf("parsing ike_sa_init response: required payload is missing")
	}
	if len(sa.Proposals) == 0 {
		return negotiatedIKESA{}, nil, nil, fmt.Errorf("parsing ike_sa_init response: security association is empty")
	}
	proposal, err := negotiatedIKESAFromProposal(sa.Proposals[0])
	if err != nil {
		return negotiatedIKESA{}, nil, nil, err
	}
	return proposal, nonce.Data, ke.Data, nil
}

func negotiatedIKESAFromProposal(proposal Proposal) (negotiatedIKESA, error) {
	parsed := negotiatedIKESA{}
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			parsed.Encryption = transform.ID
			for _, attr := range transform.Attributes {
				if attr.Type == transformAttrKeyLength {
					if value, ok := attr.Uint16(); ok {
						parsed.EncryptionKeyLen = value
					}
				}
			}
		case transformTypeINTEG:
			parsed.Integrity = transform.ID
		case transformTypePRF:
			parsed.PRF = transform.ID
		}
	}
	if parsed.Encryption == 0 || parsed.EncryptionKeyLen == 0 || parsed.Integrity == 0 || parsed.PRF == 0 {
		return negotiatedIKESA{}, fmt.Errorf("parsing ike_sa_init response: negotiated transform is incomplete")
	}
	return parsed, nil
}

func tunnelInfoFromChildSA(payloads []Payload) (TunnelInfo, error) {
	config, proposal, err := childSAConfig(payloads)
	if err != nil {
		return TunnelInfo{}, err
	}
	tunnel, err := tunnelInfoFromProposal(proposal)
	if err != nil {
		return TunnelInfo{}, err
	}
	if err := applyTunnelAddresses(&tunnel, config); err != nil {
		return TunnelInfo{}, err
	}
	return tunnel, nil
}

func childSAConfig(payloads []Payload) (*ConfigPayload, Proposal, error) {
	config := findConfigPayload(payloads)
	sa := findSAPayload(payloads)
	if config == nil || sa == nil || len(sa.Proposals) == 0 {
		return nil, Proposal{}, fmt.Errorf("parsing ike_auth response: missing child sa or configuration")
	}
	return config, sa.Proposals[0], nil
}

func tunnelInfoFromProposal(proposal Proposal) (TunnelInfo, error) {
	tunnel := TunnelInfo{}
	if len(proposal.SPI) != 4 {
		return TunnelInfo{}, fmt.Errorf("parsing ike_auth response: invalid responder esp spi length %d", len(proposal.SPI))
	}
	tunnel.ESPResponderSPI = binary.BigEndian.Uint32(proposal.SPI)
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			tunnel.Encryption = transform.ID
			for _, attr := range transform.Attributes {
				if attr.Type == transformAttrKeyLength {
					if value, ok := attr.Uint16(); ok {
						tunnel.EncryptionKeyLen = value
					}
				}
			}
		case transformTypeINTEG:
			tunnel.Integrity = transform.ID
		}
	}
	if tunnel.Encryption == 0 || tunnel.EncryptionKeyLen == 0 || tunnel.Integrity == 0 {
		return TunnelInfo{}, fmt.Errorf("parsing ike_auth response: negotiated esp transform is incomplete")
	}
	return tunnel, nil
}

func applyTunnelAddresses(tunnel *TunnelInfo, config *ConfigPayload) error {
	if tunnel == nil || config == nil {
		return fmt.Errorf("parsing ike_auth response: missing child sa or configuration")
	}
	internalIPv4, internalIPv6, pcscfIPv4, pcscfIPv6 := tunnelAddresses(config.Attributes)
	switch {
	case internalIPv6 != nil && pcscfIPv6 != nil:
		tunnel.InnerIP = internalIPv6
		tunnel.PCSCFIP = pcscfIPv6
	case internalIPv4 != nil && pcscfIPv4 != nil:
		tunnel.InnerIP = internalIPv4
		tunnel.PCSCFIP = pcscfIPv4
	default:
		return fmt.Errorf("parsing ike_auth response: p-cscf and internal ip families do not match")
	}
	return nil
}

func tunnelAddresses(attrs []Attribute) (internalIPv4, internalIPv6, pcscfIPv4, pcscfIPv6 net.IP) {
	for _, attr := range attrs {
		switch attr.Type {
		case configAttrInternalIPv4Address:
			if len(attr.Value) >= net.IPv4len {
				internalIPv4 = append(net.IP(nil), attr.Value[:net.IPv4len]...)
			}
		case configAttrInternalIPv6Address:
			if len(attr.Value) >= net.IPv6len {
				internalIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		case configAttrPCSCFIPv4Address:
			if pcscfIPv4 == nil && len(attr.Value) >= net.IPv4len {
				pcscfIPv4 = append(net.IP(nil), attr.Value[:net.IPv4len]...)
			}
		case configAttrPCSCFIPv6Address:
			if pcscfIPv6 == nil && len(attr.Value) >= net.IPv6len {
				pcscfIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		}
	}
	return internalIPv4, internalIPv6, pcscfIPv4, pcscfIPv6
}

func defaultIKESAInitPayloads(crypto *ikeCrypto, local, remote *net.UDPAddr) []Payload {
	proposals := []Proposal{
		{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACMD596}, {TransformType: transformTypePRF, ID: transformPRFHMACMD5}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}},
		{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 256)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACMD596}, {TransformType: transformTypePRF, ID: transformPRFHMACMD5}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}},
		{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypePRF, ID: transformPRFHMACSHA1}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}},
		{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 256)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypePRF, ID: transformPRFHMACSHA1}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}},
		{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA256}, {TransformType: transformTypePRF, ID: transformPRFHMACSHA256}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}},
		{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 256)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA256}, {TransformType: transformTypePRF, ID: transformPRFHMACSHA256}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}},
	}
	natSourceHash := natDetectionHash(crypto.initiatorSPI, crypto.responderSPI, local)
	natDestHash := natDetectionHash(crypto.initiatorSPI, crypto.responderSPI, remote)
	return []Payload{
		&SecurityAssociationPayload{Proposals: proposals},
		&KeyExchangePayload{DHGroup: transformDH1024MODP, Data: crypto.PublicKey()},
		&NoncePayload{Data: append([]byte(nil), crypto.nonceI...)},
		&NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeNATDetectionSourceIP, Data: natSourceHash[:]},
		&NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeNATDetectionDestIP, Data: natDestHash[:]},
	}
}

func defaultIKEAuthInitPayloads(identity string, espSPI uint32) ([]Payload, error) {
	childSA := &SecurityAssociationPayload{Proposals: []Proposal{
		{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(espSPI), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACMD596}, {TransformType: transformTypeESN, ID: 0}}},
		{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(espSPI), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 256)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACMD596}, {TransformType: transformTypeESN, ID: 0}}},
		{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(espSPI), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypeESN, ID: 0}}},
		{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(espSPI), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 256)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypeESN, ID: 0}}},
		{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(espSPI), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA256}, {TransformType: transformTypeESN, ID: 0}}},
		{ProtocolID: proposalProtocolESP, SPI: uint32Bytes(espSPI), Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 256)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA256}, {TransformType: transformTypeESN, ID: 0}}},
	}}
	config := &ConfigPayload{ConfigType: configTypeRequest, Attributes: []Attribute{
		NewTLVAttribute(configAttrInternalIPv4Address, nil),
		NewTLVAttribute(configAttrInternalIPv4DNS, nil),
		NewTLVAttribute(configAttrInternalIPv6Address, nil),
		NewTLVAttribute(configAttrInternalIPv6DNS, nil),
		NewTLVAttribute(configAttrPCSCFIPv4Address, nil),
		NewTLVAttribute(configAttrPCSCFIPv6Address, nil),
		NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, nil),
	}}
	selectors := trafficSelectorsAny()
	return []Payload{
		&IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte(identity)},
		&IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte("ims")},
		config,
		childSA,
		&TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: selectors},
		&TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: selectors},
		&NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeEAPOnlyAuthentication},
	}, nil
}

func uint32Bytes(value uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	return buf
}

func integrityName(transform uint16) string {
	switch transform {
	case transformINTEGHMACMD596:
		return IntegrityHMACMD596
	case transformINTEGHMACSHA196:
		return IntegrityHMACSHA196
	case transformINTEGHMACSHA256:
		return IntegrityHMACSHA256128
	default:
		return IntegrityNone
	}
}

func randomUint64() (uint64, error) {
	buf := make([]byte, 8)
	if _, err := crand.Read(buf); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf), nil
}

func randomUint32() (uint32, error) {
	buf := make([]byte, 4)
	if _, err := crand.Read(buf); err != nil {
		return 0, err
	}
	value := binary.BigEndian.Uint32(buf)
	if value == 0 {
		value = 1
	}
	return value, nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := crand.Read(buf)
	return buf, err
}
