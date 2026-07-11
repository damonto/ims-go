package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	imssession "github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/ipsec/packet"
)

const (
	tcpDefaultSegmentSize = 1024
	tcpDefaultRemotePort  = 5060
	tcpEphemeralPortBase  = 40000
	tcpEphemeralPortRange = 20000
	tcpDefaultWindow      = 65535
	tcpCloseTimeout       = 500 * time.Millisecond
	tcpSendLockPoll       = 5 * time.Millisecond
	tcpInitialRTO         = 1 * time.Second
	tcpRTOBackoffCeiling  = 60 * time.Second
	tcpSYNMinTimeout      = 3 * time.Minute
	tcpDataMinTimeout     = 100 * time.Second
)

var tcpSYNTimeouts = []time.Duration{
	tcpInitialRTO,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
	64 * time.Second,
	64 * time.Second,
}

var tcpDataACKTimeouts = []time.Duration{
	tcpInitialRTO,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
	64 * time.Second,
}

var tcpDataACKTimeoutsAfterSYNTimeout = []time.Duration{
	3 * time.Second,
	6 * time.Second,
	12 * time.Second,
	24 * time.Second,
	48 * time.Second,
	64 * time.Second,
}

var tcpRandomISS = randomUint32

var errPendingSegmentCanceled = errors.New("tcp pending segment canceled")

var _ imssession.Transport = (*TCPConn)(nil)

type TCPConfig struct {
	LocalPort       int
	RemotePort      int
	RemoteIP        net.IP
	DataACKTimeouts []time.Duration
}

type SecureTCPConfig struct {
	TCPConfig
	OutboundSPI  uint32
	InboundSPI   uint32
	Encryption   string
	Integrity    string
	Mode         string
	Associations *SecurityAssociations

	EncryptionKey []byte
	IntegrityKey  []byte
	Salt          [4]byte
}

type TCPConn struct {
	session    PacketSession
	attachment Attachment
	local      *net.TCPAddr
	remote     *net.TCPAddr
	secure     bool
	passive    bool
	initialSeq uint32

	outboundESP  esp.Codec
	inboundESP   esp.Codec
	secureMode   string
	associations *SecurityAssociations

	mu          sync.Mutex
	writeMu     sync.Mutex
	sendMu      sync.Mutex
	established bool
	closed      bool
	terminalErr error
	sendSeq     uint32
	recvSeq     uint32
	stream      []byte
	ackedSeq    uint32
	peerMSS     uint16
	pending     *tcpPendingSegment
	// Keep out-of-order data bounded so the missing in-order segment still has
	// room to arrive and unblock delivery.
	pendingRcvdSegments []tcpReceivedSegment
	pendingRcvdBytes    int
	msgCh               chan []byte
	errCh               chan error
	readyCh             chan struct{}
	ackCh               chan struct{}
	done                chan struct{}
	closeOnce           sync.Once
	readyOnce           sync.Once

	dataACKTimeouts []time.Duration
}

type tcpPendingSegment struct {
	seq     uint32
	nextSeq uint32
	ack     uint32
	flags   byte
	payload []byte
}

type tcpSegmentResponse struct {
	seq        uint32
	ack        uint32
	flags      byte
	retransmit bool
}

func DialTCP(ctx context.Context, s PacketSession, cfg TCPConfig) (*TCPConn, error) {
	return dialTCP(ctx, s, cfg, nil)
}

func DialSecureTCP(ctx context.Context, s PacketSession, cfg SecureTCPConfig) (*TCPConn, error) {
	return dialTCP(ctx, s, cfg.TCPConfig, &cfg)
}

func ListenSecureTCP(s PacketSession, cfg SecureTCPConfig) (*TCPConn, error) {
	innerLocal, innerRemote, err := connectedUDPAddrs(s, cfg.RemoteIP)
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	if cfg.LocalPort == 0 || cfg.RemotePort == 0 {
		return nil, errors.New("listening secure tcp transport: ports are required")
	}
	if err := validateSecureSPIs(cfg.OutboundSPI, cfg.InboundSPI); err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	encryption, err := secureEncryption(cfg.Encryption)
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	mode, err := secureMode(cfg.Mode)
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	if err := validateSecureESPConfig(encryption, cfg.Integrity, cfg.EncryptionKey, cfg.IntegrityKey); err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	dataACKTimeouts, err := normalizedTCPDataACKTimeouts(cfg.DataACKTimeouts)
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	seq, err := randomUint32()
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	conn := &TCPConn{
		session:         s,
		local:           &net.TCPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: cfg.LocalPort, Zone: innerLocal.Zone},
		remote:          tcpRemoteAddr(innerRemote, cfg.RemotePort, cfg.RemoteIP),
		secure:          true,
		passive:         true,
		initialSeq:      seq,
		sendSeq:         seq + 1,
		ackedSeq:        seq,
		msgCh:           make(chan []byte, 16),
		errCh:           make(chan error, 1),
		readyCh:         make(chan struct{}),
		ackCh:           make(chan struct{}, 1),
		done:            make(chan struct{}),
		dataACKTimeouts: dataACKTimeouts,
		associations:    secureAssociations(cfg.Associations),
		outboundESP:     secureESPCodec(cfg.OutboundSPI, encryption, cfg.EncryptionKey, cfg.Integrity, cfg.IntegrityKey, cfg.Salt),
		inboundESP:      secureESPCodec(cfg.InboundSPI, encryption, cfg.EncryptionKey, cfg.Integrity, cfg.IntegrityKey, cfg.Salt),
		secureMode:      mode,
	}
	attachment, err := s.Attach(conn)
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	conn.attachment = attachment
	return conn, nil
}

func dialTCP(ctx context.Context, s PacketSession, cfg TCPConfig, secure *SecureTCPConfig) (*TCPConn, error) {
	innerLocal, innerRemote, err := connectedUDPAddrs(s, cfg.RemoteIP)
	if err != nil {
		return nil, fmt.Errorf("dialing tcp transport: %w", err)
	}
	remotePort := cfg.RemotePort
	if remotePort == 0 {
		remotePort = tcpDefaultRemotePort
	}
	localPort := cfg.LocalPort
	if localPort == 0 {
		rnd, err := randomUint32()
		if err != nil {
			return nil, fmt.Errorf("dialing tcp transport: %w", err)
		}
		localPort = int(tcpEphemeralPortBase + rnd%tcpEphemeralPortRange)
	}
	seq, err := randomUint32()
	if err != nil {
		return nil, fmt.Errorf("dialing tcp transport: %w", err)
	}
	dataACKTimeouts, err := normalizedTCPDataACKTimeouts(cfg.DataACKTimeouts)
	if err != nil {
		return nil, fmt.Errorf("dialing tcp transport: %w", err)
	}
	customDataACKTimeouts := len(cfg.DataACKTimeouts) > 0
	conn := &TCPConn{
		session:         s,
		local:           &net.TCPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: localPort, Zone: innerLocal.Zone},
		remote:          tcpRemoteAddr(innerRemote, remotePort, cfg.RemoteIP),
		initialSeq:      seq,
		sendSeq:         seq + 1,
		ackedSeq:        seq,
		msgCh:           make(chan []byte, 16),
		errCh:           make(chan error, 1),
		readyCh:         make(chan struct{}),
		ackCh:           make(chan struct{}, 1),
		done:            make(chan struct{}),
		dataACKTimeouts: dataACKTimeouts,
	}
	if secure != nil {
		if err := validateSecureSPIs(secure.OutboundSPI, secure.InboundSPI); err != nil {
			return nil, fmt.Errorf("dialing secure tcp transport: %w", err)
		}
		encryption, err := secureEncryption(secure.Encryption)
		if err != nil {
			return nil, fmt.Errorf("dialing secure tcp transport: %w", err)
		}
		mode, err := secureMode(secure.Mode)
		if err != nil {
			return nil, fmt.Errorf("dialing secure tcp transport: %w", err)
		}
		if err := validateSecureESPConfig(encryption, secure.Integrity, secure.EncryptionKey, secure.IntegrityKey); err != nil {
			return nil, fmt.Errorf("dialing secure tcp transport: %w", err)
		}
		conn.secure = true
		conn.secureMode = mode
		conn.associations = secureAssociations(secure.Associations)
		conn.outboundESP = secureESPCodec(secure.OutboundSPI, encryption, secure.EncryptionKey, secure.Integrity, secure.IntegrityKey, secure.Salt)
		conn.inboundESP = secureESPCodec(secure.InboundSPI, encryption, secure.EncryptionKey, secure.Integrity, secure.IntegrityKey, secure.Salt)
	}
	attachment, err := s.Attach(conn)
	if err != nil {
		return nil, fmt.Errorf("dialing tcp transport: %w", err)
	}
	conn.attachment = attachment

	synTimedOut := false
	finishDial := func() *TCPConn {
		conn.applySYNTimeoutDataRTO(customDataACKTimeouts, synTimedOut)
		conn.startUDPEncTunnelKeepalive()
		return conn
	}
	for attempt, timeout := range tcpSYNTimeouts {
		if ready, err := conn.dialReady(transportActionDialTCP); ready || err != nil {
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return finishDial(), nil
		}
		if err := conn.sendSegmentWithSeq(ctx, seq, 0, packet.TCPFlagSYN, nil); err != nil {
			_ = conn.Close()
			return nil, err
		}
		wait := time.NewTimer(timeout)
		select {
		case <-ctx.Done():
			wait.Stop()
			_ = conn.Close()
			return nil, ctx.Err()
		case <-conn.readyCh:
			wait.Stop()
			if err := conn.readyResult(transportActionDialTCP); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return finishDial(), nil
		case <-wait.C:
			synTimedOut = true
			if ready, err := conn.dialReady(transportActionDialTCP); ready || err != nil {
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				return finishDial(), nil
			}
			s.Logger().Debug("TCP SYN timed out", "attempt", attempt+1, "timeout", timeout)
		}
	}
	_ = conn.Close()
	return nil, errors.New("dialing tcp transport: waiting for syn-ack: timeout")
}

func (t *TCPConn) LocalAddr() net.Addr {
	return cloneTCPAddr(t.local)
}

func (t *TCPConn) RemoteAddr() net.Addr {
	return cloneTCPAddr(t.remote)
}

func (t *TCPConn) WritePacket(ctx context.Context, data []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	t.mu.Lock()
	if t.closed {
		err := t.terminalErrOr("writing tcp packet: transport is closed")
		t.mu.Unlock()
		return err
	}
	if !t.established {
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.done:
			return t.closedErr("writing tcp packet: transport is closed")
		case <-t.readyCh:
		}
		t.mu.Lock()
		if t.closed {
			err := t.terminalErrOr("writing tcp packet: transport is closed")
			t.mu.Unlock()
			return err
		}
		if !t.established {
			t.mu.Unlock()
			return errors.New("writing tcp packet: transport is not established")
		}
	}
	t.mu.Unlock()

	timeouts := t.tcpDataACKTimeouts()
	remaining := data
	for len(remaining) > 0 {
		maxPayload := t.maxPayloadSize()
		chunk := remaining
		flags := byte(packet.TCPFlagACK)
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		} else {
			flags |= packet.TCPFlagPSH
		}

		pending, err := t.reserveAndSendSegment(ctx, flags, chunk)
		if err != nil {
			return err
		}
		if err := t.waitPendingSegmentAck(ctx, pending, timeouts, "writing tcp packet"); err != nil {
			return err
		}
		remaining = remaining[len(chunk):]
	}
	return nil
}

func (t *TCPConn) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		default:
		}
		if msg, ok := t.nextMessage(); ok {
			return msg, t.RemoteAddr(), nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-t.done:
			if msg, ok := t.nextMessage(); ok {
				return msg, t.RemoteAddr(), nil
			}
			return nil, nil, t.closedErr("reading tcp packet: transport is closed")
		case err := <-t.errCh:
			if msg, ok := t.nextMessage(); ok {
				return msg, t.RemoteAddr(), nil
			}
			return nil, nil, err
		case msg, ok := <-t.msgCh:
			if !ok {
				return nil, nil, t.closedErr("reading tcp packet: transport is closed")
			}
			return msg, t.RemoteAddr(), nil
		}
	}
}

func (t *TCPConn) nextMessage() ([]byte, bool) {
	select {
	case msg, ok := <-t.msgCh:
		if !ok {
			return nil, false
		}
		return msg, true
	default:
		return nil, false
	}
}

func (t *TCPConn) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), tcpCloseTimeout)
	defer cancel()

	if err := t.closeWithFIN(ctx); err != nil && t.session != nil {
		t.session.Logger().Debug("closing tcp transport after FIN failed", "err", err)
	}
	return nil
}

func (t *TCPConn) closeWithFIN(ctx context.Context) error {
	fin, ok := t.beginLocalClose()
	if !ok {
		return nil
	}
	if err := t.lockSend(ctx); err != nil {
		return err
	}
	defer t.sendMu.Unlock()
	if err := t.sendSegmentWithSeq(ctx, fin.seq, fin.ack, fin.flags, fin.payload); err != nil {
		return err
	}
	return nil
}

func (t *TCPConn) beginLocalClose() (tcpPendingSegment, bool) {
	var fin tcpPendingSegment
	closed := false
	t.closeOnce.Do(func() {
		t.mu.Lock()
		if t.established {
			seq := t.sendSeq
			end := seq + tcpControlSequenceLen(packet.TCPFlagACK|packet.TCPFlagFIN)
			t.sendSeq = end
			fin = tcpPendingSegment{
				seq:     seq,
				nextSeq: end,
				ack:     t.recvSeq,
				flags:   packet.TCPFlagACK | packet.TCPFlagFIN,
			}
		}
		t.closed = true
		attachment := t.attachment
		t.mu.Unlock()
		if attachment != nil {
			_ = attachment.Close()
		}
		t.signalReady()
		close(t.done)
		close(t.msgCh)
		closed = true
	})
	return fin, closed && fin.flags != 0
}

func (t *TCPConn) HandleInnerPacket(pkt packet.InnerPacket) bool {
	if !t.secure {
		if pkt.TCP == nil {
			return false
		}
		if !tcpFlowMatches(pkt.TCP, t.local, t.remote) {
			t.session.Logger().Debug("dropping TCP segment for unexpected flow", "src_addr", pkt.TCP.Src, "dst_addr", pkt.TCP.Dst)
			return false
		}
		t.handleSegment(*pkt.TCP)
		return true
	}
	t.mu.Lock()
	mode := t.secureMode
	t.mu.Unlock()
	espPayload, ok := secureESPPayload(pkt, mode)
	if !ok {
		return false
	}
	spi := packetSPI(espPayload)
	if spi != t.inboundESP.SPI {
		return false
	}
	if sequence, ok := packetESPSequence(espPayload); ok && !t.mayAcceptInboundESP(sequence) {
		t.session.Logger().Debug("dropping replayed secure TCP packet before decode", "spi", spi, "esp_sequence", sequence)
		return false
	}
	espPacket, err := t.inboundESP.Decode(espPayload)
	if err != nil {
		return false
	}
	var inner packet.InnerPacket
	if mode == SecureModeUDPEncTunnel {
		if espPacket.NextHeader != packet.OuterIPv4 && espPacket.NextHeader != packet.OuterIPv6 {
			return false
		}
		if err := inner.UnmarshalBinary(espPacket.Payload); err != nil || inner.TCP == nil {
			t.session.Logger().Debug("parsing secure TCP tunnel packet failed", "spi", spi, "local_addr", t.local, "remote_addr", t.remote, "err", err)
			return false
		}
	} else if espPacket.NextHeader == packet.ProtocolTCP {
		inner, err = packet.DecodePayload(packet.ProtocolTCP, pkt.IP.SrcIP, pkt.IP.DstIP, espPacket.Payload)
		if err != nil || inner.TCP == nil {
			t.session.Logger().Debug("parsing secure TCP packet failed", "spi", spi, "local_addr", t.local, "remote_addr", t.remote, "err", err)
			return false
		}
	} else {
		return false
	}
	if !tcpFlowMatches(inner.TCP, t.local, t.remote) {
		t.session.Logger().Debug("secure TCP flow mismatch", "spi", spi, "src_addr", inner.TCP.Src, "dst_addr", inner.TCP.Dst, "expected_remote_addr", t.remote, "expected_local_addr", t.local)
		return false
	}
	if !t.acceptInboundESP(espPacket.Sequence) {
		t.session.Logger().Debug("dropping replayed secure TCP packet", "spi", spi, "esp_sequence", espPacket.Sequence)
		return false
	}
	t.handleSegment(*inner.TCP)
	return true
}

func (t *TCPConn) HandleError(err error) {
	t.closeWithError(fmt.Errorf("reading tcp packet: %w", err))
}

func (t *TCPConn) closeWithError(err error) {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		if err != nil {
			t.terminalErr = err
		}
		attachment := t.attachment
		t.mu.Unlock()
		if attachment != nil {
			_ = attachment.Close()
		}
		t.signalReady()
		if err != nil {
			select {
			case t.errCh <- err:
			default:
			}
		}
		close(t.done)
		close(t.msgCh)
	})
}

func (t *TCPConn) startUDPEncTunnelKeepalive() {
	t.mu.Lock()
	mode := t.secureMode
	t.mu.Unlock()
	if mode != SecureModeUDPEncTunnel {
		return
	}
	startUDPEncTunnelKeepalive(t.done, t.writeUDPEncTunnelKeepalive, func(err error) {
		if t.session != nil {
			t.session.Logger().Debug("writing UDP-enc-tun keepalive", "err", err)
		}
	})
}

func (t *TCPConn) writeUDPEncTunnelKeepalive(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("writing UDP-enc-tun keepalive: transport is closed")
	}
	session := t.session
	local := cloneTCPAddr(t.local)
	remote := cloneTCPAddr(t.remote)
	t.mu.Unlock()
	if local == nil || remote == nil {
		return errors.New("writing UDP-enc-tun keepalive: endpoint is nil")
	}
	return writeUDPEncTunnelKeepalive(ctx, session, local.IP, remote.IP)
}

func (t *TCPConn) acceptInboundESP(sequence uint32) bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return false
	}
	codec := t.inboundESP
	associations := t.associations
	t.mu.Unlock()
	return associations.acceptInboundESP(codec, sequence)
}

func (t *TCPConn) mayAcceptInboundESP(sequence uint32) bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return false
	}
	codec := t.inboundESP
	associations := t.associations
	t.mu.Unlock()
	return associations.mayAcceptInboundESP(codec, sequence)
}

func (t *TCPConn) tcpDataACKTimeouts() []time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.dataACKTimeouts) == 0 {
		return append([]time.Duration(nil), tcpDataACKTimeouts...)
	}
	return append([]time.Duration(nil), t.dataACKTimeouts...)
}

func (t *TCPConn) applySYNTimeoutDataRTO(customDataACKTimeouts bool, synTimedOut bool) {
	if customDataACKTimeouts || !synTimedOut {
		return
	}
	t.mu.Lock()
	t.dataACKTimeouts = append([]time.Duration(nil), tcpDataACKTimeoutsAfterSYNTimeout...)
	t.mu.Unlock()
}

func (t *TCPConn) sendState() (uint32, uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ackedSeq, t.sendSeq
}

func (t *TCPConn) waitForAck(ctx context.Context, want uint32) error {
	for {
		t.mu.Lock()
		acked := t.ackedSeq
		closed := t.closed
		pending := t.pending
		t.mu.Unlock()
		if !tcpSeqAfter(want, acked) {
			return nil
		}
		if closed {
			return t.closedErr("waiting for ack: transport is closed")
		}
		if pending == nil || pending.nextSeq != want {
			return errPendingSegmentCanceled
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.done:
			return t.closedErr("waiting for ack: transport is closed")
		case err := <-t.errCh:
			return err
		case <-t.ackCh:
		}
	}
}

func (t *TCPConn) noteAck(ack uint32) {
	if !tcpSeqAfter(ack, t.ackedSeq) || tcpSeqAfter(ack, t.sendSeq) {
		return
	}
	t.ackedSeq = ack
	if t.pending != nil && !tcpSeqAfter(t.pending.nextSeq, ack) {
		t.pending = nil
	}
	select {
	case t.ackCh <- struct{}{}:
	default:
	}
}

func (t *TCPConn) reserveSendSegment(flags byte, payload []byte) (tcpPendingSegment, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return tcpPendingSegment{}, t.terminalErrOr("writing tcp packet: transport is closed")
	}
	seq := t.sendSeq
	nextSeq := seq + uint32(len(payload)) + tcpControlSequenceLen(flags)
	t.sendSeq = nextSeq
	pending := tcpPendingSegment{
		seq:     seq,
		nextSeq: nextSeq,
		ack:     t.recvSeq,
		flags:   flags,
		payload: append([]byte(nil), payload...),
	}
	t.pending = &pending
	return pending, nil
}

func (t *TCPConn) reserveAndSendSegment(ctx context.Context, flags byte, payload []byte) (tcpPendingSegment, error) {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	pending, err := t.reserveSendSegment(flags, payload)
	if err != nil {
		return tcpPendingSegment{}, err
	}
	if err := t.sendSegmentWithSeq(ctx, pending.seq, pending.ack, pending.flags, pending.payload); err != nil {
		t.closeWithError(err)
		return tcpPendingSegment{}, err
	}
	return pending, nil
}

func (t *TCPConn) sendPendingSegment(ctx context.Context, pending tcpPendingSegment) error {
	t.sendMu.Lock()
	defer t.sendMu.Unlock()

	return t.sendSegmentWithSeq(ctx, pending.seq, pending.ack, pending.flags, pending.payload)
}

func (t *TCPConn) lockSend(ctx context.Context) error {
	ticker := time.NewTicker(tcpSendLockPoll)
	defer ticker.Stop()
	for {
		if t.sendMu.TryLock() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (t *TCPConn) waitPendingSegmentAck(ctx context.Context, pending tcpPendingSegment, timeouts []time.Duration, action string) error {
	for attempt, timeout := range timeouts {
		if attempt > 0 {
			if err := t.sendPendingSegment(ctx, pending); err != nil {
				t.closeWithError(err)
				return err
			}
		}
		waitCtx, cancel := context.WithTimeout(ctx, timeout)
		err := t.waitForAck(waitCtx, pending.nextSeq)
		cancel()
		if err == nil {
			return nil
		}
		if ctx.Err() != nil {
			err := fmt.Errorf("%s: %w", action, ctx.Err())
			t.closeWithError(err)
			return err
		}
		if !errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		ackedSeq, sendSeq := t.sendState()
		t.session.Logger().Debug("TCP ACK timed out", "action", action, "seq", pending.seq, "want_ack", pending.nextSeq, "acked_seq", ackedSeq, "send_seq", sendSeq, "attempt", attempt+1)
	}
	ackedSeq, sendSeq := t.sendState()
	err := fmt.Errorf("%s: waiting for ack %d (acked %d, seq %d, send_seq %d, attempts %d)", action, pending.nextSeq, ackedSeq, pending.seq, sendSeq, len(timeouts))
	t.closeWithError(err)
	return err
}

func (t *TCPConn) startPendingRetransmission(pending tcpPendingSegment, timeouts []time.Duration, action string) {
	timeouts = append([]time.Duration(nil), timeouts...)
	go func() {
		_ = t.waitPendingSegmentAck(context.Background(), pending, timeouts, action)
	}()
}

func tcpControlSequenceLen(flags byte) uint32 {
	if flags&(packet.TCPFlagSYN|packet.TCPFlagFIN) == 0 {
		return 0
	}
	return 1
}

func (t *TCPConn) maxPayloadSize() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	size := tcpDefaultSegmentSize
	if t.peerMSS != 0 && int(t.peerMSS) < size {
		size = int(t.peerMSS)
	}
	return max(size, 1)
}

func (t *TCPConn) notePeerMSSLocked(mss uint16) {
	if mss == 0 {
		return
	}
	if t.peerMSS == 0 || mss < t.peerMSS {
		t.peerMSS = mss
	}
}

func tcpSeqAfter(a, b uint32) bool {
	return int32(a-b) > 0
}

// tcpSeqInWindow follows gVisor's Linux-compatible right-edge behavior for
// zero-length control segments.
func tcpSeqInWindow(value, start uint32, window uint32) bool {
	if window == 0 {
		return value == start
	}
	return !tcpSeqAfter(start, value) && !tcpSeqAfter(value, start+window)
}

func tcpSegmentAcceptable(seq uint32, length uint32, recvSeq uint32, window uint32) bool {
	if window == 0 {
		return length == 0 && seq == recvSeq
	}
	if length == 0 {
		return tcpSeqInWindow(seq, recvSeq, window)
	}
	return tcpSeqAfter(seq+length, recvSeq) && !tcpSeqAfter(seq, recvSeq+window)
}

func (t *TCPConn) ackContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-t.done:
			cancel()
		case <-stop:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			cancel()
		})
	}
}

func (t *TCPConn) handleSegment(segment packet.TCPSegment) {
	t.mu.Lock()
	response, terminalErr := t.processSegment(segment)
	t.mu.Unlock()

	if response.flags != 0 {
		ctx, cancel := t.ackContext(5 * time.Second)
		err := t.sendSegmentWithSeq(ctx, response.seq, response.ack, response.flags, nil)
		cancel()
		if err != nil {
			t.session.Logger().Debug("sending TCP response failed", "tcp_flags", response.flags, "seq", response.seq, "ack", response.ack, "err", err)
		}
		if response.retransmit && err == nil {
			pending := tcpPendingSegment{
				seq:     response.seq,
				nextSeq: response.seq + tcpControlSequenceLen(response.flags),
				ack:     response.ack,
				flags:   response.flags,
			}
			t.startPendingRetransmission(pending, tcpSYNTimeouts, "passive tcp handshake")
		}
	}
	if terminalErr != nil {
		t.closeWithError(terminalErr)
	}
}

func (t *TCPConn) processSegment(segment packet.TCPSegment) (tcpSegmentResponse, error) {
	if t.closed {
		return tcpSegmentResponse{}, nil
	}
	t.session.Logger().Debug("received TCP segment", "src_addr", segment.Src, "dst_addr", segment.Dst, "tcp_flags", segment.Flags, "seq", segment.Seq, "ack", segment.Ack, "payload_len", len(segment.Payload))

	if segment.Flags&packet.TCPFlagRST != 0 {
		return t.processResetSegment(segment)
	}

	if !t.established {
		if t.passive {
			if segment.Flags&packet.TCPFlagSYN != 0 && segment.Flags&packet.TCPFlagACK == 0 {
				if t.recvSeq != 0 {
					if segment.Seq+1 == t.recvSeq {
						return tcpSegmentResponse{seq: t.initialSeq, ack: t.recvSeq, flags: packet.TCPFlagSYN | packet.TCPFlagACK}, nil
					}
					t.returnToPassiveListenLocked()
					return tcpSegmentResponse{}, nil
				}
				if err := t.selectPassiveISSLocked(); err != nil {
					return tcpSegmentResponse{}, err
				}
				t.notePeerMSSLocked(segment.MSS)
				t.recvSeq = segment.Seq + 1
				ack := t.recvSeq
				synSeq := t.initialSeq
				response := tcpSegmentResponse{seq: synSeq, ack: ack, flags: packet.TCPFlagSYN | packet.TCPFlagACK}
				pending := tcpPendingSegment{
					seq:     synSeq,
					nextSeq: t.sendSeq,
					ack:     ack,
					flags:   packet.TCPFlagSYN | packet.TCPFlagACK,
				}
				t.pending = &pending
				response.retransmit = true
				return response, nil
			}
			if segment.Flags&packet.TCPFlagACK != 0 {
				if t.recvSeq == 0 || segment.Ack != t.sendSeq {
					return tcpSegmentResponse{seq: segment.Ack, flags: packet.TCPFlagRST}, nil
				}
				if segment.Seq != t.recvSeq {
					return tcpSegmentResponse{seq: t.sendSeq, ack: t.recvSeq, flags: packet.TCPFlagACK}, nil
				}
				t.noteAck(segment.Ack)
				t.established = true
				t.signalReady()
				if len(segment.Payload) == 0 && segment.Flags&packet.TCPFlagFIN == 0 {
					return tcpSegmentResponse{}, nil
				}
				return t.processEstablishedSegment(segment)
			}
		} else if segment.Flags&(packet.TCPFlagSYN|packet.TCPFlagACK) == packet.TCPFlagSYN|packet.TCPFlagACK {
			if segment.Ack != t.sendSeq {
				return tcpSegmentResponse{}, nil
			}
			t.notePeerMSSLocked(segment.MSS)
			t.recvSeq = segment.Seq + 1
			t.noteAck(segment.Ack)
			t.established = true
			t.signalReady()
			ack := t.recvSeq
			return tcpSegmentResponse{seq: t.sendSeq, ack: ack, flags: packet.TCPFlagACK}, nil
		}
		return tcpSegmentResponse{}, nil
	}

	return t.processEstablishedSegment(segment)
}

func (t *TCPConn) processResetSegment(segment packet.TCPSegment) (tcpSegmentResponse, error) {
	if !t.established && t.passive {
		if t.resetAcceptableLocked(segment) {
			t.returnToPassiveListenLocked()
			return tcpSegmentResponse{}, nil
		}
		if t.resetInWindowLocked(segment) {
			return tcpSegmentResponse{seq: t.sendSeq, ack: t.recvSeq, flags: packet.TCPFlagACK}, nil
		}
		return tcpSegmentResponse{}, nil
	}
	if t.resetAcceptableLocked(segment) {
		return tcpSegmentResponse{}, errors.New("reading tcp packet: peer reset connection")
	}
	if t.established && tcpSeqInWindow(segment.Seq, t.recvSeq, uint32(tcpDefaultWindow)) {
		return tcpSegmentResponse{seq: t.sendSeq, ack: t.recvSeq, flags: packet.TCPFlagACK}, nil
	}
	return tcpSegmentResponse{}, nil
}

func (t *TCPConn) resetAcceptableLocked(segment packet.TCPSegment) bool {
	if !t.established && !t.passive {
		return segment.Flags&packet.TCPFlagACK != 0 && tcpSeqAfter(segment.Ack, t.ackedSeq) && !tcpSeqAfter(segment.Ack, t.sendSeq)
	}
	if !t.established && t.passive {
		return t.recvSeq != 0 && segment.Seq == t.recvSeq
	}
	return segment.Seq == t.recvSeq
}

func (t *TCPConn) resetInWindowLocked(segment packet.TCPSegment) bool {
	return t.recvSeq != 0 && tcpSeqInWindow(segment.Seq, t.recvSeq, uint32(tcpDefaultWindow))
}

func (t *TCPConn) selectPassiveISSLocked() error {
	seq, err := tcpRandomISS()
	if err != nil {
		return fmt.Errorf("selecting passive tcp iss: %w", err)
	}
	t.initialSeq = seq
	t.sendSeq = seq + 1
	t.ackedSeq = seq
	return nil
}

func (t *TCPConn) returnToPassiveListenLocked() {
	t.recvSeq = 0
	t.stream = nil
	t.pendingRcvdSegments = nil
	t.pendingRcvdBytes = 0
	t.peerMSS = 0
	t.pending = nil
	t.established = false
	select {
	case t.ackCh <- struct{}{}:
	default:
	}
}

func (t *TCPConn) processEstablishedSegment(segment packet.TCPSegment) (tcpSegmentResponse, error) {
	ack := t.recvSeq
	if segment.Flags&packet.TCPFlagSYN != 0 {
		return tcpSegmentResponse{seq: t.sendSeq, ack: ack, flags: packet.TCPFlagACK}, nil
	}
	if segment.Flags&packet.TCPFlagACK == 0 {
		return tcpSegmentResponse{}, nil
	}
	if tcpSeqAfter(segment.Ack, t.sendSeq) {
		return tcpSegmentResponse{seq: t.sendSeq, ack: ack, flags: packet.TCPFlagACK}, nil
	}

	segLen := uint32(len(segment.Payload)) + tcpControlSequenceLen(segment.Flags)
	if !tcpSegmentAcceptable(segment.Seq, segLen, t.recvSeq, uint32(tcpDefaultWindow)) {
		return tcpSegmentResponse{seq: t.sendSeq, ack: ack, flags: packet.TCPFlagACK}, nil
	}

	t.noteAck(segment.Ack)

	if segLen == 0 {
		return tcpSegmentResponse{}, nil
	}

	seq := segment.Seq
	payload := segment.Payload
	flags := segment.Flags
	if tcpSeqAfter(t.recvSeq, seq) {
		skip := t.recvSeq - seq

		skip = min(skip, uint32(len(payload)))

		payload = payload[skip:]
		seq = t.recvSeq
	}
	if seq != t.recvSeq {
		t.queuePendingSegment(seq, flags, payload)
		return tcpSegmentResponse{seq: t.sendSeq, ack: ack, flags: packet.TCPFlagACK}, nil
	}

	if err := t.consumeSegment(seq, flags, payload); errors.Is(err, errTCPReceiveQueueFull) {
		return tcpSegmentResponse{seq: t.sendSeq, ack: ack, flags: packet.TCPFlagACK}, nil
	} else if err != nil {
		return tcpSegmentResponse{seq: t.sendSeq, ack: t.recvSeq, flags: packet.TCPFlagACK}, err
	}
	if err := t.consumePendingSegments(); err != nil {
		return tcpSegmentResponse{seq: t.sendSeq, ack: t.recvSeq, flags: packet.TCPFlagACK}, err
	}
	return tcpSegmentResponse{seq: t.sendSeq, ack: t.recvSeq, flags: packet.TCPFlagACK}, nil
}

func (t *TCPConn) signalReady() {
	t.readyOnce.Do(func() {
		close(t.readyCh)
	})
}

func (t *TCPConn) closedErr(fallback string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.terminalErrOr(fallback)
}

func (t *TCPConn) terminalErrOr(fallback string) error {
	if t.terminalErr != nil {
		return t.terminalErr
	}
	return errors.New(fallback)
}

func (t *TCPConn) readyResult(action transportAction) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.established {
		return nil
	}
	if t.closed {
		return fmt.Errorf("%s: %w", action, t.terminalErrOr("transport is closed"))
	}
	return fmt.Errorf("%s: transport is not established", action)
}

func (t *TCPConn) dialReady(action transportAction) (bool, error) {
	select {
	case <-t.readyCh:
		if err := t.readyResult(action); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, nil
	}
}

func (t *TCPConn) sendSegmentWithSeq(ctx context.Context, seq, ack uint32, flags byte, payload []byte) error {
	t.session.Logger().Debug("sending TCP segment", "src_addr", t.local, "dst_addr", t.remote, "tcp_flags", flags, "seq", seq, "ack", ack, "payload_len", len(payload), "secure", t.secure)
	segment := packet.TCPSegment{
		Src:     cloneTCPAddr(t.local),
		Dst:     cloneTCPAddr(t.remote),
		Seq:     seq,
		Ack:     ack,
		Flags:   flags,
		Window:  tcpDefaultWindow,
		Payload: append([]byte(nil), payload...),
	}
	if !t.secure {
		return t.session.WriteInnerPacket(ctx, packet.InnerPacket{TCP: &segment})
	}
	wire, err := segment.MarshalBinary()
	if err != nil {
		return fmt.Errorf("writing secure tcp packet: %w", err)
	}
	t.mu.Lock()
	codec := t.outboundESP
	mode := t.secureMode
	associations := t.associations
	t.mu.Unlock()
	nextHeader := packet.ProtocolTCP
	espPayload := wire
	if mode == SecureModeUDPEncTunnel {
		inner := packet.InnerPacket{TCP: &segment}
		espPayload, err = inner.MarshalBinary()
		if err != nil {
			return fmt.Errorf("writing secure tcp packet: %w", err)
		}
		nextHeader, err = secureTunnelNextHeader(t.local.IP, t.remote.IP)
		if err != nil {
			return fmt.Errorf("writing secure tcp packet: %w", err)
		}
	}
	sealed, err := associations.sealESP(codec, nextHeader, espPayload)
	if err != nil {
		return fmt.Errorf("writing secure tcp packet: %w", err)
	}
	inner, err := secureInnerPacket(t.local.IP, t.remote.IP, mode, sealed)
	if err != nil {
		return fmt.Errorf("writing secure tcp packet: %w", err)
	}
	return t.session.WriteInnerPacket(ctx, inner)
}

func normalizedTCPDataACKTimeouts(values []time.Duration) ([]time.Duration, error) {
	if len(values) == 0 {
		return append([]time.Duration(nil), tcpDataACKTimeouts...), nil
	}
	timeouts := append([]time.Duration(nil), values...)
	var budget time.Duration
	for i, timeout := range timeouts {
		if timeout < tcpInitialRTO {
			return nil, fmt.Errorf("tcp data ack timeout must be >= %s", tcpInitialRTO)
		}
		if i > 0 {
			minTimeout := tcpNextRTOFloor(timeouts[i-1])
			if timeout < minTimeout {
				return nil, fmt.Errorf("tcp data ack timeout %s is more aggressive than %s", timeout, minTimeout)
			}
		}
		budget += timeout
	}
	if budget < tcpDataMinTimeout {
		return nil, fmt.Errorf("tcp data ack timeout budget must be >= %s", tcpDataMinTimeout)
	}
	return timeouts, nil
}

func tcpNextRTOFloor(previous time.Duration) time.Duration {
	if previous >= tcpRTOBackoffCeiling {
		return previous
	}
	doubled := previous * 2
	if doubled > tcpRTOBackoffCeiling {
		return tcpRTOBackoffCeiling
	}
	return doubled
}
