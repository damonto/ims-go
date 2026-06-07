package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	imssession "github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/packet"
	"github.com/damonto/vowifi-go/swu/tunnel"
)

const (
	tcpDefaultSegmentSize = 1024
	tcpDefaultRemotePort  = 5060
	tcpEphemeralPortBase  = 40000
	tcpEphemeralPortRange = 20000
	tcpDefaultWindow      = 65535
	tcpMaxSIPHeaderBytes  = 32 * 1024
	tcpMaxSIPMessageBytes = 1024 * 1024
)

var tcpDataACKTimeouts = []time.Duration{
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
}

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
	Associations *SecurityAssociations

	EncryptionKey []byte
	IntegrityKey  []byte
}

type TCPConn struct {
	session    *tunnel.Session
	attachment tunnel.Attachment
	local      *net.TCPAddr
	remote     *net.TCPAddr
	secure     bool
	passive    bool
	initialSeq uint32

	outboundESP  esp.Codec
	inboundESP   esp.Codec
	associations *SecurityAssociations

	mu          sync.Mutex
	writeMu     sync.Mutex
	established bool
	closed      bool
	terminalErr error
	sendSeq     uint32
	recvSeq     uint32
	stream      []byte
	ackedSeq    uint32
	msgCh       chan []byte
	errCh       chan error
	readyCh     chan struct{}
	ackCh       chan struct{}
	done        chan struct{}
	closeOnce   sync.Once
	readyOnce   sync.Once

	dataACKTimeouts []time.Duration
}

type tcpSegmentResponse struct {
	seq   uint32
	ack   uint32
	flags byte
}

func DialTCP(ctx context.Context, s *tunnel.Session, cfg TCPConfig) (*TCPConn, error) {
	return dialTCP(ctx, s, cfg, nil)
}

func DialSecureTCP(ctx context.Context, s *tunnel.Session, cfg SecureTCPConfig) (*TCPConn, error) {
	return dialTCP(ctx, s, cfg.TCPConfig, &cfg)
}

func ListenSecureTCP(s *tunnel.Session, cfg SecureTCPConfig) (*TCPConn, error) {
	innerLocal, innerRemote, err := connectedUDPAddrs(s)
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
		outboundESP:     esp.Codec{SPI: cfg.OutboundSPI, Encryption: encryption, EncryptionKey: append([]byte(nil), cfg.EncryptionKey...), Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
		inboundESP:      esp.Codec{SPI: cfg.InboundSPI, Encryption: encryption, EncryptionKey: append([]byte(nil), cfg.EncryptionKey...), Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
	}
	attachment, err := s.Attach(conn)
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	conn.attachment = attachment
	return conn, nil
}

func dialTCP(ctx context.Context, s *tunnel.Session, cfg TCPConfig, secure *SecureTCPConfig) (*TCPConn, error) {
	innerLocal, innerRemote, err := connectedUDPAddrs(s)
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
		if err := validateSecureESPConfig(encryption, secure.Integrity, secure.EncryptionKey, secure.IntegrityKey); err != nil {
			return nil, fmt.Errorf("dialing secure tcp transport: %w", err)
		}
		conn.secure = true
		conn.associations = secureAssociations(secure.Associations)
		conn.outboundESP = esp.Codec{
			SPI:           secure.OutboundSPI,
			Encryption:    encryption,
			EncryptionKey: append([]byte(nil), secure.EncryptionKey...),
			Integrity:     secure.Integrity,
			IntegrityKey:  append([]byte(nil), secure.IntegrityKey...),
		}
		conn.inboundESP = esp.Codec{
			SPI:           secure.InboundSPI,
			Encryption:    encryption,
			EncryptionKey: append([]byte(nil), secure.EncryptionKey...),
			Integrity:     secure.Integrity,
			IntegrityKey:  append([]byte(nil), secure.IntegrityKey...),
		}
	}
	attachment, err := s.Attach(conn)
	if err != nil {
		return nil, fmt.Errorf("dialing tcp transport: %w", err)
	}
	conn.attachment = attachment

	for attempt := range 3 {
		if ready, err := conn.dialReady(transportActionDialTCP); ready || err != nil {
			if err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		}
		if err := conn.sendSegmentWithSeq(ctx, seq, 0, packet.TCPFlagSYN, nil); err != nil {
			_ = conn.Close()
			return nil, err
		}
		wait := time.NewTimer(2 * time.Second)
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
			return conn, nil
		case <-wait.C:
			if ready, err := conn.dialReady(transportActionDialTCP); ready || err != nil {
				if err != nil {
					_ = conn.Close()
					return nil, err
				}
				return conn, nil
			}
			s.Logger().Debug("TCP SYN timed out", "attempt", attempt+1)
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
		chunk := remaining
		flags := byte(packet.TCPFlagACK)
		if len(chunk) > tcpDefaultSegmentSize {
			chunk = chunk[:tcpDefaultSegmentSize]
		} else {
			flags |= packet.TCPFlagPSH
		}

		seq, wantAck, err := t.reserveSendSeq(len(chunk))
		if err != nil {
			return err
		}
		acked := false
		for attempt, timeout := range timeouts {
			if err := t.sendSegmentWithSeq(ctx, seq, t.currentAck(), flags, chunk); err != nil {
				t.closeWithError(err)
				return err
			}
			waitCtx, cancel := context.WithTimeout(ctx, timeout)
			err := t.waitForAck(waitCtx, wantAck)
			cancel()
			if err == nil {
				acked = true
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			ackedSeq, sendSeq := t.sendState()
			t.session.Logger().Debug("TCP data ACK timed out", "seq", seq, "want_ack", wantAck, "acked_seq", ackedSeq, "send_seq", sendSeq, "attempt", attempt+1)
		}
		if !acked {
			ackedSeq, sendSeq := t.sendState()
			err := fmt.Errorf("writing tcp packet: waiting for ack %d (acked %d, seq %d, send_seq %d, attempts %d)", wantAck, ackedSeq, seq, sendSeq, len(timeouts))
			t.closeWithError(err)
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
	t.closeWithError(nil)
	return nil
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
	if pkt.IP.Protocol != packet.ProtocolESP {
		return false
	}
	spi := packetSPI(pkt.IP.Payload)
	if spi != t.inboundESP.SPI {
		return false
	}
	espPacket, err := t.inboundESP.Decode(pkt.IP.Payload)
	if err != nil {
		return false
	}
	if espPacket.NextHeader != packet.ProtocolTCP {
		return false
	}
	inner, err := packet.DecodePayload(packet.ProtocolTCP, pkt.IP.SrcIP, pkt.IP.DstIP, espPacket.Payload)
	if err != nil || inner.TCP == nil {
		t.session.Logger().Debug("parsing secure TCP packet failed", "spi", spi, "local_addr", t.local, "remote_addr", t.remote, "err", err)
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

func (t *TCPConn) currentAck() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.recvSeq
}

func (t *TCPConn) tcpDataACKTimeouts() []time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.dataACKTimeouts) == 0 {
		return append([]time.Duration(nil), tcpDataACKTimeouts...)
	}
	return append([]time.Duration(nil), t.dataACKTimeouts...)
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
		t.mu.Unlock()
		if !tcpSeqAfter(want, acked) {
			return nil
		}
		if closed {
			return t.closedErr("waiting for ack: transport is closed")
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
	select {
	case t.ackCh <- struct{}{}:
	default:
	}
}

func (t *TCPConn) reserveSendSeq(payloadLen int) (uint32, uint32, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return 0, 0, t.terminalErrOr("writing tcp packet: transport is closed")
	}
	seq := t.sendSeq
	nextSeq := seq + uint32(payloadLen)
	t.sendSeq = nextSeq
	return seq, nextSeq, nil
}

func tcpSeqAfter(a, b uint32) bool {
	return int32(a-b) > 0
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
		return tcpSegmentResponse{}, errors.New("reading tcp packet: peer reset connection")
	}

	if !t.established {
		if t.passive {
			if segment.Flags&packet.TCPFlagSYN != 0 && segment.Flags&packet.TCPFlagACK == 0 {
				t.recvSeq = segment.Seq + 1
				ack := t.recvSeq
				synSeq := t.initialSeq
				return tcpSegmentResponse{seq: synSeq, ack: ack, flags: packet.TCPFlagSYN | packet.TCPFlagACK}, nil
			}
			if segment.Flags&packet.TCPFlagACK != 0 && segment.Ack == t.sendSeq {
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

func (t *TCPConn) processEstablishedSegment(segment packet.TCPSegment) (tcpSegmentResponse, error) {
	if segment.Flags&packet.TCPFlagACK != 0 {
		t.noteAck(segment.Ack)
	}
	fin := segment.Flags&packet.TCPFlagFIN != 0
	if len(segment.Payload) == 0 && !fin {
		return tcpSegmentResponse{}, nil
	}

	if segment.Seq != t.recvSeq {
		ack := t.recvSeq
		return tcpSegmentResponse{seq: t.sendSeq, ack: ack, flags: packet.TCPFlagACK}, nil
	}

	nextRecv := segment.Seq + uint32(len(segment.Payload))
	if fin {
		nextRecv++
	}
	t.recvSeq = nextRecv
	ack := t.recvSeq
	response := tcpSegmentResponse{seq: t.sendSeq, ack: ack, flags: packet.TCPFlagACK}
	if len(segment.Payload) == 0 {
		return response, errors.New("reading tcp packet: peer closed connection")
	}

	t.stream = append(t.stream, segment.Payload...)
	for {
		msg, rest, ok, err := nextSIPMessage(t.stream)
		if err != nil {
			return response, err
		}
		if !ok {
			t.stream = rest
			if fin {
				return response, errors.New("reading tcp packet: peer closed connection")
			}
			return response, nil
		}
		t.stream = rest
		select {
		case t.msgCh <- msg:
		default:
			return response, errors.New("reading tcp packet: message queue is full")
		}
	}
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
	associations := t.associations
	t.mu.Unlock()
	sealed, err := associations.sealESP(codec, packet.ProtocolTCP, wire)
	if err != nil {
		return fmt.Errorf("writing secure tcp packet: %w", err)
	}
	return t.session.WriteInnerPacket(ctx, packet.InnerPacket{
		IP: packet.IPPacket{
			SrcIP:    append(net.IP(nil), t.local.IP...),
			DstIP:    append(net.IP(nil), t.remote.IP...),
			Protocol: packet.ProtocolESP,
			Payload:  sealed,
		},
	})
}

func nextSIPMessage(stream []byte) ([]byte, []byte, bool, error) {
	stream = trimLeadingSIPCRLF(stream)
	headersEnd := bytes.Index(stream, []byte("\r\n\r\n"))
	if headersEnd < 0 {
		if len(stream) > tcpMaxSIPHeaderBytes {
			return nil, stream, false, errors.New("reading tcp packet: SIP header too large")
		}
		return nil, stream, false, nil
	}
	if headersEnd > tcpMaxSIPHeaderBytes {
		return nil, stream, false, errors.New("reading tcp packet: SIP header too large")
	}
	headersBlob := string(stream[:headersEnd])
	contentLength := 0
	foundContentLength := false
	for line := range strings.SplitSeq(headersBlob, "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if !strings.EqualFold(name, "Content-Length") && !strings.EqualFold(name, "l") {
			continue
		}
		foundContentLength = true
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return nil, stream, false, fmt.Errorf("reading tcp packet: parsing Content-Length: %w", err)
		}
		if parsed < 0 {
			return nil, stream, false, errors.New("reading tcp packet: invalid negative Content-Length")
		}
		contentLength = parsed
		break
	}
	if !foundContentLength {
		return nil, stream, false, errors.New("reading tcp packet: missing Content-Length")
	}
	headersSize := headersEnd + 4
	if contentLength > tcpMaxSIPMessageBytes-headersSize {
		return nil, stream, false, errors.New("reading tcp packet: SIP message too large")
	}
	total := headersSize + contentLength
	if len(stream) < total {
		return nil, stream, false, nil
	}
	return append([]byte(nil), stream[:total]...), append([]byte(nil), stream[total:]...), true, nil
}

func trimLeadingSIPCRLF(stream []byte) []byte {
	for len(stream) >= 2 && stream[0] == '\r' && stream[1] == '\n' {
		stream = stream[2:]
	}
	return stream
}

func normalizedTCPDataACKTimeouts(values []time.Duration) ([]time.Duration, error) {
	if len(values) == 0 {
		return append([]time.Duration(nil), tcpDataACKTimeouts...), nil
	}
	timeouts := append([]time.Duration(nil), values...)
	for _, timeout := range timeouts {
		if timeout <= 0 {
			return nil, errors.New("tcp data ack timeout must be > 0")
		}
	}
	return timeouts, nil
}
