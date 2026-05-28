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

const tcpDefaultSegmentSize = 1024

var tcpDataACKTimeout = 2 * time.Second

var _ imssession.Transport = (*TCPConn)(nil)

type TCPConfig struct {
	LocalPort  int
	RemotePort int
}

type SecureTCPConfig struct {
	TCPConfig
	OutboundSPI   uint32
	InboundSPI    uint32
	Encryption    string
	EncryptionKey []byte
	Integrity     string
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
	espSeq     uint32

	outboundESP   esp.Codec
	inboundESP    esp.Codec
	inboundReplay esp.ReplayWindow

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
	if cfg.OutboundSPI == 0 || cfg.InboundSPI == 0 {
		return nil, errors.New("listening secure tcp transport: spi is zero")
	}
	if len(cfg.IntegrityKey) == 0 {
		return nil, errors.New("listening secure tcp transport: integrity key is empty")
	}
	encryption := secureEncryption(cfg.Encryption)
	if encryption == esp.EncryptionAESCBC && len(cfg.EncryptionKey) == 0 {
		return nil, errors.New("listening secure tcp transport: encryption key is empty")
	}
	seq, err := randomUint32()
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: %w", err)
	}
	conn := &TCPConn{
		session:     s,
		local:       &net.TCPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: cfg.LocalPort, Zone: innerLocal.Zone},
		remote:      &net.TCPAddr{IP: append(net.IP(nil), innerRemote.IP...), Port: cfg.RemotePort, Zone: innerRemote.Zone},
		secure:      true,
		passive:     true,
		initialSeq:  seq,
		sendSeq:     seq + 1,
		ackedSeq:    seq,
		msgCh:       make(chan []byte, 16),
		errCh:       make(chan error, 1),
		readyCh:     make(chan struct{}),
		ackCh:       make(chan struct{}, 1),
		done:        make(chan struct{}),
		outboundESP: esp.Codec{SPI: cfg.OutboundSPI, Encryption: encryption, EncryptionKey: append([]byte(nil), cfg.EncryptionKey...), Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
		inboundESP:  esp.Codec{SPI: cfg.InboundSPI, Encryption: encryption, EncryptionKey: append([]byte(nil), cfg.EncryptionKey...), Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
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
		remotePort = 5060
	}
	localPort := cfg.LocalPort
	if localPort == 0 {
		rnd, err := randomUint32()
		if err != nil {
			return nil, fmt.Errorf("dialing tcp transport: %w", err)
		}
		localPort = int(40000 + rnd%20000)
	}
	seq, err := randomUint32()
	if err != nil {
		return nil, fmt.Errorf("dialing tcp transport: %w", err)
	}
	conn := &TCPConn{
		session:    s,
		local:      &net.TCPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: localPort, Zone: innerLocal.Zone},
		remote:     &net.TCPAddr{IP: append(net.IP(nil), innerRemote.IP...), Port: remotePort, Zone: innerRemote.Zone},
		initialSeq: seq,
		sendSeq:    seq + 1,
		ackedSeq:   seq,
		msgCh:      make(chan []byte, 16),
		errCh:      make(chan error, 1),
		readyCh:    make(chan struct{}),
		ackCh:      make(chan struct{}, 1),
		done:       make(chan struct{}),
	}
	if secure != nil {
		if secure.OutboundSPI == 0 || secure.InboundSPI == 0 {
			return nil, errors.New("dialing secure tcp transport: spi is zero")
		}
		if len(secure.IntegrityKey) == 0 {
			return nil, errors.New("dialing secure tcp transport: integrity key is empty")
		}
		encryption := secureEncryption(secure.Encryption)
		if encryption == esp.EncryptionAESCBC && len(secure.EncryptionKey) == 0 {
			return nil, errors.New("dialing secure tcp transport: encryption key is empty")
		}
		conn.secure = true
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
			if err := conn.readyResult("dialing tcp transport"); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return conn, nil
		case <-wait.C:
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
		err := t.closedErrLocked("writing tcp packet: transport is closed")
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
			err := t.closedErrLocked("writing tcp packet: transport is closed")
			t.mu.Unlock()
			return err
		}
		if !t.established {
			t.mu.Unlock()
			return errors.New("writing tcp packet: transport is not established")
		}
	}
	t.mu.Unlock()

	remaining := data
	for len(remaining) > 0 {
		chunk := remaining
		flags := byte(packet.TCPFlagACK)
		if len(chunk) > tcpDefaultSegmentSize {
			chunk = chunk[:tcpDefaultSegmentSize]
		} else {
			flags |= packet.TCPFlagPSH
		}

		t.mu.Lock()
		seq := t.sendSeq
		t.mu.Unlock()
		wantAck := seq + uint32(len(chunk))
		acked := false
		for attempt := range 3 {
			if err := t.sendSegmentWithSeq(ctx, seq, t.currentAck(), flags, chunk); err != nil {
				return err
			}
			if attempt == 0 {
				t.noteSent(wantAck)
			}
			waitCtx, cancel := context.WithTimeout(ctx, tcpDataACKTimeout)
			err := t.waitForAck(waitCtx, wantAck)
			cancel()
			if err == nil {
				acked = true
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			t.session.Logger().Debug("TCP data ACK timed out", "seq", seq, "want_ack", wantAck, "attempt", attempt+1)
		}
		if !acked {
			err := fmt.Errorf("writing tcp packet: waiting for ack %d", wantAck)
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
		case <-t.done:
			return nil, nil, t.closedErr("reading tcp packet: transport is closed")
		case err := <-t.errCh:
			return nil, nil, err
		case msg, ok := <-t.msgCh:
			if !ok {
				return nil, nil, t.closedErr("reading tcp packet: transport is closed")
			}
			return msg, t.RemoteAddr(), nil
		}
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
		if pkt.TCP.Dst.Port != t.local.Port || !pkt.TCP.Src.IP.Equal(t.remote.IP) || pkt.TCP.Src.Port != t.remote.Port {
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
	espPacket, err := t.inboundESP.Decode(pkt.IP.Payload)
	if err != nil || espPacket.SPI != t.inboundESP.SPI {
		return false
	}
	if !t.acceptInboundESP(espPacket.Sequence) {
		t.session.Logger().Debug("dropping replayed secure TCP packet", "spi", spi, "esp_sequence", espPacket.Sequence)
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
	if inner.TCP.Dst.Port != t.local.Port || !inner.TCP.Src.IP.Equal(t.remote.IP) || inner.TCP.Src.Port != t.remote.Port {
		t.session.Logger().Debug("secure TCP flow mismatch", "spi", spi, "src_addr", inner.TCP.Src, "dst_addr", inner.TCP.Dst, "expected_remote_addr", t.remote, "expected_local_addr", t.local)
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
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	return t.inboundReplay.Accept(sequence)
}

func (t *TCPConn) currentAck() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.recvSeq
}

func (t *TCPConn) waitForAck(ctx context.Context, want uint32) error {
	for {
		t.mu.Lock()
		acked := t.ackedSeq
		closed := t.closed
		t.mu.Unlock()
		if acked >= want {
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

func (t *TCPConn) noteAckLocked(ack uint32) {
	if ack <= t.ackedSeq {
		return
	}
	t.ackedSeq = ack
	select {
	case t.ackCh <- struct{}{}:
	default:
	}
}

func (t *TCPConn) noteSent(nextSeq uint32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if nextSeq > t.sendSeq {
		t.sendSeq = nextSeq
	}
}

func (t *TCPConn) ackContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

func (t *TCPConn) handleSegment(segment packet.TCPSegment) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.session.Logger().Debug("received TCP segment", "src_addr", segment.Src, "dst_addr", segment.Dst, "tcp_flags", segment.Flags, "seq", segment.Seq, "ack", segment.Ack, "payload_len", len(segment.Payload))

	if !t.established {
		if t.passive {
			if segment.Flags&packet.TCPFlagSYN != 0 && segment.Flags&packet.TCPFlagACK == 0 {
				t.recvSeq = segment.Seq + 1
				ack := t.recvSeq
				synSeq := t.initialSeq
				go func() {
					ctx, cancel := t.ackContext(5 * time.Second)
					defer cancel()
					_ = t.sendSegmentWithSeq(ctx, synSeq, ack, packet.TCPFlagSYN|packet.TCPFlagACK, nil)
				}()
				return
			}
			if segment.Flags&packet.TCPFlagACK != 0 && segment.Ack >= t.sendSeq {
				t.noteAckLocked(segment.Ack)
				t.established = true
				t.signalReady()
				return
			}
		} else if segment.Flags&(packet.TCPFlagSYN|packet.TCPFlagACK) == packet.TCPFlagSYN|packet.TCPFlagACK {
			t.recvSeq = segment.Seq + 1
			t.noteAckLocked(segment.Ack)
			t.established = true
			t.signalReady()
			ack := t.recvSeq
			go func(seq uint32) {
				ctx, cancel := t.ackContext(5 * time.Second)
				defer cancel()
				_ = t.sendSegmentWithSeq(ctx, seq, ack, packet.TCPFlagACK, nil)
			}(t.sendSeq)
		}
		return
	}

	t.noteAckLocked(segment.Ack)
	if len(segment.Payload) == 0 {
		if segment.Flags&packet.TCPFlagFIN != 0 {
			t.recvSeq = segment.Seq + 1
			ack := t.recvSeq
			go func(seq uint32) {
				ctx, cancel := t.ackContext(5 * time.Second)
				defer cancel()
				_ = t.sendSegmentWithSeq(ctx, seq, ack, packet.TCPFlagACK, nil)
			}(t.sendSeq)
			select {
			case t.errCh <- errors.New("reading tcp packet: peer closed connection"):
			default:
			}
		}
		return
	}

	if segment.Seq != t.recvSeq {
		ack := t.recvSeq
		go func(seq uint32) {
			ctx, cancel := t.ackContext(5 * time.Second)
			defer cancel()
			_ = t.sendSegmentWithSeq(ctx, seq, ack, packet.TCPFlagACK, nil)
		}(t.sendSeq)
		return
	}

	t.recvSeq += uint32(len(segment.Payload))
	ack := t.recvSeq
	go func(seq uint32) {
		ctx, cancel := t.ackContext(5 * time.Second)
		defer cancel()
		_ = t.sendSegmentWithSeq(ctx, seq, ack, packet.TCPFlagACK, nil)
	}(t.sendSeq)

	t.stream = append(t.stream, segment.Payload...)
	for {
		msg, rest, ok, err := nextSIPMessage(t.stream)
		if err != nil {
			select {
			case t.errCh <- err:
			default:
			}
			return
		}
		if !ok {
			break
		}
		t.stream = rest
		select {
		case t.msgCh <- msg:
		default:
			select {
			case t.errCh <- errors.New("reading tcp packet: message queue is full"):
			default:
			}
			return
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
	return t.closedErrLocked(fallback)
}

func (t *TCPConn) closedErrLocked(fallback string) error {
	if t.terminalErr != nil {
		return t.terminalErr
	}
	return errors.New(fallback)
}

func (t *TCPConn) readyResult(action string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.established {
		return nil
	}
	if t.closed {
		return fmt.Errorf("%s: %w", action, t.closedErrLocked("transport is closed"))
	}
	return fmt.Errorf("%s: transport is not established", action)
}

func (t *TCPConn) sendSegmentWithSeq(ctx context.Context, seq, ack uint32, flags byte, payload []byte) error {
	t.session.Logger().Debug("sending TCP segment", "src_addr", t.local, "dst_addr", t.remote, "tcp_flags", flags, "seq", seq, "ack", ack, "payload_len", len(payload), "secure", t.secure)
	segment := packet.TCPSegment{
		Src:     cloneTCPAddr(t.local),
		Dst:     cloneTCPAddr(t.remote),
		Seq:     seq,
		Ack:     ack,
		Flags:   flags,
		Window:  65535,
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
	espSeq, ok := esp.NextSequence(&t.espSeq)
	codec := t.outboundESP
	t.mu.Unlock()
	if !ok {
		_ = t.Close()
		return errors.New("writing secure tcp packet: esp sequence number overflow")
	}
	sealed, err := codec.Encode(esp.ESPPacket{SPI: codec.SPI, Sequence: espSeq, NextHeader: packet.ProtocolTCP, Payload: wire})
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
	headersEnd := bytes.Index(stream, []byte("\r\n\r\n"))
	if headersEnd < 0 {
		return nil, stream, false, nil
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
	total := headersEnd + 4 + contentLength
	if len(stream) < total {
		return nil, stream, false, nil
	}
	return append([]byte(nil), stream[:total]...), append([]byte(nil), stream[total:]...), true, nil
}
