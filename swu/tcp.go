package swu

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10

	tcpDefaultSegmentSize = 1024
)

type tcpSegment struct {
	src     *net.TCPAddr
	dst     *net.TCPAddr
	seq     uint32
	ack     uint32
	flags   byte
	window  uint16
	payload []byte
}

type SecureTCPConfig struct {
	LocalPort    int
	RemotePort   int
	OutboundSPI  uint32
	InboundSPI   uint32
	Integrity    string
	IntegrityKey []byte
}

type TCPTransport struct {
	session       *Session
	local         *net.TCPAddr
	remote        *net.TCPAddr
	secure        bool
	passive       bool
	initialSeq    uint32
	espSeq        uint32
	outboundESP   ESPCodec
	inboundESP    ESPCodec
	inboundReplay replayWindow

	mu          sync.Mutex
	established bool
	closed      bool
	sendSeq     uint32
	recvSeq     uint32
	stream      []byte
	ackedSeq    uint32
	msgCh       chan []byte
	errCh       chan error
	readyCh     chan struct{}
	ackCh       chan struct{}
	closeOnce   sync.Once
}

func (s *Session) DialTCP(ctx context.Context, localPort, remotePort int) (*TCPTransport, error) {
	return s.dialTCP(ctx, localPort, remotePort, nil)
}

func (s *Session) DialSecureTCP(ctx context.Context, cfg SecureTCPConfig) (*TCPTransport, error) {
	return s.dialTCP(ctx, cfg.LocalPort, cfg.RemotePort, &cfg)
}

func (s *Session) dialTCP(ctx context.Context, localPort, remotePort int, secure *SecureTCPConfig) (*TCPTransport, error) {
	if s.conn == nil {
		return nil, errors.New("dialing tcp transport: session is closed")
	}
	s.mu.RLock()
	innerLocal := cloneUDPAddr(s.innerLocal)
	innerRemote := cloneUDPAddr(s.innerRemote)
	connected := s.connected
	s.mu.RUnlock()
	if !connected || innerLocal == nil || innerRemote == nil {
		return nil, errors.New("dialing tcp transport: session is not connected")
	}
	if remotePort == 0 {
		remotePort = s.cfg.SIPPort
		if remotePort == 0 {
			remotePort = 5060
		}
	}
	if localPort == 0 {
		rnd, err := randomUint32()
		if err != nil {
			return nil, fmt.Errorf("dialing tcp transport: generating local port: %w", err)
		}
		localPort = int(40000 + rnd%20000)
	}
	seq, err := randomUint32()
	if err != nil {
		return nil, fmt.Errorf("dialing tcp transport: generating initial sequence: %w", err)
	}

	transport := &TCPTransport{
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
	}
	if secure != nil {
		if secure.OutboundSPI == 0 || secure.InboundSPI == 0 {
			return nil, errors.New("dialing secure tcp transport: spi is zero")
		}
		if len(secure.IntegrityKey) == 0 {
			return nil, errors.New("dialing secure tcp transport: integrity key is empty")
		}
		transport.secure = true
		transport.outboundESP = ESPCodec{
			SPI:          secure.OutboundSPI,
			Encryption:   EncryptionNull,
			Integrity:    secure.Integrity,
			IntegrityKey: append([]byte(nil), secure.IntegrityKey...),
		}
		transport.inboundESP = ESPCodec{
			SPI:          secure.InboundSPI,
			Encryption:   EncryptionNull,
			Integrity:    secure.Integrity,
			IntegrityKey: append([]byte(nil), secure.IntegrityKey...),
		}
	}

	s.tcpMu.Lock()
	if s.tcp != nil {
		s.tcpMu.Unlock()
		return nil, errors.New("dialing tcp transport: only one tcp transport is supported")
	}
	s.tcp = transport
	s.tcpMu.Unlock()

	synSeq := seq
	for attempt := range 3 {
		if err := transport.sendSegmentWithSeq(ctx, synSeq, 0, tcpFlagSYN, nil); err != nil {
			s.clearTCPTransport(transport)
			return nil, err
		}
		wait := time.NewTimer(2 * time.Second)
		select {
		case <-ctx.Done():
			wait.Stop()
			transport.Close()
			return nil, ctx.Err()
		case <-transport.readyCh:
			wait.Stop()
			return transport, nil
		case <-wait.C:
			transport.session.logger.Debug("TCP SYN timed out", "attempt", attempt+1)
		}
	}
	transport.Close()
	return nil, errors.New("dialing tcp transport: waiting for syn-ack: timeout")
}

func (s *Session) ListenSecureTCP(cfg SecureTCPConfig) (*TCPTransport, error) {
	if s.conn == nil {
		return nil, errors.New("listening secure tcp transport: session is closed")
	}
	s.mu.RLock()
	innerLocal := cloneUDPAddr(s.innerLocal)
	innerRemote := cloneUDPAddr(s.innerRemote)
	connected := s.connected
	s.mu.RUnlock()
	if !connected || innerLocal == nil || innerRemote == nil {
		return nil, errors.New("listening secure tcp transport: session is not connected")
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
	seq, err := randomUint32()
	if err != nil {
		return nil, fmt.Errorf("listening secure tcp transport: generating initial sequence: %w", err)
	}
	transport := &TCPTransport{
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
		outboundESP: ESPCodec{SPI: cfg.OutboundSPI, Encryption: EncryptionNull, Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
		inboundESP:  ESPCodec{SPI: cfg.InboundSPI, Encryption: EncryptionNull, Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
	}
	s.tcpMu.Lock()
	if s.tcpServer != nil {
		s.tcpMu.Unlock()
		return nil, errors.New("listening secure tcp transport: only one server transport is supported")
	}
	s.tcpServer = transport
	s.tcpMu.Unlock()
	return transport, nil
}

func (s *Session) clearTCPTransport(transport *TCPTransport) {
	s.tcpMu.Lock()
	if s.tcp == transport {
		s.tcp = nil
	}
	if s.tcpServer == transport {
		s.tcpServer = nil
	}
	s.tcpMu.Unlock()
}

func (t *TCPTransport) LocalAddr() net.Addr {
	if t.local == nil {
		return nil
	}
	return &net.TCPAddr{IP: append(net.IP(nil), t.local.IP...), Port: t.local.Port, Zone: t.local.Zone}
}

func (t *TCPTransport) RemoteAddr() net.Addr {
	if t.remote == nil {
		return nil
	}
	return &net.TCPAddr{IP: append(net.IP(nil), t.remote.IP...), Port: t.remote.Port, Zone: t.remote.Zone}
}

func (t *TCPTransport) DialSecure(ctx context.Context, cfg SecureTCPConfig) (*TCPTransport, error) {
	return t.session.DialSecureTCP(ctx, cfg)
}

func (t *TCPTransport) WritePacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("writing tcp packet: transport is closed")
	}
	if !t.established {
		t.mu.Unlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-t.readyCh:
		}
		t.mu.Lock()
	}
	t.mu.Unlock()

	remaining := data
	for len(remaining) > 0 {
		chunk := remaining
		flags := byte(tcpFlagACK)
		if len(chunk) > tcpDefaultSegmentSize {
			chunk = chunk[:tcpDefaultSegmentSize]
		} else {
			flags |= tcpFlagPSH
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
			waitCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			err := t.waitForAck(waitCtx, wantAck)
			cancel()
			if err == nil {
				acked = true
				break
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			t.session.logger.Debug("TCP data ACK timed out", "seq", seq, "want_ack", wantAck, "attempt", attempt+1)
		}
		if !acked {
			return fmt.Errorf("writing tcp packet: waiting for ack %d", wantAck)
		}
		t.mu.Lock()
		t.sendSeq = wantAck
		t.mu.Unlock()
		remaining = remaining[len(chunk):]
	}
	return nil
}

func (t *TCPTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case err := <-t.errCh:
			return nil, nil, err
		case msg, ok := <-t.msgCh:
			if !ok {
				return nil, nil, errors.New("reading tcp packet: transport is closed")
			}
			return msg, t.RemoteAddr(), nil
		}
	}
}

func (t *TCPTransport) Close() error {
	var err error
	t.closeOnce.Do(func() {
		t.mu.Lock()
		alreadyClosed := t.closed
		t.closed = true
		t.mu.Unlock()
		if !alreadyClosed {
			t.session.clearTCPTransport(t)
		}
		close(t.msgCh)
	})
	return err
}

func (t *TCPTransport) fail(err error) {
	t.mu.Lock()
	alreadyClosed := t.closed
	t.closed = true
	t.mu.Unlock()
	if alreadyClosed {
		return
	}
	t.session.clearTCPTransport(t)
	if err == nil {
		return
	}
	select {
	case t.errCh <- err:
	default:
	}
}

func (t *TCPTransport) acceptInboundESP(sequence uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	return t.inboundReplay.Accept(sequence)
}

func (t *TCPTransport) currentAck() uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.recvSeq
}

func (t *TCPTransport) waitForAck(ctx context.Context, want uint32) error {
	for {
		t.mu.Lock()
		acked := t.ackedSeq
		closed := t.closed
		t.mu.Unlock()
		if acked >= want {
			return nil
		}
		if closed {
			return errors.New("waiting for ack: transport is closed")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-t.errCh:
			return err
		case <-t.ackCh:
		}
	}
}

func (t *TCPTransport) noteAckLocked(ack uint32) {
	if ack <= t.ackedSeq {
		return
	}
	t.ackedSeq = ack
	select {
	case t.ackCh <- struct{}{}:
	default:
	}
}

func (t *TCPTransport) ackContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	base := context.Background()
	if t != nil && t.session != nil && t.session.closeCtx != nil {
		base = t.session.closeCtx
	}
	return context.WithTimeout(base, timeout)
}

func (t *TCPTransport) handleSegment(segment tcpSegment) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	t.session.logger.Debug("received TCP segment", "src_addr", segment.src, "dst_addr", segment.dst, "tcp_flags", segment.flags, "seq", segment.seq, "ack", segment.ack, "payload_len", len(segment.payload))

	if !t.established {
		if t.passive {
			if segment.flags&tcpFlagSYN != 0 && segment.flags&tcpFlagACK == 0 {
				t.recvSeq = segment.seq + 1
				ack := t.recvSeq
				synSeq := t.initialSeq
				go func() {
					ctx, cancel := t.ackContext(5 * time.Second)
					defer cancel()
					_ = t.sendSegmentWithSeq(ctx, synSeq, ack, tcpFlagSYN|tcpFlagACK, nil)
				}()
				return
			}
			if segment.flags&tcpFlagACK != 0 && segment.ack >= t.sendSeq {
				t.noteAckLocked(segment.ack)
				t.established = true
				close(t.readyCh)
				return
			}
		} else if segment.flags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN|tcpFlagACK {
			t.recvSeq = segment.seq + 1
			t.noteAckLocked(segment.ack)
			t.established = true
			close(t.readyCh)
			ack := t.recvSeq
			go func(seq uint32) {
				ctx, cancel := t.ackContext(5 * time.Second)
				defer cancel()
				_ = t.sendSegmentWithSeq(ctx, seq, ack, tcpFlagACK, nil)
			}(t.sendSeq)
		}
		return
	}

	t.noteAckLocked(segment.ack)
	if len(segment.payload) == 0 {
		if segment.flags&tcpFlagFIN != 0 {
			t.recvSeq = segment.seq + 1
			ack := t.recvSeq
			go func(seq uint32) {
				ctx, cancel := t.ackContext(5 * time.Second)
				defer cancel()
				_ = t.sendSegmentWithSeq(ctx, seq, ack, tcpFlagACK, nil)
			}(t.sendSeq)
			select {
			case t.errCh <- errors.New("reading tcp packet: peer closed connection"):
			default:
			}
		}
		return
	}

	if segment.seq != t.recvSeq {
		ack := t.recvSeq
		go func(seq uint32) {
			ctx, cancel := t.ackContext(5 * time.Second)
			defer cancel()
			_ = t.sendSegmentWithSeq(ctx, seq, ack, tcpFlagACK, nil)
		}(t.sendSeq)
		return
	}

	t.recvSeq += uint32(len(segment.payload))
	ack := t.recvSeq
	go func(seq uint32) {
		ctx, cancel := t.ackContext(5 * time.Second)
		defer cancel()
		_ = t.sendSegmentWithSeq(ctx, seq, ack, tcpFlagACK, nil)
	}(t.sendSeq)

	t.stream = append(t.stream, segment.payload...)
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
		}
	}
}

func nextSIPMessage(stream []byte) ([]byte, []byte, bool, error) {
	headersEnd := bytes.Index(stream, []byte("\r\n\r\n"))
	if headersEnd < 0 {
		return nil, stream, false, nil
	}
	headersBlob := string(stream[:headersEnd])
	contentLength := 0
	for line := range strings.SplitSeq(headersBlob, "\r\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			continue
		}
		parsed, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil {
			if parsed < 0 {
				return nil, stream, false, errors.New("reading tcp packet: invalid negative Content-Length")
			}
			contentLength = parsed
		}
		break
	}
	total := headersEnd + 4 + contentLength
	if len(stream) < total {
		return nil, stream, false, nil
	}
	return append([]byte(nil), stream[:total]...), append([]byte(nil), stream[total:]...), true, nil
}

func (t *TCPTransport) sendSegmentWithSeq(ctx context.Context, seq, ack uint32, flags byte, payload []byte) error {
	options := tcpOptionsForFlags(flags)
	t.session.logger.Debug("sending TCP segment", "src_addr", t.local, "dst_addr", t.remote, "tcp_flags", flags, "seq", seq, "ack", ack, "payload_len", len(payload), "secure", t.secure)
	if t.secure {
		segment, err := buildTCPSegment(t.local, t.remote, seq, ack, flags, 65535, payload, options)
		if err != nil {
			return fmt.Errorf("writing tcp packet: %w", err)
		}
		t.mu.Lock()
		espSeq, ok := nextESPSequence(&t.espSeq)
		codec := t.outboundESP
		t.mu.Unlock()
		if !ok {
			_ = t.Close()
			return errors.New("writing secure tcp packet: esp sequence number overflow")
		}
		sealed, err := codec.Encode(ESPPacket{SPI: codec.SPI, Sequence: espSeq, NextHeader: 6, Payload: segment})
		if err != nil {
			return fmt.Errorf("writing secure tcp packet: %w", err)
		}
		packet, nextHeader, err := buildInnerIPPacket(t.local.IP, t.remote.IP, 50, sealed)
		if err != nil {
			return fmt.Errorf("writing secure tcp packet: %w", err)
		}
		return t.session.writeInner(ctx, packet, nextHeader)
	}
	packet, nextHeader, err := buildInnerTCPPacket(t.local, t.remote, seq, ack, flags, 65535, payload, options)
	if err != nil {
		return fmt.Errorf("writing tcp packet: %w", err)
	}
	return t.session.writeInner(ctx, packet, nextHeader)
}

func buildTCPSegment(src, dst *net.TCPAddr, seq, ack uint32, flags byte, window uint16, payload, options []byte) ([]byte, error) {
	if src == nil || dst == nil {
		return nil, errors.New("building inner tcp packet: endpoint is nil")
	}
	srcIP := append(net.IP(nil), src.IP...)
	dstIP := append(net.IP(nil), dst.IP...)
	options = padTCPOptions(options)
	headerLen := 20 + len(options)
	tcp := make([]byte, headerLen+len(payload))
	binary.BigEndian.PutUint16(tcp[0:2], uint16(src.Port))
	binary.BigEndian.PutUint16(tcp[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint32(tcp[4:8], seq)
	binary.BigEndian.PutUint32(tcp[8:12], ack)
	tcp[12] = byte((headerLen / 4) << 4)
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:16], window)
	copy(tcp[20:headerLen], options)
	copy(tcp[headerLen:], payload)
	if srcIP.To4() != nil && dstIP.To4() != nil {
		binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv4(srcIP.To4(), dstIP.To4(), tcp))
		return tcp, nil
	}
	if srcIP.To16() == nil || dstIP.To16() == nil {
		return nil, errors.New("building inner tcp packet: mismatched ip family")
	}
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv6(srcIP.To16(), dstIP.To16(), tcp))
	return tcp, nil
}

func buildInnerTCPPacket(src, dst *net.TCPAddr, seq, ack uint32, flags byte, window uint16, payload, options []byte) ([]byte, byte, error) {
	tcp, err := buildTCPSegment(src, dst, seq, ack, flags, window, payload, options)
	if err != nil {
		return nil, 0, err
	}
	return buildInnerIPPacket(src.IP, dst.IP, 6, tcp)
}

func tcpOptionsForFlags(flags byte) []byte {
	if flags&tcpFlagSYN == 0 || flags&tcpFlagACK != 0 {
		return nil
	}
	return []byte{
		0x02, 0x04, 0x05, 0x50,
		0x04, 0x02,
		0x01,
		0x03, 0x03, 0x07,
	}
}

func padTCPOptions(options []byte) []byte {
	if len(options) == 0 {
		return nil
	}
	padded := append([]byte(nil), options...)
	for len(padded)%4 != 0 {
		padded = append(padded, 0x01)
	}
	return padded
}

func tcpChecksumIPv4(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 12+len(tcp))
	copy(pseudo[0:4], src)
	copy(pseudo[4:8], dst)
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	copy(pseudo[12:], tcp)
	return checksum(pseudo)
}

func tcpChecksumIPv6(src, dst net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 40+len(tcp))
	copy(pseudo[0:16], src)
	copy(pseudo[16:32], dst)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(tcp)))
	pseudo[39] = 6
	copy(pseudo[40:], tcp)
	return checksum(pseudo)
}

func decodeInnerIPPacket(packet []byte, nextHeader byte) (byte, net.IP, net.IP, []byte, error) {
	if len(packet) == 0 {
		return 0, nil, nil, nil, errors.New("parsing inner ip packet: packet is empty")
	}
	switch nextHeader {
	case 4:
		return decodeIPv4Packet(packet)
	case 41:
		return decodeIPv6Packet(packet)
	default:
		switch packet[0] >> 4 {
		case 4:
			return decodeIPv4Packet(packet)
		case 6:
			return decodeIPv6Packet(packet)
		default:
			return 0, nil, nil, nil, fmt.Errorf("parsing inner ip packet: unsupported next header %d", nextHeader)
		}
	}
}

func decodeIPv4Packet(packet []byte) (byte, net.IP, net.IP, []byte, error) {
	if len(packet) < 20 {
		return 0, nil, nil, nil, errors.New("parsing ipv4 packet: packet too short")
	}
	ihl := int(packet[0]&0x0f) * 4
	if ihl < 20 || len(packet) < ihl {
		return 0, nil, nil, nil, errors.New("parsing ipv4 packet: invalid header length")
	}
	total := int(binary.BigEndian.Uint16(packet[2:4]))
	if total < ihl || len(packet) < total {
		return 0, nil, nil, nil, errors.New("parsing ipv4 packet: invalid total length")
	}
	return packet[9], append(net.IP(nil), packet[12:16]...), append(net.IP(nil), packet[16:20]...), append([]byte(nil), packet[ihl:total]...), nil
}

func decodeIPv6Packet(packet []byte) (byte, net.IP, net.IP, []byte, error) {
	if len(packet) < 40 {
		return 0, nil, nil, nil, errors.New("parsing ipv6 packet: packet too short")
	}
	length := int(binary.BigEndian.Uint16(packet[4:6]))
	if len(packet) < 40+length {
		return 0, nil, nil, nil, errors.New("parsing ipv6 packet: invalid payload length")
	}
	return packet[6], append(net.IP(nil), packet[8:24]...), append(net.IP(nil), packet[24:40]...), append([]byte(nil), packet[40:40+length]...), nil
}

func decodeTCPSegment(srcIP, dstIP net.IP, payload []byte) (tcpSegment, error) {
	if len(payload) < 20 {
		return tcpSegment{}, errors.New("parsing tcp segment: packet too short")
	}
	offset := int(payload[12]>>4) * 4
	if offset < 20 || len(payload) < offset {
		return tcpSegment{}, errors.New("parsing tcp segment: invalid data offset")
	}
	seg := tcpSegment{
		src:     &net.TCPAddr{IP: append(net.IP(nil), srcIP...), Port: int(binary.BigEndian.Uint16(payload[0:2]))},
		dst:     &net.TCPAddr{IP: append(net.IP(nil), dstIP...), Port: int(binary.BigEndian.Uint16(payload[2:4]))},
		seq:     binary.BigEndian.Uint32(payload[4:8]),
		ack:     binary.BigEndian.Uint32(payload[8:12]),
		flags:   payload[13],
		window:  binary.BigEndian.Uint16(payload[14:16]),
		payload: append([]byte(nil), payload[offset:]...),
	}
	return seg, nil
}
