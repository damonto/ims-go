package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
)

func buildIKEWire(request []byte, nat bool) []byte {
	if !nat {
		return request
	}
	return prependNonESPMarker(request)
}

func buildIKEWires(packets [][]byte, nat bool) [][]byte {
	if !nat {
		return packets
	}
	return prependNonESPMarkerPackets(packets)
}

func prependNonESPMarker(packet []byte) []byte {
	wire := make([]byte, 0, nonESPMarkerLen+len(packet))
	wire = append(wire, nonESPMarker[:]...)
	return append(wire, packet...)
}

func prependNonESPMarkerPackets(packets [][]byte) [][]byte {
	wires := make([][]byte, 0, len(packets))
	for _, packet := range packets {
		wires = append(wires, prependNonESPMarker(packet))
	}
	return wires
}

func (s *Session) writeIKERequest(ctx context.Context, addr *net.UDPAddr, request []byte, nat bool, messageID uint32) error {
	wire := buildIKEWire(request, nat)
	if err := s.writeOuter(ctx, wire, addr); err != nil {
		return fmt.Errorf("sending message %d: %w", messageID, err)
	}
	return nil
}

func (s *Session) awaitIKEAttemptWithDelay(ctx context.Context, expected ikeResponseMatch, attempt int, delay time.Duration, udpEncap bool) ([]byte, *net.UDPAddr, error) {
	response, peer, err := s.readIKEMessage(ctx, expected, delay, udpEncap)
	if err == nil {
		s.logger.Debug("received IKE message", "message_id", expected.messageID, "peer_addr", peer, "response_len", len(response))
		return response, peer, nil
	}
	s.logger.Debug("waiting for IKE message", "message_id", expected.messageID, "attempt", attempt+1, "err", err)
	return nil, nil, err
}

func (s *Session) exchangeIKE(ctx context.Context, addr *net.UDPAddr, request []byte, nat bool, messageID uint32) ([]byte, *net.UDPAddr, error) {
	s.logger.Debug("sending IKE message", "message_id", messageID, "use_natt", nat, "remote_addr", addr, "request_len", len(request))
	expected, err := newIKEResponseMatch(request, addr)
	if err != nil {
		return nil, nil, err
	}
	for attempt, delay := range s.ikeRetransmitDelays() {
		if err := s.writeIKERequest(ctx, addr, request, nat, messageID); err != nil {
			return nil, nil, err
		}
		response, peer, err := s.awaitIKEAttemptWithDelay(ctx, expected, attempt, delay, nat)
		if err == nil {
			return response, peer, nil
		}
		if !errors.Is(err, handshake.ErrIKETimeout) {
			return nil, nil, err
		}
	}
	return nil, nil, fmt.Errorf("waiting message %d: %w", messageID, handshake.ErrIKETimeout)
}

type protectedIKEExchange struct {
	peer                   *net.UDPAddr
	requests               [][]byte
	useNATT                bool
	messageID              uint32
	crypto                 *ikeCrypto
	senderInitiator        bool
	fragmentationSupported bool
	action                 ikeAction
}

type protectedIKERead struct {
	expected               ikeResponseMatch
	useNATT                bool
	crypto                 *ikeCrypto
	senderInitiator        bool
	fragmentationSupported bool
	action                 ikeAction
}

func (s *Session) exchangeProtectedIKE(ctx context.Context, exchange protectedIKEExchange) ([]ike.Payload, *net.UDPAddr, error) {
	if len(exchange.requests) == 0 {
		return nil, nil, fmt.Errorf("%s: request is empty", exchange.action)
	}
	s.logger.Debug("sending protected IKE message", "message_id", exchange.messageID, "use_natt", exchange.useNATT, "remote_addr", exchange.peer, "fragment_count", len(exchange.requests))
	expected, err := newIKEResponseMatch(exchange.requests[0], exchange.peer)
	if err != nil {
		return nil, nil, err
	}
	read := protectedIKERead{
		expected:               expected,
		useNATT:                exchange.useNATT,
		crypto:                 exchange.crypto,
		senderInitiator:        exchange.senderInitiator,
		fragmentationSupported: exchange.fragmentationSupported,
		action:                 exchange.action,
	}
	for attempt, delay := range s.ikeRetransmitDelays() {
		for _, request := range exchange.requests {
			if err := s.writeIKERequest(ctx, exchange.peer, request, exchange.useNATT, exchange.messageID); err != nil {
				return nil, nil, err
			}
		}
		payloads, peer, err := s.awaitProtectedIKEAttempt(ctx, read, delay)
		if err == nil {
			return payloads, peer, nil
		}
		if !errors.Is(err, handshake.ErrIKETimeout) {
			return nil, nil, err
		}
		s.logger.Debug("waiting for protected IKE message", "message_id", exchange.messageID, "attempt", attempt+1, "err", err)
	}
	return nil, nil, fmt.Errorf("%s: waiting message %d: timeout", exchange.action, exchange.messageID)
}

func (s *Session) awaitProtectedIKEAttempt(ctx context.Context, read protectedIKERead, timeout time.Duration) ([]ike.Payload, *net.UDPAddr, error) {
	payloads, peer, err := s.readProtectedIKEMessage(ctx, read, timeout)
	if peer != nil && (err == nil || payloads != nil) {
		s.logger.Debug("received protected IKE message", "message_id", read.expected.messageID, "peer_addr", peer, "payload_count", len(payloads))
	}
	if err == nil {
		return payloads, peer, nil
	}
	return nil, nil, err
}

func (s *Session) readProtectedIKEMessage(ctx context.Context, read protectedIKERead, timeout time.Duration) ([]ike.Payload, *net.UDPAddr, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, maxUDPPacketSize)
	reassembly := ikeFragmentReassembly{}
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if ikeReadTimedOut(deadline) {
			return nil, nil, handshake.ErrIKETimeout
		}
		data, udpAddr, err := s.readIKECandidate(deadline, buf, read.useNATT)
		if err != nil {
			if errors.Is(err, handshake.ErrIKETimeout) {
				continue
			}
			return nil, nil, err
		}
		if !matchesIKEMessage(data, udpAddr, read.expected) {
			continue
		}
		var packet ike.IKEPacket
		if err := packet.UnmarshalBinary(data); err != nil {
			if isIKEFragmentPacket(data) {
				continue
			}
			return nil, nil, fmt.Errorf("%s: parsing response: %w", read.action, err)
		}
		payloads, complete, err := openIKEPacketMaybeFragmented(read.crypto, packet, read.senderInitiator, read.fragmentationSupported, &reassembly)
		if err != nil {
			if !hasEncryptedPayload(packet.Payloads) {
				if notifyErr := plaintextIKENotifyError(packet.Payloads); notifyErr != nil {
					return nil, nil, fmt.Errorf("%s: %w", read.action, notifyErr)
				}
			}
			return nil, nil, fmt.Errorf("%s: opening response: %w", read.action, err)
		}
		if complete {
			if err := protectedIKEAuthNotifyError(read.action, payloads); err != nil {
				return payloads, udpAddr, err
			}
			return payloads, udpAddr, nil
		}
	}
}

func openIKEPacketMaybeFragmented(crypto *ikeCrypto, packet ike.IKEPacket, senderInitiator bool, fragmentationSupported bool, reassembly *ikeFragmentReassembly) ([]ike.Payload, bool, error) {
	if len(packet.Payloads) != 1 {
		return nil, false, errors.New("expected encrypted payload container")
	}
	if _, ok := packet.Payloads[0].(*ike.EncryptedFragmentPayload); ok {
		if !fragmentationSupported {
			return nil, false, errors.New("ike fragmentation is not negotiated")
		}
		fragment, err := crypto.OpenIKEFragment(packet, senderInitiator)
		if err != nil {
			return nil, false, nil
		}
		payloads, _, complete, stored, err := reassembly.add(fragment, packet.Raw)
		if !stored {
			return nil, false, nil
		}
		return payloads, complete, err
	}
	payloads, err := crypto.OpenIKE(packet, senderInitiator)
	if err != nil {
		return nil, false, err
	}
	return payloads, true, nil
}

func isIKEFragmentPacket(data []byte) bool {
	var header ike.IKEHeader
	if err := header.UnmarshalBinary(data); err != nil {
		return false
	}
	return header.NextPayload == payloadTypeEncryptedFragment
}

var defaultIKERetransmitDelays = []time.Duration{
	500 * time.Millisecond,
	1 * time.Second,
	2 * time.Second,
	4 * time.Second,
	8 * time.Second,
	16 * time.Second,
	32 * time.Second,
	64 * time.Second,
	128 * time.Second,
	256 * time.Second,
	512 * time.Second,
	1024 * time.Second,
}

func (s *Session) ikeRetransmitDelays() []time.Duration {
	return s.cfg.IKERetransmitDelays
}

func (s *Session) readIKEMessage(ctx context.Context, expected ikeResponseMatch, timeout time.Duration, udpEncap bool) ([]byte, *net.UDPAddr, error) {
	deadline := time.Now().Add(timeout)
	buf := make([]byte, maxUDPPacketSize)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if ikeReadTimedOut(deadline) {
			return nil, nil, handshake.ErrIKETimeout
		}
		packet, udpAddr, err := s.readIKECandidate(deadline, buf, udpEncap)
		if err != nil {
			if errors.Is(err, handshake.ErrIKETimeout) {
				continue
			}
			return nil, nil, err
		}
		if !matchesIKEMessage(packet, udpAddr, expected) {
			continue
		}
		return packet, udpAddr, nil
	}
}

func ikeReadTimedOut(deadline time.Time) bool {
	return time.Now().After(deadline)
}

func nextIKEReadDeadline(deadline time.Time) time.Time {
	readDeadline := time.Now().Add(outerReadPollDelay)
	if readDeadline.After(deadline) {
		return deadline
	}
	return readDeadline
}

func (s *Session) readIKECandidate(deadline time.Time, buf []byte, udpEncap bool) ([]byte, *net.UDPAddr, error) {
	if err := s.conn.SetReadDeadline(nextIKEReadDeadline(deadline)); err != nil {
		return nil, nil, fmt.Errorf("setting read deadline: %w", err)
	}
	n, addr, err := s.conn.ReadFrom(buf)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, nil, handshake.ErrIKETimeout
		}
		return nil, nil, fmt.Errorf("reading ike response: %w", err)
	}
	packet := normalizeIKEPacket(buf[:n], udpEncap)
	udpAddr, _ := addr.(*net.UDPAddr)
	return packet, cloneUDPAddr(udpAddr), nil
}

func normalizeIKEPacket(packet []byte, udpEncap bool) []byte {
	packet = append([]byte(nil), packet...)
	if udpEncap && hasNonESPMarker(packet) {
		return packet[nonESPMarkerLen:]
	}
	return packet
}

type ikeResponseMatch struct {
	peer         *net.UDPAddr
	initiatorSPI uint64
	responderSPI uint64
	exchangeType byte
	messageID    uint32
}

func newIKEResponseMatch(request []byte, peer *net.UDPAddr) (ikeResponseMatch, error) {
	var header ike.IKEHeader
	if err := header.UnmarshalBinary(request); err != nil {
		return ikeResponseMatch{}, fmt.Errorf("parsing outbound ike header: %w", err)
	}
	return ikeResponseMatch{
		peer:         cloneUDPAddr(peer),
		initiatorSPI: header.InitiatorSPI,
		responderSPI: header.ResponderSPI,
		exchangeType: header.ExchangeType,
		messageID:    header.MessageID,
	}, nil
}

func matchesIKEMessage(packet []byte, peer *net.UDPAddr, expected ikeResponseMatch) bool {
	var header ike.IKEHeader
	if err := header.UnmarshalBinary(packet); err != nil {
		return false
	}
	if expected.peer != nil && !sameUDPAddr(peer, expected.peer) {
		return false
	}
	if header.Version>>4 != 2 {
		return false
	}
	if header.MessageID != expected.messageID || header.ExchangeType != expected.exchangeType {
		return false
	}
	if header.InitiatorSPI != expected.initiatorSPI {
		return false
	}
	if expected.responderSPI != 0 && header.ResponderSPI != expected.responderSPI {
		return false
	}
	if header.Flags&flagResponse == 0 {
		return false
	}
	return header.Flags&flagInitiator == 0
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Port == b.Port && a.Zone == b.Zone && a.IP.Equal(b.IP)
}

func (s *Session) writeOuter(ctx context.Context, data []byte, addr net.Addr) error {
	s.outerWriteMu.Lock()
	defer s.outerWriteMu.Unlock()

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

func (s *Session) writeProtectedWire(ctx context.Context, action ikeAction, crypto *ikeCrypto, wire []byte, peer net.Addr, skipIKESAByteAccounting bool) error {
	protectedBytes, err := currentIKEProtectedBytes(crypto, wire, skipIKESAByteAccounting)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if protectedBytes != 0 {
		s.mu.RLock()
		expired := s.ikeSAByteExpired(protectedBytes)
		s.mu.RUnlock()
		if expired {
			s.failSecurityAssociations(errIKESAExpired)
			return fmt.Errorf("%s: %w", action, errIKESAExpired)
		}
	}
	if err := s.writeOuter(ctx, wire, peer); err != nil {
		return fmt.Errorf("%s: writing packet: %w", action, err)
	}
	now := time.Now()
	if s.addIKESAOutboundBytes(protectedBytes, now) {
		s.failSecurityAssociations(errIKESAExpired)
	}
	s.markProtectedTx(now)
	return nil
}

func (s *Session) writeProtectedWires(ctx context.Context, action ikeAction, crypto *ikeCrypto, wires [][]byte, peer net.Addr, skipIKESAByteAccounting bool) error {
	if len(wires) == 0 {
		return fmt.Errorf("%s: request is empty", action)
	}
	for _, wire := range wires {
		if err := s.writeProtectedWire(ctx, action, crypto, wire, peer, skipIKESAByteAccounting); err != nil {
			return err
		}
	}
	return nil
}

func currentIKEProtectedBytes(crypto *ikeCrypto, wire []byte, skipIKESAByteAccounting bool) (uint64, error) {
	if skipIKESAByteAccounting {
		return 0, nil
	}
	return crypto.ProtectedBytes(wire)
}

func (s *Session) acceptIKEProtectedBytes(crypto *ikeCrypto, wire []byte, now time.Time) (ikeAcceptResult, error) {
	protectedBytes, err := currentIKEProtectedBytes(crypto, wire, false)
	if err != nil {
		return ikeAcceptResult{}, err
	}
	return s.acceptIKESAInboundBytes(protectedBytes, now), nil
}

func (s *Session) readOuterClosed() error {
	if s.isClosed() {
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
	buf := make([]byte, maxUDPPacketSize)
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
