package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/ims-client/swu/handshake"
	"github.com/damonto/ims-client/swu/ike"
)

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

var (
	errIKETimeout = handshake.ErrIKETimeout
	ErrIKETimeout = handshake.ErrIKETimeout
)

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
	var header ike.IKEHeader
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
