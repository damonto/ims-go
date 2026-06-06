package session

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Session) WriteResponse(ctx context.Context, req Request, resp sip.Message) error {
	if err := s.ensureOpen(); err != nil {
		return fmt.Errorf("writing response: %w", err)
	}
	s.applyResponseDecorator(&resp)
	if err := s.writeResponse(ctx, req.Transport, req.PeerAddr, req.Message, resp); err != nil {
		return err
	}
	s.recordServerTransactionResponse(req, resp)
	return nil
}

func (s *Session) WriteStatus(ctx context.Context, req Request, code int, reason string) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	return s.WriteResponse(ctx, req, resp)
}

func (s *Session) SetResponseDecorator(fn func(*sip.Message)) {
	s.mu.Lock()
	s.responseDecorator = fn
	s.mu.Unlock()
}

func (s *Session) applyResponseDecorator(resp *sip.Message) {
	s.mu.Lock()
	fn := s.responseDecorator
	s.mu.Unlock()
	if fn == nil {
		fn = s.cfg.ResponseDecorator
	}
	if fn != nil {
		fn(resp)
	}
}

func (s *Session) writePacket(ctx context.Context, transport Transport, data []byte) error {
	return s.writePacketTo(ctx, transport, data, nil)
}

func (s *Session) writePacketTo(ctx context.Context, transport Transport, data []byte, addr net.Addr) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if addr == nil {
		return transport.WritePacket(ctx, data)
	}
	writer, ok := transport.(targetedPacketWriter)
	if !ok {
		return transport.WritePacket(ctx, data)
	}
	return writer.WritePacketTo(ctx, data, addr)
}

func (s *Session) writeResponse(ctx context.Context, transport Transport, peer net.Addr, req sip.Message, resp sip.Message) error {
	data, err := messagePacket(resp)
	if err != nil {
		return fmt.Errorf("encoding %d response: %w", resp.StatusCode(), err)
	}
	remote := peer
	if remote == nil {
		remote = transport.RemoteAddr()
	}
	target := responseDestination(remote, req.Header("Via"))
	if peer != nil {
		transport = s.responseTransport(transport, target)
	}
	s.logger.Debug("sip message", "direction", "send", "start_line", resp.StartLine, "sip_message", string(data), "target_addr", target)
	return s.writePacketTo(ctx, transport, data, target)
}

func (s *Session) responseTransport(fallback Transport, target net.Addr) Transport {
	if fallback != nil {
		s.mu.Lock()
		routed := s.responseRoutes[fallback]
		_, active := s.active[routed]
		s.mu.Unlock()
		if active && (target == nil || sameAddr(routed.RemoteAddr(), target)) {
			return routed
		}
	}
	if target == nil {
		return fallback
	}
	if fallback != nil && sameAddr(fallback.RemoteAddr(), target) {
		return fallback
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for transport := range s.active {
		if sameAddr(transport.RemoteAddr(), target) {
			return transport
		}
	}
	return fallback
}

func sameAddr(left, right net.Addr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Network() == right.Network() && left.String() == right.String()
}

func messagePacket(msg sip.Message) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := msg.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func responseDestination(remote net.Addr, via string) net.Addr {
	udpRemote, ok := remote.(*net.UDPAddr)
	if !ok || udpRemote == nil {
		return nil
	}
	target := &net.UDPAddr{IP: append(net.IP(nil), udpRemote.IP...), Port: topViaResponsePort(via, udpRemote.Port), Zone: udpRemote.Zone}
	if received := sip.TopViaReceived(via); received != "" {
		if ip := net.ParseIP(stripHostBrackets(received)); ip != nil {
			target.IP = ip
		}
		return target
	}
	if host := topViaSentByHost(via); host != "" {
		if ip := net.ParseIP(stripHostBrackets(host)); ip != nil {
			target.IP = ip
		}
	}
	return target
}

func (s *Session) dispatchResponse(inbound inboundMessage) bool {
	key := sip.PendingKey(inbound.msg)
	s.mu.Lock()
	tx, ok := s.transactions[key]
	s.mu.Unlock()
	if !ok {
		return false
	}
	if !tx.acceptsResponse(inbound.msg) {
		return true
	}
	tx.handleResponse(inbound)
	return true
}

func topViaResponsePort(via string, remotePort int) int {
	if rport := sip.TopViaRPort(via); rport != "" {
		if port, err := strconv.Atoi(rport); err == nil && port > 0 {
			return port
		}
	}
	if sip.TopViaHasRPort(via) && remotePort > 0 {
		return remotePort
	}
	sentBy := sip.TopViaSentBy(via)
	if sentBy == "" {
		return 5060
	}
	_, portText, err := net.SplitHostPort(sentBy)
	if err != nil {
		return 5060
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		return 5060
	}
	return port
}

func topViaSentByHost(via string) string {
	sentBy := sip.TopViaSentBy(via)
	if sentBy == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(sentBy)
	if err == nil {
		return host
	}
	return strings.TrimSpace(strings.Trim(sentBy, "[]"))
}

func stripHostBrackets(host string) string {
	host = strings.TrimPrefix(host, "[")
	return strings.TrimSuffix(host, "]")
}
