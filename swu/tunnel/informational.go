package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/ims-client/swu/ike"
)

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

type informationalState struct {
	connected    bool
	ike          *ikeCrypto
	initiatorSPI uint64
	responderSPI uint64
	identity     string
	peer         *net.UDPAddr
	inboundSPI   uint32
	outboundSPI  uint32
}

type informationalAction struct {
	deleteIKE   bool
	deleteChild bool
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
		inboundSPI:   s.tunnel.ESPInitiatorSPI,
		outboundSPI:  s.tunnel.ESPResponderSPI,
	}
}

func (state informationalState) matches(packet ike.IKEPacket) bool {
	if state.ike == nil {
		return false
	}
	return packet.Header.InitiatorSPI == state.initiatorSPI && packet.Header.ResponderSPI == state.responderSPI
}

func (state informationalState) canSendDelete() bool {
	return state.available()
}

func (state informationalState) sealDeleteRequest(messageID uint32) ([]byte, error) {
	return state.sealInitiatorRequest(messageID, []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}})
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

func (state informationalState) initiatorHeader(messageID uint32) ike.IKEHeader {
	return ike.IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		ResponderSPI: state.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        flagInitiator,
		MessageID:    messageID,
	}
}

func (state informationalState) sealInitiatorRequest(messageID uint32, payloads []ike.Payload) ([]byte, error) {
	return state.ike.SealIKE(state.initiatorHeader(messageID), payloads, true)
}

func (s *Session) sendInformational(ctx context.Context, payloads []ike.Payload) ([]ike.Payload, error) {
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

func (s *Session) exchangeInformational(ctx context.Context, state informationalState, messageID uint32, wire []byte, waiter <-chan inboundIKE) ([]ike.Payload, error) {
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

func (s *Session) awaitInformationalResponse(ctx context.Context, crypto *ikeCrypto, waiter <-chan inboundIKE, attempt int) ([]ike.Payload, bool, error) {
	timer := time.NewTimer(ikeRetransmitDelay(attempt))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, false, ctx.Err()
	case <-s.closeDone():
		return nil, false, errors.New("sending informational: session is closed")
	case response := <-waiter:
		payloads, err := s.openInformationalResponse(crypto, response.data)
		if err != nil {
			return nil, false, err
		}
		return payloads, true, nil
	case <-timer.C:
		return nil, false, nil
	}
}

func (s *Session) openInformationalResponse(crypto *ikeCrypto, data []byte) ([]ike.Payload, error) {
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("sending informational: parsing response: %w", err)
	}
	payloads, err := crypto.OpenIKE(packet, false)
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

func buildDeviceIdentityResponsePayload(payloads []ike.Payload, identity string) (*ike.NotifyPayload, bool, error) {
	notify := ike.FindNotifyPayload(payloads, notifyTypeDeviceIdentity)
	if notify == nil {
		return nil, false, nil
	}
	requestedType, requestedValue, err := ike.DecodeDeviceIdentity(notify.Data)
	if err != nil {
		return nil, false, err
	}
	if len(requestedValue) != 0 {
		return nil, false, nil
	}
	data, err := ike.EncodeDeviceIdentityForType(identity, requestedType)
	if err != nil {
		return nil, false, err
	}
	return &ike.NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeDeviceIdentity, Data: data}, true, nil
}

func buildInformationalConfigReply(payloads []ike.Payload) *ike.ConfigPayload {
	request := ike.FindConfigPayload(payloads)
	if request == nil || request.ConfigType != configTypeRequest {
		return nil
	}
	attrs := make([]ike.Attribute, 0, len(request.Attributes))
	for _, attr := range request.Attributes {
		switch attr.Type {
		case configAttrPCSCFIPv4Address, configAttrPCSCFIPv6Address, configAttrTimeoutPeriodForLivenessCheck:
			attrs = append(attrs, ike.NewTLVAttribute(attr.Type, nil))
		}
	}
	if len(attrs) == 0 {
		return nil
	}
	return &ike.ConfigPayload{ConfigType: configTypeReply, Attributes: attrs}
}

func buildInformationalResponsePayloads(state informationalState, payloads []ike.Payload, identity string) ([]ike.Payload, informationalAction, error) {
	if responsePayloads, action, ok, err := buildDeleteResponsePayloads(state, payloads); ok || err != nil {
		return responsePayloads, action, err
	}
	responsePayloads := make([]ike.Payload, 0, 2)
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(payloads, identity)
	if err != nil {
		return nil, informationalAction{}, fmt.Errorf("building informational device identity: %w", err)
	}
	if ok {
		responsePayloads = append(responsePayloads, deviceIdentityPayload)
	}
	if configReply := buildInformationalConfigReply(payloads); configReply != nil {
		responsePayloads = append(responsePayloads, configReply)
	}
	return responsePayloads, informationalAction{}, nil
}

func buildDeleteResponsePayloads(state informationalState, payloads []ike.Payload) ([]ike.Payload, informationalAction, bool, error) {
	deletePayloads := findDeletePayloads(payloads)
	if len(deletePayloads) == 0 {
		return nil, informationalAction{}, false, nil
	}
	for _, deletePayload := range deletePayloads {
		if deletePayload == nil {
			continue
		}
		if deletePayload.ProtocolID == protocolIDIKE {
			return nil, informationalAction{deleteIKE: true}, true, nil
		}
	}
	if state.inboundSPI == 0 || state.outboundSPI == 0 {
		return nil, informationalAction{}, true, nil
	}
	for _, deletePayload := range deletePayloads {
		if deletePayload == nil || deletePayload.ProtocolID != protocolIDESP {
			continue
		}
		for _, spi := range deletePayload.SPIs {
			if len(spi) != 4 {
				return nil, informationalAction{}, true, fmt.Errorf("parsing informational delete: invalid esp spi length %d", len(spi))
			}
			if binary.BigEndian.Uint32(spi) != state.outboundSPI {
				continue
			}
			return []ike.Payload{
				&ike.DeletePayload{
					ProtocolID: protocolIDESP,
					SPIs:       [][]byte{uint32Bytes(state.inboundSPI)},
				},
			}, informationalAction{deleteChild: true}, true, nil
		}
	}
	return nil, informationalAction{}, true, nil
}

func findDeletePayloads(payloads []ike.Payload) []*ike.DeletePayload {
	deletes := make([]*ike.DeletePayload, 0)
	for _, payload := range payloads {
		deletePayload, ok := payload.(*ike.DeletePayload)
		if ok {
			deletes = append(deletes, deletePayload)
		}
	}
	return deletes
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

func (s *Session) handleInformationalResponse(crypto *ikeCrypto, packet ike.IKEPacket, data []byte, addr net.Addr) (bool, error) {
	if _, err := crypto.OpenIKE(packet, false); err != nil {
		return true, fmt.Errorf("opening informational response: %w", err)
	}
	s.markProtectedRx(time.Now())
	udpAddr, _ := addr.(*net.UDPAddr)
	if s.deliverInformationalWaiter(packet.Header.MessageID, inboundIKE{data: append([]byte(nil), data...), addr: cloneUDPAddr(udpAddr)}) {
		s.logger.Debug("matched informational response", "message_id", packet.Header.MessageID)
	}
	return true, nil
}

func (s *Session) writeInformationalResponse(state informationalState, messageID uint32, payloads []ike.Payload, addr net.Addr) error {
	responseHeader := ike.IKEHeader{
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

func (s *Session) handleInformationalRequest(state informationalState, packet ike.IKEPacket, addr net.Addr) (bool, error) {
	payloads, err := state.ike.OpenIKE(packet, false)
	if err != nil {
		return true, fmt.Errorf("opening informational request: %w", err)
	}
	s.markProtectedRx(time.Now())
	responsePayloads, action, err := buildInformationalResponsePayloads(state, payloads, state.identity)
	if err != nil {
		return true, err
	}
	if err := s.writeInformationalResponse(state, packet.Header.MessageID, responsePayloads, addr); err != nil {
		return true, err
	}
	if action.deleteIKE {
		s.logger.Debug("received IKE delete request", "message_id", packet.Header.MessageID)
		s.failSecurityAssociations(errors.New("peer deleted IKE SA"))
	}
	if action.deleteChild {
		s.logger.Debug("received child sa delete request", "message_id", packet.Header.MessageID, "inbound_spi", state.inboundSPI, "outbound_spi", state.outboundSPI)
		s.discardChildSecurityAssociations(errors.New("peer deleted child SA"))
	}
	return true, nil
}

func (s *Session) handleIKEPacket(data []byte, addr net.Addr) (bool, error) {
	var packet ike.IKEPacket
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
