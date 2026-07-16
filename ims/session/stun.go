package session

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	stunBindingRequest         = 0x0001
	stunBindingIndication      = 0x0011
	stunBindingSuccessResponse = 0x0101
	stunBindingErrorResponse   = 0x0111
	stunMagicCookie            = 0x2112A442
	stunHeaderBytes            = 20
	stunMappedAddress          = 0x0001
	stunXORMappedAddress       = 0x0020
	stunErrorCode              = 0x0009
	stunUnknownAttributes      = 0x000a
	stunRequestCount           = 7
	stunFinalWaitRTOs          = 16
)

type stunResult struct {
	mapped string
	err    error
}

type stunPendingTransaction struct {
	transport Transport
	resultCh  chan stunResult
}

func (s *Session) sendSTUNBindingRequest(ctx context.Context, transport Transport) error {
	packet, transactionID, err := newSTUNBindingRequest()
	if err != nil {
		return fmt.Errorf("creating STUN binding request: %w", err)
	}
	resultCh := make(chan stunResult, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errSessionClosed
	}
	s.stunPending[transactionID] = stunPendingTransaction{transport: transport, resultCh: resultCh}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.stunPending, transactionID)
		s.mu.Unlock()
	}()

	result, err := s.awaitSTUNBinding(ctx, transport, packet, resultCh, max(s.cfg.TransactionTimers.T1, 500*time.Millisecond))
	if err != nil {
		return err
	}
	if result.err != nil {
		return result.err
	}
	if result.mapped == "" {
		return errors.New("receiving STUN binding response: XOR-MAPPED-ADDRESS is missing")
	}
	s.mu.Lock()
	previous := s.stunMapped[transport]
	s.stunMapped[transport] = result.mapped
	s.mu.Unlock()
	if previous != "" && previous != result.mapped {
		return fmt.Errorf("checking STUN binding: mapped address changed from %s to %s", previous, result.mapped)
	}
	return nil
}

func (s *Session) awaitSTUNBinding(ctx context.Context, transport Transport, packet []byte, resultCh <-chan stunResult, rto time.Duration) (stunResult, error) {
	if rto <= 0 {
		return stunResult{}, errors.New("sending STUN binding request: RTO must be positive")
	}
	initialRTO := rto
	for attempt := 1; attempt <= stunRequestCount; attempt++ {
		if err := s.writePacket(ctx, transport, packet); err != nil {
			return stunResult{}, err
		}
		wait := rto
		if attempt == stunRequestCount {
			wait = stunFinalWaitRTOs * initialRTO
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			stopTimer(timer)
			return stunResult{}, fmt.Errorf("waiting for STUN binding response: %w", ctx.Err())
		case <-s.closedCh:
			stopTimer(timer)
			return stunResult{}, errSessionClosed
		case result := <-resultCh:
			stopTimer(timer)
			return result, nil
		case <-timer.C:
			rto *= 2
		}
	}
	return stunResult{}, errors.New("waiting for STUN binding response: transaction timeout")
}

func (s *Session) sendCRLFKeepAlive(ctx context.Context, transport Transport) error {
	responseCh := make(chan error, 1)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errSessionClosed
	}
	if s.crlfPending[transport] != nil {
		s.mu.Unlock()
		return errors.New("sending CRLF keepalive: another keepalive is pending")
	}
	s.crlfPending[transport] = responseCh
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.crlfPending[transport] == responseCh {
			delete(s.crlfPending, transport)
		}
		s.mu.Unlock()
	}()
	if err := s.writePacket(ctx, transport, sipCRLFKeepAlive); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("waiting for CRLF keepalive response: %w", ctx.Err())
	case <-s.closedCh:
		return errSessionClosed
	case err := <-responseCh:
		return err
	}
}

func (s *Session) handleKeepAlivePacket(ctx context.Context, inbound inboundMessage) error {
	if isCRLFKeepAlivePacket(inbound.packet) {
		if string(inbound.packet) == string(sipCRLFKeepAlive) {
			return s.writePacketTo(ctx, inbound.transport, []byte("\r\n"), inbound.peer)
		}
		s.mu.Lock()
		responseCh := s.crlfPending[inbound.transport]
		s.mu.Unlock()
		if responseCh != nil {
			select {
			case responseCh <- nil:
			default:
			}
		}
		return nil
	}
	var message stunMessage
	if err := message.UnmarshalBinary(inbound.packet); err != nil {
		return nil // RFC 5389 section 7.3 requires malformed STUN to be discarded silently.
	}
	switch message.messageType {
	case stunBindingRequest:
		if len(message.unknownRequiredAttrs) != 0 {
			response := stunUnknownAttributesResponse(message.transactionID, message.unknownRequiredAttrs)
			return s.writePacketTo(ctx, inbound.transport, response, inbound.peer)
		}
		response, err := stunBindingResponse(message.transactionID, inbound.peer)
		if err != nil {
			return nil
		}
		return s.writePacketTo(ctx, inbound.transport, response, inbound.peer)
	case stunBindingSuccessResponse, stunBindingErrorResponse:
		s.mu.Lock()
		pending := s.stunPending[message.transactionID]
		s.mu.Unlock()
		if pending.resultCh == nil || pending.transport != inbound.transport {
			return nil
		}
		result := stunResult{mapped: message.mapped}
		if message.messageType == stunBindingErrorResponse {
			result.err = errors.New("receiving STUN binding response: server returned an error")
		} else if len(message.unknownRequiredAttrs) != 0 {
			result.err = errors.New("receiving STUN binding response: unknown required attribute")
		} else if !message.hasXORMappedAddress {
			result.err = errors.New("receiving STUN binding response: XOR-MAPPED-ADDRESS is missing")
		}
		select {
		case pending.resultCh <- result:
		default:
		}
	}
	return nil
}

func (s *Session) abortTransportKeepAlives(transport Transport, err error) {
	s.mu.Lock()
	stunChannels := make([]chan stunResult, 0)
	for transactionID, pending := range s.stunPending {
		if pending.transport == transport {
			delete(s.stunPending, transactionID)
			stunChannels = append(stunChannels, pending.resultCh)
		}
	}
	delete(s.stunMapped, transport)
	crlfCh := s.crlfPending[transport]
	delete(s.crlfPending, transport)
	s.mu.Unlock()
	for _, resultCh := range stunChannels {
		select {
		case resultCh <- stunResult{err: err}:
		default:
		}
	}
	if crlfCh != nil {
		select {
		case crlfCh <- err:
		default:
		}
	}
}

type stunMessage struct {
	messageType          uint16
	transactionID        [12]byte
	mapped               string
	hasXORMappedAddress  bool
	unknownRequiredAttrs []uint16
}

func newSTUNBindingRequest() ([]byte, [12]byte, error) {
	var transactionID [12]byte
	if _, err := rand.Read(transactionID[:]); err != nil {
		return nil, transactionID, err
	}
	packet := stunHeader(stunBindingRequest, transactionID, 0)
	return packet, transactionID, nil
}

func stunBindingResponse(transactionID [12]byte, peer net.Addr) ([]byte, error) {
	addr, ok := peer.(*net.UDPAddr)
	if !ok || addr == nil {
		return nil, errors.New("creating STUN binding response: peer is not UDP")
	}
	attribute, err := xorMappedAddress(addr, transactionID)
	if err != nil {
		return nil, err
	}
	packet := stunHeader(stunBindingSuccessResponse, transactionID, len(attribute))
	return append(packet, attribute...), nil
}

func stunUnknownAttributesResponse(transactionID [12]byte, unknown []uint16) []byte {
	reason := []byte("Unknown Attribute")
	errorValue := make([]byte, 4+len(reason))
	errorValue[2] = 4
	errorValue[3] = 20
	copy(errorValue[4:], reason)
	attributes := stunAttribute(stunErrorCode, errorValue)
	unknownValue := make([]byte, 2*len(unknown))
	for i, attributeType := range unknown {
		binary.BigEndian.PutUint16(unknownValue[2*i:], attributeType)
	}
	attributes = append(attributes, stunAttribute(stunUnknownAttributes, unknownValue)...)
	packet := stunHeader(stunBindingErrorResponse, transactionID, len(attributes))
	return append(packet, attributes...)
}

func stunAttribute(attributeType uint16, value []byte) []byte {
	padded := (len(value) + 3) &^ 3
	attribute := make([]byte, 4+padded)
	binary.BigEndian.PutUint16(attribute[0:2], attributeType)
	binary.BigEndian.PutUint16(attribute[2:4], uint16(len(value)))
	copy(attribute[4:], value)
	return attribute
}

func stunHeader(messageType uint16, transactionID [12]byte, attributesLength int) []byte {
	packet := make([]byte, stunHeaderBytes)
	binary.BigEndian.PutUint16(packet[0:2], messageType)
	binary.BigEndian.PutUint16(packet[2:4], uint16(attributesLength))
	binary.BigEndian.PutUint32(packet[4:8], stunMagicCookie)
	copy(packet[8:20], transactionID[:])
	return packet
}

func (m *stunMessage) UnmarshalBinary(packet []byte) error {
	if !isSTUNPacket(packet) {
		return errors.New("invalid STUN message")
	}
	message := stunMessage{messageType: binary.BigEndian.Uint16(packet[0:2])}
	switch message.messageType {
	case stunBindingRequest, stunBindingIndication, stunBindingSuccessResponse, stunBindingErrorResponse:
	default:
		return errors.New("unsupported STUN method or class")
	}
	copy(message.transactionID[:], packet[8:20])
	for attributes := packet[stunHeaderBytes:]; len(attributes) >= 4; {
		attributeType := binary.BigEndian.Uint16(attributes[0:2])
		length := int(binary.BigEndian.Uint16(attributes[2:4]))
		if length > len(attributes)-4 {
			return errors.New("invalid STUN attribute length")
		}
		value := attributes[4 : 4+length]
		if attributeType == stunXORMappedAddress || attributeType == stunMappedAddress {
			addr, err := parseMappedAddress(attributeType, value, message.transactionID)
			if err != nil {
				return err
			}
			if attributeType == stunXORMappedAddress || !message.hasXORMappedAddress {
				message.mapped = addr.String()
			}
			message.hasXORMappedAddress = message.hasXORMappedAddress || attributeType == stunXORMappedAddress
		} else if attributeType < 0x8000 && attributeType != stunErrorCode && attributeType != stunUnknownAttributes {
			message.unknownRequiredAttrs = append(message.unknownRequiredAttrs, attributeType)
		}
		padded := (length + 3) &^ 3
		if 4+padded > len(attributes) {
			return errors.New("invalid padded STUN attribute length")
		}
		attributes = attributes[4+padded:]
	}
	*m = message
	return nil
}

func xorMappedAddress(addr *net.UDPAddr, transactionID [12]byte) ([]byte, error) {
	ip := addr.IP.To4()
	family := byte(0x01)
	if ip == nil {
		ip = addr.IP.To16()
		family = 0x02
	}
	if ip == nil {
		return nil, errors.New("creating STUN binding response: invalid IP address")
	}
	attribute := make([]byte, 8+len(ip))
	binary.BigEndian.PutUint16(attribute[0:2], stunXORMappedAddress)
	binary.BigEndian.PutUint16(attribute[2:4], uint16(4+len(ip)))
	attribute[5] = family
	binary.BigEndian.PutUint16(attribute[6:8], uint16(addr.Port)^uint16(stunMagicCookie>>16))
	mask := make([]byte, 16)
	binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
	copy(mask[4:], transactionID[:])
	for i := range ip {
		attribute[8+i] = ip[i] ^ mask[i]
	}
	return attribute, nil
}

func parseMappedAddress(attributeType uint16, value []byte, transactionID [12]byte) (*net.UDPAddr, error) {
	if len(value) != 8 && len(value) != 20 {
		return nil, errors.New("parsing STUN mapped address: invalid attribute length")
	}
	if value[1] != 0x01 && value[1] != 0x02 {
		return nil, errors.New("parsing STUN mapped address: unsupported address family")
	}
	wantLength := 8
	if value[1] == 0x02 {
		wantLength = 20
	}
	if len(value) != wantLength {
		return nil, errors.New("parsing STUN mapped address: address family length mismatch")
	}
	port := binary.BigEndian.Uint16(value[2:4])
	ip := append(net.IP(nil), value[4:]...)
	if attributeType == stunXORMappedAddress {
		port ^= uint16(stunMagicCookie >> 16)
		mask := make([]byte, 16)
		binary.BigEndian.PutUint32(mask[0:4], stunMagicCookie)
		copy(mask[4:], transactionID[:])
		for i := range ip {
			ip[i] ^= mask[i]
		}
	}
	return &net.UDPAddr{IP: ip, Port: int(port)}, nil
}
