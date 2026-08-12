package transport

import (
	"errors"
	"sync"

	"github.com/damonto/ims-go/ipsec/esp"
)

type SecurityAssociations struct {
	mu       sync.Mutex
	outbound map[associationKey]*outboundAssociation
	inbound  map[associationKey]*inboundAssociation
}

type associationKey struct {
	spi uint32
}

type outboundAssociation struct {
	seq uint32
}

type inboundAssociation struct {
	replay esp.ReplayWindow
}

func NewSecurityAssociations() *SecurityAssociations {
	return &SecurityAssociations{
		outbound: make(map[associationKey]*outboundAssociation),
		inbound:  make(map[associationKey]*inboundAssociation),
	}
}

func (s *SecurityAssociations) sealESP(codec esp.Codec, nextHeader byte, payload []byte) ([]byte, error) {
	if nextHeader == esp.NextHeaderNoNext {
		return nil, errors.New("encoding ESP: IMS dummy packets are not supported")
	}
	key := newAssociationKey(codec)

	s.mu.Lock()
	s.ensureState()
	outbound := s.outbound[key]
	if outbound == nil {
		outbound = &outboundAssociation{}
		s.outbound[key] = outbound
	}
	seq, ok := esp.NextSequence(&outbound.seq)
	s.mu.Unlock()
	if !ok {
		return nil, errors.New("esp sequence number overflow")
	}
	return codec.Encode(esp.Packet{SPI: codec.SPI, Sequence: seq, NextHeader: nextHeader, Payload: payload})
}

func (s *SecurityAssociations) acceptInboundESP(codec esp.Codec, sequence uint32) bool {
	if !espReplayProtected(codec) {
		return true
	}
	key := newAssociationKey(codec)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureState()
	inbound := s.inbound[key]
	if inbound == nil {
		inbound = &inboundAssociation{}
		s.inbound[key] = inbound
	}
	return inbound.replay.Accept(sequence)
}

func (s *SecurityAssociations) mayAcceptInboundESP(codec esp.Codec, sequence uint32) bool {
	if !espReplayProtected(codec) {
		return true
	}
	key := newAssociationKey(codec)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.ensureState()
	inbound := s.inbound[key]
	if inbound == nil {
		return sequence != 0
	}
	return inbound.replay.WouldAccept(sequence)
}

func (s *SecurityAssociations) ensureState() {
	if s.outbound == nil {
		s.outbound = make(map[associationKey]*outboundAssociation)
	}
	if s.inbound == nil {
		s.inbound = make(map[associationKey]*inboundAssociation)
	}
}

func newAssociationKey(codec esp.Codec) associationKey {
	// RFC 4303 uses the SPI to identify a unicast SA. Keeping keys or salt in
	// this key would allow one SPI to create multiple sequence/replay states.
	return associationKey{spi: codec.SPI}
}
