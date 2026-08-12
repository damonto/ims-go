package tunnel

import (
	"net"
	"time"

	"github.com/damonto/ims-go/swu/ike"
)

type informationalState struct {
	connected                 bool
	ike                       *ikeCrypto
	localInitiator            bool
	ikeRekeying               bool
	pendingIKESA              bool
	retiredIKESA              bool
	ikeFragmentationSupported bool
	useNATT                   bool
	childRekeying             bool
	cfg                       Config
	initiatorSPI              uint64
	responderSPI              uint64
	identity                  string
	peer                      *net.UDPAddr
	info                      Info
	inboundSPI                uint32
	outboundSPI               uint32
	pendingChild              bool
	oldInboundSPI             uint32
	retiredChildSAs           []retiredChildSAState
	promoteIKESA              bool
	nextPeerMessageID         uint32
	responses                 map[uint32][][]byte
	responseReqs              map[uint32][]byte
}

type retiredChildSAState struct {
	inboundSPI  uint32
	outboundSPI uint32
}

func (s *Session) currentInformationalState() informationalState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentInformationalStateSnapshot()
}

func (s *Session) currentInformationalStateSnapshot() informationalState {
	ikeState := s.ikeSAState()
	childState := s.childSAState()
	return informationalState{
		connected:                 s.connected,
		ike:                       s.ike,
		localInitiator:            s.ikeLocalInitiator,
		ikeRekeying:               ikeState == ikeSAStateRekeying,
		pendingIKESA:              ikeState == ikeSAStatePendingInstall,
		ikeFragmentationSupported: s.ikeFragmentationSupported,
		useNATT:                   s.useNATT,
		childRekeying:             childState == childSAStateRekeying,
		cfg:                       s.cfg,
		initiatorSPI:              s.initiatorSPI,
		responderSPI:              s.responderSPI,
		identity:                  s.deviceIdentity,
		peer:                      outerIKEPeer(s.useNATT, s.outerRemote, s.outerNAT),
		info:                      cloneInfo(s.tunnel),
		inboundSPI:                s.tunnel.ESPInitiatorSPI,
		outboundSPI:               s.tunnel.ESPResponderSPI,
		pendingChild:              childState == childSAStatePendingOutbound,
		oldInboundSPI:             s.pendingChildSA.oldInbound,
		retiredChildSAs:           retiredChildSAStates(s.retiredChildSAs),
		nextPeerMessageID:         s.nextPeerMessageID,
		responses:                 cloneIKEMessageResponses(s.informResponses),
		responseReqs:              cloneIKEMessageRequests(s.informResponseReqs),
	}
}

func retiredChildSAStates(children []retiredChildSA) []retiredChildSAState {
	states := make([]retiredChildSAState, 0, len(children))
	for _, child := range children {
		states = append(states, retiredChildSAState{
			inboundSPI:  child.inbound.SPI,
			outboundSPI: child.outboundSPI,
		})
	}
	return states
}

func (s *Session) informationalStateForPacket(packet ike.Packet) (informationalState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.pruneRetiredIKESAs(now)
	state := s.currentInformationalStateSnapshot()
	if state.matches(packet) {
		return state, true
	}
	if s.pendingIKESAReady {
		pending := state
		pending.ike = s.pendingIKESA.crypto
		pending.localInitiator = s.pendingIKESA.localInitiator
		pending.initiatorSPI = s.pendingIKESA.initiatorSPI
		pending.responderSPI = s.pendingIKESA.responderSPI
		pending.ikeRekeying = false
		pending.pendingIKESA = false
		pending.promoteIKESA = true
		pending.nextPeerMessageID = 0
		pending.responses = nil
		pending.responseReqs = nil
		if pending.matches(packet) {
			return pending, true
		}
	}
	for _, retired := range s.retiredIKESAs {
		retiredState := state
		retiredState.ike = retired.ike
		retiredState.localInitiator = retired.localInitiator
		retiredState.initiatorSPI = retired.initiatorSPI
		retiredState.responderSPI = retired.responderSPI
		retiredState.peer = cloneUDPAddr(retired.peer)
		retiredState.ikeRekeying = false
		retiredState.pendingIKESA = false
		retiredState.retiredIKESA = true
		retiredState.useNATT = retired.useNATT
		retiredState.promoteIKESA = false
		retiredState.nextPeerMessageID = retired.nextPeerMessageID
		retiredState.responses = cloneIKEMessageResponses(retired.responses)
		retiredState.responseReqs = cloneIKEMessageRequests(retired.responseReqs)
		if retiredState.matches(packet) {
			return retiredState, true
		}
	}
	return informationalState{}, false
}

func (s informationalState) matches(packet ike.Packet) bool {
	if s.ike == nil {
		return false
	}
	return packet.Header.InitiatorSPI == s.initiatorSPI && packet.Header.ResponderSPI == s.responderSPI
}

func (s informationalState) canSendDelete() bool {
	return s.available()
}

func (s informationalState) available() bool {
	return s.ike != nil && s.peer != nil
}

func (s informationalState) responseMessageKey(messageID uint32, exchangeType byte) ikeMessageKey {
	return ikeMessageKeyForSPIs(s.initiatorSPI, s.responderSPI, exchangeType, ikeMessageFlags(s.peerInitiator(), true), messageID)
}

func ikeMessageKeyForHeader(header ike.Header) ikeMessageKey {
	return ikeMessageKeyForSPIs(header.InitiatorSPI, header.ResponderSPI, header.ExchangeType, header.Flags, header.MessageID)
}

func ikeMessageKeyForSPIs(initiatorSPI, responderSPI uint64, exchangeType byte, flags byte, messageID uint32) ikeMessageKey {
	return ikeMessageKey{
		initiatorSPI: initiatorSPI,
		responderSPI: responderSPI,
		exchangeType: exchangeType,
		flags:        ikeMessageDirectionFlags(flags),
		messageID:    messageID,
	}
}

func ikeMessageFlags(senderInitiator bool, response bool) byte {
	var flags byte
	if senderInitiator {
		flags |= flagInitiator
	}
	if response {
		flags |= flagResponse
	}
	return flags
}

func ikeMessageDirectionFlags(flags byte) byte {
	return flags & (flagInitiator | flagResponse)
}

func (s informationalState) initiatorHeader(messageID uint32) ike.Header {
	flags := byte(0)
	if s.localInitiator {
		flags = flagInitiator
	}
	return ike.Header{
		InitiatorSPI: s.initiatorSPI,
		ResponderSPI: s.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func (s informationalState) sealInitiatorRequest(messageID uint32, payloads []ike.Payload) ([][]byte, error) {
	return sealIKEPackets(s.ike, s.initiatorHeader(messageID), payloads, s.localInitiator, s.ikeFragmentationSupported)
}

func (s informationalState) peerInitiator() bool {
	return !s.localInitiator
}

func (s informationalState) createChildSARequestState() createChildSARequestState {
	return createChildSARequestState{
		ike:                       s.ike,
		localInitiator:            s.localInitiator,
		ikeRekeying:               s.ikeRekeying,
		pendingIKESA:              s.pendingIKESA,
		retiredIKESA:              s.retiredIKESA,
		ikeFragmentationSupported: s.ikeFragmentationSupported,
		useNATT:                   s.useNATT,
		childRekeying:             s.childRekeying,
		cfg:                       s.cfg,
		info:                      cloneInfo(s.info),
		initiatorSPI:              s.initiatorSPI,
		responderSPI:              s.responderSPI,
		peer:                      cloneUDPAddr(s.peer),
		inboundSPI:                s.inboundSPI,
		outboundSPI:               s.outboundSPI,
		promoteIKESA:              s.promoteIKESA,
		nextPeerMessageID:         s.nextPeerMessageID,
		responses:                 cloneIKEMessageResponses(s.responses),
		responseReqs:              cloneIKEMessageRequests(s.responseReqs),
	}
}
