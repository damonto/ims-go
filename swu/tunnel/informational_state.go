package tunnel

import (
	"net"
	"time"

	"github.com/damonto/vowifi-go/swu/ike"
)

type informationalState struct {
	connected         bool
	ike               *ikeCrypto
	localInitiator    bool
	ikeRekeying       bool
	pendingIKESA      bool
	retiredIKESA      bool
	childRekeying     bool
	cfg               Config
	initiatorSPI      uint64
	responderSPI      uint64
	identity          string
	peer              *net.UDPAddr
	info              Info
	inboundSPI        uint32
	outboundSPI       uint32
	pendingChild      bool
	oldInboundSPI     uint32
	retiredChildSAs   []retiredChildSAState
	promoteIKESA      bool
	nextPeerMessageID uint32
	responses         map[uint32][]byte
	responseReqs      map[uint32][]byte
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
		connected:         s.connected,
		ike:               s.ike,
		localInitiator:    s.ikeLocalInitiator,
		ikeRekeying:       ikeState == ikeSAStateRekeying,
		pendingIKESA:      ikeState == ikeSAStatePendingInstall,
		childRekeying:     childState == childSAStateRekeying,
		cfg:               s.cfg,
		initiatorSPI:      s.initiatorSPI,
		responderSPI:      s.responderSPI,
		identity:          s.deviceIdentity,
		peer:              cloneUDPAddr(s.outerNAT),
		info:              cloneInfo(s.tunnel),
		inboundSPI:        s.tunnel.ESPInitiatorSPI,
		outboundSPI:       s.tunnel.ESPResponderSPI,
		pendingChild:      childState == childSAStatePendingOutbound,
		oldInboundSPI:     s.pendingChildSA.oldInbound,
		retiredChildSAs:   retiredChildSAStates(s.retiredChildSAs),
		nextPeerMessageID: s.nextPeerMessageID,
		responses:         cloneIKEMessageResponses(s.informResponses),
		responseReqs:      cloneIKEMessageResponses(s.informResponseReqs),
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

func (s *Session) informationalStateForPacket(packet ike.IKEPacket) (informationalState, bool) {
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
		retiredState.promoteIKESA = false
		retiredState.nextPeerMessageID = retired.nextPeerMessageID
		retiredState.responses = cloneIKEMessageResponses(retired.responses)
		retiredState.responseReqs = cloneIKEMessageResponses(retired.responseReqs)
		if retiredState.matches(packet) {
			return retiredState, true
		}
	}
	return informationalState{}, false
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

func (state informationalState) available() bool {
	return state.ike != nil && state.peer != nil
}

func (state informationalState) messageKey(messageID uint32) ikeMessageKey {
	return ikeMessageKey{
		initiatorSPI: state.initiatorSPI,
		responderSPI: state.responderSPI,
		messageID:    messageID,
	}
}

func ikeMessageKeyForHeader(header ike.IKEHeader) ikeMessageKey {
	return ikeMessageKeyForSPIs(header.InitiatorSPI, header.ResponderSPI, header.MessageID)
}

func ikeMessageKeyForSPIs(initiatorSPI, responderSPI uint64, messageID uint32) ikeMessageKey {
	return ikeMessageKey{
		initiatorSPI: initiatorSPI,
		responderSPI: responderSPI,
		messageID:    messageID,
	}
}

func (state informationalState) initiatorHeader(messageID uint32) ike.IKEHeader {
	flags := byte(0)
	if state.localInitiator {
		flags = flagInitiator
	}
	return ike.IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		ResponderSPI: state.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func (state informationalState) sealInitiatorRequest(messageID uint32, payloads []ike.Payload) ([]byte, error) {
	return state.ike.SealIKE(state.initiatorHeader(messageID), payloads, state.localInitiator)
}

func (state informationalState) peerInitiator() bool {
	return !state.localInitiator
}

func (state informationalState) createChildSARequestState() createChildSARequestState {
	return createChildSARequestState{
		ike:               state.ike,
		localInitiator:    state.localInitiator,
		ikeRekeying:       state.ikeRekeying,
		pendingIKESA:      state.pendingIKESA,
		retiredIKESA:      state.retiredIKESA,
		childRekeying:     state.childRekeying,
		cfg:               state.cfg,
		info:              cloneInfo(state.info),
		initiatorSPI:      state.initiatorSPI,
		responderSPI:      state.responderSPI,
		peer:              cloneUDPAddr(state.peer),
		inboundSPI:        state.inboundSPI,
		outboundSPI:       state.outboundSPI,
		promoteIKESA:      state.promoteIKESA,
		nextPeerMessageID: state.nextPeerMessageID,
		responses:         cloneIKEMessageResponses(state.responses),
		responseReqs:      cloneIKEMessageResponses(state.responseReqs),
	}
}
