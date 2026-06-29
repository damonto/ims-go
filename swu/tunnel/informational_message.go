package tunnel

import (
	"bytes"
	"errors"
	"time"
)

const informationalResponseCacheWindow = 8
const maxIKEMessageID = ^uint32(0)
const invalidMessageIDNotifyMinInterval = 10 * time.Second

var errIKESASuperseded = errors.New("ike sa was superseded")
var errIKEMessageIDExhausted = errors.New("ike message id exhausted")

type ikeMessageIDRelation byte

type ikeMessageIDs struct {
	nextMessageID        uint32
	nextPeerMessageID    uint32
	lastInvalidMessageID time.Time
}

const (
	ikeMessageIDCurrent ikeMessageIDRelation = iota
	ikeMessageIDOld
	ikeMessageIDFuture
)

type ikeMessageKey struct {
	initiatorSPI uint64
	responderSPI uint64
	exchangeType byte
	flags        byte
	messageID    uint32
}

func (s *Session) allocateMessageID() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextMessageID == maxIKEMessageID {
		return 0, errIKEMessageIDExhausted
	}
	messageID := s.nextMessageID
	s.nextMessageID = messageID + 1
	return messageID, nil
}

func (s *Session) peerRequestMessageIDCurrent(messageID uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return messageID == s.nextPeerMessageID
}

func (s *Session) allowInvalidMessageIDNotification(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastInvalidMessageID.IsZero() && now.Sub(s.lastInvalidMessageID) < invalidMessageIDNotifyMinInterval {
		return false
	}
	s.lastInvalidMessageID = now
	return true
}

func (s *Session) advancePeerRequestMessageID(messageID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if messageID == s.nextPeerMessageID {
		if messageID == maxIKEMessageID {
			return errIKEMessageIDExhausted
		}
		s.nextPeerMessageID = messageID + 1
	}
	return nil
}

func (s *Session) peerRequestMessageIDRelationForState(state informationalState, messageID uint32) ikeMessageIDRelation {
	expected := state.nextPeerMessageID
	if !state.retiredIKESA && !state.promoteIKESA {
		s.mu.RLock()
		expected = s.nextPeerMessageID
		s.mu.RUnlock()
	}
	switch {
	case messageID == expected:
		return ikeMessageIDCurrent
	case messageID < expected:
		return ikeMessageIDOld
	default:
		return ikeMessageIDFuture
	}
}

func (s *Session) advancePeerRequestMessageIDForState(state informationalState, messageID uint32) error {
	if !state.retiredIKESA {
		return s.advancePeerRequestMessageID(messageID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.retiredIKESAs {
		if !retiredIKESAMatches(s.retiredIKESAs[i], state.initiatorSPI, state.responderSPI) {
			continue
		}
		if messageID == s.retiredIKESAs[i].nextPeerMessageID {
			if messageID == maxIKEMessageID {
				return errIKEMessageIDExhausted
			}
			s.retiredIKESAs[i].nextPeerMessageID = messageID + 1
		}
		return nil
	}
	return nil
}

func (s *Session) registerInformationalWaiter(key ikeMessageKey) chan inboundIKE {
	ch := make(chan inboundIKE, 1)
	s.mu.Lock()
	if s.informWaiters == nil {
		s.informWaiters = make(map[ikeMessageKey]chan inboundIKE)
	}
	s.informWaiters[key] = ch
	s.mu.Unlock()
	return ch
}

func (s *Session) unregisterInformationalWaiter(key ikeMessageKey, ch chan inboundIKE) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.informWaiters[key]; ok && current == ch {
		delete(s.informWaiters, key)
	}
}

func (s *Session) hasInformationalWaiter(key ikeMessageKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.informWaiters[key]
	return ok
}

func (s *Session) deliverInformationalWaiter(key ikeMessageKey, packet inboundIKE) bool {
	s.mu.Lock()
	ch, ok := s.informWaiters[key]
	if ok {
		delete(s.informWaiters, key)
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

func (s *Session) abortInformationalWaiters(err error) {
	s.mu.Lock()
	waiters := s.informWaiters
	s.informWaiters = nil
	s.mu.Unlock()
	notifyInformationalWaiters(waiters, err)
}

func notifyInformationalWaiters(waiters map[ikeMessageKey]chan inboundIKE, err error) {
	if err == nil {
		return
	}
	for _, ch := range waiters {
		select {
		case ch <- inboundIKE{err: err}:
		default:
		}
	}
}

func (s *Session) cachedInformationalResponse(messageID uint32, request []byte) ([][]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.informResponses) == 0 {
		return nil, false
	}
	wires, ok := s.informResponses[messageID]
	if !ok {
		return nil, false
	}
	if cachedRequest, ok := s.informResponseReqs[messageID]; ok && !bytes.Equal(cachedRequest, request) {
		return nil, false
	}
	return cloneIKEPackets(wires), true
}

func (s *Session) cachedInformationalResponseForState(state informationalState, messageID uint32, request []byte) ([][]byte, bool) {
	if state.promoteIKESA {
		return nil, false
	}
	if !state.retiredIKESA {
		return s.cachedInformationalResponse(messageID, request)
	}
	wires, ok := state.responses[messageID]
	if !ok {
		return nil, false
	}
	if cachedRequest, ok := state.responseReqs[messageID]; ok && !bytes.Equal(cachedRequest, request) {
		return nil, false
	}
	return cloneIKEPackets(wires), true
}

func (s *Session) cacheInformationalResponse(messageID uint32, request []byte, wires [][]byte) {
	if len(wires) == 0 {
		return
	}
	s.mu.Lock()
	if s.informResponses == nil {
		s.informResponses = make(map[uint32][][]byte)
	}
	s.informResponses[messageID] = cloneIKEPackets(wires)
	if len(request) != 0 {
		if s.informResponseReqs == nil {
			s.informResponseReqs = make(map[uint32][]byte)
		}
		s.informResponseReqs[messageID] = append([]byte(nil), request...)
	}
	for cachedID := range s.informResponses {
		if messageID >= cachedID && messageID-cachedID >= informationalResponseCacheWindow {
			delete(s.informResponses, cachedID)
			delete(s.informResponseReqs, cachedID)
		}
	}
	s.mu.Unlock()
}

func (s *Session) cacheInformationalResponseForState(state informationalState, messageID uint32, request []byte, wires [][]byte) {
	if !state.retiredIKESA {
		s.cacheInformationalResponse(messageID, request, wires)
		return
	}
	if len(wires) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.retiredIKESAs {
		if !retiredIKESAMatches(s.retiredIKESAs[i], state.initiatorSPI, state.responderSPI) {
			continue
		}
		if s.retiredIKESAs[i].responses == nil {
			s.retiredIKESAs[i].responses = make(map[uint32][][]byte)
		}
		s.retiredIKESAs[i].responses[messageID] = cloneIKEPackets(wires)
		if len(request) != 0 {
			if s.retiredIKESAs[i].responseReqs == nil {
				s.retiredIKESAs[i].responseReqs = make(map[uint32][]byte)
			}
			s.retiredIKESAs[i].responseReqs[messageID] = append([]byte(nil), request...)
		}
		for cachedID := range s.retiredIKESAs[i].responses {
			if messageID >= cachedID && messageID-cachedID >= informationalResponseCacheWindow {
				delete(s.retiredIKESAs[i].responses, cachedID)
				delete(s.retiredIKESAs[i].responseReqs, cachedID)
			}
		}
		return
	}
}
