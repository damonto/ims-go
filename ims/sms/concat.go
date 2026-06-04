package sms

import (
	"fmt"
	"strings"
	"time"
)

func newConcatState(total int) concatState {
	return concatState{
		total:    total,
		parts:    make(map[int]string, max(total, 0)),
		rawTPDUs: make(map[int][]byte, max(total, 0)),
	}
}

func (state concatState) expired(now time.Time) bool {
	return now.Sub(state.updatedAt) > concatRetention
}

func (state *concatState) reset(total int) {
	*state = newConcatState(total)
}

func (state *concatState) addPart(sequence int, msg Incoming, now time.Time) {
	if state.parts == nil {
		state.parts = make(map[int]string, max(state.total, 0))
	}
	if state.rawTPDUs == nil {
		state.rawTPDUs = make(map[int][]byte, max(state.total, 0))
	}
	state.parts[sequence] = msg.Text
	state.rawTPDUs[sequence] = append([]byte(nil), msg.RawTPDU...)
	state.reservedMTI = state.reservedMTI || msg.ReservedMTI
	state.updatedAt = now
}

func (state concatState) joinedText() (string, bool) {
	if state.total <= 0 || len(state.parts) < state.total {
		return "", false
	}
	parts := make([]string, state.total)
	for i := 1; i <= state.total; i++ {
		part, ok := state.parts[i]
		if !ok {
			return "", false
		}
		parts[i-1] = part
	}
	return strings.Join(parts, ""), true
}

func (state concatState) joinedRawTPDUs() [][]byte {
	raw := make([][]byte, 0, state.total)
	for i := 1; i <= state.total; i++ {
		if part := state.rawTPDUs[i]; len(part) != 0 {
			raw = append(raw, append([]byte(nil), part...))
		}
	}
	return raw
}

func (s *Service) deliverConcat(msg Incoming, concat concatInfo) {
	if s.cfg.OnIncoming == nil {
		return
	}
	incoming, complete, concatKey := s.appendConcat(msg, concat)
	if !complete {
		return
	}
	if s.markConcatSeen(concatKey) {
		s.cfg.OnIncoming(incoming)
	}
}

func (s *Service) markConcatSeen(key string) bool {
	return s.markRecentKey("concat|"+key, concatRetention)
}

func (s *Service) concatKey(msg Incoming, concat concatInfo) string {
	sender := msg.From
	if sender == "" {
		sender = msg.FromURI
	}
	return fmt.Sprintf("%t|%d|%s|%s", concat.SixteenBit, concat.Reference, sender, msg.ServiceCenter)
}

func (s *Service) evictExpiredConcat(now time.Time) {
	for cacheKey, state := range s.concat {
		if state.expired(now) {
			delete(s.concat, cacheKey)
		}
	}
}

func (s *Service) appendConcat(msg Incoming, concat concatInfo) (Incoming, bool, string) {
	key := s.concatKey(msg, concat)
	now := time.Now()
	s.mu.Lock()
	s.evictExpiredConcat(now)
	state := s.concat[key]
	if state.parts == nil || state.total != int(concat.Total) {
		state.reset(int(concat.Total))
	}
	state.addPart(int(concat.Sequence), msg, now)
	text, ok := state.joinedText()
	if !ok {
		s.concat[key] = state
		s.mu.Unlock()
		return Incoming{}, false, key
	}
	delete(s.concat, key)
	s.mu.Unlock()
	msg.Text = text
	msg.RawTPDUs = state.joinedRawTPDUs()
	msg.ReservedMTI = state.reservedMTI
	return msg, true, key
}
