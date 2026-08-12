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

func (cs concatState) expired(now time.Time) bool {
	return now.Sub(cs.updatedAt) > concatRetention
}

func (cs *concatState) reset(total int) {
	*cs = newConcatState(total)
}

func (cs *concatState) addPart(sequence int, msg Incoming, now time.Time) {
	if cs.parts == nil {
		cs.parts = make(map[int]string, max(cs.total, 0))
	}
	if cs.rawTPDUs == nil {
		cs.rawTPDUs = make(map[int][]byte, max(cs.total, 0))
	}
	cs.parts[sequence] = msg.Text
	cs.rawTPDUs[sequence] = append([]byte(nil), msg.RawTPDU...)
	cs.reservedMTI = cs.reservedMTI || msg.ReservedMTI
	cs.updatedAt = now
}

func (cs concatState) joinedText() (string, bool) {
	if cs.total <= 0 || len(cs.parts) < cs.total {
		return "", false
	}
	parts := make([]string, cs.total)
	for i := 1; i <= cs.total; i++ {
		part, ok := cs.parts[i]
		if !ok {
			return "", false
		}
		parts[i-1] = part
	}
	return strings.Join(parts, ""), true
}

func (cs concatState) joinedRawTPDUs() [][]byte {
	raw := make([][]byte, 0, cs.total)
	for i := 1; i <= cs.total; i++ {
		if part := cs.rawTPDUs[i]; len(part) != 0 {
			raw = append(raw, append([]byte(nil), part...))
		}
	}
	return raw
}

func (s *Endpoint) deliverConcat(msg Incoming, concat concatInfo) {
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

func (s *Endpoint) markConcatSeen(key string) bool {
	return s.markRecentKey("concat|"+key, concatRetention)
}

func (s *Endpoint) concatKey(msg Incoming, concat concatInfo) string {
	sender := msg.From
	if sender == "" {
		sender = msg.FromURI
	}
	// TS 23.040 9.2.3.24 recommends not using the SC address because segments
	// of one message can be routed through different service centres.
	return fmt.Sprintf("%t|%d|%s", concat.SixteenBit, concat.Reference, sender)
}

func (s *Endpoint) evictExpiredConcat(now time.Time) {
	for cacheKey, state := range s.concat {
		if state.expired(now) {
			delete(s.concat, cacheKey)
		}
	}
}

func (s *Endpoint) appendConcat(msg Incoming, concat concatInfo) (Incoming, bool, string) {
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
