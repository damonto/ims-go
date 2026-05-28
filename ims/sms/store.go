package sms

import (
	"github.com/damonto/vowifi-go/ims/sip"
	"strings"
	"time"
)

func (s *Service) markRecentKey(key string, ttl time.Duration) bool {
	if key == "" {
		return true
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for seenKey, seenAt := range s.recent {
		if now.Sub(seenAt) > ttl {
			delete(s.recent, seenKey)
		}
	}
	if seenAt, exists := s.recent[key]; exists && now.Sub(seenAt) <= ttl {
		return false
	}
	s.recent[key] = now
	return true
}

func (s *Service) clearRecentKey(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.recent, key)
	s.mu.Unlock()
}

func (s *Service) markSeen(msg sip.Message) bool {
	key, ok := seenKey(msg)
	if !ok {
		return true
	}
	return s.markRecentKey("sip|"+key, 2*time.Minute)
}

func (s *Service) markDeliveryReportSent(msg sip.Message) bool {
	key, ok := seenKey(msg)
	if !ok {
		return true
	}
	return s.markRecentKey("report|"+key, 2*time.Minute)
}

func (s *Service) clearDeliveryReportSent(msg sip.Message) {
	key, ok := seenKey(msg)
	if !ok {
		return
	}
	s.clearRecentKey("report|" + key)
}

func seenKey(msg sip.Message) (string, bool) {
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	if callID == "" || cseq == "" {
		return "", false
	}
	return callID + "|" + cseq, true
}
