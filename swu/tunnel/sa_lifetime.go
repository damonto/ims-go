package tunnel

import (
	crand "crypto/rand"
	"fmt"
	"math/big"
	"time"
)

func childSAExpiry(now time.Time, lifetime time.Duration) time.Time {
	if lifetime <= 0 {
		return time.Time{}
	}
	return now.Add(lifetime)
}

var saRekeyJitter = randomSARekeyJitter

func childSARekeyTime(now time.Time, lifetime, margin time.Duration) time.Time {
	if lifetime <= 0 || margin <= 0 {
		return time.Time{}
	}
	return now.Add(lifetime - margin + saRekeyJitter(margin/2))
}

func saByteExpiry(lifetime uint64) uint64 {
	return lifetime
}

func saByteRekeyLimit(lifetime, margin uint64) uint64 {
	if lifetime == 0 || margin == 0 {
		return 0
	}
	return lifetime - margin
}

func byteLifetimeWouldExpire(current, add, limit uint64) bool {
	if limit == 0 {
		return false
	}
	if current >= limit {
		return true
	}
	return add > limit-current
}

func addByteCount(current, add uint64) uint64 {
	if add > ^uint64(0)-current {
		return ^uint64(0)
	}
	return current + add
}

func randomSARekeyJitter(maxDelay time.Duration) time.Duration {
	if maxDelay <= 0 {
		return 0
	}
	n, err := crand.Int(crand.Reader, big.NewInt(int64(maxDelay)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

func (s *Session) ikeSAExpired(now time.Time) bool {
	return s.ike != nil && !s.ikeSAExpiresAt.IsZero() && !now.Before(s.ikeSAExpiresAt)
}

func (s *Session) ikeSAByteExpired(add uint64) bool {
	return s.ike != nil && byteLifetimeWouldExpire(s.ikeSAOutboundBytes, add, s.ikeSAByteExpiresAt)
}

func (s *Session) expireIKESAIfNeeded(action string) error {
	s.mu.RLock()
	expired := s.ikeSAExpired(time.Now()) || s.ikeSAByteExpired(0)
	s.mu.RUnlock()
	if !expired {
		return nil
	}
	s.failSecurityAssociations(errIKESAExpired)
	return fmt.Errorf("%s: %w", action, errIKESAExpired)
}

func (s *Session) addIKESAOutboundBytes(protectedBytes uint64, now time.Time) bool {
	if protectedBytes == 0 {
		return false
	}
	rekeyNow := false
	s.mu.Lock()
	if s.ike == nil {
		s.mu.Unlock()
		return false
	}
	s.ikeSAOutboundBytes = addByteCount(s.ikeSAOutboundBytes, protectedBytes)
	if s.ikeSAByteRekeyAt != 0 && s.ikeSAOutboundBytes >= s.ikeSAByteRekeyAt && (s.ikeSARekeyAt.IsZero() || now.Before(s.ikeSARekeyAt)) {
		s.ikeSARekeyAt = now
		rekeyNow = true
	}
	expired := s.ikeSAByteExpiresAt != 0 && s.ikeSAOutboundBytes >= s.ikeSAByteExpiresAt
	s.mu.Unlock()
	if rekeyNow {
		s.notifyRekeyStateChanged()
	}
	return expired
}

type ikeAcceptResult struct {
	accepted bool
	expired  bool
}

func (s *Session) acceptIKESAInboundBytes(protectedBytes uint64, now time.Time) ikeAcceptResult {
	if protectedBytes == 0 {
		return ikeAcceptResult{accepted: true}
	}
	rekeyNow := false
	s.mu.Lock()
	if s.ike == nil {
		s.mu.Unlock()
		return ikeAcceptResult{}
	}
	if byteLifetimeWouldExpire(s.ikeSAInboundBytes, protectedBytes, s.ikeSAByteExpiresAt) {
		s.mu.Unlock()
		return ikeAcceptResult{expired: true}
	}
	s.ikeSAInboundBytes = addByteCount(s.ikeSAInboundBytes, protectedBytes)
	if s.ikeSAByteRekeyAt != 0 && s.ikeSAInboundBytes >= s.ikeSAByteRekeyAt && (s.ikeSARekeyAt.IsZero() || now.Before(s.ikeSARekeyAt)) {
		s.ikeSARekeyAt = now
		rekeyNow = true
	}
	result := ikeAcceptResult{
		accepted: true,
		expired:  s.ikeSAByteExpiresAt != 0 && s.ikeSAInboundBytes >= s.ikeSAByteExpiresAt,
	}
	s.mu.Unlock()
	if rekeyNow {
		s.notifyRekeyStateChanged()
	}
	return result
}

func (s *Session) childSAExpired(now time.Time) bool {
	return s.connected && !s.childSAExpiresAt.IsZero() && !now.Before(s.childSAExpiresAt)
}

func (s *Session) childSAByteExpired(add uint64) bool {
	return s.connected && byteLifetimeWouldExpire(s.childSAOutboundBytes, add, s.childSAByteExpiresAt)
}

func (s *Session) expireChildSAIfNeeded(action string) error {
	s.mu.RLock()
	expired := s.childSAExpired(time.Now())
	s.mu.RUnlock()
	if !expired {
		return nil
	}
	s.discardChildSecurityAssociations(errChildSAExpired)
	return fmt.Errorf("%s: %w", action, errChildSAExpired)
}

func (s *Session) addCurrentChildSAOutboundBytes(protectedBytes uint64, now time.Time) bool {
	if protectedBytes == 0 {
		return false
	}
	rekeyNow := false
	s.mu.Lock()
	if !s.connected {
		s.mu.Unlock()
		return false
	}
	s.childSAOutboundBytes = addByteCount(s.childSAOutboundBytes, protectedBytes)
	if s.childSAByteRekeyAt != 0 && s.childSAOutboundBytes >= s.childSAByteRekeyAt && (s.childSARekeyAt.IsZero() || now.Before(s.childSARekeyAt)) {
		s.childSARekeyAt = now
		rekeyNow = true
	}
	expired := s.childSAByteExpiresAt != 0 && s.childSAOutboundBytes >= s.childSAByteExpiresAt
	s.mu.Unlock()
	if rekeyNow {
		s.notifyRekeyStateChanged()
	}
	return expired
}
