package tunnel

import (
	"errors"
	"fmt"
	"time"
)

const natKeepaliveWriteTimeout = 2 * time.Second

var livenessCheckTimeout = 30 * time.Second

func (s *Session) livenessLoop() {
	defer s.wg.Done()
	for {
		if !s.waitForLivenessCheck(s.nextLivenessCheckDeadline()) {
			return
		}
		s.mu.RLock()
		timeout := s.livenessTimeout
		lastRx := s.lastProtectedRx
		s.mu.RUnlock()
		if timeout <= 0 || lastRx.IsZero() || time.Since(lastRx) < timeout {
			continue
		}
		ctx, cancel := s.timeoutContext(livenessCheckTimeout)
		_, err := s.sendInformational(ctx, nil)
		cancel()
		if err == nil {
			s.markProtectedRx(time.Now())
			continue
		}
		if errors.Is(err, errIKESARekeyInProgress) {
			if !s.waitForLivenessCheck(time.Now().Add(time.Second)) {
				return
			}
			continue
		}
		cause := fmt.Errorf("liveness check: %w", err)
		s.failSecurityAssociations(cause)
		return
	}
}

func (s *Session) nextLivenessCheckDeadline() time.Time {
	s.mu.RLock()
	timeout := s.livenessTimeout
	lastRx := s.lastProtectedRx
	s.mu.RUnlock()
	if timeout <= 0 || lastRx.IsZero() {
		return time.Time{}
	}
	return lastRx.Add(timeout)
}

func (s *Session) waitForLivenessCheck(deadline time.Time) bool {
	if deadline.IsZero() {
		<-s.closeDone()
		return false
	}
	if !time.Now().Before(deadline) {
		return true
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-s.closeDone():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Session) natKeepaliveLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeDone():
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
		ctx, cancel := s.timeoutContext(natKeepaliveWriteTimeout)
		err := s.writeOuter(ctx, []byte{0xff}, peer)
		cancel()
		if err != nil {
			if !s.isClosed() {
				s.logger.Debug("sending NAT keepalive failed", "err", err)
			}
			continue
		}
		s.markProtectedTx(time.Now())
	}
}
