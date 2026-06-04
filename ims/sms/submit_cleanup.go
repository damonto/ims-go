package sms

import "time"

func (s *Service) submitSweepInterval() time.Duration {
	interval := s.cfg.SubmitReportTimeout / 4
	if interval < 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	if interval > time.Second {
		return time.Second
	}
	return interval
}

func (s *Service) runSubmitCleanup() {
	timer := time.NewTimer(s.submitSweepInterval())
	defer timer.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-timer.C:
			s.expireSubmitState(time.Now())
			timer.Reset(s.submitSweepInterval())
		}
	}
}

func (s *Service) expireSubmitState(now time.Time) {
	var expired []pendingEntry
	s.mu.Lock()
	s.evictExpiredConcat(now)
	for callID, entry := range s.submitted {
		if !entry.expiresAt.After(now) {
			delete(s.submitted, callID)
		}
	}
	for callID, entry := range s.pending {
		if !entry.async || entry.expiresAt.IsZero() || entry.expiresAt.After(now) {
			continue
		}
		delete(s.pending, callID)
		expired = append(expired, entry)
	}
	s.mu.Unlock()
	for _, entry := range expired {
		s.expirePendingSegment(entry)
	}
}
