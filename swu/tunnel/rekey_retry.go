package tunnel

import (
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/swu/ike"
)

var (
	rekeyTemporaryFailureRetryDelay  = 30 * time.Second
	rekeyTemporaryFailureMaxDuration = 3 * time.Minute
)

type rekeyTemporaryFailureBackoff struct {
	first   time.Time
	retryAt time.Time
}

func (b *rekeyTemporaryFailureBackoff) waiting(now time.Time) bool {
	return !b.retryAt.IsZero() && now.Before(b.retryAt)
}

func (b *rekeyTemporaryFailureBackoff) record(now time.Time) bool {
	if b.first.IsZero() {
		b.first = now
	}
	if now.Sub(b.first) >= rekeyTemporaryFailureMaxDuration {
		return false
	}
	b.retryAt = now.Add(rekeyTemporaryFailureRetryDelay)
	return true
}

func (b *rekeyTemporaryFailureBackoff) reset() {
	*b = rekeyTemporaryFailureBackoff{}
}

func rekeyHardLifetimeExpired(expiresAt, now time.Time) bool {
	return !expiresAt.IsZero() && !now.Before(expiresAt)
}

func nextRekeyRetryAt(now, expiresAt time.Time) time.Time {
	retryAt := now.Add(rekeyTemporaryFailureRetryDelay)
	if !expiresAt.IsZero() && expiresAt.Before(retryAt) {
		return expiresAt
	}
	return retryAt
}

func (s *Session) deferIKESARekey(now, expiresAt time.Time) time.Time {
	retryAt := nextRekeyRetryAt(now, expiresAt)
	s.mu.Lock()
	if !s.ikeSARekeyAt.IsZero() && !now.Before(s.ikeSARekeyAt) {
		s.ikeSARekeyAt = retryAt
	}
	s.mu.Unlock()
	return retryAt
}

func (s *Session) deferChildSARekey(now, expiresAt time.Time) time.Time {
	retryAt := nextRekeyRetryAt(now, expiresAt)
	s.mu.Lock()
	if !s.childSARekeyAt.IsZero() && !now.Before(s.childSARekeyAt) {
		s.childSARekeyAt = retryAt
	}
	s.mu.Unlock()
	return retryAt
}

func (s *Session) notifyRekeyStateChanged() {
	select {
	case s.rekeyWake <- struct{}{}:
	default:
	}
}

func (s *Session) waitForRekeyDeadline(lifetimeState func() (time.Time, time.Time), temporaryFailure rekeyTemporaryFailureBackoff) (time.Time, time.Time, bool) {
	for {
		now := time.Now()
		rekeyAt, expiresAt := lifetimeState()
		deadline := nextRekeyLoopDeadline(rekeyAt, expiresAt, temporaryFailure, now)
		if deadline.IsZero() {
			if !s.waitForRekeyStateChange() {
				return time.Time{}, time.Time{}, false
			}
			continue
		}
		if !now.Before(deadline) {
			return rekeyAt, expiresAt, true
		}
		if !s.waitForRekeyStateChangeUntil(deadline) {
			return time.Time{}, time.Time{}, false
		}
	}
}

func (s *Session) waitForRekeyStateChange() bool {
	select {
	case <-s.closeCtx.Done():
		return false
	case <-s.rekeyWake:
		return true
	}
}

func (s *Session) waitForRekeyStateChangeUntil(deadline time.Time) bool {
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-s.closeCtx.Done():
		return false
	case <-s.rekeyWake:
		return true
	case <-timer.C:
		return true
	}
}

func nextRekeyLoopDeadline(rekeyAt, expiresAt time.Time, temporaryFailure rekeyTemporaryFailureBackoff, now time.Time) time.Time {
	if !rekeyAt.IsZero() && !now.Before(rekeyAt) && temporaryFailure.waiting(now) {
		return earliestTime(temporaryFailure.retryAt, expiresAt)
	}
	return earliestTime(rekeyAt, expiresAt)
}

func earliestTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}

func createChildSAResponseNotifyError(payloads []ike.Payload) error {
	if notify := ike.FindNotifyPayload(payloads, notifyTypeTemporaryFailure); notify != nil {
		return fmt.Errorf("create_child_sa rejected: %w", errIKETemporaryFailure)
	}
	if notify := ike.FindNotifyPayload(payloads, notifyTypeChildSANotFound); notify != nil {
		return fmt.Errorf("create_child_sa rejected: %w", errChildSANotFound)
	}
	if notify := firstErrorNotifyPayload(payloads); notify != nil {
		return fmt.Errorf("create_child_sa rejected with notify %d", notify.NotifyType)
	}
	return nil
}

func firstErrorNotifyPayload(payloads []ike.Payload) *ike.NotifyPayload {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if ok && notify.NotifyType < notifyTypeStatusMin {
			return notify
		}
	}
	return nil
}
