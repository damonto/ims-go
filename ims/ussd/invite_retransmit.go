package ussd

import (
	"time"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Session) startInviteOKRetransmit(req session.Request, resp sip.Message) {
	s.mu.Lock()
	if s.inviteOKStop != nil || s.state == sessionStateClosed {
		s.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	s.inviteOKStop = stop
	s.mu.Unlock()

	s.service.startBackgroundTask(func(done <-chan struct{}) {
		timers := s.service.sess.TransactionTimers()
		interval := timers.T1
		timer := time.NewTimer(interval)
		defer timer.Stop()
		deadline := time.NewTimer(inviteOKTimeoutMultiplier * timers.T1)
		defer deadline.Stop()

		for {
			select {
			case <-done:
				return
			case <-stop:
				return
			case <-deadline.C:
				s.service.logger.Warn("USSD INVITE 200 OK ACK timeout", "call_id", s.callID)
				s.finish(false)
				return
			case <-timer.C:
				ctx, cancel := contextWithDoneTimeout(done, min(inviteOKWriteTimeout, interval))
				if err := s.service.sess.WriteResponse(ctx, req, resp); err != nil {
					s.service.logger.Warn("retransmitting USSD INVITE 200 OK", "call_id", s.callID, "err", err)
				}
				cancel()
				interval = min(interval*2, timers.T2)
				timer.Reset(interval)
			}
		}
	})
}
