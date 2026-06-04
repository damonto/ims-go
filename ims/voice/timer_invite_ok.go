package voice

import (
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) startInviteOKRetransmit(req session.Request, resp sip.Message) {
	c.mu.Lock()
	if c.inviteOKStop != nil || c.closed {
		c.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	c.inviteOKStop = stop
	c.inviteOKCSeq = sip.CSeqNumber(req.Message.Header("CSeq"))
	c.mu.Unlock()

	c.service.startBackgroundTask(func(done <-chan struct{}) {
		timers := c.service.timers
		interval := timers.T1
		timer := time.NewTimer(interval)
		defer timer.Stop()
		deadline := time.NewTimer(sipTransactionTimeoutMultiplier * timers.T1)
		defer deadline.Stop()

		for {
			select {
			case <-done:
				return
			case <-stop:
				return
			case <-deadline.C:
				c.finish(CallStateEnded, "ack timeout")
				return
			case <-timer.C:
				ctx, cancel := contextWithDoneTimeout(done, min(inviteOKWriteTimeout, interval))
				if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
					c.service.emitError(fmt.Errorf("retransmitting call 200 OK: %w", err))
				}
				cancel()
				interval = min(interval*2, timers.T2)
				timer.Reset(interval)
			}
		}
	})
}

func (c *Call) stopInviteOKRetransmit() {
	c.mu.Lock()
	stop := c.inviteOKStop
	c.inviteOKStop = nil
	c.inviteOKCSeq = 0
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}
