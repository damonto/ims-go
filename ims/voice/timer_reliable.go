package voice

import (
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) startReliableProvisionalRetransmit(req session.Request, resp sip.Message, rseq int64) {
	c.mu.Lock()
	if c.reliableStop != nil || c.closed || c.pendingReliable.rseq != rseq {
		c.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	c.reliableStop = stop
	c.reliableResponse = cloneSIPMessage(resp)
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
				ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
				if err := c.service.writeStatus(ctx, req, sipStatusServerInternalError, "Reliable Response Timed Out"); err != nil {
					c.service.emitError(fmt.Errorf("rejecting INVITE after PRACK timeout: %w", err))
				}
				cancel()
				c.finish(CallStateFailed, "prack timeout")
				return
			case <-timer.C:
				ctx, cancel := contextWithDoneTimeout(done, min(inviteOKWriteTimeout, interval))
				if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
					c.service.emitError(fmt.Errorf("retransmitting reliable provisional response: %w", err))
				}
				cancel()
				interval = nextReliableProvisionalRetransmitInterval(interval)
				timer.Reset(interval)
			}
		}
	})
}
