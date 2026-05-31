package voice

import (
	"context"
	"fmt"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"time"
)

const sipTransactionTimeoutMultiplier = 64

func (c *Call) startRingbackTimer() {
	timeout := c.service.cfg.RingbackTimeout
	if timeout <= 0 {
		return
	}
	c.mu.Lock()
	if c.ringbackStop != nil || c.closed || c.direction != CallDirectionOutgoing {
		c.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	c.ringbackStop = stop
	c.mu.Unlock()

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := context.WithTimeout(context.Background(), callReleaseTimeout)
			defer cancel()
			if err := c.cancelOutgoingInvite(ctx); err != nil {
				c.service.emitError(fmt.Errorf("ringback timeout: %w", err))
			}
		}
	}()
}

func (c *Call) stopRingbackTimer() {
	c.mu.Lock()
	stop := c.ringbackStop
	c.ringbackStop = nil
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (c *Call) startRingingTimer() {
	timeout := c.service.cfg.RingingTimeout
	if timeout <= 0 {
		return
	}
	c.mu.Lock()
	if c.ringingStop != nil || c.closed || c.direction != CallDirectionIncoming || c.incomingRequest == nil {
		c.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	c.ringingStop = stop
	c.mu.Unlock()

	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-stop:
			return
		case <-timer.C:
			c.rejectAfterRingingTimeout()
		}
	}()
}

func (c *Call) stopRingingTimer() {
	c.mu.Lock()
	stop := c.ringingStop
	c.ringingStop = nil
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (c *Call) rejectAfterRingingTimeout() {
	c.mu.Lock()
	if c.closed || c.direction != CallDirectionIncoming || c.state != CallStateRinging || c.incomingRequest == nil {
		c.mu.Unlock()
		return
	}
	req := *c.incomingRequest
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), callReleaseTimeout)
	defer cancel()
	if err := c.service.writeStatus(ctx, req, sipStatusBusyHere, "Busy Here"); err != nil {
		c.service.emitError(fmt.Errorf("ringing timeout: %w", err))
		c.finish(CallStateFailed, err.Error())
		return
	}
	c.finish(CallStateEnded, "ringing timeout")
}

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

	go func() {
		timers := c.service.timers
		interval := timers.T1
		timer := time.NewTimer(interval)
		defer timer.Stop()
		deadline := time.NewTimer(sipTransactionTimeoutMultiplier * timers.T1)
		defer deadline.Stop()

		for {
			select {
			case <-stop:
				return
			case <-deadline.C:
				c.finish(CallStateEnded, "ack timeout")
				return
			case <-timer.C:
				ctx, cancel := context.WithTimeout(context.Background(), min(inviteOKWriteTimeout, interval))
				if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
					c.service.emitError(fmt.Errorf("retransmitting call 200 OK: %w", err))
				}
				cancel()
				interval = min(interval*2, timers.T2)
				timer.Reset(interval)
			}
		}
	}()
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

	go func() {
		timers := c.service.timers
		interval := timers.T1
		timer := time.NewTimer(interval)
		defer timer.Stop()
		deadline := time.NewTimer(sipTransactionTimeoutMultiplier * timers.T1)
		defer deadline.Stop()

		for {
			select {
			case <-stop:
				return
			case <-deadline.C:
				ctx, cancel := context.WithTimeout(context.Background(), callReleaseTimeout)
				if err := c.service.writeStatus(ctx, req, sipStatusServerInternalError, "Reliable Response Timed Out"); err != nil {
					c.service.emitError(fmt.Errorf("rejecting INVITE after PRACK timeout: %w", err))
				}
				cancel()
				c.finish(CallStateFailed, "prack timeout")
				return
			case <-timer.C:
				ctx, cancel := context.WithTimeout(context.Background(), min(inviteOKWriteTimeout, interval))
				if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
					c.service.emitError(fmt.Errorf("retransmitting reliable provisional response: %w", err))
				}
				cancel()
				interval = nextReliableProvisionalRetransmitInterval(interval)
				timer.Reset(interval)
			}
		}
	}()
}

func resetTimer(timer *time.Timer, timeout time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(timeout)
}
