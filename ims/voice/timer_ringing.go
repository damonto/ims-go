package voice

import (
	"fmt"
	"time"
)

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

	c.service.startBackgroundTask(func(done <-chan struct{}) {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-stop:
			return
		case <-timer.C:
			ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
			defer cancel()
			if err := c.cancelOutgoingInvite(ctx); err != nil {
				c.service.emitError(fmt.Errorf("ringback timeout: %w", err))
			}
		}
	})
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

	c.service.startBackgroundTask(func(done <-chan struct{}) {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-stop:
			return
		case <-timer.C:
			c.rejectAfterRingingTimeout(done)
		}
	})
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

func (c *Call) rejectAfterRingingTimeout(done <-chan struct{}) {
	c.mu.Lock()
	if c.closed || c.direction != CallDirectionIncoming || c.state != CallStateRinging || c.incomingRequest == nil {
		c.mu.Unlock()
		return
	}
	req := *c.incomingRequest
	c.mu.Unlock()

	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	defer cancel()
	if err := c.service.writeStatus(ctx, req, sipStatusBusyHere, "Busy Here"); err != nil {
		c.service.emitError(fmt.Errorf("ringing timeout: %w", err))
		c.finish(CallStateFailed, err.Error())
		return
	}
	c.finish(CallStateEnded, "ringing timeout")
}
