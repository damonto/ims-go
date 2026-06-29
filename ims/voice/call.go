package voice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) ID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id
}

func (c *Call) Media() NegotiatedMedia {
	c.mu.Lock()
	defer c.mu.Unlock()
	media := c.media
	media.RemoteIP = append(net.IP(nil), media.RemoteIP...)
	media.RemoteRTCPIP = append(net.IP(nil), media.RemoteRTCPIP...)
	return media
}

func (c *Call) Answer(ctx context.Context, offer MediaOffer) error {
	if err := c.waitForReliableProvisionalAnswer(ctx); err != nil {
		return err
	}

	c.mu.Lock()
	if c.direction != CallDirectionIncoming {
		c.mu.Unlock()
		return errors.New("answering call: call is not incoming")
	}
	if c.state != CallStateRinging {
		c.mu.Unlock()
		return fmt.Errorf("answering call: call state is %s", c.state)
	}
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("answering call: incoming request is missing")
	}
	remoteOffer := c.remoteOffer
	localPort := c.localPort
	prackAnsweredOffer := c.prackAnsweredOffer
	provisionalAnswer := c.provisionalAnswer
	c.mu.Unlock()

	var (
		answer []byte
		media  NegotiatedMedia
		err    error
	)
	if c.delayedOffer && prackAnsweredOffer {
		// The delayed offer/answer exchange completed in reliable provisional response + PRACK.
	} else if provisionalAnswer {
		// The INVITE offer was already answered in a provisional response.
	} else if c.delayedOffer {
		answer, media, err = buildSDPOffer(c.endpoint.cfg, c.endpoint.localIP(), localPort, offer)
	} else {
		answer, media, err = buildSDPAnswer(c.endpoint.cfg, c.endpoint.localIP(), localPort, remoteOffer, offer)
	}
	if err != nil {
		return err
	}
	if !prackAnsweredOffer && !provisionalAnswer {
		c.mu.Lock()
		c.media = media
		c.mu.Unlock()
	}
	if c.delayedOffer && prackAnsweredOffer {
		// Media was opened after the PRACK SDP answer.
	} else if c.delayedOffer {
		if err := c.prepareMedia(ctx); err != nil {
			return err
		}
	} else {
		if err := c.openMedia(ctx); err != nil {
			return err
		}
		c.startMediaInactivityWatch()
	}
	c.stopRingingTimer()
	return c.writeInviteOK(ctx, answer)
}

func (c *Call) Reject(ctx context.Context, code int, reason string) error {
	if code == 0 {
		code = sipStatusBusyHere
	}
	if reason == "" {
		reason = "Busy Here"
	}
	c.mu.Lock()
	if c.direction != CallDirectionIncoming {
		c.mu.Unlock()
		return errors.New("rejecting call: call is not incoming")
	}
	if c.state != CallStateRinging {
		c.mu.Unlock()
		return fmt.Errorf("rejecting call: call state is %s", c.state)
	}
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("rejecting call: incoming request is missing")
	}
	req := *c.incomingRequest
	c.mu.Unlock()
	c.stopRingingTimer()
	if err := c.endpoint.writeStatus(ctx, req, code, reason); err != nil {
		return fmt.Errorf("rejecting call: %w", err)
	}
	c.finish(CallStateEnded, reason)
	return nil
}

func (c *Call) Hangup(ctx context.Context) error {
	c.mu.Lock()
	state := c.state
	direction := c.direction
	c.mu.Unlock()

	if direction == CallDirectionIncoming && state == CallStateRinging {
		return c.Reject(ctx, sipStatusBusyHere, "Busy Here")
	}
	if direction == CallDirectionOutgoing && (state == CallStateDialing || state == CallStateRinging || state == CallStateEarlyMedia) {
		return c.cancelOutgoingInvite(ctx)
	}
	if state == CallStateEnding || state == CallStateEnded {
		return nil
	}
	if state != CallStateActive && state != CallStateConfirmed {
		return fmt.Errorf("hanging up call: call state is %s", state)
	}
	c.setState(CallStateEnding, "")
	_ = c.closeMedia()
	resp, err := c.endpoint.sess.Exchange(ctx, c.buildBYE(reasonUserTriggered))
	if !byeReleaseCompleted(resp, err) {
		err := byeReleaseError(callActionHangUp, resp, err)
		c.finish(CallStateFailed, err.Error())
		return err
	}
	c.finish(CallStateEnded, "")
	return nil
}

func byeReleaseCompleted(resp sip.Message, err error) bool {
	if err != nil {
		return errors.Is(err, context.DeadlineExceeded)
	}
	code := resp.StatusCode()
	return (code >= sipStatusOK && code < sipStatusMultipleChoices) || code == sipStatusRequestTimeout || code == sipStatusCallTransactionDoesNotExist
}

func byeReleaseError(action callAction, resp sip.Message, err error) error {
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	return fmt.Errorf("%s: expected BYE termination response, got %w", action, sip.NewResponseError(resp))
}

func (c *Call) releaseAcknowledgedInviteFailure(err error, reason string) {
	_ = c.closeMedia()
	releaseCtx, cancel := c.endpoint.timeoutContext(callReleaseTimeout)
	defer cancel()

	resp, releaseErr := c.endpoint.sess.Exchange(releaseCtx, c.buildBYE(reason))
	if !byeReleaseCompleted(resp, releaseErr) {
		c.endpoint.emitError(byeReleaseError(callActionReleaseAcknowledgedFailure, resp, releaseErr))
	}
	c.finish(CallStateFailed, err.Error())
}

func (c *Call) cancelOutgoingInvite(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	if c.direction != CallDirectionOutgoing || (c.state != CallStateDialing && c.state != CallStateRinging && c.state != CallStateEarlyMedia) {
		state := c.state
		c.mu.Unlock()
		return fmt.Errorf("cancelling call: call state is %s", state)
	}
	if !c.inviteResponse {
		c.cancelOnResponse = true
		c.mu.Unlock()
		c.stopRingbackTimer()
		c.setState(CallStateEnding, "cancelled")
		_ = c.closeMedia()
		return nil
	}
	if c.cancelSent {
		c.mu.Unlock()
		return nil
	}
	c.cancelSent = true
	snap := c.dialogSnapshot()
	c.mu.Unlock()

	cancel := snap.buildCANCEL(reasonUserTriggered)
	c.setState(CallStateEnding, "cancelled")
	c.stopRingbackTimer()
	_ = c.closeMedia()
	return c.exchangeCancel(ctx, cancel)
}

func (c *Call) exchangeCancel(ctx context.Context, cancel sip.Message) error {
	resp, err := c.endpoint.sess.Exchange(ctx, cancel)
	if err != nil {
		return fmt.Errorf("cancelling call: %w", err)
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		return fmt.Errorf("cancelling call: expected 2xx, got %w", sip.NewResponseError(resp))
	}
	return nil
}

func (c *Call) setState(state CallState, cause string) {
	c.mu.Lock()
	if c.state == state && cause == "" {
		c.mu.Unlock()
		return
	}
	if !callCanTransition(c.state, state) {
		from := c.state
		id := c.id
		c.mu.Unlock()
		c.endpoint.logger.Warn("ignoring invalid call state transition", "call_id", id, "from", from, "to", state, "cause", cause)
		return
	}
	c.state = state
	id := c.id
	hold := normalizeHoldState(c.hold)
	c.mu.Unlock()
	c.endpoint.emit(CallEvent{Call: c, CallID: id, State: state, Hold: hold, Cause: cause, At: time.Now()})
}

func callCanTransition(from, to CallState) bool {
	if from == "" || from == to {
		return true
	}
	if from == CallStateEnded || from == CallStateFailed {
		return false
	}
	if to == CallStateEnded || to == CallStateFailed {
		return true
	}
	switch from {
	case CallStateDialing:
		return to == CallStateRinging || to == CallStateEarlyMedia || to == CallStateConfirmed || to == CallStateEnding
	case CallStateRinging:
		return to == CallStateEarlyMedia || to == CallStateAnswering || to == CallStateConfirmed || to == CallStateActive || to == CallStateEnding
	case CallStateEarlyMedia:
		return to == CallStateRinging || to == CallStateConfirmed || to == CallStateActive || to == CallStateEnding
	case CallStateAnswering:
		return to == CallStateActive || to == CallStateEnding
	case CallStateConfirmed:
		return to == CallStateActive || to == CallStateEnding
	case CallStateActive:
		return to == CallStateEnding
	case CallStateEnding:
		return false
	default:
		return true
	}
}

func (c *Call) finish(state CallState, cause string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	id := c.id
	emit := c.state != state || cause != ""
	c.state = state
	hold := normalizeHoldState(c.hold)
	attachment := c.dialogAttachment
	stop := c.inviteOKStop
	ringbackStop := c.ringbackStop
	ringingStop := c.ringingStop
	mediaStop := c.mediaWatchStop
	reliableStop := c.reliableStop
	sessionTimerStop := c.sessionTimerStop
	provisionalReady := c.provisionalReady
	c.inviteOKStop = nil
	c.inviteOKCSeq = 0
	c.ringbackStop = nil
	c.ringingStop = nil
	c.mediaActivity = nil
	c.mediaWatchStop = nil
	c.reliableStop = nil
	c.sessionTimerStop = nil
	c.provisionalReady = nil
	c.dialogAttachment = nil
	c.mu.Unlock()

	if stop != nil {
		close(stop)
	}
	if ringbackStop != nil {
		close(ringbackStop)
	}
	if ringingStop != nil {
		close(ringingStop)
	}
	if mediaStop != nil {
		close(mediaStop)
	}
	if reliableStop != nil {
		close(reliableStop)
	}
	if sessionTimerStop != nil {
		close(sessionTimerStop)
	}
	if provisionalReady != nil {
		close(provisionalReady)
	}
	if attachment != nil {
		_ = attachment.Close()
	}
	_ = c.closeMedia()
	c.endpoint.removeCall(id)
	if emit {
		c.endpoint.emit(CallEvent{Call: c, CallID: id, State: state, Hold: hold, Cause: cause, At: time.Now()})
	}
}

const sipTransactionTimeoutMultiplier = 64

func resetTimer(timer *time.Timer, timeout time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(timeout)
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

	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		timers := c.endpoint.timers
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
				if err := c.endpoint.sess.WriteResponse(ctx, req, resp); err != nil {
					c.endpoint.emitError(fmt.Errorf("retransmitting call 200 OK: %w", err))
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

	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		timers := c.endpoint.timers
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
				if err := c.endpoint.writeStatus(ctx, req, sipStatusServerInternalError, "Reliable Response Timed Out"); err != nil {
					c.endpoint.emitError(fmt.Errorf("rejecting INVITE after PRACK timeout: %w", err))
				}
				cancel()
				c.finish(CallStateFailed, "prack timeout")
				return
			case <-timer.C:
				ctx, cancel := contextWithDoneTimeout(done, min(inviteOKWriteTimeout, interval))
				if err := c.endpoint.sess.WriteResponse(ctx, req, resp); err != nil {
					c.endpoint.emitError(fmt.Errorf("retransmitting reliable provisional response: %w", err))
				}
				cancel()
				interval = nextReliableProvisionalRetransmitInterval(interval)
				timer.Reset(interval)
			}
		}
	})
}

func (c *Call) startRingbackTimer() {
	timeout := c.endpoint.cfg.RingbackTimeout
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

	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
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
				c.endpoint.emitError(fmt.Errorf("ringback timeout: %w", err))
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
	timeout := c.endpoint.cfg.RingingTimeout
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

	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
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
	if err := c.endpoint.writeStatus(ctx, req, sipStatusBusyHere, "Busy Here"); err != nil {
		c.endpoint.emitError(fmt.Errorf("ringing timeout: %w", err))
		c.finish(CallStateFailed, err.Error())
		return
	}
	c.finish(CallStateEnded, "ringing timeout")
}
