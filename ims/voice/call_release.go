package voice

import (
	"context"
	"errors"
	"fmt"

	"github.com/damonto/vowifi-go/ims/sip"
)

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
	releaseCtx, cancel := c.service.timeoutContext(callReleaseTimeout)
	defer cancel()

	resp, releaseErr := c.service.sess.Exchange(releaseCtx, c.buildBYE(reason))
	if !byeReleaseCompleted(resp, releaseErr) {
		c.service.emitError(byeReleaseError(callActionReleaseAcknowledgedFailure, resp, releaseErr))
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
	resp, err := c.service.sess.Exchange(ctx, cancel)
	if err != nil {
		return fmt.Errorf("cancelling call: %w", err)
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		return fmt.Errorf("cancelling call: expected 2xx, got %w", sip.NewResponseError(resp))
	}
	return nil
}
