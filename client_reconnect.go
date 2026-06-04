package vowifi

import (
	"context"
	"errors"
	"time"

	"github.com/damonto/vowifi-go/ims/registration"
	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
)

func (c *Client) startReconnect() bool {
	return c.state.startReconnect()
}

func (c *Client) finishReconnect() {
	c.state.finishReconnect()
}

func (c *Client) reconnect(cause error) (*activeConn, error) {
	reconnectID := c.state.nextReconnectID()
	c.recordSWUBackoff(cause, time.Now())
	if terminalReconnectError(cause) {
		return nil, cause
	}

	backoff := newReconnectBackoff(c.cfg.ReconnectDelay, c.cfg.ReconnectMaxDelay)
	registrationBackoff := newReconnectBackoff(c.cfg.IMS.RegistrationRetryBase, c.cfg.IMS.RegistrationRetryMax)
	initialDelay := c.reconnectDelay(cause, backoff, registrationBackoff)
	c.logger.Info("reconnect scheduled", "reconnect_id", reconnectID, "delay", initialDelay, "cause", cause)
	clientCtx, stopClientCtx := c.state.context(context.Background())
	defer stopClientCtx()
	if err := sleepContext(clientCtx, initialDelay); err != nil {
		return nil, err
	}

	for attempt := 1; ; attempt++ {
		c.logger.Info("reconnect attempt started", "reconnect_id", reconnectID, "attempt", attempt)
		active, err := c.connectOnce(clientCtx, true)
		if err == nil {
			c.logger.Info("reconnect attempt succeeded", "reconnect_id", reconnectID, "attempt", attempt)
			return active, nil
		}
		if clientCtx.Err() != nil {
			return nil, clientCtx.Err()
		}
		if terminalReconnectError(err) {
			return nil, err
		}

		nextDelay := c.reconnectDelay(err, backoff, registrationBackoff)
		c.logger.Warn("reconnect attempt failed", "reconnect_id", reconnectID, "attempt", attempt, "err", err, "next_delay", nextDelay)
		if err := sleepContext(clientCtx, nextDelay); err != nil {
			return nil, err
		}
	}
}

func terminalReconnectError(err error) bool {
	return swutunnel.AccessRejected(err) || swutunnel.BackoffDeactivated(err) || errors.Is(err, errSWUBackoffDeactivated)
}

func (c *Client) reconnectDelay(err error, backoff, registrationBackoff *reconnectBackoff) time.Duration {
	if swutunnel.ReactivationRequested(err) || swutunnel.PCSCFReselectionRequested(err) {
		return 0
	}
	if registration.InitialRegistrationRequired(err) {
		delay := registrationBackoff.Next()
		if retryAfter, ok := registration.RetryAfterDelay(err); ok {
			delay = max(delay, retryAfter)
		}
		if tunnelBackoff, ok := swutunnel.BackoffDelay(err); ok {
			delay = max(delay, tunnelBackoff)
		}
		return delay
	}

	delay := backoff.Next()
	if retryAfter, ok := registration.RetryAfterDelay(err); ok {
		delay = max(delay, retryAfter)
	}
	if tunnelBackoff, ok := swutunnel.BackoffDelay(err); ok {
		delay = max(delay, tunnelBackoff)
	}
	return delay
}

type reconnectBackoff struct {
	next time.Duration
	max  time.Duration
}

func newReconnectBackoff(first, maxDelay time.Duration) *reconnectBackoff {
	return &reconnectBackoff{next: first, max: maxDelay}
}

func (b *reconnectBackoff) Next() time.Duration {
	delay := b.next
	if delay <= 0 {
		return 0
	}
	next := delay * 2
	if next < delay || next > b.max {
		next = b.max
	}
	b.next = next
	return delay
}

func sleepContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
