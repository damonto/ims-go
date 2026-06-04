package voice

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) refreshSession() {
	c.mu.Lock()
	if c.closed || !c.sessionTimer.active || !c.sessionTimer.localRefresher {
		c.mu.Unlock()
		return
	}
	timer := c.sessionTimer
	snap := c.dialogSnapshot()
	c.mu.Unlock()

	req := snap.buildSessionRefreshRequest(c.nextCSeq(), timer)
	clearLocalINVITEPending := c.markLocalINVITEPending(req.Method())
	defer clearLocalINVITEPending()

	ctx, cancel := c.service.backgroundContext()
	defer cancel()

	resp, err := c.exchangeSessionRefresh(ctx, req)
	if err == nil && resp.StatusCode() == sipStatusSessionIntervalTooSmall {
		resp, err = c.retrySessionRefreshWithMinSE(ctx, req, resp)
	}
	if err != nil {
		c.service.emitError(fmt.Errorf("refreshing session timer: %w", err))
		c.terminateAfterSessionRefreshFailure()
		return
	}
	switch {
	case resp.StatusCode() >= sipStatusOK && resp.StatusCode() < sipStatusMultipleChoices:
		if req.Method() == "INVITE" {
			if err := c.acknowledgeSessionRefreshINVITE(ctx, resp); err != nil {
				c.service.emitError(err)
				c.terminateAfterSessionRefreshFailure()
				return
			}
			c.updateRemoteTargetFromResponse(resp)
			if err := c.applySessionRefreshINVITEAnswer(resp); err != nil {
				c.service.emitError(err)
				c.terminateAfterSessionRefreshFailure()
				return
			}
		} else {
			c.updateRemoteAllow(resp)
		}
		if err := c.applySessionTimerUACResponse(resp, false); err != nil {
			c.service.emitError(err)
			c.terminateAfterSessionRefreshFailure()
		}
	case resp.StatusCode() == sipStatusRequestTimeout || resp.StatusCode() == sipStatusCallTransactionDoesNotExist:
		c.terminateAfterSessionRefreshFailure()
	default:
		c.service.emitError(fmt.Errorf("refreshing session timer: expected 2xx, got %w", sip.NewResponseError(resp)))
		c.terminateAfterSessionRefreshFailure()
	}
}

func (c *Call) exchangeSessionRefresh(ctx context.Context, req sip.Message) (sip.Message, error) {
	ctx, cancel := context.WithTimeout(ctx, c.service.timers.TF+c.service.timers.T1)
	defer cancel()
	resp, err := c.service.sess.Exchange(ctx, req)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) {
			return sip.Message{}, err
		}
		return sip.Message{}, fmt.Errorf("sending %s session refresh: %w", req.Method(), err)
	}
	return resp, nil
}

func (c *Call) retrySessionRefreshWithMinSE(ctx context.Context, req sip.Message, resp sip.Message) (sip.Message, error) {
	minSE, ok := parseMinSessionSeconds(resp.Header("Min-SE"))
	if !ok {
		return sip.Message{}, fmt.Errorf("session timer retry: invalid Min-SE %q", resp.Header("Min-SE"))
	}
	retry := req
	retry.Headers = req.Headers.Clone()
	retry.Body = append([]byte(nil), req.Body...)
	retry.Headers.Set("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), c.service.reg.State().ContactHost, c.service.reg.State().MessagePort, sip.RandomAlphaNum(15)))
	retry.Headers.Set("CSeq", fmt.Sprintf("%d %s", c.nextCSeq(), req.Method()))
	retry.Headers.Set("Min-SE", strconv.Itoa(minSE))
	if sessionExpires, ok := parseSessionExpiresHeader(retry.Header("Session-Expires")); ok {
		if sessionExpires.seconds < minSE {
			sessionExpires.seconds = minSE
			retry.Headers.Set("Session-Expires", sessionExpires.String())
		}
	}
	c.mu.Lock()
	if c.sessionTimer.minSE < minSE {
		c.sessionTimer.minSE = minSE
	}
	c.mu.Unlock()
	return c.exchangeSessionRefresh(ctx, retry)
}

func (c *Call) acknowledgeSessionRefreshINVITE(ctx context.Context, resp sip.Message) error {
	c.mu.Lock()
	snap := c.dialogSnapshot()
	c.mu.Unlock()
	ack := snap.buildACKForSessionRefreshINVITE(resp)
	ctx, cancel := context.WithTimeout(ctx, callReleaseTimeout)
	defer cancel()
	if err := c.service.sess.Send(ctx, ack); err != nil {
		return fmt.Errorf("acknowledging session refresh re-INVITE: %w", err)
	}
	return nil
}

func (c *Call) applySessionRefreshINVITEAnswer(resp sip.Message) error {
	body, ok := sdpBody(resp)
	if !ok {
		return errors.New("refreshing session timer: missing re-INVITE SDP answer")
	}
	answer, err := parseSDP(body)
	if err != nil {
		return fmt.Errorf("refreshing session timer: parsing re-INVITE SDP answer: %w", err)
	}
	negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
	if !ok {
		return errors.New("refreshing session timer: no compatible re-INVITE answer codec")
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.service.cfg.Codecs, negotiated.ClockRate)
	c.mu.Lock()
	current := c.media
	c.media = negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, current.PTime), dtmf, hasDTMF)
	c.mu.Unlock()

	ctx, cancel := c.service.timeoutContext(callReleaseTimeout)
	defer cancel()
	if err := c.openMedia(ctx); err != nil {
		return fmt.Errorf("refreshing session timer: %w", err)
	}
	c.restartMediaInactivityWatch()
	return nil
}
