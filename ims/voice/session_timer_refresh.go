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
		resp, err = c.retrySessionRefreshesWithMinSE(ctx, req, resp)
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

func (c *Call) retrySessionRefreshesWithMinSE(ctx context.Context, req sip.Message, resp sip.Message) (sip.Message, error) {
	for resp.StatusCode() == sipStatusSessionIntervalTooSmall {
		minSE, ok := parseMinSessionSeconds(resp.Header("Min-SE"))
		if !ok {
			return sip.Message{}, fmt.Errorf("session timer retry: invalid Min-SE %q", resp.Header("Min-SE"))
		}
		c.mu.Lock()
		if c.sessionTimer.minSE < minSE {
			c.sessionTimer.minSE = minSE
		}
		retryMinSE := max(minSE, c.sessionTimer.minSE)
		c.mu.Unlock()
		if retryMinSE <= requestMinSessionExpiresSeconds(req) {
			return resp, nil
		}
		retry := c.sessionRefreshRetryRequest(req, retryMinSE)
		next, err := c.exchangeSessionRefresh(ctx, retry)
		if err != nil {
			return sip.Message{}, err
		}
		req = retry
		resp = next
	}
	return resp, nil
}

func requestMinSessionExpiresSeconds(req sip.Message) int {
	if minSE, ok := parseMinSessionSeconds(req.Header("Min-SE")); ok {
		return minSE
	}
	return durationSeconds(defaultMinSessionExpires)
}

func (c *Call) sessionRefreshRetryRequest(req sip.Message, minSE int) sip.Message {
	retry := req
	retry.Headers = req.Headers.Clone()
	retry.Body = append([]byte(nil), req.Body...)
	state := c.service.reg.State()
	retry.Headers.Set("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	retry.Headers.Set("CSeq", fmt.Sprintf("%d %s", c.nextCSeq(), req.Method()))
	retry.Headers.Set("Min-SE", strconv.Itoa(minSE))
	sessionExpires, ok := parseSessionExpiresHeader(retry.Header("Session-Expires"))
	if !ok {
		sessionExpires = sessionExpiresHeader{
			seconds:   max(durationSeconds(defaultSessionExpires), minSE),
			refresher: sessionRefresherUAC,
		}
	}
	if sessionExpires.seconds < minSE {
		sessionExpires.seconds = minSE
	}
	if sessionExpires.refresher == "" {
		sessionExpires.refresher = sessionRefresherUAC
	}
	retry.Headers.Set("Session-Expires", sessionExpires.String())
	return retry
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
