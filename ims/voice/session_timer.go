package voice

import (
	"context"
	"fmt"

	"github.com/damonto/vowifi-go/ims/session"
)

func (c *Call) handleSessionRefresh(ctx context.Context, req session.Request) error {
	if c.service.unsupportedRequiredTimer(req.Message) {
		return c.service.writeUnsupportedRequired(ctx, req, sessionTimerOption)
	}
	if invalidSessionTimerRefresher(req.Message) {
		return c.service.writeStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	c.rememberSessionTimerMinSE(req.Message)
	if minSE, tooSmall := incomingSessionTimerTooSmall(req.Message, c.service.cfg); tooSmall {
		return c.service.writeSessionIntervalTooSmall(ctx, req, minSE)
	}
	answer, media, hold, ok, err := c.sessionRefreshAnswer(req.Message)
	if err != nil {
		return c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
	}
	if ok {
		c.mu.Lock()
		c.media = media
		c.mu.Unlock()
		if err := c.openMedia(ctx); err != nil {
			return c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
		c.restartMediaInactivityWatch()
		c.setHoldState(hold, callActionRemoteSessionModification)
	}
	resp := c.buildSessionRefreshOK(req.Message)
	if len(answer) != 0 {
		resp.Headers.Add("Content-Type", "application/sdp")
		if c.service.usesPreconditions(req.Message) && sdpUsesPreconditions(answer) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
		resp.Body = answer
	}
	if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
		return fmt.Errorf("handling session refresh: %w", err)
	}
	if len(answer) != 0 {
		c.mu.Lock()
		c.localSDP = append([]byte(nil), answer...)
		c.mu.Unlock()
	}
	c.updateRemoteTargetFromRequest(req.Message)
	if err := c.applySessionTimerUASResponse(resp); err != nil {
		return err
	}
	return nil
}

func (c *Call) handleReINVITE(ctx context.Context, req session.Request) error {
	if handled, err := c.handleReINVITEGlare(ctx, req); handled || err != nil {
		return err
	}
	defer c.clearRemoteINVITEPending()

	if c.service.unsupportedRequiredTimer(req.Message) {
		return c.service.writeUnsupportedRequired(ctx, req, sessionTimerOption)
	}
	if invalidSessionTimerRefresher(req.Message) {
		return c.service.writeStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	c.rememberSessionTimerMinSE(req.Message)
	if minSE, tooSmall := incomingSessionTimerTooSmall(req.Message, c.service.cfg); tooSmall {
		return c.service.writeSessionIntervalTooSmall(ctx, req, minSE)
	}
	answer, media, hold, ok, err := c.sessionRefreshAnswer(req.Message)
	if err != nil {
		return c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
	}
	if ok {
		c.mu.Lock()
		c.media = media
		c.mu.Unlock()
		if err := c.openMedia(ctx); err != nil {
			return c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
		c.restartMediaInactivityWatch()
		c.setHoldState(hold, callActionRemoteSessionModification)
	}
	resp := c.buildSessionRefreshOK(req.Message)
	if len(answer) != 0 {
		if err := setInviteResponseBody(&resp, c.service.cfg, c.localURI, false, answer); err != nil {
			return err
		}
		if c.service.usesPreconditions(req.Message) && sdpUsesPreconditions(answer) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
	}
	if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
		return fmt.Errorf("handling re-INVITE: %w", err)
	}
	c.startInviteOKRetransmit(req, resp)
	if len(answer) != 0 {
		c.mu.Lock()
		c.localSDP = append([]byte(nil), answer...)
		c.mu.Unlock()
	}
	c.updateRemoteTargetFromRequest(req.Message)
	if err := c.applySessionTimerUASResponse(resp); err != nil {
		return err
	}
	return nil
}
