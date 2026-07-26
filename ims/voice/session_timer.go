package voice

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

type incomingUPDATEFollowup struct {
	offer         sdpOffer
	media         NegotiatedMedia
	early         bool
	inviteRequest *session.Request
}

func (c *Call) handleSessionRefresh(ctx context.Context, req session.Request) error {
	if c.endpoint.unsupportedRequiredTimer(req.Message) {
		return c.endpoint.writeUnsupportedRequired(ctx, req, sessionTimerOption)
	}
	if invalidSessionTimerRefresher(req.Message) {
		return c.endpoint.writeStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	c.rememberSessionTimerMinSE(req.Message)
	if minSE, tooSmall := incomingSessionTimerTooSmall(req.Message, c.endpoint.cfg); tooSmall {
		return c.endpoint.writeSessionIntervalTooSmall(ctx, req, minSE)
	}
	answer, media, hold, ok, err := c.sessionRefreshAnswer(req.Message)
	if err != nil {
		body, _ := sdpBody(req.Message)
		return c.endpoint.writeSDPFailure(ctx, req, body, err)
	}
	if ok {
		c.mu.Lock()
		c.media = media
		c.mu.Unlock()
		if err := c.openMedia(ctx); err != nil {
			return c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
		c.restartMediaInactivityWatch()
		c.setHoldState(hold, callActionRemoteSessionModification)
	}
	resp := c.buildSessionRefreshOK(req.Message)
	if len(answer) != 0 {
		resp.Headers.Add("Content-Type", "application/sdp")
		if c.sdpConfig().Preconditions && sdpUsesPreconditions(answer) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
		resp.Body = answer
	}
	var followup *incomingUPDATEFollowup
	if len(answer) != 0 {
		c.mu.Lock()
		c.localSDP = append([]byte(nil), answer...)
		c.mu.Unlock()
		followup = c.updateIncomingPreconditions(req.Message, media)
	}
	if err := c.endpoint.sess.WriteResponse(ctx, req, resp); err != nil {
		c.discardIncomingUPDATEFollowup(followup)
		return fmt.Errorf("handling session refresh: %w", err)
	}
	c.updateRemoteTargetFromRequest(req.Message)
	if err := c.applySessionTimerUASResponse(resp); err != nil {
		c.discardIncomingUPDATEFollowup(followup)
		return err
	}
	if followup != nil {
		if !c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
			c.completeIncomingUPDATE(done, *followup)
		}) {
			c.discardIncomingUPDATEFollowup(followup)
			return errors.New("handling session refresh: starting precondition confirmation")
		}
	}
	if err := c.tryAlertIncoming(ctx); err != nil {
		return err
	}
	return nil
}

func (c *Call) handleReINVITE(ctx context.Context, req session.Request) error {
	if handled, err := c.handleReINVITEGlare(ctx, req); handled || err != nil {
		return err
	}
	defer c.clearRemoteINVITEPending()

	if c.endpoint.unsupportedRequiredTimer(req.Message) {
		return c.endpoint.writeUnsupportedRequired(ctx, req, sessionTimerOption)
	}
	if invalidSessionTimerRefresher(req.Message) {
		return c.endpoint.writeStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	c.rememberSessionTimerMinSE(req.Message)
	if minSE, tooSmall := incomingSessionTimerTooSmall(req.Message, c.endpoint.cfg); tooSmall {
		return c.endpoint.writeSessionIntervalTooSmall(ctx, req, minSE)
	}
	answer, media, hold, ok, err := c.sessionRefreshAnswer(req.Message)
	if err != nil {
		body, _ := sdpBody(req.Message)
		return c.endpoint.writeSDPFailure(ctx, req, body, err)
	}
	if ok {
		c.mu.Lock()
		c.media = media
		c.mu.Unlock()
		if err := c.openMedia(ctx); err != nil {
			return c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
		c.restartMediaInactivityWatch()
		c.setHoldState(hold, callActionRemoteSessionModification)
	}
	resp := c.buildSessionRefreshOK(req.Message)
	if len(answer) != 0 {
		cfg := c.sdpConfig()
		if err := setInviteResponseBody(&resp, cfg, c.localURI, false, answer); err != nil {
			return err
		}
		if cfg.Preconditions && sdpUsesPreconditions(answer) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
	}
	if err := c.endpoint.sess.WriteResponse(ctx, req, resp); err != nil {
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

func (c *Call) terminateAfterSessionRefreshFailure() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	c.expireUnrefreshedSession()
}

func (c *Call) expireUnrefreshedSession() {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	ctx, cancel := c.endpoint.timeoutContext(callReleaseTimeout)
	defer cancel()
	c.setState(CallStateEnding, "session timer expired")
	_ = c.closeMedia()
	resp, err := c.endpoint.sess.Exchange(ctx, c.buildBYE(""))
	if !byeReleaseCompleted(resp, err) {
		err := byeReleaseError(callActionExpireSessionTimer, resp, err)
		c.finish(CallStateFailed, err.Error())
		c.endpoint.emitError(err)
		return
	}
	c.finish(CallStateEnded, "session timer expired")
}

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

	ctx, cancel := c.endpoint.backgroundContext()
	defer cancel()

	resp, err := c.exchangeSessionRefresh(ctx, req)
	if err == nil && resp.StatusCode() == sipStatusSessionIntervalTooSmall {
		resp, err = c.retrySessionRefreshesWithMinSE(ctx, req, resp)
	}
	if err != nil {
		c.endpoint.emitError(fmt.Errorf("refreshing session timer: %w", err))
		c.terminateAfterSessionRefreshFailure()
		return
	}
	switch {
	case resp.StatusCode() >= sipStatusOK && resp.StatusCode() < sipStatusMultipleChoices:
		c.mu.Lock()
		c.refreshGlareRetried = false
		c.mu.Unlock()
		if req.Method() == "INVITE" {
			if err := c.acknowledgeSessionRefreshINVITE(ctx, resp); err != nil {
				c.endpoint.emitError(err)
				c.terminateAfterSessionRefreshFailure()
				return
			}
			c.updateRemoteTargetFromResponse(resp)
			if err := c.applySessionRefreshINVITEAnswer(resp); err != nil {
				c.endpoint.emitError(err)
				c.terminateAfterSessionRefreshFailure()
				return
			}
		} else {
			c.updateRemoteAllow(resp)
		}
		if err := c.applySessionTimerUACResponse(resp, false); err != nil {
			c.endpoint.emitError(err)
			c.terminateAfterSessionRefreshFailure()
		}
	case resp.StatusCode() == sipStatusRequestTimeout || resp.StatusCode() == sipStatusCallTransactionDoesNotExist:
		c.terminateAfterSessionRefreshFailure()
	case resp.StatusCode() == sipStatusRequestPending && req.Method() == "INVITE":
		if c.markSessionRefreshGlareRetry() {
			c.retrySessionRefreshAfterGlare()
			return
		}
		c.endpoint.emitError(fmt.Errorf("refreshing session timer: repeated 491 response: %w", sip.NewResponseError(resp)))
	default:
		c.endpoint.emitError(fmt.Errorf("refreshing session timer: expected 2xx, got %w", sip.NewResponseError(resp)))
		c.terminateAfterSessionRefreshFailure()
	}
}

func (c *Call) markSessionRefreshGlareRetry() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.refreshGlareRetried {
		return false
	}
	c.refreshGlareRetried = true
	return true
}

func (c *Call) retrySessionRefreshAfterGlare() {
	ownerDelay := time.Duration(2100+rand.Int64N(1901)) * time.Millisecond
	if c.Direction() == CallDirectionIncoming {
		ownerDelay = time.Duration(rand.Int64N(2001)) * time.Millisecond
	}
	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		timer := time.NewTimer(ownerDelay)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-timer.C:
		}
		c.mu.Lock()
		if c.closed || c.state == CallStateEnding || c.state == CallStateEnded || c.state == CallStateFailed {
			c.mu.Unlock()
			return
		}
		c.mu.Unlock()
		c.refreshSession()
	})
}

func (c *Call) exchangeSessionRefresh(ctx context.Context, req sip.Message) (sip.Message, error) {
	ctx, cancel := context.WithTimeout(ctx, c.endpoint.timers.TF+c.endpoint.timers.T1)
	defer cancel()
	resp, err := c.endpoint.sess.Exchange(ctx, req)
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

		c.sessionTimer.minSE = max(c.sessionTimer.minSE, minSE)
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
	state := c.endpoint.reg.State()
	retry.Headers.Set("Via", sip.BuildVia(sip.TransportToken(c.endpoint.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	retry.Headers.Set("CSeq", fmt.Sprintf("%d %s", c.nextCSeq(), req.Method()))
	retry.Headers.Set("Min-SE", strconv.Itoa(minSE))
	sessionExpires, ok := parseSessionExpiresHeader(retry.Header("Session-Expires"))
	if !ok {
		sessionExpires = sessionExpiresHeader{
			seconds:   max(durationSeconds(defaultSessionExpires), minSE),
			refresher: sessionRefresherUAC,
		}
	}

	sessionExpires.seconds = max(sessionExpires.seconds, minSE)

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
	if err := c.endpoint.sess.Send(ctx, ack); err != nil {
		return fmt.Errorf("acknowledging session refresh re-INVITE: %w", err)
	}
	return nil
}

func (c *Call) applySessionRefreshINVITEAnswer(resp sip.Message) error {
	body, ok := sdpBody(resp)
	if !ok {
		return errors.New("refreshing session timer: missing re-INVITE SDP answer")
	}
	var answer sdpOffer
	if err := answer.UnmarshalBinary(body); err != nil {
		return fmt.Errorf("refreshing session timer: parsing re-INVITE SDP answer: %w", err)
	}
	negotiated, ok := chooseCodec(answer, c.endpoint.cfg.Codecs)
	if !ok {
		return errors.New("refreshing session timer: no compatible re-INVITE answer codec")
	}
	if err := c.acceptRemotePayloadMappings(answer); err != nil {
		return fmt.Errorf("refreshing session timer: invalid re-INVITE SDP answer: %w", err)
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.endpoint.cfg.Codecs, negotiated.ClockRate)
	c.mu.Lock()
	current := c.media
	c.media = negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, current.PTime), nonZeroDuration(answer.MaxPTime, current.MaxPTime, c.endpoint.cfg.MaxPTime), dtmf, hasDTMF)
	c.mu.Unlock()

	ctx, cancel := c.endpoint.timeoutContext(callReleaseTimeout)
	defer cancel()
	if err := c.openMedia(ctx); err != nil {
		return fmt.Errorf("refreshing session timer: %w", err)
	}
	c.restartMediaInactivityWatch()
	return nil
}

func (c *Call) applySessionTimerUACResponse(resp sip.Message, allowFallback bool) error {
	return c.applySessionTimerResponse(resp, true, allowFallback)
}

func (c *Call) applySessionTimerUASResponse(resp sip.Message) error {
	return c.applySessionTimerResponse(resp, false, false)
}

func (c *Call) applySessionTimerResponse(resp sip.Message, localWasUAC bool, allowUACFallback bool) error {
	value := resp.Header("Session-Expires")
	if value == "" {
		if tokenHeaderContains(resp, "Require", sessionTimerOption) {
			return errors.New("handling session timer: Require timer without Session-Expires")
		}
		if allowUACFallback {
			timer, ok := c.localSessionTimerFallback(localWasUAC)
			if !ok {
				c.stopSessionTimer()
				return nil
			}
			c.replaceSessionTimer(timer)
			return nil
		}
		c.stopSessionTimer()
		return nil
	}
	h, ok := parseSessionExpiresHeader(value)
	if !ok || h.refresher == "" {
		return fmt.Errorf("handling session timer: invalid Session-Expires %q", value)
	}
	interval := time.Duration(h.seconds) * time.Second
	if interval < defaultMinSessionExpires {
		return fmt.Errorf("handling session timer: Session-Expires %q is below %s", value, defaultMinSessionExpires)
	}
	localRefresher := h.refresher == sessionRefresherUAC
	if !localWasUAC {
		localRefresher = h.refresher == sessionRefresherUAS
	}
	timer := sessionTimerState{
		active:         true,
		interval:       interval,
		minSE:          durationSeconds(defaultMinSessionExpires),
		localRefresher: localRefresher,
	}
	c.mu.Lock()

	timer.minSE = max(timer.minSE, c.sessionTimer.minSE)

	c.mu.Unlock()
	c.replaceSessionTimer(timer)
	return nil
}

func (c *Call) localSessionTimerFallback(localWasUAC bool) (sessionTimerState, bool) {
	if !localWasUAC || !c.endpoint.cfg.SessionTimer {
		return sessionTimerState{}, false
	}
	c.mu.Lock()
	current := c.sessionTimer
	c.mu.Unlock()
	if current.active {
		return sessionTimerState{}, false
	}
	if strings.TrimSpace(c.inviteRequest.Header("Session-Expires")) == "" {
		return sessionTimerState{}, false
	}
	seconds := sessionExpiresSeconds(c.endpoint.cfg, c.inviteRequest)
	timer := sessionTimerState{
		active:         true,
		interval:       time.Duration(seconds) * time.Second,
		minSE:          durationSeconds(defaultMinSessionExpires),
		localRefresher: true,
	}

	timer.minSE = max(timer.minSE, current.minSE)

	if timer.minSE > seconds {
		timer.interval = time.Duration(timer.minSE) * time.Second
	}
	return timer, true
}

func (c *Call) stopSessionTimer() {
	c.mu.Lock()
	stop := c.sessionTimerStop
	c.sessionTimerStop = nil
	c.sessionTimer = sessionTimerState{}
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (c *Call) replaceSessionTimer(timer sessionTimerState) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	old := c.sessionTimerStop
	stop := make(chan struct{})
	c.sessionTimer = timer
	c.sessionTimerStop = stop
	c.mu.Unlock()

	if old != nil {
		close(old)
	}
	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		c.runSessionTimer(timer, stop, done)
	})
}

func (c *Call) runSessionTimer(timer sessionTimerState, stop, done <-chan struct{}) {
	delay := sessionRefreshDelay(timer)
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-done:
		return
	case <-stop:
		return
	case <-t.C:
	}
	if timer.localRefresher {
		c.refreshSession()
		return
	}
	c.expireUnrefreshedSession()
}

func sessionRefreshDelay(timer sessionTimerState) time.Duration {
	if timer.localRefresher {
		return timer.interval / 2
	}
	beforeExpiration := min(32*time.Second, timer.interval/3)
	delay := timer.interval - beforeExpiration
	if delay <= 0 {
		return timer.interval / 2
	}
	return delay
}

func (c *Call) handleReINVITEGlare(ctx context.Context, req session.Request) (bool, error) {
	cseq := sip.CSeqNumber(req.Message.Header("CSeq"))
	c.mu.Lock()
	switch {
	case c.localINVITEPending:
		c.mu.Unlock()
		return true, c.endpoint.writeStatus(ctx, req, sipStatusRequestPending, "Request Pending")
	case c.remoteINVITEPending:
		c.mu.Unlock()
		return true, c.endpoint.writeRetryAfter(ctx, req, sipStatusServerInternalError, "Server Internal Error", rand.IntN(11))
	default:
		c.remoteINVITEPending = true
		c.remoteINVITECSeq = cseq
		c.mu.Unlock()
		return false, nil
	}
}

func (c *Call) clearRemoteINVITEPending() {
	c.mu.Lock()
	c.remoteINVITEPending = false
	c.remoteINVITECSeq = 0
	c.mu.Unlock()
}

func (c *Call) markLocalINVITEPending(method string) func() {
	if method != "INVITE" {
		return func() {}
	}
	c.mu.Lock()
	c.localINVITEPending = true
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		c.localINVITEPending = false
		c.mu.Unlock()
	}
}

func (c *Call) sessionRefreshAnswer(msg sip.Message) ([]byte, NegotiatedMedia, CallHoldState, bool, error) {
	if len(msg.Body) == 0 {
		return nil, NegotiatedMedia{}, "", false, nil
	}
	body, ok := sdpBody(msg)
	if !ok {
		return nil, NegotiatedMedia{}, "", false, errors.New("handling re-INVITE: missing SDP offer")
	}
	var offer sdpOffer
	if err := offer.UnmarshalBinary(body); err != nil {
		return nil, NegotiatedMedia{}, "", false, err
	}
	c.mu.Lock()
	localPort := c.localPort
	currentHold := c.hold
	c.mu.Unlock()
	direction := answerDirection(offer.Direction, holdHasLocal(currentHold))
	cfg := c.sdpConfig()
	answer, media, err := buildSDPAnswerWithState(cfg, c.endpoint.localIP(), localPort, offer, MediaOffer{}, sdpAnswerState{
		direction:      direction,
		localQoSStatus: qosStatusNone,
	})
	if err != nil {
		return nil, NegotiatedMedia{}, "", false, err
	}
	if localQoSStatus := c.confirmedQoSStatus(media); localQoSStatus != qosStatusNone {
		answer, media, err = buildSDPAnswerWithState(cfg, c.endpoint.localIP(), localPort, offer, MediaOffer{}, sdpAnswerState{
			direction:      direction,
			localQoSStatus: localQoSStatus,
		})
		if err != nil {
			return nil, NegotiatedMedia{}, "", false, err
		}
	}
	if err := c.acceptRemotePayloadMappings(offer); err != nil {
		return nil, NegotiatedMedia{}, "", false, fmt.Errorf("handling re-INVITE: %w", err)
	}
	return answer, media, setRemoteHold(currentHold, remoteHoldFromDirection(offer.Direction)), true, nil
}

func (c *Call) updateIncomingPreconditions(msg sip.Message, media NegotiatedMedia) *incomingUPDATEFollowup {
	body, ok := sdpBody(msg)
	if !ok {
		return nil
	}
	var offer sdpOffer
	if offer.UnmarshalBinary(body) != nil {
		return nil
	}
	c.mu.Lock()
	c.remoteOffer = offer
	c.remoteSDP = append([]byte(nil), body...)
	if c.direction != CallDirectionIncoming || !c.preconditions || !offer.Preconditions {
		c.mu.Unlock()
		return nil
	}
	c.incomingQoS = incomingQoSState{
		desired:      answerQoSDesiredStatus(offer.DesiredQoS),
		remoteStatus: invertQoSStatus(offer.LocalQoSStatus),
	}
	c.incomingUnknown = incomingUnknownPreconditions(offer)
	early := c.state == CallStateRinging && !c.incomingAlerted
	if early {
		c.incomingConfirmations++
	}
	followup := &incomingUPDATEFollowup{
		offer:         offer,
		media:         cloneNegotiatedMedia(media),
		early:         early,
		inviteRequest: c.incomingRequest,
	}
	c.mu.Unlock()
	return followup
}

func (c *Call) discardIncomingUPDATEFollowup(followup *incomingUPDATEFollowup) {
	if followup == nil || !followup.early {
		return
	}
	c.mu.Lock()
	if c.incomingConfirmations > 0 {
		c.incomingConfirmations--
	}
	c.mu.Unlock()
}

func (c *Call) completeIncomingUPDATE(done <-chan struct{}, followup incomingUPDATEFollowup) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if c.callDone == nil {
		c.callDone = make(chan struct{})
	}
	callDone := c.callDone
	c.mu.Unlock()
	ctx, cancel := contextWithDone(done)
	ctx, cancel = cancelContextWithDone(ctx, cancel, callDone)
	defer cancel()

	if err := c.confirmMediaResources(ctx, followup.media); err != nil {
		c.failIncomingUPDATE(ctx, followup, err)
		return
	}
	if followup.offer.RemoteQoSConfirmation {
		if err := c.sendIncomingPreconditionUPDATE(ctx, followup.offer, followup.media); err != nil {
			c.failIncomingUPDATE(ctx, followup, err)
			return
		}
	}

	if followup.early {
		c.mu.Lock()
		if c.incomingConfirmations > 0 {
			c.incomingConfirmations--
		}
		c.mu.Unlock()
	}
	if err := c.tryAlertIncoming(ctx); err != nil {
		c.endpoint.emitError(err)
		c.finish(CallStateFailed, err.Error())
	}
}

func (c *Call) failIncomingUPDATE(ctx context.Context, followup incomingUPDATEFollowup, cause error) {
	if followup.early {
		c.failIncomingMedia(ctx, followup.inviteRequest, cause, true)
		return
	}
	if !errors.Is(cause, context.Canceled) {
		c.endpoint.emitError(cause)
	}
}

func (c *Call) buildSessionRefreshOK(req sip.Message) sip.Message {
	resp := sip.NewResponse(sipStatusOK, "OK")
	resp.Headers = sip.ResponseHeaders(req, sipStatusOK)
	c.endpoint.addAccessNetworkInfo(&resp)
	resp.Headers.Add("Contact", contactValue(c.endpoint.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	addInviteOKSessionTimer(&resp, req, c.endpoint.cfg)
	return resp
}

func (c *Call) rememberSessionTimerMinSE(msg sip.Message) {
	minSE, ok := parseMinSessionSeconds(msg.Header("Min-SE"))
	if !ok {
		return
	}
	c.mu.Lock()

	c.sessionTimer.minSE = max(c.sessionTimer.minSE, minSE)

	c.mu.Unlock()
}
