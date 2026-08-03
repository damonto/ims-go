package voice

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/identity"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func (s *Endpoint) canSendReliableProvisional(msg sip.Message) bool {
	return s.cfg.ReliableProvisional &&
		(tokenHeaderContains(msg, "Supported", reliableProvisionalOption) ||
			tokenHeaderContains(msg, "Require", reliableProvisionalOption))
}

func (s *Endpoint) usesPreconditions(msg sip.Message) bool {
	return s.cfg.Preconditions &&
		(tokenHeaderContains(msg, "Supported", preconditionOption) ||
			tokenHeaderContains(msg, "Require", preconditionOption))
}

func sdpUsesPreconditions(body []byte) bool {
	lines := strings.FieldsFunc(string(body), func(r rune) bool { return r == '\n' || r == '\r' })
	for _, line := range lines {
		if isPreconditionAttribute(strings.TrimSpace(line)) {
			return true
		}
	}
	return false
}

func (s *Endpoint) unsupportedRequiredReliableProvisional(msg sip.Message) bool {
	return !s.cfg.ReliableProvisional && tokenHeaderContains(msg, "Require", reliableProvisionalOption)
}

func incomingCallerNumber(msg sip.Message) string {
	for _, header := range []string{"P-Asserted-Identity", "Remote-Party-ID", "From"} {
		for _, value := range msg.HeadersByName(header) {
			for _, part := range sip.SplitHeaderList(value) {
				if number := identity.MSISDN(part); number != "" {
					return number
				}
			}
		}
	}
	return ""
}

func (s *Endpoint) handleIncomingInvite(ctx context.Context, req session.Request) error {
	if existing := s.lookupIncoming(req.Message); existing != nil {
		existing.mu.Lock()
		resp := existing.inviteOK
		alerted := existing.incomingAlerted
		existing.mu.Unlock()
		if resp.StartLine != "" {
			return s.sess.WriteResponse(ctx, req, resp)
		}
		if resp, ok := existing.pendingReliableProvisionalResponse(); ok {
			return s.sess.WriteResponse(ctx, req, resp)
		}
		if alerted {
			return s.writeRinging(ctx, req, existing)
		}
		return s.writeStatus(ctx, req, sipStatusTrying, "Trying")
	}
	if s.unsupportedRequiredReliableProvisional(req.Message) {
		return s.writeUnsupportedRequired(ctx, req, reliableProvisionalOption)
	}
	if s.unsupportedRequiredTimer(req.Message) {
		return s.writeUnsupportedRequired(ctx, req, sessionTimerOption)
	}
	if s.unsupportedRequiredPrecondition(req.Message) {
		return s.writeUnsupportedRequired(ctx, req, preconditionOption)
	}
	if invalidSessionTimerRefresher(req.Message) {
		return s.writeStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	if minSE, tooSmall := incomingSessionTimerTooSmall(req.Message, s.cfg); tooSmall {
		return s.writeSessionIntervalTooSmall(ctx, req, minSE)
	}

	preconditions := s.usesPreconditions(req.Message)
	callCfg := s.cfg
	localPort := s.reserveRTPPort()
	localIP := s.localIP()
	var (
		offer        sdpOffer
		answerBody   []byte
		remoteBody   []byte
		media        NegotiatedMedia
		delayedOffer = len(req.Message.Body) == 0
	)
	if !delayedOffer {
		body, ok := sdpBody(req.Message)
		if !ok {
			return s.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
		remoteBody = append([]byte(nil), body...)
		if err := offer.UnmarshalText(body); err != nil {
			return s.writeSDPFailure(ctx, req, body, err)
		}
		preconditions = preconditions && (offer.Preconditions || len(offer.UnknownLocalMandatory) != 0)
		callCfg.Preconditions = preconditions
		var err error
		answerBody, media, err = buildSDPAnswer(callCfg, localIP, localPort, offer, MediaOffer{})
		if err != nil {
			return s.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
	}
	callCfg.Preconditions = preconditions

	state := s.reg.State()
	call := &Call{
		endpoint:         s,
		id:               req.Message.Header("Call-ID"),
		sessionID:        nonEmpty(req.Message.Header("Session-ID"), sip.RandomHex(32)),
		direction:        CallDirectionIncoming,
		state:            CallStateRinging,
		localURI:         nonEmpty(sip.AddressURI(req.Message.Header("To")), preferredIdentity(state)),
		localTag:         sip.ResponseTag(req.Message),
		remoteURI:        nonEmpty(sip.AddressURI(req.Message.Header("From")), sip.AddressURI(req.Message.Header("Contact"))),
		remoteTag:        sip.HeaderTag(req.Message.Header("From")),
		remoteTo:         req.Message.Header("From"),
		remoteAllow:      req.Message.Header("Allow"),
		targetURI:        nonEmpty(sip.AddressURI(req.Message.Header("Contact")), sip.AddressURI(req.Message.Header("From"))),
		routeSet:         req.Message.HeaderList("Record-Route"),
		inviteSeq:        sip.CSeqNumber(req.Message.Header("CSeq")),
		remoteCSeq:       sip.CSeqNumber(req.Message.Header("CSeq")),
		localSDP:         append([]byte(nil), answerBody...),
		localPort:        localPort,
		localQoSStatus:   qosStatusNone,
		incomingRequest:  &req,
		preconditions:    preconditions,
		incomingOffer:    mediaDescriptionFromSDP(offer),
		incomingReceived: time.Now(),
		remoteSDP:        remoteBody,
		remoteOffer:      offer,
		remotePayloads:   remotePayloadMappings(offer),
		delayedOffer:     delayedOffer,
		media:            media,
		rtcpSSRC:         randomRTCPSSRC(),
	}
	if offer.Preconditions && !delayedOffer {
		call.incomingQoS = incomingQoSState{
			desired:      answerQoSDesiredStatus(offer.DesiredQoS),
			remoteStatus: invertQoSStatus(offer.LocalQoSStatus),
		}
	}
	call.incomingUnknown = incomingUnknownPreconditions(offer)
	if err := s.storeCall(call); err != nil {
		return err
	}
	s.storeIncoming(req.Message, call)

	if err := s.writeStatus(ctx, req, sipStatusTrying, "Trying"); err != nil {
		return fmt.Errorf("handling call INVITE: sending 100 Trying: %w", err)
	}
	reliableProgress := s.canSendReliableProvisional(req.Message)
	if delayedOffer && reliableProgress {
		offerBody, offerMedia, err := buildSDPOffer(callCfg, localIP, localPort, MediaOffer{})
		if err != nil {
			call.finish(CallStateFailed, err.Error())
			return err
		}
		call.mu.Lock()
		call.media = offerMedia
		call.localSDP = append([]byte(nil), offerBody...)
		if preconditions {
			call.incomingQoS = incomingQoSState{
				desired:      defaultQoSDesiredStatus(),
				remoteStatus: qosStatusNone,
			}
		}
		call.mu.Unlock()
		if err := call.prepareMedia(ctx); err != nil {
			call.finish(CallStateFailed, err.Error())
			return err
		}
		if err := s.writeProgress(ctx, req, call, offerBody, true); err != nil {
			return fmt.Errorf("handling call INVITE: sending 183 Session Progress: %w", err)
		}
		return nil
	}

	if !delayedOffer {
		if s.cfg.PrepareMedia != nil || reliableProgress || preconditions {
			if err := s.writeProgress(ctx, req, call, answerBody, reliableProgress); err != nil {
				return fmt.Errorf("handling call INVITE: sending 183 Session Progress: %w", err)
			}
			if reliableProgress {
				return nil
			}
		}
		if !s.startBackgroundTask(func(done <-chan struct{}) {
			call.completeIncomingInitial(done, &req)
		}) {
			call.finish(CallStateFailed, "starting incoming media preparation")
			return errors.New("handling call INVITE: starting incoming media preparation")
		}
		return nil
	}

	call.mu.Lock()
	call.incomingMediaReady = true
	call.mu.Unlock()
	if err := call.tryAlertIncoming(ctx); err != nil {
		call.finish(CallStateFailed, err.Error())
		return err
	}
	return nil
}

func (c *Call) completeIncomingInitial(done <-chan struct{}, req *session.Request) {
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

	if err := c.prepareMedia(ctx); err != nil {
		c.failIncomingMedia(ctx, req, err, false)
		return
	}
	c.mu.Lock()
	media := cloneNegotiatedMedia(c.media)
	preconditions := c.preconditions
	remote := c.remoteOffer
	c.mu.Unlock()
	if preconditions || c.endpoint.cfg.WaitMediaReady != nil {
		if err := c.confirmMediaResources(ctx, media); err != nil {
			c.failIncomingMedia(ctx, req, err, preconditions)
			return
		}
	}
	if preconditions && remote.RemoteQoSConfirmation {
		if err := c.sendIncomingPreconditionUPDATE(ctx, remote, media); err != nil {
			c.failIncomingMedia(ctx, req, err, true)
			return
		}
	}
	c.mu.Lock()
	c.incomingMediaReady = true
	c.mu.Unlock()
	if err := c.tryAlertIncoming(ctx); err != nil {
		c.endpoint.emitError(err)
		c.finish(CallStateFailed, err.Error())
	}
}

func (c *Call) sdpConfig() Config {
	cfg := c.endpoint.cfg
	c.mu.Lock()
	if c.direction == CallDirectionIncoming {
		cfg.Preconditions = c.preconditions
	}
	c.mu.Unlock()
	return cfg
}

func (c *Call) incomingResourcesReadyLocked() bool {
	if !c.incomingMediaReady || c.incomingConfirmations != 0 {
		return false
	}
	if c.preconditions || c.endpoint.cfg.WaitMediaReady != nil {
		if normalizedQoSStatus(c.localQoSStatus) != qosStatusSendRecv {
			return false
		}
	}
	if !c.preconditions {
		return true
	}
	localReady := qosStatusMeetsMandatory(
		c.localQoSStatus,
		c.incomingQoS.desired.localSend,
		c.incomingQoS.desired.localRecv,
	)
	remoteReady := qosStatusMeetsMandatory(
		c.incomingQoS.remoteStatus,
		c.incomingQoS.desired.remoteSend,
		c.incomingQoS.desired.remoteRecv,
	)
	if !localReady || !remoteReady {
		return false
	}
	for _, precondition := range c.incomingUnknown {
		if !qosStatusMeetsDirection(precondition.remoteStatus, precondition.direction) {
			return false
		}
	}
	return true
}

func incomingUnknownPreconditions(offer sdpOffer) []incomingUnknownPrecondition {
	preconditions := make([]incomingUnknownPrecondition, 0, len(offer.UnknownLocalMandatory))
	for _, desired := range offer.UnknownLocalMandatory {
		preconditions = append(preconditions, incomingUnknownPrecondition{
			preconditionType: desired.preconditionType,
			direction:        invertQoSStatus(desired.direction),
			remoteStatus:     invertQoSStatus(offer.UnknownLocalStatus[desired.preconditionType]),
		})
	}
	return preconditions
}

func (c *Call) tryAlertIncoming(ctx context.Context) error {
	c.mu.Lock()
	if c.closed || c.incomingAlerted || c.incomingAlerting {
		c.mu.Unlock()
		return nil
	}
	if !c.incomingResourcesReadyLocked() {
		stop := c.startIncomingPreconditionTimerLocked()
		c.mu.Unlock()
		if stop != nil {
			c.runIncomingPreconditionTimer(stop)
		}
		return nil
	}
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("alerting incoming call: incoming request is missing")
	}
	c.incomingAlerting = true
	preconditionStop := c.preconditionStop
	c.preconditionStop = nil
	req := *c.incomingRequest
	c.mu.Unlock()
	if preconditionStop != nil {
		close(preconditionStop)
	}

	if err := c.endpoint.writeRinging(ctx, req, c); err != nil {
		c.mu.Lock()
		c.incomingAlerting = false
		c.mu.Unlock()
		return fmt.Errorf("alerting incoming call: sending 180 Ringing: %w", err)
	}

	c.mu.Lock()
	if c.closed {
		c.incomingAlerting = false
		c.mu.Unlock()
		return nil
	}
	c.incomingAlerting = false
	c.incomingAlerted = true
	event := IncomingCall{
		Call:       c,
		From:       c.remoteURI,
		FromURI:    c.remoteURI,
		FromNumber: incomingCallerNumber(req.Message),
		Offer:      c.incomingOffer,
		Received:   c.incomingReceived,
	}
	c.mu.Unlock()

	c.startRingingTimer()
	if c.endpoint.cfg.OnIncomingCall != nil {
		c.endpoint.cfg.OnIncomingCall(event)
	}
	return nil
}

func (c *Call) startIncomingPreconditionTimerLocked() chan struct{} {
	if c.direction != CallDirectionIncoming || !c.preconditions || !c.incomingMediaReady || c.preconditionStop != nil {
		return nil
	}
	stop := make(chan struct{})
	c.preconditionStop = stop
	return stop
}

func (c *Call) runIncomingPreconditionTimer(stop chan struct{}) {
	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		timer := time.NewTimer(c.endpoint.cfg.IncomingPreconditionTimeout)
		defer timer.Stop()
		select {
		case <-done:
			return
		case <-stop:
			return
		case <-timer.C:
		}

		c.mu.Lock()
		if c.closed || c.incomingAlerted || c.preconditionStop != stop {
			c.mu.Unlock()
			return
		}
		c.preconditionStop = nil
		c.incomingAlerting = true
		req := c.incomingRequest
		c.mu.Unlock()

		ctx, cancel := contextWithDone(done)
		defer cancel()
		c.failIncomingMedia(ctx, req, errors.New("incoming preconditions timed out"), true)
	})
}

func (s *Endpoint) writeStatus(ctx context.Context, req session.Request, code int, reason string) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeSDPFailure(ctx context.Context, req session.Request, remote []byte, cause error) error {
	failure, ok := errors.AsType[*sdpPreconditionFailureError](cause)
	if !ok {
		return s.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
	}
	return s.writePreconditionFailure(ctx, req, remote, *failure)
}

func (s *Endpoint) writePreconditionFailure(ctx context.Context, req session.Request, remote []byte, failure sdpPreconditionFailureError) error {
	resp := sip.NewResponse(sipStatusPreconditionFailure, "Precondition Failure")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusPreconditionFailure)
	s.addAccessNetworkInfo(&resp)
	if len(remote) != 0 {
		resp.Headers.Add("Content-Type", "application/sdp")
		resp.Body = buildPreconditionFailureSDP(remote, failure)
	}
	return s.sess.WriteResponse(ctx, req, resp)
}

func (c *Call) failIncomingMedia(ctx context.Context, req *session.Request, cause error, precondition bool) {
	c.mu.Lock()
	closed := c.closed
	remote := append([]byte(nil), c.remoteSDP...)
	c.mu.Unlock()
	if closed {
		return
	}
	if req != nil {
		var err error
		if precondition {
			err = c.endpoint.writePreconditionFailure(ctx, *req, remote, sdpPreconditionFailureError{
				preconditionType: "qos",
				statusType:       "remote",
				direction:        qosStatusSendRecv,
				strength:         qosStrengthFailure,
			})
		} else {
			err = c.endpoint.writeStatus(ctx, *req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			c.endpoint.emitError(fmt.Errorf("rejecting incoming call: %w", err))
		}
	}
	c.finish(CallStateFailed, cause.Error())
}

func (s *Endpoint) writePRACKOK(ctx context.Context, req session.Request, sdp []byte) error {
	resp := sip.NewResponse(sipStatusOK, "OK")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusOK)
	s.addAccessNetworkInfo(&resp)
	if len(sdp) != 0 {
		resp.Headers.Add("Content-Type", "application/sdp")
		if s.usesPreconditions(req.Message) && sdpUsesPreconditions(sdp) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
		resp.Body = sdp
	}
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeRetryAfter(ctx context.Context, req session.Request, code int, reason string, seconds int) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	resp.Headers.Set("Retry-After", strconv.Itoa(seconds))
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeUnsupportedRequired(ctx context.Context, req session.Request, option string) error {
	resp := sip.NewResponse(sipStatusBadExtension, "Bad Extension")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusBadExtension)
	resp.Headers.Set("Unsupported", option)
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeSessionIntervalTooSmall(ctx context.Context, req session.Request, minSE int) error {
	resp := sip.NewResponse(sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusSessionIntervalTooSmall)
	resp.Headers.Set("Min-SE", strconv.Itoa(minSE))
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeRinging(ctx context.Context, req session.Request, call *Call) error {
	resp := sip.NewResponse(sipStatusRinging, "Ringing")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusRinging)
	s.addAccessNetworkInfo(&resp)
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(false, false))
	var rseq int64
	if call != nil && s.canSendReliableProvisional(req.Message) {
		resp.Headers.Add("Require", reliableProvisionalOption)
		rseq = call.beginReliableProvisional(sipStatusRinging, sip.CSeqNumber(req.Message.Header("CSeq")), "INVITE")
		resp.Headers.Add("RSeq", strconv.FormatInt(rseq, 10))
	}
	if err := s.sess.WriteResponse(ctx, req, resp); err != nil {
		return err
	}
	if rseq != 0 {
		call.startReliableProvisionalRetransmit(req, resp, rseq)
	}
	return nil
}

func (s *Endpoint) writeProgress(ctx context.Context, req session.Request, call *Call, body []byte, reliable bool) error {
	resp := sip.NewResponse(sipStatusSessionProgress, "Session Progress")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusSessionProgress)
	s.addAccessNetworkInfo(&resp)
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Message.Header("To"), call.localURI, call.localTag))
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(false, false))
	var rseq int64
	if reliable {
		resp.Headers.Add("Require", reliableProvisionalOption)
		rseq = call.beginReliableProvisional(sipStatusSessionProgress, sip.CSeqNumber(req.Message.Header("CSeq")), "INVITE")
		resp.Headers.Add("RSeq", strconv.FormatInt(rseq, 10))
	}
	if len(body) != 0 {
		if err := setInviteResponseBody(&resp, s.cfg, call.localURI, false, body); err != nil {
			return err
		}
		if s.usesPreconditions(req.Message) && sdpUsesPreconditions(body) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
		call.mu.Lock()
		call.localSDP = append([]byte(nil), body...)
		call.mu.Unlock()
	}
	if err := s.sess.WriteResponse(ctx, req, resp); err != nil {
		return err
	}
	if rseq != 0 {
		call.startReliableProvisionalRetransmit(req, resp, rseq)
	}
	return nil
}

func (s *Endpoint) addAccessNetworkInfo(resp *sip.Message) {
	state := s.reg.State()
	if value := strings.TrimSpace(state.UserAgent); value != "" && strings.TrimSpace(resp.Header("Server")) == "" {
		resp.Headers.Add("Server", value)
	}
	if !responseCanCarryAccessNetworkInfo(*resp) {
		return
	}
	if value := strings.TrimSpace(state.AccessNetworkInfo); value != "" && strings.TrimSpace(resp.Header("P-Access-Network-Info")) == "" {
		resp.Headers.Add("P-Access-Network-Info", value)
	}
}

func responseCanCarryAccessNetworkInfo(resp sip.Message) bool {
	return !strings.EqualFold(sip.CSeqMethod(resp.Header("CSeq")), "CANCEL")
}
