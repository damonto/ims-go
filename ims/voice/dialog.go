package voice

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"strconv"
	"strings"
	"time"
)

func (c *Call) handleRequest(ctx context.Context, req session.Request) error {
	method := strings.ToUpper(req.Message.Method())
	if method != "ACK" && method != "CANCEL" {
		if status, reason := c.recordRemoteCSeq(req.Message); status != 0 {
			return c.service.writeStatus(ctx, req, status, reason)
		}
	}
	switch method {
	case "ACK":
		if !c.ackMatchesInvite(req.Message) {
			c.service.logger.Debug("ignoring ACK with mismatched CSeq", "call_id", c.id, "cseq", req.Message.Header("CSeq"), "invite_cseq", c.inviteSeq)
			return nil
		}
		if err := c.handleACK(ctx, req); err != nil {
			return err
		}
		c.stopInviteOKRetransmit()
		return nil
	case "BYE":
		if err := c.service.writeStatus(ctx, req, sipStatusOK, "OK"); err != nil {
			return err
		}
		c.finish(CallStateEnded, "remote bye")
		return nil
	case "CANCEL":
		c.finish(CallStateEnded, "remote cancel")
		return nil
	case "INVITE":
		return c.handleReINVITE(ctx, req)
	case "INFO":
		return c.handleINFO(ctx, req)
	case "PRACK":
		return c.handlePRACK(ctx, req)
	case "UPDATE":
		return c.handleSessionRefresh(ctx, req)
	default:
		return nil
	}
}

func (c *Call) ackMatchesInvite(msg sip.Message) bool {
	if !strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), "ACK") {
		return false
	}
	cseq := sip.CSeqNumber(msg.Header("CSeq"))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.inviteOKStop != nil && c.inviteOKCSeq > 0 {
		return cseq == c.inviteOKCSeq
	}
	return cseq == c.inviteSeq
}

func (c *Call) recordRemoteCSeq(msg sip.Message) (int, string) {
	cseq := sip.CSeqNumber(msg.Header("CSeq"))
	if cseq <= 0 {
		return sipStatusBadRequest, "Bad Request"
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remoteCSeq != 0 && cseq <= c.remoteCSeq {
		return sipStatusServerInternalError, "Server Internal Error"
	}
	c.remoteCSeq = cseq
	return 0, ""
}

func (c *Call) handleACK(ctx context.Context, req session.Request) error {
	c.mu.Lock()
	delayedOffer := c.delayedOffer
	prackAnsweredOffer := c.prackAnsweredOffer
	state := c.state
	media := c.media
	c.mu.Unlock()
	if !delayedOffer || prackAnsweredOffer {
		c.setState(CallStateActive, "")
		return nil
	}
	if state != CallStateAnswering {
		return nil
	}
	body, ok := sdpBody(req.Message)
	if !ok {
		c.finish(CallStateFailed, "missing delayed-offer sdp answer")
		return nil
	}
	answer, err := parseSDP(body)
	if err != nil {
		c.finish(CallStateFailed, err.Error())
		return nil
	}
	negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
	if !ok {
		c.finish(CallStateFailed, "no compatible delayed-offer answer codec")
		return nil
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.service.cfg.Codecs, negotiated.ClockRate)
	answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, media.PTime), dtmf, hasDTMF)
	c.mu.Lock()
	c.media = answerMedia
	c.mu.Unlock()
	if err := c.openMedia(ctx); err != nil {
		c.finish(CallStateFailed, err.Error())
		return nil
	}
	c.startMediaInactivityWatch()
	c.setState(CallStateActive, "")
	return nil
}

func (c *Call) handleResponse(ctx context.Context, msg sip.Message) error {
	c.mu.Lock()
	if c.direction != CallDirectionOutgoing || sip.CSeqNumber(msg.Header("CSeq")) != c.inviteSeq {
		c.mu.Unlock()
		return nil
	}
	tag := sip.HeaderTag(msg.Header("To"))
	if tag != "" && c.remoteTag != "" && tag != c.remoteTag {
		snap := c.dialogSnapshot()
		c.mu.Unlock()
		ack := snap.buildACKForResponse(msg)
		bye := snap.buildBYEForResponse(msg, c.nextCSeq(), reasonUserTriggered)
		if err := c.service.sess.Send(ctx, ack); err != nil {
			return fmt.Errorf("acknowledging forked call 2xx: %w", err)
		}
		resp, err := c.service.sess.Exchange(ctx, bye)
		if !byeReleaseCompleted(resp, err) {
			return byeReleaseError("releasing forked call 2xx", resp, err)
		}
		return nil
	}
	ack := c.inviteACK
	c.mu.Unlock()
	if ack.StartLine == "" {
		return nil
	}
	if err := c.service.sess.Send(ctx, ack); err != nil {
		return fmt.Errorf("acknowledging retransmitted call 2xx: %w", err)
	}
	return nil
}

func (c *Call) handleProvisionalResponse(ctx context.Context, msg sip.Message) error {
	c.mu.Lock()
	if c.direction != CallDirectionOutgoing || sip.CSeqNumber(msg.Header("CSeq")) != c.inviteSeq {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	if msg.StatusCode() == sipStatusEarlyDialogTerminated {
		c.handleEarlyDialogTerminated(msg)
		return nil
	}
	needsPRACK := false
	if isReliableProvisional(msg) {
		c.mu.Lock()
		var err error
		needsPRACK, err = c.recordReliableProvisional(msg)
		if err != nil {
			c.mu.Unlock()
			return err
		}
		if !needsPRACK {
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
	}
	if msg.StatusCode() == sipStatusRinging {
		c.setState(CallStateRinging, "")
		c.startRingbackTimer()
	}
	c.updateRemoteAllow(msg)

	remoteTag := sip.HeaderTag(msg.Header("To"))
	var authorized bool
	var earlyTarget string
	var earlyRoutes []string
	var preconditionUpdateBody []byte
	if remoteTag != "" {
		c.mu.Lock()
		if c.earlyDialogs == nil {
			c.earlyDialogs = make(map[string]earlyDialog)
		}
		dialog := c.earlyDialogs[remoteTag]
		if dialog.remoteTarget == "" {
			dialog.remoteTarget = nonEmpty(sip.AddressURI(msg.Header("Contact")), sip.AddressURI(msg.Header("To")), c.targetURI)
			dialog.routeSet = routeSetFromResponse(msg)
		}
		if hasEarlyMediaHeader(msg) {
			dialog.earlyMediaAuthorized = earlyMediaAuthorized(msg)
		}
		authorized = dialog.earlyMediaAuthorized
		earlyTarget = dialog.remoteTarget
		earlyRoutes = make([]string, len(dialog.routeSet))
		copy(earlyRoutes, dialog.routeSet)
		c.earlyDialogs[remoteTag] = dialog
		c.mu.Unlock()
	}
	if body, ok := sdpBody(msg); ok {
		answer, err := parseSDP(body)
		if err != nil {
			return fmt.Errorf("handling provisional call answer: %w", err)
		}
		if authorized {
			if err := c.openEarlyMedia(ctx, answer); err != nil {
				return err
			}
		}
		c.mu.Lock()
		if remoteTag != "" {
			dialog := c.earlyDialogs[remoteTag]
			dialog.answer = answer
			dialog.hasAnswer = true
			c.earlyDialogs[remoteTag] = dialog
		}
		if c.service.cfg.Preconditions && tokenHeaderContains(msg, "Require", preconditionOption) && answer.Preconditions {
			body, err := buildSDPPreconditionUpdate(c.service.cfg, c.service.localIP(), c.localPort, answer, c.media)
			if err != nil {
				c.mu.Unlock()
				return err
			}
			preconditionUpdateBody = body
		}
		c.mu.Unlock()
	} else if remoteTag != "" {
		c.mu.Lock()
		if c.earlyDialogs == nil {
			c.earlyDialogs = make(map[string]earlyDialog)
		}
		if _, ok := c.earlyDialogs[remoteTag]; !ok {
			c.earlyDialogs[remoteTag] = earlyDialog{}
		}
		c.mu.Unlock()
	}

	if !needsPRACK {
		return nil
	}
	c.mu.Lock()
	snap := c.dialogSnapshot()
	c.mu.Unlock()
	prack, err := snap.buildPRACKForResponse(msg, c.nextCSeq(), earlyTarget, earlyRoutes)
	if err != nil {
		return err
	}
	var preconditionUpdate sip.Message
	if len(preconditionUpdateBody) != 0 {
		preconditionUpdate = snap.buildPreconditionUPDATEForResponse(msg, c.nextCSeq(), earlyTarget, earlyRoutes, preconditionUpdateBody)
	}
	go c.sendPRACK(prack, preconditionUpdate)
	return nil
}

func (c *Call) markInviteResponse(ctx context.Context) {
	c.mu.Lock()
	c.inviteResponse = true
	if !c.cancelOnResponse || c.cancelSent || c.direction != CallDirectionOutgoing {
		c.mu.Unlock()
		return
	}
	c.cancelSent = true
	snap := c.dialogSnapshot()
	c.mu.Unlock()

	cancel := snap.buildCANCEL(reasonUserTriggered)
	go c.sendCancel(ctx, cancel)
}

func (c *Call) sendCancel(parent context.Context, cancel sip.Message) {
	ctx, stop := context.WithTimeout(context.WithoutCancel(parent), callReleaseTimeout)
	defer stop()
	if err := c.exchangeCancel(ctx, cancel); err != nil {
		c.service.emitError(err)
	}
}

func (c *Call) handleEarlyDialogTerminated(msg sip.Message) {
	remoteTag := sip.HeaderTag(msg.Header("To"))
	if remoteTag == "" {
		return
	}
	c.mu.Lock()
	if _, ok := c.earlyDialogs[remoteTag]; !ok {
		c.mu.Unlock()
		return
	}
	delete(c.earlyDialogs, remoteTag)
	id := c.id
	state := c.state
	c.mu.Unlock()
	c.service.emit(CallEvent{Call: c, CallID: id, State: state, Cause: "early dialog terminated", At: time.Now()})
}

func (c *Call) answerFromFinalResponse(resp sip.Message) (sdpOffer, bool, error) {
	if answerBody, ok := sdpBody(resp); ok {
		answer, err := parseSDP(answerBody)
		if err != nil {
			return sdpOffer{}, false, err
		}
		return answer, true, nil
	}
	remoteTag := sip.HeaderTag(resp.Header("To"))
	if remoteTag == "" {
		return sdpOffer{}, false, nil
	}
	c.mu.Lock()
	dialog, ok := c.earlyDialogs[remoteTag]
	c.mu.Unlock()
	if !ok || !dialog.hasAnswer {
		return sdpOffer{}, false, nil
	}
	return dialog.answer, true, nil
}

func (c *Call) releaseCancelledInvite2xx(ctx context.Context, resp sip.Message) error {
	c.mu.Lock()
	c.remoteTag = sip.HeaderTag(resp.Header("To"))
	c.remoteTo = nonEmpty(resp.Header("To"), c.remoteTo)
	c.remoteURI = nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), c.remoteURI)
	c.targetURI = c.remoteURI
	c.routeSet = reverseValues(resp.HeadersByName("Record-Route"))
	c.earlyDialogs = nil
	snap := c.dialogSnapshot()
	c.mu.Unlock()

	ack := snap.buildACK()
	bye := snap.buildBYE(reasonUserTriggered, c.nextCSeq())
	if err := c.refreshDialogRegistration(); err != nil {
		return err
	}
	if err := c.service.sess.Send(ctx, ack); err != nil {
		return fmt.Errorf("acknowledging cancelled call 2xx: %w", err)
	}
	resp, err := c.service.sess.Exchange(ctx, bye)
	if !byeReleaseCompleted(resp, err) {
		return byeReleaseError("releasing cancelled call 2xx", resp, err)
	}
	return nil
}

type dialogSnapshot struct {
	id                string
	sessionID         string
	localURI          string
	localTag          string
	remoteTo          string
	peerAllowsUPDATE  bool
	targetURI         string
	routeSet          []string
	inviteSeq         int64
	inviteRequest     sip.Message
	localSDP          []byte
	sessionTimer      bool
	preconditions     bool
	flow              registration.Flow
	userAgent         string
	accessNetworkInfo string
	transport         string
	contactHost       string
	messagePort       int
	contact           string
}

func (c *Call) dialogSnapshot() dialogSnapshot {
	// Keep SIP builders off Call's mutable fields. Callers take this snapshot
	// while holding c.mu, then build messages from the copied state.
	state := c.service.reg.State()
	invite := c.inviteRequest
	invite.Headers = invite.Headers.Clone()
	invite.Body = append([]byte(nil), invite.Body...)
	return dialogSnapshot{
		id:                c.id,
		sessionID:         c.sessionID,
		localURI:          c.localURI,
		localTag:          c.localTag,
		remoteTo:          c.remoteTo,
		peerAllowsUPDATE:  sip.TokenListContains(c.remoteAllow, "UPDATE"),
		targetURI:         c.targetURI,
		routeSet:          append([]string(nil), c.routeSet...),
		inviteSeq:         c.inviteSeq,
		inviteRequest:     invite,
		localSDP:          append([]byte(nil), c.localSDP...),
		sessionTimer:      c.service.cfg.SessionTimer,
		preconditions:     c.service.cfg.Preconditions,
		flow:              state.Flow,
		userAgent:         state.UserAgent,
		accessNetworkInfo: state.AccessNetworkInfo,
		transport:         sip.TransportToken(c.service.sess.LocalAddr()),
		contactHost:       state.ContactHost,
		messagePort:       state.MessagePort,
		contact:           contactValue(state),
	}
}

func (c *Call) nextCSeq() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localCSeq++
	return c.localCSeq
}

func (s dialogSnapshot) requestPolicy(routes []string) sip.ClientRequestPolicy {
	if routes == nil {
		routes = s.routeSet
	}
	return s.flow.DialogRequestPolicy(routes, s.userAgent, s.accessNetworkInfo)
}

func (s dialogSnapshot) applyRequestPolicy(msg *sip.Message, routes []string) {
	s.requestPolicy(routes).Apply(msg)
	if s.sessionTimer && !strings.EqualFold(msg.Method(), "ACK") {
		addTokenHeader(msg, "Supported", sessionTimerOption)
	}
}

func (s dialogSnapshot) addDialogHeaders(msg *sip.Message, method string, cseq int64) {
	msg.Headers.Add("Via", sip.BuildVia(s.transport, s.contactHost, s.messagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", s.localURI, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.id)
	if s.sessionID != "" {
		msg.Headers.Add("Session-ID", s.sessionID)
	}
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", cseq, method))
}

func (s dialogSnapshot) buildACK() sip.Message {
	msg := sip.NewRequest("ACK", s.targetURI)
	s.addDialogHeaders(&msg, "ACK", s.inviteSeq)
	msg.Headers.Del("Session-ID")
	s.applyRequestPolicy(&msg, nil)
	return msg
}

func (s dialogSnapshot) buildACKForResponse(resp sip.Message) sip.Message {
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), s.targetURI)
	msg := sip.NewRequest("ACK", targetURI)
	s.addDialogHeaders(&msg, "ACK", s.inviteSeq)
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	msg.Headers.Del("Session-ID")
	s.applyRequestPolicy(&msg, reverseValues(resp.HeadersByName("Record-Route")))
	return msg
}

func (s dialogSnapshot) buildACKForSessionRefreshINVITE(resp sip.Message) sip.Message {
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), s.targetURI)
	msg := sip.NewRequest("ACK", targetURI)
	s.addDialogHeaders(&msg, "ACK", sip.CSeqNumber(resp.Header("CSeq")))
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	msg.Headers.Del("Session-ID")
	s.applyRequestPolicy(&msg, nil)
	return msg
}

func (s dialogSnapshot) buildCANCEL(reason string) sip.Message {
	invite := s.inviteRequest
	msg := sip.NewRequest("CANCEL", sip.RequestURI(invite))
	if via := invite.Header("Via"); via != "" {
		msg.Headers.Add("Via", via)
	}
	msg.Headers.Add("From", invite.Header("From"))
	msg.Headers.Add("To", invite.Header("To"))
	msg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	msg.Headers.Add("CSeq", fmt.Sprintf("%d CANCEL", s.inviteSeq))
	if maxForwards := invite.Header("Max-Forwards"); maxForwards != "" {
		msg.Headers.Add("Max-Forwards", maxForwards)
	}
	for _, route := range invite.HeadersByName("Route") {
		msg.Headers.Add("Route", route)
	}
	if userAgent := strings.TrimSpace(s.userAgent); userAgent != "" {
		msg.Headers.Add("User-Agent", userAgent)
	}
	if securityVerify := invite.Header("Security-Verify"); securityVerify != "" {
		msg.Headers.Add("Security-Verify", securityVerify)
	}
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	return msg
}

func (c *Call) buildBYE(reason string) sip.Message {
	c.mu.Lock()
	snap := c.dialogSnapshot()
	c.mu.Unlock()
	return snap.buildBYE(reason, c.nextCSeq())
}

func (s dialogSnapshot) buildBYE(reason string, cseq int64) sip.Message {
	msg := s.buildDialogRequest("BYE", cseq)
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	return msg
}

func (s dialogSnapshot) buildSessionRefreshUPDATE(cseq int64, timer sessionTimerState) sip.Message {
	msg := s.buildDialogRequest("UPDATE", cseq)
	addTokenHeader(&msg, "Supported", sessionTimerOption)
	if timer.active {
		seconds := durationSeconds(timer.interval)
		if timer.minSE > seconds {
			seconds = timer.minSE
		}
		msg.Headers.Set("Session-Expires", sessionExpiresHeader{
			seconds:   seconds,
			refresher: sessionRefresherUAC,
		}.String())
	}
	if timer.minSE > durationSeconds(defaultMinSessionExpires) {
		msg.Headers.Set("Min-SE", strconv.Itoa(timer.minSE))
	}
	return msg
}

func (s dialogSnapshot) buildPreconditionUPDATEForResponse(resp sip.Message, cseq int64, remoteTarget string, routes []string, body []byte) sip.Message {
	targetURI := nonEmpty(remoteTarget, sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), s.targetURI)
	msg := sip.NewRequest("UPDATE", targetURI)
	s.addDialogHeaders(&msg, "UPDATE", cseq)
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	msg.Headers.Add("Contact", s.contact)
	msg.Headers.Set("Content-Type", "application/sdp")
	msg.Headers.Add("Require", preconditionOption)
	msg.Body = append([]byte(nil), body...)
	s.applyRequestPolicy(&msg, routes)
	return msg
}

func (s dialogSnapshot) buildPreconditionUPDATE(cseq int64, body []byte) sip.Message {
	msg := s.buildDialogRequest("UPDATE", cseq)
	msg.Headers.Set("Content-Type", "application/sdp")
	msg.Headers.Add("Require", preconditionOption)
	msg.Body = append([]byte(nil), body...)
	return msg
}

func (s dialogSnapshot) buildSessionRefreshRequest(cseq int64, timer sessionTimerState) sip.Message {
	if s.peerAllowsUPDATE {
		return s.buildSessionRefreshUPDATE(cseq, timer)
	}
	msg := s.buildDialogRequest("INVITE", cseq)
	addTokenHeader(&msg, "Supported", sessionTimerOption)
	if len(s.localSDP) != 0 {
		msg.Headers.Set("Content-Type", "application/sdp")
		msg.Body = append([]byte(nil), s.localSDP...)
		s.addPreconditionSupport(&msg, s.localSDP)
	}
	if timer.active {
		seconds := durationSeconds(timer.interval)
		if timer.minSE > seconds {
			seconds = timer.minSE
		}
		msg.Headers.Set("Session-Expires", sessionExpiresHeader{
			seconds:   seconds,
			refresher: sessionRefresherUAC,
		}.String())
	}
	if timer.minSE > durationSeconds(defaultMinSessionExpires) {
		msg.Headers.Set("Min-SE", strconv.Itoa(timer.minSE))
	}
	return msg
}

func (s dialogSnapshot) buildMediaReINVITE(cseq int64, timer sessionTimerState, body []byte) sip.Message {
	msg := s.buildDialogRequest("INVITE", cseq)
	msg.Headers.Set("Content-Type", "application/sdp")
	msg.Body = append([]byte(nil), body...)
	addTokenHeader(&msg, "Supported", sessionTimerOption)
	s.addPreconditionSupport(&msg, body)
	if timer.active {
		seconds := durationSeconds(timer.interval)
		if timer.minSE > seconds {
			seconds = timer.minSE
		}
		msg.Headers.Set("Session-Expires", sessionExpiresHeader{
			seconds:   seconds,
			refresher: sessionRefresherUAC,
		}.String())
	}
	if timer.minSE > durationSeconds(defaultMinSessionExpires) {
		msg.Headers.Set("Min-SE", strconv.Itoa(timer.minSE))
	}
	return msg
}

func (s dialogSnapshot) addPreconditionSupport(msg *sip.Message, body []byte) {
	if s.preconditions && sdpUsesPreconditions(body) {
		addTokenHeader(msg, "Supported", preconditionOption)
	}
}

func (s dialogSnapshot) buildBYEForResponse(resp sip.Message, cseq int64, reason string) sip.Message {
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), s.targetURI)
	msg := sip.NewRequest("BYE", targetURI)
	s.addDialogHeaders(&msg, "BYE", cseq)
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	msg.Headers.Add("Contact", s.contact)
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	s.applyRequestPolicy(&msg, reverseValues(resp.HeadersByName("Record-Route")))
	return msg
}

func (s dialogSnapshot) buildDialogRequest(method string, cseq int64) sip.Message {
	msg := sip.NewRequest(method, s.targetURI)
	s.addDialogHeaders(&msg, method, cseq)
	msg.Headers.Add("Contact", s.contact)
	s.applyRequestPolicy(&msg, nil)
	return msg
}

func (c *Call) refreshDialogRegistration() error {
	c.mu.Lock()
	id := sip.DialogID{
		CallID:    c.id,
		LocalTag:  c.localTag,
		RemoteTag: c.remoteTag,
	}
	key := c.id
	c.mu.Unlock()

	attachment, err := c.service.sess.RegisterDialog(id, key)
	if err != nil {
		return fmt.Errorf("refreshing call dialog: %w", err)
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = attachment.Close()
		return errors.New("refreshing call dialog: call is closed")
	}
	old := c.dialogAttachment
	c.dialogAttachment = attachment
	c.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (c *Call) writeInviteOK(ctx context.Context, body []byte) error {
	c.mu.Lock()
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("answering call: incoming request is missing")
	}
	req := *c.incomingRequest
	c.mu.Unlock()
	resp, err := c.buildInviteOK(req.Message, body)
	if err != nil {
		return err
	}
	if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
		c.finish(CallStateFailed, err.Error())
		return fmt.Errorf("answering call: %w", err)
	}
	c.mu.Lock()
	c.inviteOK = resp
	if len(body) != 0 {
		c.localSDP = append([]byte(nil), body...)
	}
	c.mu.Unlock()
	if err := c.applySessionTimerUASResponse(resp); err != nil {
		c.finish(CallStateFailed, err.Error())
		return err
	}
	c.setState(CallStateAnswering, "")
	c.startInviteOKRetransmit(req, resp)
	return nil
}

func (c *Call) buildInviteOK(msg sip.Message, body []byte) (sip.Message, error) {
	ok := sip.NewResponse(sipStatusOK, "OK")
	ok.Headers = sip.ResponseHeaders(msg, sipStatusOK)
	c.service.addAccessNetworkInfo(&ok)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), c.localURI, c.localTag))
	ok.Headers.Add("Session-ID", c.sessionID)
	ok.Headers.Add("Contact", contactValue(c.service.reg.State()))
	ok.Headers.Add("Allow", sip.DefaultClientAllow)
	ok.Headers.Add("Accept", callAcceptHeader(false, false))
	addInviteOKSessionTimer(&ok, msg, c.service.cfg)
	if len(body) != 0 {
		if err := setInviteResponseBody(&ok, c.service.cfg, c.localURI, false, body); err != nil {
			return sip.Message{}, err
		}
		if c.service.usesPreconditions(msg) && sdpUsesPreconditions(body) {
			addTokenHeader(&ok, "Require", preconditionOption)
		}
	}
	return ok, nil
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
		c.service.logger.Warn("ignoring invalid call state transition", "call_id", id, "from", from, "to", state, "cause", cause)
		return
	}
	c.state = state
	id := c.id
	hold := normalizeHoldState(c.hold)
	c.mu.Unlock()
	c.service.emit(CallEvent{Call: c, CallID: id, State: state, Hold: hold, Cause: cause, At: time.Now()})
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
	c.service.removeCall(id)
	if emit {
		c.service.emit(CallEvent{Call: c, CallID: id, State: state, Hold: hold, Cause: cause, At: time.Now()})
	}
}
