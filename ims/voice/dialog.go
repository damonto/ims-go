package voice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func (c *Call) handleRequest(ctx context.Context, req session.Request) error {
	method := strings.ToUpper(req.Message.Method())
	if method != "ACK" && method != "CANCEL" {
		if status, reason := c.recordRemoteCSeq(req.Message); status != 0 {
			return c.endpoint.writeStatus(ctx, req, status, reason)
		}
	}
	switch method {
	case "ACK":
		if !c.ackMatchesInvite(req.Message) {
			c.endpoint.logger.Debug("ignoring ACK with mismatched CSeq", "call_id", c.id, "cseq", req.Message.Header("CSeq"), "invite_cseq", c.inviteSeq)
			return nil
		}
		if err := c.handleACK(ctx, req); err != nil {
			return err
		}
		c.stopInviteOKRetransmit()
		return nil
	case "BYE":
		if err := c.endpoint.writeStatus(ctx, req, sipStatusOK, "OK"); err != nil {
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
	negotiated, ok := chooseCodec(answer, c.endpoint.cfg.Codecs)
	if !ok {
		c.finish(CallStateFailed, "no compatible delayed-offer answer codec")
		return nil
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.endpoint.cfg.Codecs, negotiated.ClockRate)
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

func (c *Call) refreshDialogRegistration() error {
	c.mu.Lock()
	id := sip.DialogID{
		CallID:    c.id,
		LocalTag:  c.localTag,
		RemoteTag: c.remoteTag,
	}
	key := c.id
	c.mu.Unlock()

	attachment, err := c.endpoint.sess.RegisterDialog(id, key)
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
	if err := c.endpoint.sess.WriteResponse(ctx, req, resp); err != nil {
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
	c.endpoint.addAccessNetworkInfo(&ok)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), c.localURI, c.localTag))
	ok.Headers.Add("Session-ID", c.sessionID)
	ok.Headers.Add("Contact", contactValue(c.endpoint.reg.State()))
	ok.Headers.Add("Allow", sip.DefaultClientAllow)
	ok.Headers.Add("Accept", callAcceptHeader(false, false))
	addInviteOKSessionTimer(&ok, msg, c.endpoint.cfg)
	if len(body) != 0 {
		if err := setInviteResponseBody(&ok, c.endpoint.cfg, c.localURI, false, body); err != nil {
			return sip.Message{}, err
		}
		if c.endpoint.usesPreconditions(msg) && sdpUsesPreconditions(body) {
			addTokenHeader(&ok, "Require", preconditionOption)
		}
	}
	return ok, nil
}

func (c *Call) updateRemoteAllow(msg sip.Message) {
	allow := strings.TrimSpace(msg.Header("Allow"))
	if allow == "" {
		return
	}
	c.mu.Lock()
	c.remoteAllow = allow
	c.mu.Unlock()
}

func (c *Call) updateRemoteTargetFromRequest(msg sip.Message) {
	c.updateRemoteTarget(msg)
}

func (c *Call) updateRemoteTargetFromResponse(msg sip.Message) {
	c.updateRemoteTarget(msg)
}

func (c *Call) updateRemoteTarget(msg sip.Message) {
	contact := sip.AddressURI(msg.Header("Contact"))
	allow := strings.TrimSpace(msg.Header("Allow"))
	if contact == "" && allow == "" {
		return
	}
	c.mu.Lock()
	if contact != "" {
		c.remoteURI = contact
		c.targetURI = contact
	}
	if allow != "" {
		c.remoteAllow = allow
	}
	c.mu.Unlock()
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
		if err := c.endpoint.sess.Send(ctx, ack); err != nil {
			return fmt.Errorf("acknowledging forked call 2xx: %w", err)
		}
		resp, err := c.endpoint.sess.Exchange(ctx, bye)
		if !byeReleaseCompleted(resp, err) {
			return byeReleaseError(callActionReleaseForked2xx, resp, err)
		}
		return nil
	}
	ack := c.inviteACK
	c.mu.Unlock()
	if ack.StartLine == "" {
		return nil
	}
	if err := c.endpoint.sess.Send(ctx, ack); err != nil {
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
		if c.endpoint.cfg.Preconditions && tokenHeaderContains(msg, "Require", preconditionOption) && answer.Preconditions {
			body, err := buildSDPPreconditionUpdate(c.endpoint.cfg, c.endpoint.localIP(), c.localPort, answer, c.media)
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
	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		c.sendPRACK(done, prack, preconditionUpdate)
	})
	return nil
}

func (c *Call) markInviteResponse() {
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
	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		c.sendCancel(done, cancel)
	})
}

func (c *Call) sendCancel(done <-chan struct{}, cancel sip.Message) {
	ctx, stop := contextWithDoneTimeout(done, callReleaseTimeout)
	defer stop()
	if err := c.exchangeCancel(ctx, cancel); err != nil {
		c.endpoint.emitError(err)
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
	c.endpoint.emit(CallEvent{Call: c, CallID: id, State: state, Cause: "early dialog terminated", At: time.Now()})
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
	if err := c.endpoint.sess.Send(ctx, ack); err != nil {
		return fmt.Errorf("acknowledging cancelled call 2xx: %w", err)
	}
	resp, err := c.endpoint.sess.Exchange(ctx, bye)
	if !byeReleaseCompleted(resp, err) {
		return byeReleaseError(callActionReleaseCancelled2xx, resp, err)
	}
	return nil
}
