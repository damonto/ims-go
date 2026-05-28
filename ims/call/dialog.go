package call

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"strings"
	"sync/atomic"
	"time"
)

func (c *Call) handleRequest(ctx context.Context, req session.Request) error {
	switch strings.ToUpper(req.Message.Method()) {
	case "ACK":
		if err := c.handleACK(ctx, req); err != nil {
			return err
		}
		c.stopInviteOKRetransmit()
		return nil
	case "BYE":
		if err := c.service.writeStatus(ctx, req, 200, "OK"); err != nil {
			return err
		}
		c.finish(StateEnded, "remote bye")
		return nil
	case "CANCEL":
		c.finish(StateEnded, "remote cancel")
		return nil
	case "PRACK":
		return c.handlePRACK(ctx, req)
	default:
		return nil
	}
}

func (c *Call) handleACK(ctx context.Context, req session.Request) error {
	c.mu.Lock()
	delayedOffer := c.delayedOffer
	prackAnsweredOffer := c.prackAnsweredOffer
	state := c.state
	media := c.media
	c.mu.Unlock()
	if !delayedOffer || prackAnsweredOffer {
		c.setState(StateActive, "")
		return nil
	}
	if state != StateAnswering {
		return nil
	}
	body, ok := sdpBody(req.Message)
	if !ok {
		c.finish(StateFailed, "missing delayed-offer sdp answer")
		return nil
	}
	answer, err := parseSDP(body)
	if err != nil {
		c.finish(StateFailed, err.Error())
		return nil
	}
	negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
	if !ok {
		c.finish(StateFailed, "no compatible delayed-offer answer codec")
		return nil
	}
	dtmf, hasDTMF := chooseTelephoneEvent(answer, c.service.cfg.Codecs)
	answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, media.PTime), dtmf, hasDTMF)
	c.mu.Lock()
	c.media = answerMedia
	c.mu.Unlock()
	if err := c.openMedia(ctx); err != nil {
		c.finish(StateFailed, err.Error())
		return nil
	}
	c.startMediaInactivityWatch()
	c.setState(StateActive, "")
	return nil
}

func (c *Call) handleResponse(ctx context.Context, msg sip.Message) error {
	c.mu.Lock()
	if c.direction != DirectionOutgoing || sip.CSeqNumber(msg.Header("CSeq")) != c.inviteSeq {
		c.mu.Unlock()
		return nil
	}
	tag := sip.HeaderTag(msg.Header("To"))
	if tag != "" && c.remoteTag != "" && tag != c.remoteTag {
		ack := c.buildACKForResponseLocked(msg)
		bye := c.buildBYEForResponseLocked(msg, reasonUserTriggered)
		c.mu.Unlock()
		if err := c.service.sess.Send(ctx, ack); err != nil {
			return fmt.Errorf("acknowledging forked call 2xx: %w", err)
		}
		resp, err := c.service.sess.Exchange(ctx, bye)
		if err != nil {
			return fmt.Errorf("releasing forked call 2xx: %w", err)
		}
		if resp.StatusCode() != 200 {
			return fmt.Errorf("releasing forked call 2xx: expected 200, got %w", sip.NewResponseError(resp))
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
	if c.direction != DirectionOutgoing || sip.CSeqNumber(msg.Header("CSeq")) != c.inviteSeq {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	if msg.StatusCode() == 199 {
		c.handleEarlyDialogTerminated(msg)
		return nil
	}
	if msg.StatusCode() == 180 {
		c.setState(StateRinging, "")
		c.startRingbackTimer()
	}

	remoteTag := sip.HeaderTag(msg.Header("To"))
	var authorized bool
	if remoteTag != "" {
		c.mu.Lock()
		if c.earlyDialogs == nil {
			c.earlyDialogs = make(map[string]earlyDialog)
		}
		dialog := c.earlyDialogs[remoteTag]
		if hasEarlyMediaHeader(msg) {
			dialog.earlyMediaAuthorized = earlyMediaAuthorized(msg)
		}
		authorized = dialog.earlyMediaAuthorized
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

	if !isReliableProvisional(msg) {
		return nil
	}
	c.mu.Lock()
	key := provisionalResponseKey(msg)
	if key == "" {
		c.mu.Unlock()
		return nil
	}
	if c.prackedRSeq == nil {
		c.prackedRSeq = make(map[string]struct{})
	}
	if _, ok := c.prackedRSeq[key]; ok {
		c.mu.Unlock()
		return nil
	}
	c.prackedRSeq[key] = struct{}{}
	prack, err := c.buildPRACKForResponseLocked(msg)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	go c.sendPRACK(prack)
	return nil
}

func (c *Call) markInviteResponse(ctx context.Context) {
	c.mu.Lock()
	c.inviteResponse = true
	if !c.cancelOnResponse || c.cancelSent || c.direction != DirectionOutgoing {
		c.mu.Unlock()
		return
	}
	c.cancelSent = true
	cancel := c.buildCANCELLocked(reasonUserTriggered)
	c.mu.Unlock()

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
	c.service.emit(Event{CallID: id, State: state, Cause: "early dialog terminated", At: time.Now()})
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
	ack := c.buildACKLocked()
	bye := c.buildBYELocked(reasonUserTriggered)
	c.mu.Unlock()

	if err := c.refreshDialogRegistration(); err != nil {
		return err
	}
	if err := c.service.sess.Send(ctx, ack); err != nil {
		return fmt.Errorf("acknowledging cancelled call 2xx: %w", err)
	}
	resp, err := c.service.sess.Exchange(ctx, bye)
	if err != nil {
		return fmt.Errorf("releasing cancelled call 2xx: %w", err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("releasing cancelled call 2xx: expected 200, got %w", sip.NewResponseError(resp))
	}
	return nil
}

func (c *Call) buildACK() sip.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buildACKLocked()
}

func (c *Call) buildACKLocked() sip.Message {
	state := c.service.reg.State()
	msg := sip.NewRequest("ACK", c.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", c.remoteTo)
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d ACK", c.inviteSeq))
	c.service.reg.DialogRequestPolicy(c.routeSet).Apply(&msg)
	return msg
}

func (c *Call) buildACKForResponseLocked(resp sip.Message) sip.Message {
	state := c.service.reg.State()
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), c.targetURI)
	msg := sip.NewRequest("ACK", targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", nonEmpty(resp.Header("To"), c.remoteTo))
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d ACK", c.inviteSeq))
	c.service.reg.DialogRequestPolicy(reverseValues(resp.HeadersByName("Record-Route"))).Apply(&msg)
	return msg
}

func (c *Call) buildCANCELLocked(reason string) sip.Message {
	invite := c.inviteRequest
	state := c.service.reg.State()
	msg := sip.NewRequest("CANCEL", sip.RequestURI(invite))
	if via := invite.Header("Via"); via != "" {
		msg.Headers.Add("Via", via)
	}
	msg.Headers.Add("From", invite.Header("From"))
	msg.Headers.Add("To", invite.Header("To"))
	msg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	msg.Headers.Add("CSeq", fmt.Sprintf("%d CANCEL", c.inviteSeq))
	if maxForwards := invite.Header("Max-Forwards"); maxForwards != "" {
		msg.Headers.Add("Max-Forwards", maxForwards)
	}
	for _, route := range invite.HeadersByName("Route") {
		msg.Headers.Add("Route", route)
	}
	if userAgent := strings.TrimSpace(state.UserAgent); userAgent != "" {
		msg.Headers.Add("User-Agent", userAgent)
	}
	if accessNetworkInfo := strings.TrimSpace(state.AccessNetworkInfo); accessNetworkInfo != "" {
		msg.Headers.Add("P-Access-Network-Info", accessNetworkInfo)
	}
	if securityVerify := invite.Header("Security-Verify"); securityVerify != "" {
		msg.Headers.Add("Security-Verify", securityVerify)
	}
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	return msg
}

func (c *Call) buildDialogRequest(method string) sip.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.service.reg.State()
	msg := sip.NewRequest(method, c.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", c.remoteTo)
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("Session-ID", c.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", atomic.AddInt64(&c.service.cseq, 1), method))
	msg.Headers.Add("Contact", contactValue(state))
	c.service.reg.DialogRequestPolicy(c.routeSet).Apply(&msg)
	return msg
}

func (c *Call) buildBYE(reason string) sip.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buildBYELocked(reason)
}

func (c *Call) buildBYELocked(reason string) sip.Message {
	msg := c.buildDialogRequestLocked("BYE")
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	return msg
}

func (c *Call) buildBYEForResponseLocked(resp sip.Message, reason string) sip.Message {
	state := c.service.reg.State()
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), c.targetURI)
	msg := sip.NewRequest("BYE", targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", nonEmpty(resp.Header("To"), c.remoteTo))
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("Session-ID", c.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d BYE", atomic.AddInt64(&c.service.cseq, 1)))
	msg.Headers.Add("Contact", contactValue(state))
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	c.service.reg.DialogRequestPolicy(reverseValues(resp.HeadersByName("Record-Route"))).Apply(&msg)
	return msg
}

func (c *Call) buildDialogRequestLocked(method string) sip.Message {
	state := c.service.reg.State()
	msg := sip.NewRequest(method, c.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", c.remoteTo)
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("Session-ID", c.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", atomic.AddInt64(&c.service.cseq, 1), method))
	msg.Headers.Add("Contact", contactValue(state))
	c.service.reg.DialogRequestPolicy(c.routeSet).Apply(&msg)
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
		c.finish(StateFailed, err.Error())
		return fmt.Errorf("answering call: %w", err)
	}
	c.mu.Lock()
	c.inviteOK = resp
	c.mu.Unlock()
	c.setState(StateAnswering, "")
	c.startInviteOKRetransmit(req, resp)
	return nil
}

func (c *Call) buildInviteOK(msg sip.Message, body []byte) (sip.Message, error) {
	ok := sip.NewResponse(200, "OK")
	ok.Headers = sip.ResponseHeaders(msg, 200)
	c.service.addAccessNetworkInfo(&ok)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), c.localURI, c.localTag))
	ok.Headers.Add("Session-ID", c.sessionID)
	ok.Headers.Add("Contact", contactValue(c.service.reg.State()))
	ok.Headers.Add("Allow", sip.DefaultClientAllow)
	ok.Headers.Add("Accept", callAcceptHeader(c.service.cfg))
	addInviteOKSessionTimer(&ok, msg, c.service.cfg)
	if len(body) != 0 {
		if err := setInviteResponseBody(&ok, c.service.cfg, c.localURI, body); err != nil {
			return sip.Message{}, err
		}
	}
	return ok, nil
}

func (c *Call) setState(state State, cause string) {
	c.mu.Lock()
	if c.state == state && cause == "" {
		c.mu.Unlock()
		return
	}
	c.state = state
	id := c.id
	c.mu.Unlock()
	c.service.emit(Event{CallID: id, State: state, Cause: cause, At: time.Now()})
}

func (c *Call) finish(state State, cause string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	id := c.id
	emit := c.state != state || cause != ""
	c.state = state
	attachment := c.dialogAttachment
	stop := c.inviteOKStop
	ringbackStop := c.ringbackStop
	ringingStop := c.ringingStop
	mediaStop := c.mediaWatchStop
	provisionalReady := c.provisionalReady
	c.inviteOKStop = nil
	c.ringbackStop = nil
	c.ringingStop = nil
	c.mediaActivity = nil
	c.mediaWatchStop = nil
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
	if provisionalReady != nil {
		close(provisionalReady)
	}
	if attachment != nil {
		_ = attachment.Close()
	}
	_ = c.closeMedia()
	c.service.removeCall(id)
	if emit {
		c.service.emit(Event{CallID: id, State: state, Cause: cause, At: time.Now()})
	}
}
