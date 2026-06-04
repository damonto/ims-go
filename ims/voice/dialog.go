package voice

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
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
