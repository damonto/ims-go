package call

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"strconv"
	"strings"
	"sync/atomic"
)

func (c *Call) handlePRACK(ctx context.Context, req session.Request) error {
	c.mu.Lock()
	delayedOffer := c.delayedOffer
	prackAnsweredOffer := c.prackAnsweredOffer
	provisionalAnswer := c.provisionalAnswer
	state := c.state
	media := c.media
	inviteReq := c.incomingRequest
	pending := c.pendingReliable
	c.mu.Unlock()

	rack, err := parseRAck(req.Message.Header("RAck"))
	if err != nil {
		return c.service.writeStatus(ctx, req, 400, "Bad Request")
	}
	if !pending.matches(rack) {
		return c.service.writeStatus(ctx, req, 481, "Call/Transaction Does Not Exist")
	}

	answeringDelayedOffer := delayedOffer && !prackAnsweredOffer && state == StateRinging && pending.status == 183
	acknowledgingProvisionalAnswer := !delayedOffer && !provisionalAnswer && state == StateRinging && pending.status == 183
	if answeringDelayedOffer {
		body, ok := sdpBody(req.Message)
		if !ok {
			if err := c.service.writeStatus(ctx, req, 488, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(StateFailed, "missing PRACK SDP answer")
			return nil
		}
		answer, err := parseSDP(body)
		if err != nil {
			if writeErr := c.service.writeStatus(ctx, req, 488, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			c.finish(StateFailed, err.Error())
			return nil
		}
		negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
		if !ok {
			if err := c.service.writeStatus(ctx, req, 488, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(StateFailed, "no compatible PRACK answer codec")
			return nil
		}
		dtmf, hasDTMF := chooseTelephoneEvent(answer, c.service.cfg.Codecs)
		answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, media.PTime), dtmf, hasDTMF)
		c.mu.Lock()
		c.media = answerMedia
		c.prackAnsweredOffer = true
		c.mu.Unlock()
		if err := c.openMedia(ctx); err != nil {
			c.finish(StateFailed, err.Error())
			c.signalProvisionalReady()
			return nil
		}
		c.startMediaInactivityWatch()
	}

	if err := c.service.writeStatus(ctx, req, 200, "OK"); err != nil {
		return err
	}
	c.clearReliableProvisional(rack.rseq)
	if acknowledgingProvisionalAnswer {
		c.mu.Lock()
		c.provisionalAnswer = true
		c.mu.Unlock()
		if err := c.prepareMedia(ctx); err != nil {
			c.finish(StateFailed, err.Error())
			c.signalProvisionalReady()
			if inviteReq != nil {
				return c.service.writeStatus(ctx, *inviteReq, 488, "Not Acceptable Here")
			}
			return nil
		}
	}
	if (answeringDelayedOffer || acknowledgingProvisionalAnswer) && inviteReq != nil {
		if err := c.service.writeRinging(ctx, *inviteReq, c); err != nil {
			c.signalProvisionalReady()
			return err
		}
		c.startRingingTimer()
	}
	c.signalProvisionalReady()
	return nil
}

func (c *Call) sendPRACK(prack sip.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), callReleaseTimeout)
	defer cancel()
	resp, err := c.service.sess.Exchange(ctx, prack)
	if err != nil {
		c.service.emitError(fmt.Errorf("sending call PRACK: %w", err))
		return
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		c.service.emitError(fmt.Errorf("sending call PRACK: expected 2xx, got %w", sip.NewResponseError(resp)))
	}
}

func (c *Call) beginReliableProvisional(status int, cseq int64, method string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextRSeq++
	if status == 183 && c.provisionalReady == nil {
		c.provisionalReady = make(chan struct{})
	}
	c.pendingReliable = reliableProvisional{
		rseq:   c.nextRSeq,
		cseq:   cseq,
		method: strings.ToUpper(strings.TrimSpace(method)),
		status: status,
	}
	return c.nextRSeq
}

func (c *Call) clearReliableProvisional(rseq int64) {
	c.mu.Lock()
	if c.pendingReliable.rseq == rseq {
		c.pendingReliable = reliableProvisional{}
	}
	c.mu.Unlock()
}

func (c *Call) waitForReliableProvisionalAnswer(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return errors.New("answering call: call is closed")
		}
		wait := c.direction == DirectionIncoming &&
			c.state == StateRinging &&
			c.pendingReliable.status == 183 &&
			((c.delayedOffer && !c.prackAnsweredOffer) || (!c.delayedOffer && !c.provisionalAnswer))
		ch := c.provisionalReady
		if wait && ch == nil {
			ch = make(chan struct{})
			c.provisionalReady = ch
		}
		c.mu.Unlock()
		if !wait {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("answering call: waiting for PRACK: %w", ctx.Err())
		case <-ch:
		}
	}
}

func (c *Call) signalProvisionalReady() {
	c.mu.Lock()
	ch := c.provisionalReady
	c.provisionalReady = nil
	c.mu.Unlock()
	if ch != nil {
		close(ch)
	}
}

func (c *Call) buildPRACKForResponseLocked(resp sip.Message) (sip.Message, error) {
	rseq, err := parseRSeq(resp.Header("RSeq"))
	if err != nil {
		return sip.Message{}, err
	}
	state := c.service.reg.State()
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), c.targetURI)
	msg := sip.NewRequest("PRACK", targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", nonEmpty(resp.Header("To"), c.remoteTo))
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("Session-ID", c.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d PRACK", atomic.AddInt64(&c.service.cseq, 1)))
	msg.Headers.Add("RAck", fmt.Sprintf("%d %d INVITE", rseq, c.inviteSeq))
	msg.Headers.Add("Contact", contactValue(state))
	c.service.reg.DialogRequestPolicy(reverseValues(resp.HeadersByName("Record-Route"))).Apply(&msg)
	return msg, nil
}

func isReliableProvisional(msg sip.Message) bool {
	if strings.TrimSpace(msg.Header("RSeq")) == "" {
		return false
	}
	return tokenHeaderContains(msg, "Require", "100rel")
}

func hasEarlyMediaHeader(msg sip.Message) bool {
	for _, value := range msg.HeadersByName("P-Early-Media") {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

func earlyMediaAuthorized(msg sip.Message) bool {
	for _, value := range msg.HeadersByName("P-Early-Media") {
		for _, token := range strings.FieldsFunc(value, func(r rune) bool {
			return r == ',' || r == ';' || r == ' ' || r == '\t'
		}) {
			switch strings.ToLower(strings.TrimSpace(token)) {
			case "sendrecv", "sendonly":
				return true
			}
		}
	}
	return false
}

func provisionalResponseKey(msg sip.Message) string {
	rseq := strings.TrimSpace(msg.Header("RSeq"))
	if rseq == "" {
		return ""
	}
	return sip.HeaderTag(msg.Header("To")) + "|" + rseq
}

func parseRSeq(value string) (int64, error) {
	rseq, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || rseq <= 0 {
		return 0, fmt.Errorf("building PRACK: invalid RSeq %q", value)
	}
	return rseq, nil
}

func parseRAck(value string) (rackHeader, error) {
	fields := strings.Fields(value)
	if len(fields) != 3 {
		return rackHeader{}, fmt.Errorf("handling PRACK: invalid RAck %q", value)
	}
	rseq, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil || rseq <= 0 {
		return rackHeader{}, fmt.Errorf("handling PRACK: invalid RAck RSeq %q", value)
	}
	cseq, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || cseq <= 0 {
		return rackHeader{}, fmt.Errorf("handling PRACK: invalid RAck CSeq %q", value)
	}
	method := strings.ToUpper(strings.TrimSpace(fields[2]))
	if method == "" {
		return rackHeader{}, fmt.Errorf("handling PRACK: invalid RAck method %q", value)
	}
	return rackHeader{rseq: rseq, cseq: cseq, method: method}, nil
}

func (p reliableProvisional) matches(rack rackHeader) bool {
	return p.rseq == rack.rseq && p.cseq == rack.cseq && strings.EqualFold(p.method, rack.method)
}

func tokenHeaderContains(msg sip.Message, name string, want string) bool {
	for _, value := range msg.HeadersByName(name) {
		if sip.TokenListContains(value, want) {
			return true
		}
	}
	return false
}
