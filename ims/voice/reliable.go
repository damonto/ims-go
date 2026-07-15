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

func (c *Call) handlePRACK(ctx context.Context, req session.Request) error {
	c.mu.Lock()
	delayedOffer := c.delayedOffer
	prackAnsweredOffer := c.prackAnsweredOffer
	provisionalAnswer := c.provisionalAnswer
	state := c.state
	media := c.media
	localPort := c.localPort
	inviteReq := c.incomingRequest
	pending := c.pendingReliable
	c.mu.Unlock()

	var rack rackHeader
	if err := rack.UnmarshalText([]byte(req.Message.Header("RAck"))); err != nil {
		return c.endpoint.writeStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	if !pending.matches(rack) {
		return c.endpoint.writeStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
	}

	answeringDelayedOffer := delayedOffer && !prackAnsweredOffer && state == CallStateRinging && pending.status == sipStatusSessionProgress
	acknowledgingProvisionalAnswer := !delayedOffer && !provisionalAnswer && state == CallStateRinging && pending.status == sipStatusSessionProgress
	var prackAnswer []byte
	var preconditionUpdate sip.Message
	if answeringDelayedOffer {
		body, ok := sdpBody(req.Message)
		if !ok {
			if err := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(CallStateFailed, "missing PRACK SDP answer")
			return nil
		}
		var answer sdpOffer
		if err := answer.UnmarshalBinary(body); err != nil {
			if writeErr := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			c.finish(CallStateFailed, err.Error())
			return nil
		}
		negotiated, ok := chooseCodec(answer, c.endpoint.cfg.Codecs)
		if !ok {
			if err := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(CallStateFailed, "no compatible PRACK answer codec")
			return nil
		}
		if err := c.acceptRemotePayloadMappings(answer); err != nil {
			if writeErr := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			c.finish(CallStateFailed, err.Error())
			return nil
		}
		dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.endpoint.cfg.Codecs, negotiated.ClockRate)
		answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, media.PTime), nonZeroDuration(answer.MaxPTime, media.MaxPTime, c.endpoint.cfg.MaxPTime), dtmf, hasDTMF)
		c.mu.Lock()
		c.media = answerMedia
		c.prackAnsweredOffer = true
		c.mu.Unlock()
		if c.endpoint.cfg.Preconditions && answer.Preconditions && answer.RemoteQoSConfirmation {
			body, err := buildSDPPreconditionUpdate(c.endpoint.cfg, c.endpoint.localIP(), localPort, answer, answerMedia)
			if err != nil {
				if writeErr := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
					return writeErr
				}
				return nil
			}
			c.mu.Lock()
			c.localSDP = append([]byte(nil), body...)
			snap := c.dialogSnapshot()
			c.mu.Unlock()
			preconditionUpdate = snap.buildPreconditionUPDATE(c.nextCSeq(), body)
		}
		if err := c.openMedia(ctx); err != nil {
			c.finish(CallStateFailed, err.Error())
			c.signalProvisionalReady()
			return nil
		}
		c.startMediaInactivityWatch()
	} else if body, ok := sdpBody(req.Message); ok {
		var offer sdpOffer
		if err := offer.UnmarshalBinary(body); err != nil {
			if writeErr := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			return nil
		}
		answer, answerMedia, err := buildSDPAnswer(c.endpoint.cfg, c.endpoint.localIP(), localPort, offer, MediaOffer{})
		if err != nil {
			if writeErr := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			return nil
		}
		if err := c.acceptRemotePayloadMappings(offer); err != nil {
			if writeErr := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			return nil
		}
		c.mu.Lock()
		c.remoteOffer = offer
		c.media = answerMedia
		c.localSDP = append([]byte(nil), answer...)
		c.mu.Unlock()
		prackAnswer = answer
	}

	if err := c.endpoint.writePRACKOK(ctx, req, prackAnswer); err != nil {
		return err
	}
	c.clearReliableProvisional(rack.rseq)
	if preconditionUpdate.StartLine != "" {
		c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
			c.sendPreconditionUPDATE(done, preconditionUpdate)
		})
	}
	if acknowledgingProvisionalAnswer {
		c.mu.Lock()
		c.provisionalAnswer = true
		c.mu.Unlock()
		if err := c.prepareMedia(ctx); err != nil {
			c.finish(CallStateFailed, err.Error())
			c.signalProvisionalReady()
			if inviteReq != nil {
				return c.endpoint.writeStatus(ctx, *inviteReq, sipStatusNotAcceptableHere, "Not Acceptable Here")
			}
			return nil
		}
	}
	if (answeringDelayedOffer || acknowledgingProvisionalAnswer) && inviteReq != nil {
		if err := c.endpoint.writeRinging(ctx, *inviteReq, c); err != nil {
			c.signalProvisionalReady()
			return err
		}
		c.startRingingTimer()
	}
	c.signalProvisionalReady()
	return nil
}

func (c *Call) sendPRACK(done <-chan struct{}, prack sip.Message, next sip.Message) {
	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	defer cancel()
	resp, err := c.endpoint.sess.Exchange(ctx, prack)
	if err != nil {
		c.endpoint.emitError(fmt.Errorf("sending call PRACK: %w", err))
		return
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.endpoint.emitError(fmt.Errorf("sending call PRACK: expected 2xx, got %w", sip.NewResponseError(resp)))
		return
	}
	if next.StartLine == "" {
		return
	}
	resp, err = c.endpoint.sess.Exchange(ctx, next)
	if err != nil {
		c.endpoint.emitError(fmt.Errorf("sending precondition UPDATE: %w", err))
		return
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.endpoint.emitError(fmt.Errorf("sending precondition UPDATE: expected 2xx, got %w", sip.NewResponseError(resp)))
	}
}

func (c *Call) sendPreconditionUPDATE(done <-chan struct{}, update sip.Message) {
	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	defer cancel()
	resp, err := c.endpoint.sess.Exchange(ctx, update)
	if err != nil {
		c.endpoint.emitError(fmt.Errorf("sending precondition UPDATE: %w", err))
		return
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.endpoint.emitError(fmt.Errorf("sending precondition UPDATE: expected 2xx, got %w", sip.NewResponseError(resp)))
	}
}

func (s dialogSnapshot) buildPRACKForResponse(resp sip.Message, cseq int64, remoteTarget string, routes []string) (sip.Message, error) {
	var rseq rseqHeader
	if err := rseq.UnmarshalText([]byte(resp.Header("RSeq"))); err != nil {
		return sip.Message{}, err
	}
	targetURI := nonEmpty(remoteTarget, sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), s.targetURI)
	msg := sip.NewRequest("PRACK", targetURI)
	s.addDialogHeaders(&msg, "PRACK", cseq)
	msg.Headers.Set("To", nonEmpty(resp.Header("To"), s.remoteTo))
	rack := rackHeader{rseq: int64(rseq), cseq: s.inviteSeq, method: "INVITE"}
	text, err := rack.MarshalText()
	if err != nil {
		return sip.Message{}, err
	}
	msg.Headers.Add("RAck", string(text))
	msg.Headers.Add("Contact", s.contact)
	s.applyRequestPolicy(&msg, routes)
	return msg, nil
}

type rseqHeader int64

const (
	rseqInitialMax = 1<<31 - 1
	sipSequenceMax = 1<<32 - 1
)

func (h rseqHeader) MarshalText() ([]byte, error) {
	if h <= 0 || h > sipSequenceMax {
		return nil, fmt.Errorf("building PRACK: invalid RSeq %d", h)
	}
	return []byte(strconv.FormatInt(int64(h), 10)), nil
}

func (h *rseqHeader) UnmarshalText(text []byte) error {
	value := string(text)
	rseq, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || rseq == 0 {
		return fmt.Errorf("building PRACK: invalid RSeq %q", value)
	}
	*h = rseqHeader(rseq)
	return nil
}

func (h rackHeader) MarshalText() ([]byte, error) {
	if h.rseq <= 0 || h.rseq > sipSequenceMax {
		return nil, fmt.Errorf("building PRACK: invalid RAck RSeq %d", h.rseq)
	}
	if h.cseq <= 0 || h.cseq > sipSequenceMax {
		return nil, fmt.Errorf("building PRACK: invalid RAck CSeq %d", h.cseq)
	}
	method := strings.TrimSpace(h.method)
	if method == "" {
		return nil, fmt.Errorf("building PRACK: invalid RAck method %q", h.method)
	}
	return fmt.Appendf(nil, "%d %d %s", h.rseq, h.cseq, method), nil
}

func (h *rackHeader) UnmarshalText(text []byte) error {
	value := string(text)
	fields := strings.Fields(value)
	if len(fields) != 3 {
		return fmt.Errorf("handling PRACK: invalid RAck %q", value)
	}
	rseq, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil || rseq == 0 {
		return fmt.Errorf("handling PRACK: invalid RAck RSeq %q", value)
	}
	cseq, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || cseq == 0 {
		return fmt.Errorf("handling PRACK: invalid RAck CSeq %q", value)
	}
	method := strings.TrimSpace(fields[2])
	if method == "" {
		return fmt.Errorf("handling PRACK: invalid RAck method %q", value)
	}
	*h = rackHeader{rseq: int64(rseq), cseq: int64(cseq), method: method}
	return nil
}

func (p reliableProvisional) matches(rack rackHeader) bool {
	return p.rseq == rack.rseq && p.cseq == rack.cseq && p.method == rack.method
}

func isReliableProvisional(msg sip.Message) bool {
	if msg.StatusCode() <= sipStatusTrying || msg.StatusCode() >= sipStatusOK {
		return false
	}
	if strings.TrimSpace(msg.Header("RSeq")) == "" {
		return false
	}
	return tokenHeaderContains(msg, "Require", reliableProvisionalOption)
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

func tokenHeaderContains(msg sip.Message, name string, want string) bool {
	for _, value := range msg.HeadersByName(name) {
		if sip.TokenListContains(value, want) {
			return true
		}
	}
	return false
}

func routeSetFromResponse(msg sip.Message) []string {
	routes := reverseValues(msg.HeadersByName("Record-Route"))
	if routes == nil {
		return []string{}
	}
	return routes
}

func cloneSIPMessage(msg sip.Message) sip.Message {
	msg.Headers = msg.Headers.Clone()
	msg.Body = append([]byte(nil), msg.Body...)
	return msg
}

func (c *Call) beginReliableProvisional(status int, cseq int64, method string) int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nextRSeq == 0 {
		c.nextRSeq = initialReliableRSeq() - 1
	}
	c.nextRSeq++
	if status == sipStatusSessionProgress && c.provisionalReady == nil {
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

func initialReliableRSeq() int64 {
	return rand.Int64N(rseqInitialMax) + 1
}

func nextReliableProvisionalRetransmitInterval(interval time.Duration) time.Duration {
	// RFC 3262 reliable 1xx retransmissions double until the 64*T1 deadline;
	// unlike INVITE 2xx retransmissions, they are not capped at T2.
	return interval * 2
}

func (c *Call) clearReliableProvisional(rseq int64) {
	c.mu.Lock()
	var stop chan struct{}
	if c.pendingReliable.rseq == rseq {
		c.pendingReliable = reliableProvisional{}
		c.reliableResponse = sip.Message{}
		stop = c.reliableStop
		c.reliableStop = nil
	}
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (c *Call) pendingReliableProvisionalResponse() (sip.Message, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pendingReliable.rseq == 0 || c.reliableResponse.StartLine == "" {
		return sip.Message{}, false
	}
	return cloneSIPMessage(c.reliableResponse), true
}

func (c *Call) waitForReliableProvisionalAnswer(ctx context.Context) error {
	for {
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return errors.New("answering call: call is closed")
		}
		wait := c.direction == CallDirectionIncoming &&
			c.state == CallStateRinging &&
			c.pendingReliable.status == sipStatusSessionProgress &&
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

func (c *Call) recordReliableProvisional(msg sip.Message) (bool, error) {
	tag := sip.HeaderTag(msg.Header("To"))
	if tag == "" {
		return false, errors.New("handling reliable provisional response: missing To tag")
	}
	var rseq rseqHeader
	if err := rseq.UnmarshalText([]byte(msg.Header("RSeq"))); err != nil {
		return false, err
	}
	if c.reliableRSeq == nil {
		c.reliableRSeq = make(map[string]int64)
	}
	last, ok := c.reliableRSeq[tag]
	current := int64(rseq)
	if !ok {
		if current > rseqInitialMax {
			return false, fmt.Errorf("handling reliable provisional response: initial RSeq %d exceeds %d", current, rseqInitialMax)
		}
		c.reliableRSeq[tag] = current
		return true, nil
	}
	if current <= last {
		return false, nil
	}
	if current != last+1 {
		return false, nil
	}
	c.reliableRSeq[tag] = current
	return true, nil
}
