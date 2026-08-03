package voice

import (
	"context"
	"encoding"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

type outgoingPreconditionUpdate struct {
	response     sip.Message
	answer       sdpOffer
	media        NegotiatedMedia
	remoteTarget string
	routes       []string
}

type outgoingPRACKFollowup struct {
	openEarlyMedia bool
	earlyMedia     sdpOffer
	precondition   *outgoingPreconditionUpdate
}

type incomingPRACKFollowup struct {
	answeringDelayedOffer          bool
	acknowledgingProvisionalAnswer bool
	delayedAnswer                  sdpOffer
	delayedAnswerMedia             NegotiatedMedia
	inviteRequest                  *session.Request
}

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
	cfg := c.sdpConfig()

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
	var delayedAnswer sdpOffer
	var delayedAnswerMedia NegotiatedMedia
	if answeringDelayedOffer {
		body, ok := sdpBody(req.Message)
		if !ok {
			if err := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(CallStateFailed, "missing PRACK SDP answer")
			return nil
		}
		if err := delayedAnswer.UnmarshalText(body); err != nil {
			if writeErr := c.endpoint.writeSDPFailure(ctx, req, body, err); writeErr != nil {
				return writeErr
			}
			c.finish(CallStateFailed, err.Error())
			return nil
		}
		if cfg.Preconditions && !delayedAnswer.Preconditions {
			if err := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(CallStateFailed, "PRACK SDP answer omitted negotiated preconditions")
			return nil
		}
		negotiated, ok := chooseCodec(delayedAnswer, cfg.Codecs)
		if !ok {
			if err := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(CallStateFailed, "no compatible PRACK answer codec")
			return nil
		}
		if err := c.acceptRemotePayloadMappings(delayedAnswer); err != nil {
			if writeErr := c.endpoint.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			c.finish(CallStateFailed, err.Error())
			return nil
		}
		dtmf, hasDTMF := chooseTelephoneEventForClock(delayedAnswer, cfg.Codecs, negotiated.ClockRate)
		delayedAnswerMedia = negotiatedMedia(delayedAnswer, negotiated, nonZeroDuration(delayedAnswer.PTime, media.PTime), nonZeroDuration(delayedAnswer.MaxPTime, media.MaxPTime, cfg.MaxPTime), dtmf, hasDTMF)
		c.mu.Lock()
		c.media = delayedAnswerMedia
		c.remoteSDP = append([]byte(nil), body...)
		if delayedAnswer.Preconditions {
			desired := strongerQoSDesiredStatus(invertQoSDesiredStatus(delayedAnswer.DesiredQoS), c.incomingQoS.desired)
			c.incomingQoS = incomingQoSState{
				desired:      desired,
				remoteStatus: invertQoSStatus(delayedAnswer.LocalQoSStatus),
			}
		}
		c.incomingUnknown = incomingUnknownPreconditions(delayedAnswer)
		c.mu.Unlock()
	} else if body, ok := sdpBody(req.Message); ok {
		var offer sdpOffer
		if err := offer.UnmarshalText(body); err != nil {
			if writeErr := c.endpoint.writeSDPFailure(ctx, req, body, err); writeErr != nil {
				return writeErr
			}
			return nil
		}
		answer, answerMedia, err := buildSDPAnswer(cfg, c.endpoint.localIP(), localPort, offer, MediaOffer{})
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
		c.remoteSDP = append([]byte(nil), body...)
		c.media = answerMedia
		c.localSDP = append([]byte(nil), answer...)
		c.mu.Unlock()
		prackAnswer = answer
	}

	if err := c.endpoint.writePRACKOK(ctx, req, prackAnswer); err != nil {
		return err
	}
	needsFollowup := answeringDelayedOffer || acknowledgingProvisionalAnswer
	if needsFollowup {
		c.mu.Lock()
		c.provisionalCompleting = true
		c.mu.Unlock()
	}
	c.clearReliableProvisional(rack.rseq)
	if !needsFollowup {
		c.signalProvisionalReady()
		return nil
	}
	followup := incomingPRACKFollowup{
		answeringDelayedOffer:          answeringDelayedOffer,
		acknowledgingProvisionalAnswer: acknowledgingProvisionalAnswer,
		delayedAnswer:                  delayedAnswer,
		delayedAnswerMedia:             delayedAnswerMedia,
		inviteRequest:                  inviteReq,
	}
	if !c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		c.completeIncomingPRACK(done, followup)
	}) {
		c.mu.Lock()
		c.provisionalCompleting = false
		c.mu.Unlock()
		c.signalProvisionalReady()
	}
	return nil
}

func (c *Call) completeIncomingPRACK(done <-chan struct{}, followup incomingPRACKFollowup) {
	defer func() {
		c.mu.Lock()
		c.provisionalCompleting = false
		c.mu.Unlock()
		c.signalProvisionalReady()
	}()

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

	if followup.answeringDelayedOffer {
		if err := c.openMedia(ctx); err != nil {
			c.failIncomingMedia(ctx, followup.inviteRequest, err, false)
			return
		}
		c.startMediaInactivityWatch()
		if c.preconditions || c.endpoint.cfg.WaitMediaReady != nil {
			if err := c.confirmMediaResources(ctx, followup.delayedAnswerMedia); err != nil {
				c.failIncomingMedia(ctx, followup.inviteRequest, err, c.preconditions)
				return
			}
		}
		if c.preconditions && followup.delayedAnswer.RemoteQoSConfirmation {
			if err := c.sendIncomingPreconditionUPDATE(ctx, followup.delayedAnswer, followup.delayedAnswerMedia); err != nil {
				c.failIncomingMedia(ctx, followup.inviteRequest, err, true)
				return
			}
		}
	}

	if followup.acknowledgingProvisionalAnswer {
		if err := c.prepareMedia(ctx); err != nil {
			c.failIncomingMedia(ctx, followup.inviteRequest, err, false)
			return
		}
		c.mu.Lock()
		preparedMedia := cloneNegotiatedMedia(c.media)
		preparedOffer := c.remoteOffer
		c.mu.Unlock()
		if c.preconditions || c.endpoint.cfg.WaitMediaReady != nil {
			if err := c.confirmMediaResources(ctx, preparedMedia); err != nil {
				c.failIncomingMedia(ctx, followup.inviteRequest, err, c.preconditions)
				return
			}
		}
		if c.preconditions && preparedOffer.RemoteQoSConfirmation {
			if err := c.sendIncomingPreconditionUPDATE(ctx, preparedOffer, preparedMedia); err != nil {
				c.failIncomingMedia(ctx, followup.inviteRequest, err, true)
				return
			}
		}
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if followup.answeringDelayedOffer {
		c.prackAnsweredOffer = true
	}
	if followup.acknowledgingProvisionalAnswer {
		c.provisionalAnswer = true
	}
	c.incomingMediaReady = true
	c.mu.Unlock()
	if err := c.tryAlertIncoming(ctx); err != nil {
		c.endpoint.emitError(err)
		c.finish(CallStateFailed, err.Error())
	}
}

func (c *Call) sendIncomingPreconditionUPDATE(ctx context.Context, remote sdpOffer, media NegotiatedMedia) error {
	c.preconditionUpdateMu.Lock()
	defer c.preconditionUpdateMu.Unlock()
	if err := context.Cause(ctx); err != nil {
		return fmt.Errorf("sending precondition UPDATE: %w", err)
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("sending precondition UPDATE: call is closed")
	}
	localQoSStatus := c.localQoSStatus
	localPort := c.localPort
	desiredQoS := c.incomingQoS.desired
	snap := c.dialogSnapshot()
	c.mu.Unlock()
	body, err := buildSDPPreconditionUpdate(c.sdpConfig(), sdpPreconditionUpdateState{
		localIP:        c.endpoint.localIP(),
		localPort:      localPort,
		answer:         remote,
		media:          media,
		localQoSStatus: localQoSStatus,
		desiredQoS:     &desiredQoS,
	})
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("sending precondition UPDATE: call is closed")
	}
	c.localSDP = append([]byte(nil), body...)
	c.mu.Unlock()
	for attempt := range 2 {
		update := snap.buildPreconditionUPDATE(c.nextCSeq(), body)
		updateCtx, cancel := context.WithTimeout(ctx, callReleaseTimeout)
		resp, err := c.endpoint.sess.Exchange(updateCtx, update)
		cancel()
		if err != nil {
			return fmt.Errorf("sending precondition UPDATE: %w", err)
		}
		if resp.StatusCode() >= sipStatusOK && resp.StatusCode() < sipStatusMultipleChoices {
			return nil
		}
		if resp.StatusCode() != sipStatusRequestPending || attempt == 1 {
			return fmt.Errorf("sending precondition UPDATE: expected 2xx, got %w", sip.NewResponseError(resp))
		}
		if err := waitPreconditionRetry(ctx, c.endpoint.preconditionRetryDelay(c.Direction())); err != nil {
			return fmt.Errorf("sending precondition UPDATE: waiting to retry after 491: %w", err)
		}
	}
	return errors.New("sending precondition UPDATE: retry exhausted")
}

func preconditionRetryDelay(direction CallDirection) time.Duration {
	if direction == CallDirectionIncoming {
		return time.Duration(rand.Int64N(2001)) * time.Millisecond
	}
	return time.Duration(2100+rand.Int64N(1901)) * time.Millisecond
}

func waitPreconditionRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return context.Cause(ctx)
	case <-timer.C:
		return nil
	}
}

func (c *Call) sendPRACK(done <-chan struct{}, prack sip.Message, followup *outgoingPRACKFollowup) {
	prackCtx, cancelPRACK := contextWithDoneTimeout(done, callReleaseTimeout)
	resp, err := c.endpoint.sess.Exchange(prackCtx, prack)
	cancelPRACK()
	if err != nil {
		c.endpoint.emitError(fmt.Errorf("sending call PRACK: %w", err))
		return
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.endpoint.emitError(fmt.Errorf("sending call PRACK: expected 2xx, got %w", sip.NewResponseError(resp)))
		return
	}
	if followup == nil {
		return
	}
	if followup.openEarlyMedia {
		mediaCtx, cancelMedia := contextWithDone(done)
		err := c.openEarlyMedia(mediaCtx, followup.earlyMedia)
		cancelMedia()
		if err != nil {
			c.endpoint.emitError(err)
			return
		}
	}
	pending := followup.precondition
	if pending == nil {
		return
	}

	readyCtx, cancelReady := contextWithDone(done)
	if err := c.confirmMediaResources(readyCtx, pending.media); err != nil {
		cancelReady()
		c.endpoint.emitError(err)
		return
	}
	cancelReady()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	localPort := c.localPort
	localQoSStatus := c.localQoSStatus
	snap := c.dialogSnapshot()
	c.mu.Unlock()
	body, err := buildSDPPreconditionUpdate(c.endpoint.cfg, sdpPreconditionUpdateState{
		localIP:        c.endpoint.localIP(),
		localPort:      localPort,
		answer:         pending.answer,
		media:          pending.media,
		localQoSStatus: localQoSStatus,
	})
	if err != nil {
		c.endpoint.emitError(err)
		return
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.localSDP = append([]byte(nil), body...)
	c.mu.Unlock()
	next := snap.buildPreconditionUPDATEForResponse(pending.response, c.nextCSeq(), pending.remoteTarget, pending.routes, body)
	updateCtx, cancelUpdate := contextWithDoneTimeout(done, callReleaseTimeout)
	defer cancelUpdate()
	resp, err = c.endpoint.sess.Exchange(updateCtx, next)
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

var (
	_ encoding.TextAppender    = rseqHeader(0)
	_ encoding.TextMarshaler   = rseqHeader(0)
	_ encoding.TextUnmarshaler = (*rseqHeader)(nil)
	_ encoding.TextAppender    = rackHeader{}
	_ encoding.TextMarshaler   = rackHeader{}
	_ encoding.TextUnmarshaler = (*rackHeader)(nil)
)

const (
	rseqInitialMax = 1<<31 - 1
	sipSequenceMax = 1<<32 - 1
)

func (h rseqHeader) MarshalText() ([]byte, error) {
	return h.AppendText(nil)
}

func (h rseqHeader) AppendText(dst []byte) ([]byte, error) {
	if h <= 0 || h > sipSequenceMax {
		return nil, fmt.Errorf("building PRACK: invalid RSeq %d", h)
	}
	return strconv.AppendInt(dst, int64(h), 10), nil
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
	return h.AppendText(nil)
}

func (h rackHeader) AppendText(dst []byte) ([]byte, error) {
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
	return fmt.Appendf(dst, "%d %d %s", h.rseq, h.cseq, method), nil
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
	return msg.HeaderHasToken(name, want)
}

func routeSetFromResponse(msg sip.Message) []string {
	routes := reverseValues(msg.HeaderList("Record-Route"))
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
			(c.provisionalCompleting ||
				(c.pendingReliable.status == sipStatusSessionProgress &&
					((c.delayedOffer && !c.prackAnsweredOffer) || (!c.delayedOffer && !c.provisionalAnswer))))
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
