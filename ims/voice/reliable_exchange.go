package voice

import (
	"fmt"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) sendPRACK(done <-chan struct{}, prack sip.Message, next sip.Message) {
	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	defer cancel()
	resp, err := c.service.sess.Exchange(ctx, prack)
	if err != nil {
		c.service.emitError(fmt.Errorf("sending call PRACK: %w", err))
		return
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.service.emitError(fmt.Errorf("sending call PRACK: expected 2xx, got %w", sip.NewResponseError(resp)))
		return
	}
	if next.StartLine == "" {
		return
	}
	resp, err = c.service.sess.Exchange(ctx, next)
	if err != nil {
		c.service.emitError(fmt.Errorf("sending precondition UPDATE: %w", err))
		return
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.service.emitError(fmt.Errorf("sending precondition UPDATE: expected 2xx, got %w", sip.NewResponseError(resp)))
	}
}

func (c *Call) sendPreconditionUPDATE(done <-chan struct{}, update sip.Message) {
	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	defer cancel()
	resp, err := c.service.sess.Exchange(ctx, update)
	if err != nil {
		c.service.emitError(fmt.Errorf("sending precondition UPDATE: %w", err))
		return
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.service.emitError(fmt.Errorf("sending precondition UPDATE: expected 2xx, got %w", sip.NewResponseError(resp)))
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
