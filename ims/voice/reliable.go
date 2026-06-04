package voice

import (
	"context"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
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
		return c.service.writeStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	if !pending.matches(rack) {
		return c.service.writeStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
	}

	answeringDelayedOffer := delayedOffer && !prackAnsweredOffer && state == CallStateRinging && pending.status == sipStatusSessionProgress
	acknowledgingProvisionalAnswer := !delayedOffer && !provisionalAnswer && state == CallStateRinging && pending.status == sipStatusSessionProgress
	var prackAnswer []byte
	var preconditionUpdate sip.Message
	if answeringDelayedOffer {
		body, ok := sdpBody(req.Message)
		if !ok {
			if err := c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(CallStateFailed, "missing PRACK SDP answer")
			return nil
		}
		answer, err := parseSDP(body)
		if err != nil {
			if writeErr := c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			c.finish(CallStateFailed, err.Error())
			return nil
		}
		negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
		if !ok {
			if err := c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); err != nil {
				return err
			}
			c.finish(CallStateFailed, "no compatible PRACK answer codec")
			return nil
		}
		dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.service.cfg.Codecs, negotiated.ClockRate)
		answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, media.PTime), dtmf, hasDTMF)
		c.mu.Lock()
		c.media = answerMedia
		c.prackAnsweredOffer = true
		c.mu.Unlock()
		if c.service.cfg.Preconditions && answer.Preconditions && answer.RemoteQoSConfirmation {
			body, err := buildSDPPreconditionUpdate(c.service.cfg, c.service.localIP(), localPort, answer, answerMedia)
			if err != nil {
				if writeErr := c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
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
		offer, err := parseSDP(body)
		if err != nil {
			if writeErr := c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
				return writeErr
			}
			return nil
		}
		answer, answerMedia, err := buildSDPAnswer(c.service.cfg, c.service.localIP(), localPort, offer, MediaOffer{})
		if err != nil {
			if writeErr := c.service.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here"); writeErr != nil {
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

	if err := c.service.writePRACKOK(ctx, req, prackAnswer); err != nil {
		return err
	}
	c.clearReliableProvisional(rack.rseq)
	if preconditionUpdate.StartLine != "" {
		c.service.startBackgroundTask(func(done <-chan struct{}) {
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
				return c.service.writeStatus(ctx, *inviteReq, sipStatusNotAcceptableHere, "Not Acceptable Here")
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
