package voice

import (
	"context"
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

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
	c.service.startBackgroundTask(func(done <-chan struct{}) {
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
	c.service.startBackgroundTask(func(done <-chan struct{}) {
		c.sendCancel(done, cancel)
	})
}

func (c *Call) sendCancel(done <-chan struct{}, cancel sip.Message) {
	ctx, stop := contextWithDoneTimeout(done, callReleaseTimeout)
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
