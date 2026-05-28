package call

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/ims-client/ims/sip"
	"net"
)

func (c *Call) ID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id
}

func (c *Call) Media() NegotiatedMedia {
	c.mu.Lock()
	defer c.mu.Unlock()
	media := c.media
	media.RemoteIP = append(net.IP(nil), media.RemoteIP...)
	return media
}

func (c *Call) Answer(ctx context.Context, offer MediaOffer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := c.waitForReliableProvisionalAnswer(ctx); err != nil {
		return err
	}

	c.mu.Lock()
	if c.direction != DirectionIncoming {
		c.mu.Unlock()
		return errors.New("answering call: call is not incoming")
	}
	if c.state != StateRinging {
		c.mu.Unlock()
		return fmt.Errorf("answering call: call state is %s", c.state)
	}
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("answering call: incoming request is missing")
	}
	remoteOffer := c.remoteOffer
	localPort := c.localPort
	prackAnsweredOffer := c.prackAnsweredOffer
	provisionalAnswer := c.provisionalAnswer
	c.mu.Unlock()

	var (
		answer []byte
		media  NegotiatedMedia
		err    error
	)
	if c.delayedOffer && prackAnsweredOffer {
		// The delayed offer/answer exchange completed in reliable provisional response + PRACK.
	} else if provisionalAnswer {
		// The INVITE offer was already answered in a provisional response.
	} else if c.delayedOffer {
		answer, media, err = buildSDPOffer(c.service.cfg, c.service.localIP(), localPort, offer)
	} else {
		answer, media, err = buildSDPAnswer(c.service.cfg, c.service.localIP(), localPort, remoteOffer, offer)
	}
	if err != nil {
		return err
	}
	if !prackAnsweredOffer && !provisionalAnswer {
		c.mu.Lock()
		c.media = media
		c.mu.Unlock()
	}
	if c.delayedOffer && prackAnsweredOffer {
		// Media was opened after the PRACK SDP answer.
	} else if c.delayedOffer {
		if err := c.prepareMedia(ctx); err != nil {
			return err
		}
	} else {
		if err := c.openMedia(ctx); err != nil {
			return err
		}
		c.startMediaInactivityWatch()
	}
	c.stopRingingTimer()
	return c.writeInviteOK(ctx, answer)
}

func (c *Call) Reject(ctx context.Context, code int, reason string) error {
	if code == 0 {
		code = 486
	}
	if reason == "" {
		reason = "Busy Here"
	}
	c.mu.Lock()
	if c.direction != DirectionIncoming {
		c.mu.Unlock()
		return errors.New("rejecting call: call is not incoming")
	}
	if c.state != StateRinging {
		c.mu.Unlock()
		return fmt.Errorf("rejecting call: call state is %s", c.state)
	}
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("rejecting call: incoming request is missing")
	}
	req := *c.incomingRequest
	c.mu.Unlock()
	c.stopRingingTimer()
	if err := c.service.writeStatus(ctx, req, code, reason); err != nil {
		return fmt.Errorf("rejecting call: %w", err)
	}
	c.finish(StateEnded, reason)
	return nil
}

func (c *Call) Hangup(ctx context.Context) error {
	c.mu.Lock()
	state := c.state
	direction := c.direction
	c.mu.Unlock()

	if direction == DirectionIncoming && state == StateRinging {
		return c.Reject(ctx, 486, "Busy Here")
	}
	if direction == DirectionOutgoing && (state == StateDialing || state == StateRinging || state == StateEarlyMedia) {
		return c.cancelOutgoingInvite(ctx)
	}
	if state == StateEnding || state == StateEnded {
		return nil
	}
	if state != StateActive && state != StateConfirmed {
		return fmt.Errorf("hanging up call: call state is %s", state)
	}
	c.setState(StateEnding, "")
	_ = c.closeMedia()
	resp, err := c.service.sess.Exchange(ctx, c.buildBYE(reasonUserTriggered))
	if err != nil {
		c.finish(StateFailed, err.Error())
		return fmt.Errorf("hanging up call: %w", err)
	}
	if resp.StatusCode() != 200 {
		err := fmt.Errorf("hanging up call: expected 200, got %w", sip.NewResponseError(resp))
		c.finish(StateFailed, err.Error())
		return err
	}
	c.finish(StateEnded, "")
	return nil
}

func (c *Call) cancelOutgoingInvite(ctx context.Context) error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	if c.direction != DirectionOutgoing || (c.state != StateDialing && c.state != StateRinging && c.state != StateEarlyMedia) {
		state := c.state
		c.mu.Unlock()
		return fmt.Errorf("cancelling call: call state is %s", state)
	}
	if !c.inviteResponse {
		c.cancelOnResponse = true
		c.mu.Unlock()
		c.stopRingbackTimer()
		c.setState(StateEnding, "cancelled")
		_ = c.closeMedia()
		return nil
	}
	if c.cancelSent {
		c.mu.Unlock()
		return nil
	}
	c.cancelSent = true
	cancel := c.buildCANCELLocked(reasonUserTriggered)
	c.mu.Unlock()

	c.setState(StateEnding, "cancelled")
	c.stopRingbackTimer()
	_ = c.closeMedia()
	return c.exchangeCancel(ctx, cancel)
}

func (c *Call) exchangeCancel(ctx context.Context, cancel sip.Message) error {
	resp, err := c.service.sess.Exchange(ctx, cancel)
	if err != nil {
		return fmt.Errorf("cancelling call: %w", err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		return fmt.Errorf("cancelling call: expected 2xx, got %w", sip.NewResponseError(resp))
	}
	return nil
}

func (c *Call) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	transport, err := c.mediaTransport("reading call media")
	if err != nil {
		return nil, nil, err
	}
	return transport.ReadPacket(ctx)
}

func (c *Call) WritePacket(ctx context.Context, data []byte) error {
	transport, err := c.mediaTransport("writing call media")
	if err != nil {
		return err
	}
	return transport.WritePacket(ctx, data)
}

func (c *Call) ReadRTP(ctx context.Context) ([]byte, net.Addr, error) {
	return c.ReadPacket(ctx)
}

func (c *Call) WriteRTP(ctx context.Context, data []byte) error {
	return c.WritePacket(ctx, data)
}

func (c *Call) ReadRTCP(ctx context.Context) ([]byte, net.Addr, error) {
	transport, err := c.mediaTransport("reading call rtcp")
	if err != nil {
		return nil, nil, err
	}
	if rtcp, ok := transport.(interface {
		ReadRTCP(context.Context) ([]byte, net.Addr, error)
	}); ok {
		return rtcp.ReadRTCP(ctx)
	}
	return nil, nil, errors.New("reading call rtcp: media transport does not support rtcp")
}

func (c *Call) WriteRTCP(ctx context.Context, data []byte) error {
	transport, err := c.mediaTransport("writing call rtcp")
	if err != nil {
		return err
	}
	if rtcp, ok := transport.(interface {
		WriteRTCP(context.Context, []byte) error
	}); ok {
		return rtcp.WriteRTCP(ctx, data)
	}
	return errors.New("writing call rtcp: media transport does not support rtcp")
}
