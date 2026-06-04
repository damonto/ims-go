package voice

import (
	"context"
	"errors"
	"fmt"
	"net"
)

func (c *Call) openEarlyMedia(ctx context.Context, answer sdpOffer) error {
	negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
	if !ok {
		return errors.New("handling provisional call answer: no compatible codec")
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.service.cfg.Codecs, negotiated.ClockRate)
	c.mu.Lock()
	current := c.media
	c.mu.Unlock()
	answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, current.PTime), dtmf, hasDTMF)
	c.mu.Lock()
	c.media = answerMedia
	c.mu.Unlock()
	if err := c.openMedia(ctx); err != nil {
		return err
	}
	c.stopRingbackTimer()
	c.startMediaInactivityWatch()
	c.setState(CallStateEarlyMedia, "")
	return nil
}

func (c *Call) prepareMedia(ctx context.Context) error {
	c.mu.Lock()
	if c.transport != nil {
		c.mu.Unlock()
		return nil
	}
	localPort := c.localPort
	media := c.media
	c.mu.Unlock()

	if c.service.cfg.PrepareMedia == nil {
		return nil
	}
	transport, err := c.service.cfg.PrepareMedia(ctx, MediaConfig{
		LocalPort: localPort,
		Media:     media,
	})
	if err != nil {
		return fmt.Errorf("preparing call media: %w", err)
	}
	if transport == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		if err := transport.Close(); err != nil {
			return fmt.Errorf("closing prepared call media: %w", err)
		}
		return nil
	}
	c.transport = transport
	c.mu.Unlock()
	return nil
}

func (c *Call) openMedia(ctx context.Context) error {
	c.mu.Lock()
	transport := c.transport
	localPort := c.localPort
	media := c.media
	c.mu.Unlock()

	cfg := MediaConfig{
		LocalPort:      localPort,
		RemoteIP:       append(net.IP(nil), media.RemoteIP...),
		RemotePort:     media.RemotePort,
		RemoteRTCPIP:   append(net.IP(nil), media.RemoteRTCPIP...),
		RemoteRTCPPort: media.RemoteRTCPPort,
		RTCPMux:        media.RTCPMux,
		Media:          media,
		OnPacket:       c.recordMediaPacket,
	}
	if transport != nil {
		if configurable, ok := transport.(mediaConfigurator); ok {
			if err := configurable.ConfigureRemote(ctx, cfg); err != nil {
				return fmt.Errorf("configuring voice media remote: %w", err)
			}
			return nil
		}
		if c.service.cfg.OpenMedia == nil {
			return nil
		}
		c.mu.Lock()
		if c.transport == transport {
			c.transport = nil
		}
		c.mu.Unlock()
		if err := transport.Close(); err != nil {
			return fmt.Errorf("closing prepared call media: %w", err)
		}
	}

	if c.service.cfg.OpenMedia == nil {
		return nil
	}
	transport, err := c.service.cfg.OpenMedia(ctx, cfg)
	if err != nil {
		return fmt.Errorf("opening call media: %w", err)
	}
	if transport == nil {
		return errors.New("opening call media: media transport is nil")
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		if err := transport.Close(); err != nil {
			return fmt.Errorf("closing opened call media: %w", err)
		}
		return nil
	}
	c.transport = transport
	c.mu.Unlock()
	return nil
}
