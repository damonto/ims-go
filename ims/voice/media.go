package voice

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

func (c *Call) openEarlyMedia(ctx context.Context, answer sdpOffer) error {
	negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
	if !ok {
		return errors.New("handling provisional call answer: no compatible codec")
	}
	dtmf, hasDTMF := chooseTelephoneEvent(answer, c.service.cfg.Codecs)
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
		if configurable, ok := transport.(interface {
			ConfigureRemote(context.Context, MediaConfig) error
		}); ok {
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

func (c *Call) recordMediaPacket(packet MediaPacket) {
	c.mu.Lock()
	activity := c.mediaActivity
	c.mu.Unlock()
	if activity == nil {
		return
	}
	select {
	case activity <- packet:
	default:
	}
}

func (c *Call) writeRTCPReport() {
	c.mu.Lock()
	transport := c.transport
	ssrc := c.rtcpSSRC
	cname := c.id
	closed := c.closed
	c.mu.Unlock()
	if closed || transport == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), callReleaseTimeout)
	defer cancel()
	packet := buildRTCPReceiverReport(ssrc, cname)
	if rtcp, ok := transport.(interface {
		WriteRTCP(context.Context, []byte) error
	}); ok {
		if err := rtcp.WriteRTCP(ctx, packet); err != nil && c.State() != CallStateEnded {
			c.service.emitError(fmt.Errorf("sending call rtcp: %w", err))
		}
		return
	}
	if c.State() != CallStateEnded {
		c.service.emitError(errors.New("sending call rtcp: media transport does not support rtcp"))
	}
}

func (c *Call) startMediaInactivityWatch() {
	rtpTimeout := *c.service.cfg.RTPInactivityTimeout
	rtcpTimeout := *c.service.cfg.RTCPInactivityTimeout
	rtcpSendInterval := *c.service.cfg.RTCPSendInterval
	endOnRTPInactivity := c.service.cfg.endsCallOnAudioInactivity(AudioInactivityRTPOnConnected)
	endOnRTCPInactivity := c.service.cfg.endsCallOnAudioInactivity(AudioInactivityRTCPOnConnected)
	if c.emergency {
		endOnRTPInactivity = c.service.cfg.endsCallOnAudioInactivity(AudioInactivityE911RTP)
		endOnRTCPInactivity = c.service.cfg.endsCallOnAudioInactivity(AudioInactivityE911RTCP)
	}
	c.mu.Lock()
	if c.mediaWatchStop != nil || c.closed {
		c.mu.Unlock()
		return
	}
	media := c.media
	transport := c.transport
	if media.RTCPDisabled {
		rtcpTimeout = 0
		rtcpSendInterval = 0
	}
	if rtcpSendInterval > 0 {
		if _, ok := transport.(interface {
			WriteRTCP(context.Context, []byte) error
		}); !ok {
			rtcpSendInterval = 0
		}
	}
	activity := make(chan MediaPacket, 16)
	stop := make(chan struct{})
	c.mediaActivity = activity
	c.mediaWatchStop = stop
	c.mu.Unlock()

	go func() {
		var rtpTimer *time.Timer
		var rtpC <-chan time.Time
		if rtpTimeout > 0 {
			rtpTimer = time.NewTimer(rtpTimeout)
			rtpC = rtpTimer.C
			defer rtpTimer.Stop()
		}
		var rtcpTimer *time.Timer
		var rtcpC <-chan time.Time
		if rtcpTimeout > 0 {
			rtcpTimer = time.NewTimer(rtcpTimeout)
			rtcpC = rtcpTimer.C
			defer rtcpTimer.Stop()
		}
		var rtcpSendTicker *time.Ticker
		var rtcpSendC <-chan time.Time
		if rtcpSendInterval > 0 {
			c.writeRTCPReport()
			rtcpSendTicker = time.NewTicker(rtcpSendInterval)
			rtcpSendC = rtcpSendTicker.C
			defer rtcpSendTicker.Stop()
		}
		for {
			select {
			case <-stop:
				return
			case packet := <-activity:
				if packet.RTCP {
					if packet.RTCPBye {
						c.endAfterMediaEvent(mediaReleaseRTCPBye)
						return
					}
					if rtcpTimer != nil {
						resetTimer(rtcpTimer, rtcpTimeout)
					}
				} else if rtpTimer != nil {
					resetTimer(rtpTimer, rtpTimeout)
				}
			case <-rtpC:
				if endOnRTPInactivity {
					c.endAfterMediaEvent(mediaReleaseRTPTimeout)
					return
				}
				c.noteMediaInactivity(mediaReleaseRTPTimeout, rtpTimeout)
				if rtpTimer != nil {
					resetTimer(rtpTimer, rtpTimeout)
				}
			case <-rtcpC:
				if endOnRTCPInactivity {
					c.endAfterMediaEvent(mediaReleaseRTCPTimeout)
					return
				}
				c.noteMediaInactivity(mediaReleaseRTCPTimeout, rtcpTimeout)
				if rtcpTimer != nil {
					resetTimer(rtcpTimer, rtcpTimeout)
				}
			case <-rtcpSendC:
				c.writeRTCPReport()
			}
		}
	}()
}

func (c *Call) noteMediaInactivity(reason mediaReleaseReason, timeout time.Duration) {
	c.mu.Lock()
	id := c.id
	state := c.state
	c.mu.Unlock()
	c.service.logger.Debug("call media inactivity", "call_id", id, "state", state, "reason", reason.cause(), "timeout", timeout)
}

func (c *Call) endAfterMediaEvent(reason mediaReleaseReason) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	state := c.state
	c.mu.Unlock()

	_ = c.closeMedia()
	cause := reason.cause()
	if state == CallStateActive || state == CallStateConfirmed {
		c.setState(CallStateEnding, cause)
		ctx, cancel := context.WithTimeout(context.Background(), callReleaseTimeout)
		resp, err := c.service.sess.Exchange(ctx, c.buildBYE(reason.sipReason()))
		cancel()
		if !byeReleaseCompleted(resp, err) {
			c.service.emitError(byeReleaseError("ending call after media event", resp, err))
		}
	}
	c.finish(CallStateEnded, cause)
}

func (c *Call) closeMedia() error {
	c.mu.Lock()
	transport := c.transport
	c.transport = nil
	c.mu.Unlock()
	if transport == nil {
		return nil
	}
	return transport.Close()
}

func (c *Call) mediaTransport(action string) (MediaTransport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, fmt.Errorf("%s: call is closed", action)
	}
	if c.transport == nil {
		return nil, fmt.Errorf("%s: media transport is not configured", action)
	}
	return c.transport, nil
}
