package voice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

func (c *Call) openEarlyMedia(ctx context.Context, answer sdpOffer) error {
	negotiated, ok := chooseCodec(answer, c.endpoint.cfg.Codecs)
	if !ok {
		return errors.New("handling provisional call answer: no compatible codec")
	}
	if err := c.acceptRemotePayloadMappings(answer); err != nil {
		return fmt.Errorf("handling provisional call answer: %w", err)
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.endpoint.cfg.Codecs, negotiated.ClockRate)
	c.mu.Lock()
	current := c.media
	c.mu.Unlock()
	answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, current.PTime), nonZeroDuration(answer.MaxPTime, current.MaxPTime, c.endpoint.cfg.MaxPTime), dtmf, hasDTMF)
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

func (c *Call) mediaTransport(action callAction) (MediaTransport, error) {
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

func (c *Call) prepareMedia(ctx context.Context) error {
	c.mu.Lock()
	if c.transport != nil {
		c.mu.Unlock()
		return nil
	}
	localPort := c.localPort
	media := c.media
	localSDP := append([]byte(nil), c.localSDP...)
	c.mu.Unlock()

	if c.endpoint.cfg.PrepareMedia == nil {
		return nil
	}
	transport, err := c.endpoint.cfg.PrepareMedia(ctx, MediaConfig{
		LocalPort:        localPort,
		LocalDescription: descriptionFromLocalSDP(localSDP),
		Media:            cloneNegotiatedMedia(media),
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
	localSDP := append([]byte(nil), c.localSDP...)
	c.mu.Unlock()

	cfg := MediaConfig{
		LocalPort:        localPort,
		LocalDescription: descriptionFromLocalSDP(localSDP),
		RemoteIP:         append(net.IP(nil), media.RemoteIP...),
		RemotePort:       media.RemotePort,
		RemoteRTCPIP:     append(net.IP(nil), media.RemoteRTCPIP...),
		RemoteRTCPPort:   media.RemoteRTCPPort,
		RTCPMux:          media.RTCPMux,
		Media:            cloneNegotiatedMedia(media),
		OnPacket:         c.recordMediaPacket,
	}
	c.endpoint.emitMedia(c, media)
	if transport != nil {
		if configurable, ok := transport.(MediaTransportConfigurer); ok {
			if err := configurable.ConfigureRemote(ctx, cfg); err != nil {
				return fmt.Errorf("configuring voice media remote: %w", err)
			}
			return nil
		}
		if c.endpoint.cfg.OpenMedia == nil {
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

	if c.endpoint.cfg.OpenMedia == nil {
		return nil
	}
	transport, err := c.endpoint.cfg.OpenMedia(ctx, cfg)
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

func descriptionFromLocalSDP(body []byte) MediaDescription {
	if len(body) == 0 {
		return MediaDescription{}
	}
	var description MediaDescription
	if err := description.UnmarshalBinary(body); err != nil {
		return MediaDescription{RawSDP: append([]byte(nil), body...)}
	}
	return description
}

func (c *Call) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	transport, err := c.mediaTransport(callActionReadMedia)
	if err != nil {
		return nil, nil, err
	}
	return transport.ReadPacket(ctx)
}

func (c *Call) WritePacket(ctx context.Context, data []byte) error {
	c.mediaSendMu.Lock()
	defer c.mediaSendMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("writing call media: call is closed")
	}
	if c.transport == nil {
		c.mu.Unlock()
		return errors.New("writing call media: media transport is not configured")
	}
	if holdHasLocal(c.hold) || localMediaSendBlocked(c.media.Direction) {
		c.mu.Unlock()
		return errors.New("writing call media: call is on hold")
	}
	transport := c.transport
	media := c.media
	c.mu.Unlock()
	wire, sent, ok, err := c.prepareOutgoingRTPPacket(data)
	if err != nil {
		return err
	}
	if err := transport.WritePacket(ctx, wire); err != nil {
		return err
	}
	if ok {
		c.saveRTPSendState(sent, media)
	}
	return nil
}

func (c *Call) ReadRTP(ctx context.Context) ([]byte, net.Addr, error) {
	return c.ReadPacket(ctx)
}

func (c *Call) WriteRTP(ctx context.Context, data []byte) error {
	return c.WritePacket(ctx, data)
}

func (c *Call) prepareOutgoingRTPPacket(data []byte) ([]byte, RTPPacket, bool, error) {
	var packet RTPPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return data, RTPPacket{}, false, nil
	}
	c.mu.Lock()
	rtp := c.rtpSend
	if rtp.initialized {
		packet.SSRC = rtp.ssrc
		packet.SequenceNumber = rtp.nextSequence
		packet.Timestamp = rtp.nextTimestamp
	}
	c.mu.Unlock()
	if !rtp.initialized {
		return data, packet, true, nil
	}
	wire := rewriteRTPHeader(data, packet)
	return wire, packet, true, nil
}

func rewriteRTPHeader(data []byte, packet RTPPacket) []byte {
	wire := append([]byte(nil), data...)
	binary.BigEndian.PutUint16(wire[2:4], packet.SequenceNumber)
	binary.BigEndian.PutUint32(wire[4:8], packet.Timestamp)
	binary.BigEndian.PutUint32(wire[8:12], packet.SSRC)
	return wire
}

func (c *Call) saveRTPSendState(packet RTPPacket, media NegotiatedMedia) {
	c.mu.Lock()
	c.rtpSend = rtpSendState{
		initialized:   true,
		ssrc:          packet.SSRC,
		nextSequence:  packet.SequenceNumber + 1,
		nextTimestamp: packet.Timestamp + mediaFrameTicks(media),
	}
	c.mu.Unlock()
}

func (c *Call) ReadRTCP(ctx context.Context) ([]byte, net.Addr, error) {
	transport, err := c.mediaTransport(callActionReadRTCP)
	if err != nil {
		return nil, nil, err
	}
	if rtcp, ok := transport.(rtcpReader); ok {
		return rtcp.ReadRTCP(ctx)
	}
	return nil, nil, errors.New("reading call rtcp: media transport does not support rtcp")
}

func (c *Call) WriteRTCP(ctx context.Context, data []byte) error {
	transport, err := c.mediaTransport(callActionWriteRTCP)
	if err != nil {
		return err
	}
	if rtcp, ok := transport.(rtcpWriter); ok {
		return rtcp.WriteRTCP(ctx, data)
	}
	return errors.New("writing call rtcp: media transport does not support rtcp")
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

func (c *Call) writeRTCPReport(done <-chan struct{}) {
	c.mu.Lock()
	transport := c.transport
	ssrc := c.rtcpSSRC
	cname := c.id
	closed := c.closed
	c.mu.Unlock()
	if closed || transport == nil {
		return
	}

	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	defer cancel()
	packet := buildRTCPReceiverReport(ssrc, cname)
	if rtcp, ok := transport.(rtcpWriter); ok {
		if err := rtcp.WriteRTCP(ctx, packet); err != nil && c.State() != CallStateEnded {
			c.endpoint.emitError(fmt.Errorf("sending call rtcp: %w", err))
		}
		return
	}
	if c.State() != CallStateEnded {
		c.endpoint.emitError(errors.New("sending call rtcp: media transport does not support rtcp"))
	}
}

func (c *Call) startMediaInactivityWatch() {
	rtpTimeout := *c.endpoint.cfg.RTPInactivityTimeout
	rtcpTimeout := *c.endpoint.cfg.RTCPInactivityTimeout
	rtcpSendInterval := *c.endpoint.cfg.RTCPSendInterval
	endOnRTPInactivity := c.endpoint.cfg.endsCallOnAudioInactivity(AudioInactivityRTPOnConnected)
	endOnRTCPInactivity := c.endpoint.cfg.endsCallOnAudioInactivity(AudioInactivityRTCPOnConnected)
	c.mu.Lock()
	held := callIsHeld(c.hold)
	emergency := c.emergency
	c.mu.Unlock()
	if held {
		rtpTimeout = 0
		endOnRTPInactivity = false
		endOnRTCPInactivity = c.endpoint.cfg.endsCallOnAudioInactivity(AudioInactivityRTCPOnHold)
	} else if emergency {
		endOnRTPInactivity = c.endpoint.cfg.endsCallOnAudioInactivity(AudioInactivityE911RTP)
		endOnRTCPInactivity = c.endpoint.cfg.endsCallOnAudioInactivity(AudioInactivityE911RTCP)
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
		if _, ok := transport.(rtcpWriter); !ok {
			rtcpSendInterval = 0
		}
	}
	activity := make(chan MediaPacket, 16)
	stop := make(chan struct{})
	c.mediaActivity = activity
	c.mediaWatchStop = stop
	c.mu.Unlock()

	c.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		c.runMediaInactivityWatch(mediaWatch{
			done:                done,
			stop:                stop,
			activity:            activity,
			rtpTimeout:          rtpTimeout,
			rtcpTimeout:         rtcpTimeout,
			rtcpSendInterval:    rtcpSendInterval,
			endOnRTPInactivity:  endOnRTPInactivity,
			endOnRTCPInactivity: endOnRTCPInactivity,
		})
	})
}

type mediaWatch struct {
	done                <-chan struct{}
	stop                <-chan struct{}
	activity            <-chan MediaPacket
	rtpTimeout          time.Duration
	rtcpTimeout         time.Duration
	rtcpSendInterval    time.Duration
	endOnRTPInactivity  bool
	endOnRTCPInactivity bool
}

func (c *Call) runMediaInactivityWatch(w mediaWatch) {
	var rtpTimer *time.Timer
	var rtpC <-chan time.Time
	if w.rtpTimeout > 0 {
		rtpTimer = time.NewTimer(w.rtpTimeout)
		rtpC = rtpTimer.C
		defer rtpTimer.Stop()
	}
	var rtcpTimer *time.Timer
	var rtcpC <-chan time.Time
	if w.rtcpTimeout > 0 {
		rtcpTimer = time.NewTimer(w.rtcpTimeout)
		rtcpC = rtcpTimer.C
		defer rtcpTimer.Stop()
	}
	var rtcpSendTicker *time.Ticker
	var rtcpSendC <-chan time.Time
	if w.rtcpSendInterval > 0 {
		c.writeRTCPReport(w.done)
		rtcpSendTicker = time.NewTicker(w.rtcpSendInterval)
		rtcpSendC = rtcpSendTicker.C
		defer rtcpSendTicker.Stop()
	}
	for {
		select {
		case <-w.done:
			return
		case <-w.stop:
			return
		case packet := <-w.activity:
			if packet.RTCP {
				if packet.RTCPBye {
					c.endAfterMediaEvent(w.done, mediaReleaseRTCPBye)
					return
				}
				if rtcpTimer != nil {
					resetTimer(rtcpTimer, w.rtcpTimeout)
				}
			} else if rtpTimer != nil {
				resetTimer(rtpTimer, w.rtpTimeout)
			}
		case <-rtpC:
			if w.endOnRTPInactivity {
				c.endAfterMediaEvent(w.done, mediaReleaseRTPTimeout)
				return
			}
			c.noteMediaInactivity(mediaReleaseRTPTimeout, w.rtpTimeout)
			if rtpTimer != nil {
				resetTimer(rtpTimer, w.rtpTimeout)
			}
		case <-rtcpC:
			if w.endOnRTCPInactivity {
				c.endAfterMediaEvent(w.done, mediaReleaseRTCPTimeout)
				return
			}
			c.noteMediaInactivity(mediaReleaseRTCPTimeout, w.rtcpTimeout)
			if rtcpTimer != nil {
				resetTimer(rtcpTimer, w.rtcpTimeout)
			}
		case <-rtcpSendC:
			c.writeRTCPReport(w.done)
		}
	}
}

func (c *Call) restartMediaInactivityWatch() {
	c.mu.Lock()
	stop := c.mediaWatchStop
	c.mediaWatchStop = nil
	c.mediaActivity = nil
	closed := c.closed
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if !closed {
		c.startMediaInactivityWatch()
	}
}

func (c *Call) noteMediaInactivity(reason mediaReleaseReason, timeout time.Duration) {
	c.mu.Lock()
	id := c.id
	state := c.state
	c.mu.Unlock()
	c.endpoint.logger.Debug("call media inactivity", "call_id", id, "state", state, "reason", reason.cause(), "timeout", timeout)
}

func (c *Call) endAfterMediaEvent(done <-chan struct{}, reason mediaReleaseReason) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	state := c.state
	stop := c.mediaWatchStop
	c.mediaWatchStop = nil
	c.mediaActivity = nil
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}

	_ = c.closeMedia()
	cause := reason.cause()
	if state != CallStateActive && state != CallStateConfirmed {
		c.endpoint.logger.Debug("call media release before confirmed dialog", "call_id", c.id, "state", state, "reason", cause)
		return
	}
	c.setState(CallStateEnding, cause)
	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	resp, err := c.endpoint.sess.Exchange(ctx, c.buildBYE(reason.sipReason()))
	cancel()
	if !byeReleaseCompleted(resp, err) {
		c.endpoint.emitError(byeReleaseError(callActionEndAfterMediaEvent, resp, err))
	}
	c.finish(CallStateEnded, cause)
}
