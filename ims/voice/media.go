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
	sentAt := time.Now()
	c.mu.Lock()
	c.rtpSend = rtpSendState{
		initialized:   true,
		ssrc:          packet.SSRC,
		nextSequence:  packet.SequenceNumber + 1,
		nextTimestamp: packet.Timestamp + mediaFrameTicks(media),
	}
	c.rtcpSend.packetCount++
	c.rtcpSend.octetCount += uint32(len(packet.Payload))
	c.rtcpSend.lastRTPTimestamp = packet.Timestamp
	c.rtcpSend.lastRTPSentAt = sentAt
	c.rtcpSend.lastRTPClockRate = media.ClockRate
	c.rtcpSend.reportsWithoutRTP = 0
	c.mu.Unlock()
}

func rtcpSenderTimestamp(state rtcpSendState, now time.Time) uint32 {
	if state.lastRTPSentAt.IsZero() || state.lastRTPClockRate <= 0 {
		return state.lastRTPTimestamp
	}
	elapsed := now.Sub(state.lastRTPSentAt)
	if elapsed <= 0 {
		return state.lastRTPTimestamp
	}
	seconds := uint64(elapsed / time.Second)
	fraction := uint64(elapsed % time.Second)
	ticks := seconds*uint64(state.lastRTPClockRate) + fraction*uint64(state.lastRTPClockRate)/uint64(time.Second)
	return state.lastRTPTimestamp + uint32(ticks)
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
	if !packet.RTCP && packet.RTPPayloadBytes > 0 {
		c.recordRTPReceiveLocked(packet)
	}
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

func (c *Call) recordRTPReceiveLocked(packet MediaPacket) {
	r := &c.rtcpRecv
	now := time.Now()
	rate := c.media.ClockRate
	arrival := int64(0)
	if rate > 0 {
		nanos := now.UnixNano()
		arrival = nanos/int64(time.Second)*int64(rate) + nanos%int64(time.Second)*int64(rate)/int64(time.Second)
	}
	if r.initialized && r.ssrc != packet.RTPSSRC {
		*r = rtcpReceiveState{}
	}
	if !r.initialized {
		r.initialized = true
		r.ssrc = packet.RTPSSRC
		r.baseSequence = packet.RTPSequenceNumber
		r.maxSequence = packet.RTPSequenceNumber
		r.received = 1
		if rate > 0 {
			r.transit = arrival - int64(packet.RTPTimestamp)
		}
		r.lastArrival = now
		return
	}
	if packet.RTPSequenceNumber < r.maxSequence {
		if r.maxSequence-packet.RTPSequenceNumber > 0x8000 {
			r.cycles += 1 << 16
			r.maxSequence = packet.RTPSequenceNumber
		}
	} else if packet.RTPSequenceNumber-r.maxSequence < 0x8000 {
		r.maxSequence = packet.RTPSequenceNumber
	}
	r.received++
	if rate > 0 && !r.lastArrival.IsZero() {
		transit := arrival - int64(packet.RTPTimestamp)
		delta := transit - r.transit
		if delta < 0 {
			delta = -delta
		}
		r.jitter += uint32((delta - int64(r.jitter)) / 16)
		r.transit = transit
	}
	r.lastArrival = now
}

func (c *Call) writeRTCPReport(done <-chan struct{}) {
	c.mu.Lock()
	now := time.Now()
	transport := c.transport
	ssrc := c.rtcpSSRC
	if c.rtpSend.initialized {
		ssrc = c.rtpSend.ssrc
	}
	cname := c.id
	closed := c.closed
	if closed || transport == nil {
		c.mu.Unlock()
		return
	}
	block := c.rtcpReceiverReportBlockLocked()
	var packet []byte
	if c.rtcpSend.packetCount != 0 && c.rtcpSend.reportsWithoutRTP < 2 {
		timestamp := rtcpSenderTimestamp(c.rtcpSend, now)
		packet = buildRTCPSenderReport(ssrc, cname, now, timestamp, c.rtcpSend.packetCount, c.rtcpSend.octetCount, block)
	} else {
		packet = buildRTCPReceiverReportWithBlock(ssrc, cname, block)
	}
	c.rtcpSend.reportsWithoutRTP++
	c.mu.Unlock()

	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	defer cancel()
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

func (c *Call) rtcpReceiverReportBlockLocked() []byte {
	r := c.rtcpRecv
	if !r.initialized {
		return nil
	}
	extendedMax := r.cycles + uint32(r.maxSequence)
	expected := extendedMax - uint32(r.baseSequence) + 1
	lost := int64(expected) - int64(r.received)
	if lost < 0 {
		lost = 0
	}
	block := make([]byte, 24)
	binary.BigEndian.PutUint32(block[0:4], r.ssrc)
	expectedInterval := expected - r.expectedPrior
	receivedInterval := r.received - r.receivedPrior
	lostInterval := int64(expectedInterval) - int64(receivedInterval)
	if expectedInterval > 0 && lostInterval > 0 {
		fraction := min(int64(255), lostInterval*256/int64(expectedInterval))
		block[4] = byte(fraction)
	}
	c.rtcpRecv.expectedPrior = expected
	c.rtcpRecv.receivedPrior = r.received
	lost24 := uint32(min(lost, 0x7fffff))
	block[5] = byte(lost24 >> 16)
	block[6] = byte(lost24 >> 8)
	block[7] = byte(lost24)
	binary.BigEndian.PutUint32(block[8:12], extendedMax)
	binary.BigEndian.PutUint32(block[12:16], r.jitter)
	return block
}

func (c *Call) startMediaInactivityWatch() {
	rtpTimeout := *c.endpoint.cfg.RTPInactivityTimeout
	rtcpTimeout := *c.endpoint.cfg.RTCPInactivityTimeout
	intervalFor := c.endpoint.rtcpInterval
	if intervalFor == nil {
		intervalFor = rtcpInterval
	}
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
	rtcpSendInterval := intervalFor(media)
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

func rtcpInterval(media NegotiatedMedia) time.Duration {
	bandwidth := media.RTCPReceiverBandwidth
	if bandwidth <= 0 {
		bandwidth = media.RTCPSenderBandwidth
	}
	if bandwidth <= 0 {
		return 5 * time.Second
	}
	const members = 2
	const compoundBytes = 64
	interval := time.Duration(float64(compoundBytes*8*members) / float64(bandwidth) * float64(time.Second))
	return max(interval, 5*time.Second)
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
