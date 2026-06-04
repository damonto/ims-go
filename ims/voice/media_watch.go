package voice

import (
	"errors"
	"fmt"
	"time"
)

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
	c.mu.Lock()
	held := callIsHeld(c.hold)
	emergency := c.emergency
	c.mu.Unlock()
	if held {
		rtpTimeout = 0
		endOnRTPInactivity = false
		endOnRTCPInactivity = c.service.cfg.endsCallOnAudioInactivity(AudioInactivityRTCPOnHold)
	} else if emergency {
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
		if _, ok := transport.(rtcpWriter); !ok {
			rtcpSendInterval = 0
		}
	}
	activity := make(chan MediaPacket, 16)
	stop := make(chan struct{})
	c.mediaActivity = activity
	c.mediaWatchStop = stop
	c.mu.Unlock()

	c.service.startBackgroundTask(func(done <-chan struct{}) {
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
	c.service.logger.Debug("call media inactivity", "call_id", id, "state", state, "reason", reason.cause(), "timeout", timeout)
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
		c.service.logger.Debug("call media release before confirmed dialog", "call_id", c.id, "state", state, "reason", cause)
		return
	}
	c.setState(CallStateEnding, cause)
	ctx, cancel := contextWithDoneTimeout(done, callReleaseTimeout)
	resp, err := c.service.sess.Exchange(ctx, c.buildBYE(reason.sipReason()))
	cancel()
	if !byeReleaseCompleted(resp, err) {
		c.service.emitError(byeReleaseError("ending call after media event", resp, err))
	}
	c.finish(CallStateEnded, cause)
}
