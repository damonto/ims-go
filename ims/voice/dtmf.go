package voice

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	defaultDTMFDuration = 100 * time.Millisecond
	minDTMFDuration     = 65 * time.Millisecond
	defaultDTMFPause    = 65 * time.Millisecond
	defaultDTMFVolume   = 10
	maxDTMFVolume       = 63
	dtmfPayloadSize     = 4
	dtmfEndRepeats      = 3
)

type DTMFRequest struct {
	Digits   string
	Duration time.Duration
	Pause    time.Duration
	Volume   int
}

func (c *Call) SendDTMF(ctx context.Context, req DTMFRequest) error {
	req.Digits = strings.TrimSpace(req.Digits)
	if req.Digits == "" {
		return errors.New("sending dtmf: digits are empty")
	}
	duration := req.Duration
	if duration == 0 {
		duration = defaultDTMFDuration
	}
	if duration < 0 {
		return errors.New("sending dtmf: duration must be >= 0")
	}
	duration = max(duration, minDTMFDuration)

	pause := req.Pause
	if pause == 0 {
		pause = defaultDTMFPause
	}
	if pause < 0 {
		return errors.New("sending dtmf: pause must be >= 0")
	}
	volume := req.Volume
	if volume == 0 {
		volume = defaultDTMFVolume
	}
	if volume < 0 || volume > maxDTMFVolume {
		return fmt.Errorf("sending dtmf: volume %d is outside 0..%d", volume, maxDTMFVolume)
	}
	events := make([]byte, 0, len(req.Digits))
	for i := range len(req.Digits) {
		event, ok := dtmfEventCode(req.Digits[i])
		if !ok {
			return fmt.Errorf("sending dtmf: unsupported digit %q", req.Digits[i])
		}
		events = append(events, event)
	}

	c.mediaSendMu.Lock()
	defer c.mediaSendMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("sending dtmf: call is closed")
	}
	state := c.state
	if state != CallStateEarlyMedia && state != CallStateConfirmed && state != CallStateActive {
		c.mu.Unlock()
		return fmt.Errorf("sending dtmf: call state is %s", state)
	}
	if c.transport == nil {
		c.mu.Unlock()
		return errors.New("sending dtmf: media transport is not configured")
	}
	if holdHasLocal(c.hold) || localMediaSendBlocked(c.media.Direction) {
		c.mu.Unlock()
		return errors.New("sending dtmf: call is on hold")
	}
	media := c.media
	if !media.HasDTMF {
		c.mu.Unlock()
		return errors.New("sending dtmf: telephone-event was not negotiated")
	}
	if media.DTMFClockRate <= 0 {
		c.mu.Unlock()
		return errors.New("sending dtmf: dtmf clock rate is not configured")
	}
	if media.ClockRate > 0 && media.DTMFClockRate != media.ClockRate {
		c.mu.Unlock()
		return fmt.Errorf("sending dtmf: dtmf clock rate %d does not match speech clock rate %d", media.DTMFClockRate, media.ClockRate)
	}
	transport := c.transport
	rtp := c.rtpSend
	if !rtp.initialized {
		rtp = rtpSendState{
			initialized:   true,
			ssrc:          randomRTCPSSRC(),
			nextSequence:  uint16(randomRTCPSSRC()),
			nextTimestamp: randomRTCPSSRC(),
		}
	}
	c.mu.Unlock()
	saveRTP := true
	defer func() {
		if !saveRTP {
			return
		}
		c.mu.Lock()
		c.rtpSend = rtp
		c.mu.Unlock()
	}()
	eventMask := dtmfEventMaskOrDefault(media.DTMFEventMask)
	for _, event := range events {
		if !dtmfEventMaskContains(eventMask, event) {
			return fmt.Errorf("sending dtmf: event %d was not negotiated", event)
		}
	}

	frameDuration := mediaFrameDuration(media)
	duration = normalizeDTMFInterval(duration, frameDuration)
	pause = normalizeDTMFInterval(pause, frameDuration)
	frameTicks := mediaFrameTicks(media)
	if frameTicks == 0 {
		frameTicks = uint32(durationTicks(defaultPTime, media.DTMFClockRate))
	}
	eventTicks := durationTicks(duration, media.DTMFClockRate)
	if eventTicks > 0xffff {
		saveRTP = false
		return errors.New("sending dtmf: duration exceeds one telephone-event segment")
	}
	pauseTicks := durationTicks(pause, media.DTMFClockRate)
	for i, event := range events {
		err := c.sendDTMFEvent(ctx, transport, media, &rtp, event, byte(volume), uint16(eventTicks), frameTicks)
		rtp.nextTimestamp += uint32(eventTicks + pauseTicks)
		if err != nil {
			return err
		}
		if i != len(events)-1 && pause > 0 {
			if err := waitContext(ctx, pause); err != nil {
				return fmt.Errorf("sending dtmf: %w", err)
			}
		}
	}
	return nil
}

func (c *Call) sendDTMFEvent(ctx context.Context, transport MediaTransport, media NegotiatedMedia, rtp *rtpSendState, event byte, volume byte, totalTicks uint16, frameTicks uint32) error {
	timestamp := rtp.nextTimestamp
	elapsed := frameTicks
	first := true
	for elapsed < uint32(totalTicks) {
		if err := c.writeDTMFRTPPacket(ctx, transport, media, rtp, timestamp, event, volume, uint16(elapsed), false, first); err != nil {
			return err
		}
		first = false
		if err := waitContext(ctx, mediaFrameDuration(media)); err != nil {
			return fmt.Errorf("sending dtmf: %w", err)
		}
		elapsed += frameTicks
	}
	for i := range dtmfEndRepeats {
		if err := c.writeDTMFRTPPacket(ctx, transport, media, rtp, timestamp, event, volume, totalTicks, true, first); err != nil {
			return err
		}
		first = false
		if i == dtmfEndRepeats-1 {
			break
		}
		if err := waitContext(ctx, mediaFrameDuration(media)); err != nil {
			return fmt.Errorf("sending dtmf: %w", err)
		}
	}
	return nil
}

func (c *Call) writeDTMFRTPPacket(ctx context.Context, transport MediaTransport, media NegotiatedMedia, rtp *rtpSendState, timestamp uint32, event byte, volume byte, duration uint16, end bool, marker bool) error {
	payload := buildDTMFPayload(event, volume, duration, end)
	wire, err := (RTPPacket{
		PayloadType:    media.DTMFPayloadType,
		SequenceNumber: rtp.nextSequence,
		Timestamp:      timestamp,
		SSRC:           rtp.ssrc,
		Marker:         marker,
		Payload:        payload,
	}).MarshalBinary()
	if err != nil {
		return fmt.Errorf("sending dtmf: %w", err)
	}
	if err := transport.WritePacket(ctx, wire); err != nil {
		return fmt.Errorf("sending dtmf: %w", err)
	}
	rtp.nextSequence++
	return nil
}

func buildDTMFPayload(event byte, volume byte, duration uint16, end bool) []byte {
	payload := make([]byte, dtmfPayloadSize)
	payload[0] = event
	payload[1] = volume & maxDTMFVolume
	if end {
		payload[1] |= 0x80
	}
	binary.BigEndian.PutUint16(payload[2:], duration)
	return payload
}

func dtmfEventCode(digit byte) (byte, bool) {
	switch digit {
	case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return digit - '0', true
	case '*':
		return 10, true
	case '#':
		return 11, true
	case 'A', 'a':
		return 12, true
	case 'B', 'b':
		return 13, true
	case 'C', 'c':
		return 14, true
	case 'D', 'd':
		return 15, true
	default:
		return 0, false
	}
}

func dtmfEventMaskContains(mask uint16, event byte) bool {
	if event >= 16 {
		return false
	}
	return mask&(1<<event) != 0
}

func mediaFrameTicks(media NegotiatedMedia) uint32 {
	rate := media.ClockRate
	if rate <= 0 {
		rate = media.DTMFClockRate
	}
	return uint32(durationTicks(mediaFrameDuration(media), rate))
}

func normalizeDTMFInterval(duration time.Duration, frame time.Duration) time.Duration {

	duration = max(duration, minDTMFDuration)

	if frame <= 0 {
		frame = defaultPTime
	}
	remainder := duration % frame
	if remainder == 0 {
		return duration
	}
	return duration + frame - remainder
}

func mediaFrameDuration(media NegotiatedMedia) time.Duration {
	if media.PTime > 0 {
		return media.PTime
	}
	return defaultPTime
}

func durationTicks(duration time.Duration, clockRate int) int64 {
	return int64(duration) * int64(clockRate) / int64(time.Second)
}

func waitContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return nil
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
