package voice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/sip"
)

type localHoldSnapshot struct {
	hold          CallHoldState
	localSDP      []byte
	rtcpOff       bool
	negotiatedOff bool
}

func (c *Call) HoldState() CallHoldState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return normalizeHoldState(c.hold)
}

func (c *Call) Hold(ctx context.Context) error {
	return c.modifyLocalHold(ctx, true)
}

func (c *Call) Resume(ctx context.Context) error {
	return c.modifyLocalHold(ctx, false)
}

func (c *Call) modifyLocalHold(ctx context.Context, hold bool) error {
	direction := MediaDirectionSendRecv
	action := callActionResume
	if hold {
		direction = MediaDirectionSendOnly
		action = callActionHold
	}

	snap, timer, body, previous, clearPending, err := c.beginLocalHoldModification(action, hold, direction)
	if err != nil {
		return err
	}
	if clearPending == nil {
		return nil
	}
	defer clearPending()

	req := snap.buildMediaReINVITE(c.nextCSeq(), timer, body)
	resp, err := c.exchangeSessionRefresh(ctx, req)
	if err == nil && resp.StatusCode() == sipStatusSessionIntervalTooSmall {
		resp, err = c.retrySessionRefreshesWithMinSE(ctx, req, resp)
	}
	if err != nil {
		c.restoreHoldModification(previous)
		return fmt.Errorf("%s: %w", action, err)
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.restoreHoldModification(previous)
		return fmt.Errorf("%s: expected 2xx, got %w", action, sip.NewResponseError(resp))
	}
	if err := c.acknowledgeSessionRefreshINVITE(ctx, resp); err != nil {
		c.restoreHoldModification(previous)
		return err
	}
	c.updateRemoteTargetFromResponse(resp)
	if err := c.applyMediaReINVITEAnswer(ctx, resp); err != nil {
		c.restoreHoldModification(previous)
		return fmt.Errorf("%s: %w", action, err)
	}
	if err := c.applySessionTimerUACResponse(resp, false); err != nil {
		c.restoreHoldModification(previous)
		return fmt.Errorf("%s: %w", action, err)
	}

	nextHold := setLocalHold(previous.hold, hold)
	c.mu.Lock()
	c.localSDP = append([]byte(nil), body...)
	if hold {
		c.localHoldRTCPOff = previous.negotiatedOff
	} else {
		c.localHoldRTCPOff = false
	}
	c.mu.Unlock()
	c.setHoldState(nextHold, action)
	return nil
}

func (c *Call) beginLocalHoldModification(action callAction, hold bool, direction MediaDirection) (dialogSnapshot, sessionTimerState, []byte, localHoldSnapshot, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return dialogSnapshot{}, sessionTimerState{}, nil, localHoldSnapshot{}, nil, fmt.Errorf("%s: call is closed", action)
	}
	if c.state != CallStateActive && c.state != CallStateConfirmed {
		return dialogSnapshot{}, sessionTimerState{}, nil, localHoldSnapshot{}, nil, fmt.Errorf("%s: call state is %s", action, c.state)
	}
	if c.emergency && hold && !c.endpoint.cfg.AllowHoldDuringEmergency {
		return dialogSnapshot{}, sessionTimerState{}, nil, localHoldSnapshot{}, nil, errors.New("holding call: emergency hold is disabled")
	}
	if c.localINVITEPending {
		return dialogSnapshot{}, sessionTimerState{}, nil, localHoldSnapshot{}, nil, fmt.Errorf("%s: local re-INVITE is already pending", action)
	}
	if c.remoteINVITEPending {
		return dialogSnapshot{}, sessionTimerState{}, nil, localHoldSnapshot{}, nil, fmt.Errorf("%s: remote re-INVITE is pending", action)
	}
	if holdHasLocal(c.hold) == hold {
		return dialogSnapshot{}, sessionTimerState{}, nil, localHoldSnapshot{}, nil, nil
	}

	previous := localHoldSnapshot{
		hold:          c.hold,
		localSDP:      append([]byte(nil), c.localSDP...),
		rtcpOff:       c.localHoldRTCPOff,
		negotiatedOff: c.media.RTCPDisabled || audioRTCPDisabled(c.localSDP),
	}
	body, err := c.localSDPWithDirection(direction)
	if err != nil {
		return dialogSnapshot{}, sessionTimerState{}, nil, localHoldSnapshot{}, nil, err
	}
	c.localINVITEPending = true
	clearPending := func() {
		c.mu.Lock()
		c.localINVITEPending = false
		c.mu.Unlock()
	}
	return c.dialogSnapshot(), c.sessionTimer, body, previous, clearPending, nil
}

func (c *Call) localSDPWithDirection(direction MediaDirection) ([]byte, error) {
	if len(c.localSDP) != 0 {
		body := sdpWithDirection(c.localSDP, direction, c.endpoint.cfg.Preconditions)
		if direction == MediaDirectionSendRecv && c.localHoldRTCPOff {
			body = disableAudioRTCP(body)
		}
		return body, nil
	}
	offer := MediaOffer{}
	if c.media.Codec != "" {
		offer.Codecs = []AudioCodec{c.media.Codec}
		offer.PayloadTypes = []int{c.media.PayloadType}
	}
	body, _, err := buildSDPOfferWithDirection(c.endpoint.cfg, c.endpoint.localIP(), c.localPort, offer, direction)
	if err != nil {
		return nil, err
	}
	if c.endpoint.cfg.Preconditions {
		body = sdpWithDirection(body, direction, true)
	}
	return body, nil
}

func sdpWithDirection(body []byte, direction MediaDirection, qosMet bool) []byte {
	lines := strings.FieldsFunc(string(body), func(r rune) bool { return r == '\r' || r == '\n' })
	rtcpDisabled := direction != MediaDirectionSendRecv && audioRTCPDisabledLines(lines)
	out := make([]string, 0, len(lines)+1)
	inAudio := false
	replaced := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if rtcpDisabled && inAudio && strings.EqualFold(line, "b=RR:0") {
			line = fmt.Sprintf("b=RR:%d", rtcpReceiverBandwidth)
		}
		if strings.HasPrefix(line, "m=") {
			if inAudio && !replaced {
				out = append(out, "a="+string(direction))
				replaced = true
			}
			inAudio = strings.HasPrefix(line, "m=audio ")
		}
		if inAudio && isSDPDirectionLine(line) {
			if !replaced {
				out = append(out, "a="+string(direction))
				replaced = true
			}
			continue
		}
		if inAudio && !replaced && (strings.HasPrefix(line, "a=curr:qos") || strings.HasPrefix(line, "a=des:qos") || strings.HasPrefix(line, "a=conf:qos")) {
			out = append(out, "a="+string(direction))
			replaced = true
		}
		if qosMet && inAudio {
			switch {
			case strings.HasPrefix(line, "a=curr:qos local "):
				out = append(out, "a=curr:qos local "+qosStatusSendRecv)
				continue
			case strings.HasPrefix(line, "a=curr:qos remote "):
				out = append(out, "a=curr:qos remote "+qosStatusSendRecv)
				continue
			}
		}
		out = append(out, line)
	}
	if inAudio && !replaced {
		out = append(out, "a="+string(direction))
	}
	return []byte(strings.Join(out, "\r\n") + "\r\n")
}

func audioRTCPDisabled(body []byte) bool {
	lines := strings.FieldsFunc(string(body), func(r rune) bool { return r == '\r' || r == '\n' })
	return audioRTCPDisabledLines(lines)
}

func audioRTCPDisabledLines(lines []string) bool {
	var inAudio, rsZero, rrZero bool
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "m=") {
			if inAudio && rsZero && rrZero {
				return true
			}
			inAudio = strings.HasPrefix(line, "m=audio ")
			rsZero, rrZero = false, false
			continue
		}
		if !inAudio {
			continue
		}
		modifier, bandwidth, ok, err := parseRTCPBandwidth(line)
		if err != nil || !ok || bandwidth != 0 {
			continue
		}
		rsZero = rsZero || modifier == "RS"
		rrZero = rrZero || modifier == "RR"
	}
	return inAudio && rsZero && rrZero
}

func disableAudioRTCP(body []byte) []byte {
	lines := strings.FieldsFunc(string(body), func(r rune) bool { return r == '\r' || r == '\n' })
	inAudio := false
	for i, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "m=") {
			inAudio = strings.HasPrefix(line, "m=audio ")
			continue
		}
		if !inAudio {
			continue
		}
		modifier, _, ok, err := parseRTCPBandwidth(line)
		if err == nil && ok && (modifier == "RS" || modifier == "RR") {
			lines[i] = "b=" + modifier + ":0"
		}
	}
	return []byte(strings.Join(lines, "\r\n") + "\r\n")
}

func (c *Call) restoreHoldModification(previous localHoldSnapshot) {
	c.mu.Lock()
	c.hold = previous.hold
	c.localSDP = append([]byte(nil), previous.localSDP...)
	c.localHoldRTCPOff = previous.rtcpOff
	c.mu.Unlock()
	c.restartMediaInactivityWatch()
}

func (c *Call) applyMediaReINVITEAnswer(ctx context.Context, resp sip.Message) error {
	body, ok := sdpBody(resp)
	if !ok {
		return errors.New("missing re-INVITE SDP answer")
	}
	var answer sdpOffer
	if err := answer.UnmarshalBinary(body); err != nil {
		return fmt.Errorf("parsing re-INVITE SDP answer: %w", err)
	}
	negotiated, ok := chooseCodec(answer, c.endpoint.cfg.Codecs)
	if !ok {
		return errors.New("no compatible re-INVITE answer codec")
	}
	if err := c.acceptRemotePayloadMappings(answer); err != nil {
		return fmt.Errorf("applying re-INVITE SDP answer: %w", err)
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.endpoint.cfg.Codecs, negotiated.ClockRate)
	c.mu.Lock()
	current := c.media
	c.media = negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, current.PTime), nonZeroDuration(answer.MaxPTime, current.MaxPTime, c.endpoint.cfg.MaxPTime), dtmf, hasDTMF)
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, callReleaseTimeout)
	defer cancel()
	if err := c.openMedia(ctx); err != nil {
		return err
	}
	c.restartMediaInactivityWatch()
	return nil
}

func (c *Call) setHoldState(hold CallHoldState, cause callAction) {
	hold = normalizeHoldState(hold)
	c.mu.Lock()
	if normalizeHoldState(c.hold) == hold {
		c.mu.Unlock()
		return
	}
	c.hold = hold
	id := c.id
	state := c.state
	c.mu.Unlock()

	c.restartMediaInactivityWatch()
	c.endpoint.emit(CallEvent{Call: c, CallID: id, State: state, Hold: hold, Cause: cause.String(), At: time.Now()})
}

func setLocalHold(state CallHoldState, local bool) CallHoldState {
	remote := holdHasRemote(state)
	return holdState(local, remote)
}

func setRemoteHold(state CallHoldState, remote bool) CallHoldState {
	local := holdHasLocal(state)
	return holdState(local, remote)
}

func holdState(local bool, remote bool) CallHoldState {
	switch {
	case local && remote:
		return CallHoldLocalRemote
	case local:
		return CallHoldLocal
	case remote:
		return CallHoldRemote
	default:
		return CallHoldNone
	}
}

func holdHasLocal(state CallHoldState) bool {
	return state == CallHoldLocal || state == CallHoldLocalRemote
}

func holdHasRemote(state CallHoldState) bool {
	return state == CallHoldRemote || state == CallHoldLocalRemote
}

func remoteHoldFromDirection(direction MediaDirection) bool {
	return direction == MediaDirectionRecvOnly || direction == MediaDirectionInactive
}

func normalizeHoldState(state CallHoldState) CallHoldState {
	switch state {
	case CallHoldLocal, CallHoldRemote, CallHoldLocalRemote:
		return state
	default:
		return CallHoldNone
	}
}

func callIsHeld(state CallHoldState) bool {
	return holdHasLocal(state) || holdHasRemote(state)
}

func localMediaSendBlocked(direction MediaDirection) bool {
	return direction == MediaDirectionRecvOnly || direction == MediaDirectionInactive
}
