package voice

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

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
	direction := mediaDirectionSendRecv
	action := "resuming call"
	if hold {
		direction = mediaDirectionSendOnly
		action = "holding call"
	}

	snap, timer, body, previousHold, previousSDP, clearPending, err := c.beginLocalHoldModification(action, hold, direction)
	if err != nil {
		return err
	}
	if clearPending == nil {
		return nil
	}
	defer clearPending()

	req := snap.buildMediaReINVITE(c.nextCSeq(), timer, body)
	resp, err := c.exchangeSessionRefresh(ctx, req)
	if err != nil {
		c.restoreHoldModification(previousHold, previousSDP)
		return fmt.Errorf("%s: %w", action, err)
	}
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		c.restoreHoldModification(previousHold, previousSDP)
		return fmt.Errorf("%s: expected 2xx, got %w", action, sip.NewResponseError(resp))
	}
	if err := c.acknowledgeSessionRefreshINVITE(ctx, resp); err != nil {
		c.restoreHoldModification(previousHold, previousSDP)
		return err
	}
	c.updateRemoteTargetFromResponse(resp)
	if err := c.applyMediaReINVITEAnswer(ctx, resp); err != nil {
		c.restoreHoldModification(previousHold, previousSDP)
		return fmt.Errorf("%s: %w", action, err)
	}
	if err := c.applySessionTimerUACResponse(resp, true); err != nil {
		c.restoreHoldModification(previousHold, previousSDP)
		return fmt.Errorf("%s: %w", action, err)
	}

	nextHold := setLocalHold(previousHold, hold)
	c.mu.Lock()
	c.localSDP = append([]byte(nil), body...)
	c.mu.Unlock()
	c.setHoldState(nextHold, action)
	return nil
}

func (c *Call) beginLocalHoldModification(action string, hold bool, direction mediaDirection) (dialogSnapshot, sessionTimerState, []byte, CallHoldState, []byte, func(), error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return dialogSnapshot{}, sessionTimerState{}, nil, "", nil, nil, fmt.Errorf("%s: call is closed", action)
	}
	if c.state != CallStateActive && c.state != CallStateConfirmed {
		return dialogSnapshot{}, sessionTimerState{}, nil, "", nil, nil, fmt.Errorf("%s: call state is %s", action, c.state)
	}
	if c.emergency && hold && !c.service.cfg.AllowHoldDuringEmergency {
		return dialogSnapshot{}, sessionTimerState{}, nil, "", nil, nil, errors.New("holding call: emergency hold is disabled")
	}
	if c.localINVITEPending {
		return dialogSnapshot{}, sessionTimerState{}, nil, "", nil, nil, fmt.Errorf("%s: local re-INVITE is already pending", action)
	}
	if c.remoteINVITEPending {
		return dialogSnapshot{}, sessionTimerState{}, nil, "", nil, nil, fmt.Errorf("%s: remote re-INVITE is pending", action)
	}
	if holdHasLocal(c.hold) == hold {
		return dialogSnapshot{}, sessionTimerState{}, nil, "", nil, nil, nil
	}

	body, err := c.localSDPWithDirection(direction)
	if err != nil {
		return dialogSnapshot{}, sessionTimerState{}, nil, "", nil, nil, err
	}
	c.localINVITEPending = true
	clearPending := func() {
		c.mu.Lock()
		c.localINVITEPending = false
		c.mu.Unlock()
	}
	return c.dialogSnapshot(), c.sessionTimer, body, c.hold, append([]byte(nil), c.localSDP...), clearPending, nil
}

func (c *Call) localSDPWithDirection(direction mediaDirection) ([]byte, error) {
	if len(c.localSDP) != 0 {
		return sdpWithDirection(c.localSDP, direction, c.service.cfg.Preconditions), nil
	}
	offer := MediaOffer{}
	if c.media.Codec != "" {
		offer.Codecs = []AudioCodec{c.media.Codec}
	}
	body, _, err := buildSDPOfferWithDirection(c.service.cfg, c.service.localIP(), c.localPort, offer, direction)
	if err != nil {
		return nil, err
	}
	if c.service.cfg.Preconditions {
		body = sdpWithDirection(body, direction, true)
	}
	return body, nil
}

func sdpWithDirection(body []byte, direction mediaDirection, qosMet bool) []byte {
	lines := strings.FieldsFunc(string(body), func(r rune) bool { return r == '\r' || r == '\n' })
	out := make([]string, 0, len(lines)+1)
	inAudio := false
	replaced := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
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

func (c *Call) restoreHoldModification(hold CallHoldState, localSDP []byte) {
	c.mu.Lock()
	c.hold = hold
	c.localSDP = append([]byte(nil), localSDP...)
	c.mu.Unlock()
	c.restartMediaInactivityWatch()
}

func (c *Call) applyMediaReINVITEAnswer(ctx context.Context, resp sip.Message) error {
	body, ok := sdpBody(resp)
	if !ok {
		return errors.New("missing re-INVITE SDP answer")
	}
	answer, err := parseSDP(body)
	if err != nil {
		return fmt.Errorf("parsing re-INVITE SDP answer: %w", err)
	}
	negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
	if !ok {
		return errors.New("no compatible re-INVITE answer codec")
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, c.service.cfg.Codecs, negotiated.ClockRate)
	c.mu.Lock()
	current := c.media
	c.media = negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, current.PTime), dtmf, hasDTMF)
	c.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, callReleaseTimeout)
	defer cancel()
	if err := c.openMedia(ctx); err != nil {
		return err
	}
	c.restartMediaInactivityWatch()
	return nil
}

func (c *Call) setHoldState(hold CallHoldState, cause string) {
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
	c.service.emit(CallEvent{Call: c, CallID: id, State: state, Hold: hold, Cause: cause, At: time.Now()})
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

func remoteHoldFromDirection(direction mediaDirection) bool {
	return direction == mediaDirectionRecvOnly || direction == mediaDirectionInactive
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

func localMediaSendBlocked(direction mediaDirection) bool {
	return direction == mediaDirectionRecvOnly || direction == mediaDirectionInactive
}
