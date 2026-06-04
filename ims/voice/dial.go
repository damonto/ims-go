package voice

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) Dial(ctx context.Context, req DialRequest) (*Call, error) {
	start, err := s.newOutgoingInvite(req)
	if err != nil {
		return nil, err
	}

	call := s.newOutgoingCall(req, start)
	if err := s.storeCall(call); err != nil {
		return nil, err
	}
	if err := call.prepareMedia(ctx); err != nil {
		s.removeCall(start.callID)
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}
	s.emit(CallEvent{Call: call, CallID: start.callID, State: CallStateDialing, At: time.Now()})

	invite := start.invite
	resp, err := s.exchangeCallInvite(ctx, invite)
	if err != nil {
		call.stopRingbackTimer()
		_ = call.closeMedia()
		s.removeCall(start.callID)
		call.setState(CallStateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	lastMinSE := 0
	for resp.StatusCode() == sipStatusSessionIntervalTooSmall && s.cfg.SessionTimer {
		minSE, ok := parseMinSessionSeconds(resp.Header("Min-SE"))
		if !ok {
			call.stopRingbackTimer()
			_ = call.closeMedia()
			s.removeCall(start.callID)
			call.setState(CallStateFailed, fmt.Sprintf("session timer retry: invalid Min-SE %q", resp.Header("Min-SE")))
			return nil, fmt.Errorf("dialing call: session timer retry: invalid Min-SE %q", resp.Header("Min-SE"))
		}
		if minSE <= lastMinSE {
			break
		}
		lastMinSE = minSE
		resp, err = s.retryInviteWithMinSE(ctx, call, invite, resp)
		if err != nil {
			call.stopRingbackTimer()
			_ = call.closeMedia()
			s.removeCall(start.callID)
			call.setState(CallStateFailed, err.Error())
			return nil, fmt.Errorf("dialing call: %w", err)
		}
		invite = call.inviteRequest
	}
	call.stopRingbackTimer()
	if resp.StatusCode() < sipStatusOK || resp.StatusCode() >= sipStatusMultipleChoices {
		if call.State() == CallStateEnding {
			call.finish(CallStateEnded, "cancelled")
			return nil, errors.New("dialing call: cancelled")
		}
		_ = call.closeMedia()
		s.removeCall(start.callID)
		err := fmt.Errorf("dialing call: expected 2xx, got %w", sip.NewResponseError(resp))
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}
	if call.State() == CallStateEnding {
		if err := call.releaseCancelledInvite2xx(ctx, resp); err != nil {
			call.finish(CallStateFailed, err.Error())
			return nil, fmt.Errorf("dialing call: %w", err)
		}
		call.finish(CallStateEnded, "cancelled")
		return nil, errors.New("dialing call: cancelled")
	}
	answer, ok, err := call.answerFromFinalResponse(resp)
	if err != nil {
		_ = call.closeMedia()
		s.removeCall(start.callID)
		call.setState(CallStateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	if !ok {
		_ = call.closeMedia()
		s.removeCall(start.callID)
		err := errors.New("dialing call: missing answer sdp")
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}
	negotiated, ok := chooseCodec(answer, s.cfg.Codecs)
	if !ok {
		_ = call.closeMedia()
		s.removeCall(start.callID)
		err := errors.New("dialing call: no compatible answer codec")
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, s.cfg.Codecs, negotiated.ClockRate)
	answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, start.media.PTime), dtmf, hasDTMF)

	call.mu.Lock()
	call.remoteTag = sip.HeaderTag(resp.Header("To"))
	call.remoteTo = nonEmpty(resp.Header("To"), call.remoteTo)
	call.remoteAllow = nonEmpty(resp.Header("Allow"), call.remoteAllow)
	call.remoteURI = nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), call.remoteURI)
	call.targetURI = call.remoteURI
	call.routeSet = reverseValues(resp.HeadersByName("Record-Route"))
	call.media = answerMedia
	call.earlyDialogs = nil
	snap := call.dialogSnapshot()
	ack := snap.buildACK()
	call.inviteACK = ack
	call.mu.Unlock()
	if err := call.refreshDialogRegistration(); err != nil {
		if ackErr := s.sess.Send(ctx, ack); ackErr != nil {
			call.finish(CallStateFailed, ackErr.Error())
			return nil, fmt.Errorf("dialing call: %w", ackErr)
		}
		call.releaseAcknowledgedInviteFailure(err, reasonMediaBearerReleased)
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	if err := s.sess.Send(ctx, ack); err != nil {
		call.finish(CallStateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}

	if err := call.openMedia(ctx); err != nil {
		call.releaseAcknowledgedInviteFailure(err, reasonMediaBearerReleased)
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	call.startMediaInactivityWatch()
	if err := call.applySessionTimerUACResponse(resp, true); err != nil {
		call.releaseAcknowledgedInviteFailure(err, reasonMediaBearerReleased)
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	call.setState(CallStateConfirmed, "")
	return call, nil
}
