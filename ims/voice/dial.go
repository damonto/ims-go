package voice

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func (s *Service) Dial(ctx context.Context, req DialRequest) (*Call, error) {
	target, err := s.initialInviteTarget(req)
	if err != nil {
		return nil, err
	}

	localPort := s.reserveRTPPort()
	localIP := s.localIP()
	offer, media, err := buildSDPOffer(s.cfg, localIP, localPort, req.Media)
	if err != nil {
		return nil, err
	}

	callID, sessionID, tag, branch := sip.NewTransaction()
	state := s.reg.State()
	localURI := preferredIdentity(state)
	pidfURI := pidfEntityURI(s.cfg, state)
	includePIDF := includePIDFForInvite(s.cfg, req)
	includeCurrentLocation := includeCurrentLocationDiscoveryForInvite(s.cfg, req)
	inviteSeq := atomic.AddInt64(&s.cseq, 1)
	invite := sip.NewRequest("INVITE", target)
	invite.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, branch))
	invite.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", localURI, tag))
	invite.Headers.Add("To", fmt.Sprintf("<%s>", target))
	invite.Headers.Add("Call-ID", callID)
	invite.Headers.Add("Session-ID", sessionID)
	invite.Headers.Add("CSeq", fmt.Sprintf("%d INVITE", inviteSeq))
	invite.Headers.Add("Accept-Contact", fmt.Sprintf(`*;+g.3gpp.icsi-ref="%s"`, mmtelICSIEncoded))
	invite.Headers.Add("P-Preferred-Service", mmtelICSI)
	invite.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", localURI))
	invite.Headers.Add("P-Early-Media", "supported")
	invite.Headers.Add("Contact", contactValue(state))
	if includeCurrentLocation {
		invite.Headers.Add("Recv-Info", currentLocationDiscoveryInfoPackage)
	}
	invite.Headers.Add("Accept", callAcceptHeader(includePIDF, includeCurrentLocation))
	s.reg.RequestPolicy().Apply(&invite)
	addInviteFeatureTags(&invite, s.cfg)
	addInviteSessionTimer(&invite, s.cfg)
	if err := setInviteBody(&invite, s.cfg, pidfURI, includePIDF, offer); err != nil {
		return nil, err
	}

	call := &Call{
		service:         s,
		id:              callID,
		sessionID:       sessionID,
		direction:       CallDirectionOutgoing,
		state:           CallStateDialing,
		localURI:        localURI,
		localTag:        tag,
		remoteURI:       target,
		remoteTo:        fmt.Sprintf("<%s>", target),
		targetURI:       target,
		inviteSeq:       inviteSeq,
		localCSeq:       inviteSeq,
		inviteRequest:   invite,
		localSDP:        append([]byte(nil), offer...),
		localPort:       localPort,
		media:           media,
		earlyDialogs:    make(map[string]earlyDialog),
		rtcpSSRC:        randomRTCPSSRC(),
		emergency:       req.Emergency,
		currentLocation: includeCurrentLocation,
	}
	if err := s.storeCall(call); err != nil {
		return nil, err
	}
	if err := call.prepareMedia(ctx); err != nil {
		s.removeCall(callID)
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}
	s.emit(CallEvent{Call: call, CallID: callID, State: CallStateDialing, At: time.Now()})

	resp, err := s.exchangeCallInvite(ctx, invite)
	if err != nil {
		call.stopRingbackTimer()
		_ = call.closeMedia()
		s.removeCall(callID)
		call.setState(CallStateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	lastMinSE := 0
	for resp.StatusCode() == sipStatusSessionIntervalTooSmall && s.cfg.SessionTimer {
		minSE, ok := parseMinSessionSeconds(resp.Header("Min-SE"))
		if !ok {
			call.stopRingbackTimer()
			_ = call.closeMedia()
			s.removeCall(callID)
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
			s.removeCall(callID)
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
		s.removeCall(callID)
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
		s.removeCall(callID)
		call.setState(CallStateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	if !ok {
		_ = call.closeMedia()
		s.removeCall(callID)
		err := errors.New("dialing call: missing answer sdp")
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}
	negotiated, ok := chooseCodec(answer, s.cfg.Codecs)
	if !ok {
		_ = call.closeMedia()
		s.removeCall(callID)
		err := errors.New("dialing call: no compatible answer codec")
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, s.cfg.Codecs, negotiated.ClockRate)
	answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, media.PTime), dtmf, hasDTMF)

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
		_ = call.closeMedia()
		s.removeCall(callID)
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}

	if err := call.openMedia(ctx); err != nil {
		_ = call.closeMedia()
		s.removeCall(callID)
		call.setState(CallStateFailed, err.Error())
		return nil, err
	}
	call.startMediaInactivityWatch()
	if err := s.sess.Send(ctx, ack); err != nil {
		call.finish(CallStateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	if err := call.applySessionTimerUACResponse(resp, true); err != nil {
		call.finish(CallStateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	call.setState(CallStateConfirmed, "")
	return call, nil
}

func (s *Service) initialInviteTarget(req DialRequest) (string, error) {
	if !req.Emergency {
		target := s.targetURI(req.To)
		if target == "" {
			return "", errors.New("dialing call: target is empty")
		}
		return target, nil
	}
	target := strings.TrimSpace(req.EmergencyURN)
	if target == "" && isEmergencyServiceURN(req.To) {
		target = strings.TrimSpace(req.To)
	}
	if target == "" {
		target = emergencyServiceURNSOS
	}
	if !isEmergencyServiceURN(target) {
		return "", fmt.Errorf("dialing emergency call: invalid service urn %q", target)
	}
	return target, nil
}

func (s *Service) exchangeCallInvite(ctx context.Context, invite sip.Message) (sip.Message, error) {
	exchangeCtx, cancelExchange := context.WithCancel(ctx)
	defer cancelExchange()

	var timedOut atomic.Bool
	stopTimer := s.startMOCallRequestTimer(func() {
		timedOut.Store(true)
		cancelExchange()
	})
	defer stopTimer()

	resp, err := s.sess.ExchangeWithOptions(exchangeCtx, invite, session.ExchangeOptions{
		OnProvisional: func(sip.Message) {
			stopTimer()
		},
	})
	if err != nil && timedOut.Load() {
		return sip.Message{}, errors.New("waiting for first provisional INVITE response: timeout")
	}
	return resp, err
}

func (s *Service) startMOCallRequestTimer(cancel func()) func() {
	if s.cfg.MOCallRequestTimeout <= 0 {
		return func() {}
	}
	timer := time.NewTimer(s.cfg.MOCallRequestTimeout)
	var once sync.Once
	done := make(chan struct{})
	go func() {
		select {
		case <-timer.C:
			once.Do(func() {
				close(done)
				cancel()
			})
		case <-done:
		}
	}()
	return func() {
		once.Do(func() {
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			close(done)
		})
	}
}

func (s *Service) retryInviteWithMinSE(ctx context.Context, call *Call, invite sip.Message, resp sip.Message) (sip.Message, error) {
	minSE, ok := parseMinSessionSeconds(resp.Header("Min-SE"))
	if !ok {
		return sip.Message{}, fmt.Errorf("session timer retry: invalid Min-SE %q", resp.Header("Min-SE"))
	}
	state := s.reg.State()
	_, _, _, branch := sip.NewTransaction()
	seq := atomic.AddInt64(&s.cseq, 1)
	retry := invite
	retry.Headers = invite.Headers.Clone()
	retry.Body = append([]byte(nil), invite.Body...)
	retry.Headers.Set("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, branch))
	retry.Headers.Set("CSeq", fmt.Sprintf("%d INVITE", seq))
	retry.Headers.Set("Min-SE", strconv.Itoa(minSE))
	retry.Headers.Set("Session-Expires", sessionExpiresRequestHeader(s.cfg, retry).String())

	call.mu.Lock()
	if call.state == CallStateEnding {
		call.mu.Unlock()
		return resp, nil
	}
	call.inviteSeq = seq
	call.localCSeq = seq
	call.inviteRequest = retry
	call.inviteResponse = false
	call.cancelOnResponse = false
	call.cancelSent = false
	call.mu.Unlock()

	next, err := s.exchangeCallInvite(ctx, retry)
	if err != nil {
		return sip.Message{}, fmt.Errorf("session timer retry: %w", err)
	}
	return next, nil
}
