package call

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

func (s *Service) Dial(ctx context.Context, req Request) (*Call, error) {
	target := s.targetURI(req.To)
	if target == "" {
		return nil, errors.New("dialing call: target is empty")
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
	invite.Headers.Add("Accept", callAcceptHeader(s.cfg))
	s.reg.RequestPolicy().Apply(&invite)
	addInviteSessionTimer(&invite, s.cfg)
	if err := setInviteBody(&invite, s.cfg, localURI, offer); err != nil {
		return nil, err
	}

	call := &Call{
		service:       s,
		id:            callID,
		sessionID:     sessionID,
		direction:     DirectionOutgoing,
		state:         StateDialing,
		localURI:      localURI,
		localTag:      tag,
		remoteURI:     target,
		remoteTo:      fmt.Sprintf("<%s>", target),
		targetURI:     target,
		inviteSeq:     inviteSeq,
		inviteRequest: invite,
		localPort:     localPort,
		media:         media,
		earlyDialogs:  make(map[string]earlyDialog),
		rtcpSSRC:      randomRTCPSSRC(),
	}
	if err := s.storeCall(call); err != nil {
		return nil, err
	}
	if err := call.prepareMedia(ctx); err != nil {
		s.removeCall(callID)
		call.setState(StateFailed, err.Error())
		return nil, err
	}
	s.emit(Event{CallID: callID, State: StateDialing, At: time.Now()})

	resp, err := s.exchangeCallInvite(ctx, invite)
	if err != nil {
		call.stopRingbackTimer()
		_ = call.closeMedia()
		s.removeCall(callID)
		call.setState(StateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	if resp.StatusCode() == 422 && s.cfg.SessionTimer {
		resp, err = s.retryInviteWithMinSE(ctx, call, invite, resp)
		if err != nil {
			call.stopRingbackTimer()
			_ = call.closeMedia()
			s.removeCall(callID)
			call.setState(StateFailed, err.Error())
			return nil, fmt.Errorf("dialing call: %w", err)
		}
	}
	call.stopRingbackTimer()
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		if call.State() == StateEnding {
			call.finish(StateEnded, "cancelled")
			return nil, errors.New("dialing call: cancelled")
		}
		_ = call.closeMedia()
		s.removeCall(callID)
		err := fmt.Errorf("dialing call: expected 2xx, got %w", sip.NewResponseError(resp))
		call.setState(StateFailed, err.Error())
		return nil, err
	}
	if call.State() == StateEnding {
		if err := call.releaseCancelledInvite2xx(ctx, resp); err != nil {
			call.finish(StateFailed, err.Error())
			return nil, fmt.Errorf("dialing call: %w", err)
		}
		call.finish(StateEnded, "cancelled")
		return nil, errors.New("dialing call: cancelled")
	}
	answer, ok, err := call.answerFromFinalResponse(resp)
	if err != nil {
		_ = call.closeMedia()
		s.removeCall(callID)
		call.setState(StateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	if !ok {
		_ = call.closeMedia()
		s.removeCall(callID)
		err := errors.New("dialing call: missing answer sdp")
		call.setState(StateFailed, err.Error())
		return nil, err
	}
	negotiated, ok := chooseCodec(answer, s.cfg.Codecs)
	if !ok {
		_ = call.closeMedia()
		s.removeCall(callID)
		err := errors.New("dialing call: no compatible answer codec")
		call.setState(StateFailed, err.Error())
		return nil, err
	}
	dtmf, hasDTMF := chooseTelephoneEvent(answer, s.cfg.Codecs)
	answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, media.PTime), dtmf, hasDTMF)

	call.mu.Lock()
	call.remoteTag = sip.HeaderTag(resp.Header("To"))
	call.remoteTo = nonEmpty(resp.Header("To"), call.remoteTo)
	call.remoteURI = nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), call.remoteURI)
	call.targetURI = call.remoteURI
	call.routeSet = reverseValues(resp.HeadersByName("Record-Route"))
	call.media = answerMedia
	call.earlyDialogs = nil
	ack := call.buildACKLocked()
	call.inviteACK = ack
	call.mu.Unlock()
	if err := call.refreshDialogRegistration(); err != nil {
		_ = call.closeMedia()
		s.removeCall(callID)
		call.setState(StateFailed, err.Error())
		return nil, err
	}

	if err := call.openMedia(ctx); err != nil {
		_ = call.closeMedia()
		s.removeCall(callID)
		call.setState(StateFailed, err.Error())
		return nil, err
	}
	call.startMediaInactivityWatch()
	if err := s.sess.Send(ctx, ack); err != nil {
		call.finish(StateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	call.setState(StateConfirmed, "")
	return call, nil
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
	minSE, ok := parseSessionSeconds(resp.Header("Min-SE"))
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
	retry.Headers.Set("Session-Expires", strconv.Itoa(max(durationSeconds(defaultSessionExpires), minSE)))

	call.mu.Lock()
	if call.state == StateEnding {
		call.mu.Unlock()
		return resp, nil
	}
	call.inviteSeq = seq
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
