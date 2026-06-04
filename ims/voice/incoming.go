package voice

import (
	"context"
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) handleIncomingInvite(ctx context.Context, req session.Request) error {
	if existing := s.lookupIncoming(req.Message); existing != nil {
		existing.mu.Lock()
		resp := existing.inviteOK
		existing.mu.Unlock()
		if resp.StartLine != "" {
			return s.sess.WriteResponse(ctx, req, resp)
		}
		if resp, ok := existing.pendingReliableProvisionalResponse(); ok {
			return s.sess.WriteResponse(ctx, req, resp)
		}
		return s.writeRinging(ctx, req, existing)
	}
	if s.unsupportedRequiredReliableProvisional(req.Message) {
		return s.writeUnsupportedRequired(ctx, req, reliableProvisionalOption)
	}
	if s.unsupportedRequiredTimer(req.Message) {
		return s.writeUnsupportedRequired(ctx, req, sessionTimerOption)
	}
	if s.unsupportedRequiredPrecondition(req.Message) {
		return s.writeUnsupportedRequired(ctx, req, preconditionOption)
	}
	if invalidSessionTimerRefresher(req.Message) {
		return s.writeStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	if minSE, tooSmall := incomingSessionTimerTooSmall(req.Message, s.cfg); tooSmall {
		return s.writeSessionIntervalTooSmall(ctx, req, minSE)
	}

	localPort := s.reserveRTPPort()
	localIP := s.localIP()
	var (
		offer        sdpOffer
		answerBody   []byte
		media        NegotiatedMedia
		delayedOffer = len(req.Message.Body) == 0
	)
	if !delayedOffer {
		body, ok := sdpBody(req.Message)
		if !ok {
			return s.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
		var err error
		offer, err = parseSDP(body)
		if err != nil {
			return s.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
		answerBody, media, err = buildSDPAnswer(s.cfg, localIP, localPort, offer, MediaOffer{})
		if err != nil {
			return s.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
		}
	}

	state := s.reg.State()
	localTag := sip.ResponseTag(req.Message)
	callID := req.Message.Header("Call-ID")
	call := &Call{
		service:         s,
		id:              callID,
		sessionID:       nonEmpty(req.Message.Header("Session-ID"), sip.RandomHex(32)),
		direction:       CallDirectionIncoming,
		state:           CallStateRinging,
		localURI:        nonEmpty(sip.AddressURI(req.Message.Header("To")), preferredIdentity(state)),
		localTag:        localTag,
		remoteURI:       nonEmpty(sip.AddressURI(req.Message.Header("From")), sip.AddressURI(req.Message.Header("Contact"))),
		remoteTag:       sip.HeaderTag(req.Message.Header("From")),
		remoteTo:        req.Message.Header("From"),
		remoteAllow:     req.Message.Header("Allow"),
		targetURI:       nonEmpty(sip.AddressURI(req.Message.Header("Contact")), sip.AddressURI(req.Message.Header("From"))),
		routeSet:        append([]string(nil), req.Message.HeadersByName("Record-Route")...),
		inviteSeq:       sip.CSeqNumber(req.Message.Header("CSeq")),
		localCSeq:       0,
		remoteCSeq:      sip.CSeqNumber(req.Message.Header("CSeq")),
		localSDP:        append([]byte(nil), answerBody...),
		localPort:       localPort,
		incomingRequest: &req,
		remoteOffer:     offer,
		delayedOffer:    delayedOffer,
		media:           media,
		rtcpSSRC:        randomRTCPSSRC(),
	}
	if err := s.storeCall(call); err != nil {
		return err
	}
	s.storeIncoming(req.Message, call)

	if err := s.writeStatus(ctx, req, sipStatusTrying, "Trying"); err != nil {
		return fmt.Errorf("handling call INVITE: sending 100 Trying: %w", err)
	}
	if delayedOffer && s.canSendReliableProvisional(req.Message) {
		offerBody, offerMedia, err := buildSDPOffer(s.cfg, localIP, localPort, MediaOffer{})
		if err != nil {
			call.finish(CallStateFailed, err.Error())
			return err
		}
		call.mu.Lock()
		call.media = offerMedia
		call.mu.Unlock()
		if err := call.prepareMedia(ctx); err != nil {
			call.finish(CallStateFailed, err.Error())
			return err
		}
		if err := s.writeProgress(ctx, req, call, offerBody, true); err != nil {
			return fmt.Errorf("handling call INVITE: sending 183 Session Progress: %w", err)
		}
	} else {
		if !delayedOffer && s.cfg.PrepareMedia != nil {
			reliableProgress := s.canSendReliableProvisional(req.Message)
			if err := s.writeProgress(ctx, req, call, answerBody, reliableProgress); err != nil {
				return fmt.Errorf("handling call INVITE: sending 183 Session Progress: %w", err)
			}
			if reliableProgress {
				call.setState(CallStateRinging, "")
				if s.cfg.OnIncomingCall != nil {
					s.cfg.OnIncomingCall(IncomingCall{
						Call:       call,
						From:       call.remoteURI,
						FromURI:    call.remoteURI,
						FromNumber: incomingCallerNumber(req.Message),
						Offer:      mediaOfferFromSDP(offer),
						Received:   time.Now(),
					})
				}
				return nil
			}
		}
		if !delayedOffer {
			if err := call.prepareMedia(ctx); err != nil {
				call.finish(CallStateFailed, err.Error())
				return s.writeStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
			}
		}
		if err := s.writeRinging(ctx, req, call); err != nil {
			return fmt.Errorf("handling call INVITE: sending 180 Ringing: %w", err)
		}
		call.startRingingTimer()
	}
	call.setState(CallStateRinging, "")
	if s.cfg.OnIncomingCall != nil {
		var incomingOffer MediaOffer
		if !delayedOffer {
			incomingOffer = mediaOfferFromSDP(offer)
		}
		s.cfg.OnIncomingCall(IncomingCall{
			Call:       call,
			From:       call.remoteURI,
			FromURI:    call.remoteURI,
			FromNumber: incomingCallerNumber(req.Message),
			Offer:      incomingOffer,
			Received:   time.Now(),
		})
	}
	return nil
}
