package voice

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/identity"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func (s *Endpoint) canSendReliableProvisional(msg sip.Message) bool {
	return s.cfg.ReliableProvisional &&
		(tokenHeaderContains(msg, "Supported", reliableProvisionalOption) ||
			tokenHeaderContains(msg, "Require", reliableProvisionalOption))
}

func (s *Endpoint) usesPreconditions(msg sip.Message) bool {
	return s.cfg.Preconditions &&
		(tokenHeaderContains(msg, "Supported", preconditionOption) ||
			tokenHeaderContains(msg, "Require", preconditionOption))
}

func sdpUsesPreconditions(body []byte) bool {
	var offer sdpOffer
	return offer.UnmarshalBinary(body) == nil && offer.Preconditions
}

func (s *Endpoint) unsupportedRequiredReliableProvisional(msg sip.Message) bool {
	return !s.cfg.ReliableProvisional && tokenHeaderContains(msg, "Require", reliableProvisionalOption)
}

func incomingCallerNumber(msg sip.Message) string {
	for _, header := range []string{"P-Asserted-Identity", "Remote-Party-ID", "From"} {
		for _, value := range msg.HeadersByName(header) {
			for _, part := range sip.SplitHeaderList(value) {
				if number := identity.MSISDN(part); number != "" {
					return number
				}
			}
		}
	}
	return ""
}

func (s *Endpoint) handleIncomingInvite(ctx context.Context, req session.Request) error {
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
		err = offer.UnmarshalBinary(body)
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
		endpoint:        s,
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
		routeSet:        req.Message.HeaderList("Record-Route"),
		inviteSeq:       sip.CSeqNumber(req.Message.Header("CSeq")),
		localCSeq:       0,
		remoteCSeq:      sip.CSeqNumber(req.Message.Header("CSeq")),
		localSDP:        append([]byte(nil), answerBody...),
		localPort:       localPort,
		incomingRequest: &req,
		remoteOffer:     offer,
		remotePayloads:  remotePayloadMappings(offer),
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
						Offer:      mediaDescriptionFromSDP(offer),
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
		var incomingOffer MediaDescription
		if !delayedOffer {
			incomingOffer = mediaDescriptionFromSDP(offer)
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

func (s *Endpoint) writeStatus(ctx context.Context, req session.Request, code int, reason string) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writePRACKOK(ctx context.Context, req session.Request, sdp []byte) error {
	resp := sip.NewResponse(sipStatusOK, "OK")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusOK)
	s.addAccessNetworkInfo(&resp)
	if len(sdp) != 0 {
		resp.Headers.Add("Content-Type", "application/sdp")
		if s.usesPreconditions(req.Message) && sdpUsesPreconditions(sdp) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
		resp.Body = sdp
	}
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeRetryAfter(ctx context.Context, req session.Request, code int, reason string, seconds int) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	resp.Headers.Set("Retry-After", strconv.Itoa(seconds))
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeUnsupportedRequired(ctx context.Context, req session.Request, option string) error {
	resp := sip.NewResponse(sipStatusBadExtension, "Bad Extension")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusBadExtension)
	resp.Headers.Set("Unsupported", option)
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeSessionIntervalTooSmall(ctx context.Context, req session.Request, minSE int) error {
	resp := sip.NewResponse(sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusSessionIntervalTooSmall)
	resp.Headers.Set("Min-SE", strconv.Itoa(minSE))
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) writeRinging(ctx context.Context, req session.Request, call *Call) error {
	resp := sip.NewResponse(sipStatusRinging, "Ringing")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusRinging)
	s.addAccessNetworkInfo(&resp)
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(false, false))
	var rseq int64
	if call != nil && s.canSendReliableProvisional(req.Message) {
		resp.Headers.Add("Require", reliableProvisionalOption)
		rseq = call.beginReliableProvisional(sipStatusRinging, sip.CSeqNumber(req.Message.Header("CSeq")), "INVITE")
		resp.Headers.Add("RSeq", strconv.FormatInt(rseq, 10))
	}
	if err := s.sess.WriteResponse(ctx, req, resp); err != nil {
		return err
	}
	if rseq != 0 {
		call.startReliableProvisionalRetransmit(req, resp, rseq)
	}
	return nil
}

func (s *Endpoint) writeProgress(ctx context.Context, req session.Request, call *Call, body []byte, reliable bool) error {
	resp := sip.NewResponse(sipStatusSessionProgress, "Session Progress")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusSessionProgress)
	s.addAccessNetworkInfo(&resp)
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Message.Header("To"), call.localURI, call.localTag))
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(false, false))
	var rseq int64
	if reliable {
		resp.Headers.Add("Require", reliableProvisionalOption)
		rseq = call.beginReliableProvisional(sipStatusSessionProgress, sip.CSeqNumber(req.Message.Header("CSeq")), "INVITE")
		resp.Headers.Add("RSeq", strconv.FormatInt(rseq, 10))
	}
	if len(body) != 0 {
		if err := setInviteResponseBody(&resp, s.cfg, call.localURI, false, body); err != nil {
			return err
		}
		if s.usesPreconditions(req.Message) && sdpUsesPreconditions(body) {
			addTokenHeader(&resp, "Require", preconditionOption)
		}
		call.mu.Lock()
		call.localSDP = append([]byte(nil), body...)
		call.mu.Unlock()
	}
	if err := s.sess.WriteResponse(ctx, req, resp); err != nil {
		return err
	}
	if rseq != 0 {
		call.startReliableProvisionalRetransmit(req, resp, rseq)
	}
	return nil
}

func (s *Endpoint) addAccessNetworkInfo(resp *sip.Message) {
	state := s.reg.State()
	if value := strings.TrimSpace(state.UserAgent); value != "" && strings.TrimSpace(resp.Header("Server")) == "" {
		resp.Headers.Add("Server", value)
	}
	if !responseCanCarryAccessNetworkInfo(*resp) {
		return
	}
	if value := strings.TrimSpace(state.AccessNetworkInfo); value != "" && strings.TrimSpace(resp.Header("P-Access-Network-Info")) == "" {
		resp.Headers.Add("P-Access-Network-Info", value)
	}
}

func responseCanCarryAccessNetworkInfo(resp sip.Message) bool {
	return !strings.EqualFold(sip.CSeqMethod(resp.Header("CSeq")), "CANCEL")
}
