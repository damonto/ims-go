package voice

import (
	"context"
	"fmt"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"net/url"
	"strconv"
	"strings"
	"time"
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
	if delayedOffer && s.shouldSendReliableDelayedOffer(req.Message) {
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
			reliableProgress := s.shouldSendReliableDelayedOffer(req.Message)
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

func (s *Service) writeStatus(ctx context.Context, req session.Request, code int, reason string) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) writePRACKOK(ctx context.Context, req session.Request, sdp []byte) error {
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

func (s *Service) writeRetryAfter(ctx context.Context, req session.Request, code int, reason string, seconds int) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	resp.Headers.Set("Retry-After", strconv.Itoa(seconds))
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) writeUnsupportedRequired(ctx context.Context, req session.Request, option string) error {
	resp := sip.NewResponse(sipStatusBadExtension, "Bad Extension")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusBadExtension)
	resp.Headers.Set("Unsupported", option)
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) writeSessionIntervalTooSmall(ctx context.Context, req session.Request, minSE int) error {
	resp := sip.NewResponse(sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusSessionIntervalTooSmall)
	resp.Headers.Set("Min-SE", strconv.Itoa(minSE))
	s.addAccessNetworkInfo(&resp)
	return s.sess.WriteResponse(ctx, req, resp)
}

func incomingCallerNumber(msg sip.Message) string {
	for _, header := range []string{"P-Asserted-Identity", "Remote-Party-ID", "From"} {
		for _, value := range msg.HeadersByName(header) {
			for _, part := range sip.SplitHeaderList(value) {
				if number := callerNumber(part); number != "" {
					return number
				}
			}
		}
	}
	return ""
}

func callerNumber(value string) string {
	uri := sip.AddressURI(value)
	if uri == "" {
		return ""
	}
	return callerNumberFromURI(uri)
}

func callerNumberFromURI(uri string) string {
	uri = strings.TrimSpace(uri)
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "tel:"):
		return cleanCallerUser(uri[len("tel:"):])
	case strings.HasPrefix(lower, "sip:"):
		return callerNumberFromSIPUser(uri[len("sip:"):])
	case strings.HasPrefix(lower, "sips:"):
		return callerNumberFromSIPUser(uri[len("sips:"):])
	default:
		return ""
	}
}

func callerNumberFromSIPUser(value string) string {
	if before, _, ok := strings.Cut(value, "@"); ok {
		value = before
	}
	number := cleanCallerUser(value)
	if !isDialableCaller(number) {
		return ""
	}
	return number
}

func cleanCallerUser(value string) string {
	if before, _, ok := strings.Cut(value, ";"); ok {
		value = before
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if unescaped, err := url.PathUnescape(value); err == nil {
		value = unescaped
	}
	return strings.TrimSpace(value)
}

func isDialableCaller(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return false
	}
	digits := 0
	for i, r := range value {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '+' && i == 0:
		case r == '*' || r == '#':
		default:
			return false
		}
	}
	return digits > 0
}

func (s *Service) writeRinging(ctx context.Context, req session.Request, call *Call) error {
	resp := sip.NewResponse(sipStatusRinging, "Ringing")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusRinging)
	s.addAccessNetworkInfo(&resp)
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(false, false))
	var rseq int64
	if call != nil && s.shouldSendReliable18x(req.Message) {
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

func (s *Service) shouldSendReliableDelayedOffer(msg sip.Message) bool {
	return s.canSendReliableProvisional(msg)
}

func (s *Service) shouldSendReliable18x(msg sip.Message) bool {
	return s.canSendReliableProvisional(msg)
}

func (s *Service) canSendReliableProvisional(msg sip.Message) bool {
	return s.cfg.ReliableProvisional &&
		(tokenHeaderContains(msg, "Supported", reliableProvisionalOption) ||
			tokenHeaderContains(msg, "Require", reliableProvisionalOption))
}

func (s *Service) usesPreconditions(msg sip.Message) bool {
	return s.cfg.Preconditions &&
		(tokenHeaderContains(msg, "Supported", preconditionOption) ||
			tokenHeaderContains(msg, "Require", preconditionOption))
}

func sdpUsesPreconditions(body []byte) bool {
	offer, err := parseSDP(body)
	return err == nil && offer.Preconditions
}

func (s *Service) unsupportedRequiredReliableProvisional(msg sip.Message) bool {
	return !s.cfg.ReliableProvisional && tokenHeaderContains(msg, "Require", reliableProvisionalOption)
}

func (s *Service) writeProgress(ctx context.Context, req session.Request, call *Call, body []byte, reliable bool) error {
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

func (s *Service) addAccessNetworkInfo(resp *sip.Message) {
	state := s.reg.State()
	if value := strings.TrimSpace(state.UserAgent); value != "" && strings.TrimSpace(resp.Header("Server")) == "" {
		resp.Headers.Add("Server", value)
	}
	if value := strings.TrimSpace(state.AccessNetworkInfo); value != "" && strings.TrimSpace(resp.Header("P-Access-Network-Info")) == "" {
		resp.Headers.Add("P-Access-Network-Info", value)
	}
}
