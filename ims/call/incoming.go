package call

import (
	"context"
	"fmt"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
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
		return s.writeRinging(ctx, req, existing)
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
			return s.writeStatus(ctx, req, 488, "Not Acceptable Here")
		}
		var err error
		offer, err = parseSDP(body)
		if err != nil {
			return s.writeStatus(ctx, req, 488, "Not Acceptable Here")
		}
		answerBody, media, err = buildSDPAnswer(s.cfg, localIP, localPort, offer, MediaOffer{})
		if err != nil {
			return s.writeStatus(ctx, req, 488, "Not Acceptable Here")
		}
	}

	state := s.reg.State()
	localTag := sip.ResponseTag(req.Message)
	callID := req.Message.Header("Call-ID")
	call := &Call{
		service:         s,
		id:              callID,
		sessionID:       nonEmpty(req.Message.Header("Session-ID"), sip.RandomHex(32)),
		direction:       DirectionIncoming,
		state:           StateRinging,
		localURI:        nonEmpty(sip.AddressURI(req.Message.Header("To")), preferredIdentity(state)),
		localTag:        localTag,
		remoteURI:       nonEmpty(sip.AddressURI(req.Message.Header("From")), sip.AddressURI(req.Message.Header("Contact"))),
		remoteTag:       sip.HeaderTag(req.Message.Header("From")),
		remoteTo:        req.Message.Header("From"),
		targetURI:       nonEmpty(sip.AddressURI(req.Message.Header("Contact")), sip.AddressURI(req.Message.Header("From"))),
		routeSet:        append([]string(nil), req.Message.HeadersByName("Record-Route")...),
		inviteSeq:       sip.CSeqNumber(req.Message.Header("CSeq")),
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

	if err := s.writeStatus(ctx, req, 100, "Trying"); err != nil {
		return fmt.Errorf("handling call INVITE: sending 100 Trying: %w", err)
	}
	if delayedOffer && s.shouldSendReliableDelayedOffer(req.Message) {
		offerBody, offerMedia, err := buildSDPOffer(s.cfg, localIP, localPort, MediaOffer{})
		if err != nil {
			call.finish(StateFailed, err.Error())
			return err
		}
		call.mu.Lock()
		call.media = offerMedia
		call.mu.Unlock()
		if err := call.prepareMedia(ctx); err != nil {
			call.finish(StateFailed, err.Error())
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
				call.setState(StateRinging, "")
				if s.cfg.OnIncoming != nil {
					s.cfg.OnIncoming(Incoming{
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
				call.finish(StateFailed, err.Error())
				return s.writeStatus(ctx, req, 488, "Not Acceptable Here")
			}
		}
		if err := s.writeRinging(ctx, req, call); err != nil {
			return fmt.Errorf("handling call INVITE: sending 180 Ringing: %w", err)
		}
		call.startRingingTimer()
	}
	call.setState(StateRinging, "")
	if s.cfg.OnIncoming != nil {
		var incomingOffer MediaOffer
		if !delayedOffer {
			incomingOffer = mediaOfferFromSDP(offer)
		}
		s.cfg.OnIncoming(Incoming{
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
	resp := sip.NewResponse(180, "Ringing")
	resp.Headers = sip.ResponseHeaders(req.Message, 180)
	s.addAccessNetworkInfo(&resp)
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(s.cfg))
	if call != nil && s.shouldSendReliable18x(req.Message) {
		resp.Headers.Add("Require", "100rel")
		resp.Headers.Add("RSeq", strconv.FormatInt(call.beginReliableProvisional(180, sip.CSeqNumber(req.Message.Header("CSeq")), "INVITE"), 10))
	}
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) shouldSendReliableDelayedOffer(msg sip.Message) bool {
	return s.cfg.ReliableProvisional && tokenHeaderContains(msg, "Supported", "100rel")
}

func (s *Service) shouldSendReliable18x(msg sip.Message) bool {
	return s.cfg.ReliableProvisional && tokenHeaderContains(msg, "Supported", "100rel")
}

func (s *Service) writeProgress(ctx context.Context, req session.Request, call *Call, body []byte, reliable bool) error {
	resp := sip.NewResponse(183, "Session Progress")
	resp.Headers = sip.ResponseHeaders(req.Message, 183)
	s.addAccessNetworkInfo(&resp)
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Message.Header("To"), call.localURI, call.localTag))
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(s.cfg))
	if reliable {
		resp.Headers.Add("Require", "100rel")
		resp.Headers.Add("RSeq", strconv.FormatInt(call.beginReliableProvisional(183, sip.CSeqNumber(req.Message.Header("CSeq")), "INVITE"), 10))
	}
	if len(body) != 0 {
		if err := setInviteResponseBody(&resp, s.cfg, call.localURI, body); err != nil {
			return err
		}
	}
	return s.sess.WriteResponse(ctx, req, resp)
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
