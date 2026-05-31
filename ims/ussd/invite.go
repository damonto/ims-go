package ussd

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"net/textproto"
	"strings"
	"sync/atomic"
	"time"
)

func (s *Service) newStart(code string) (startRequest, sip.Message, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return startRequest{}, sip.Message{}, errors.New("starting USSD: code is empty")
	}
	start := startRequest{
		code:      code,
		callID:    sip.RandomAlphaNum(24),
		sessionID: sip.RandomHex(32),
		localTag:  sip.RandomAlphaNum(10),
		branch:    sip.RandomAlphaNum(15),
		inviteSeq: atomic.AddInt64(&s.cseq, 1),
		language:  defaultValue(s.cfg.Language, defaultLang),
	}
	start.target = s.ussdTargetURI(start.code)
	boundary, body, err := s.buildInviteBody(start.code, start.language)
	if err != nil {
		return startRequest{}, sip.Message{}, err
	}
	return start, s.buildInvite(start, boundary, body), nil
}

func (s *Service) buildInviteBody(code, language string) (string, []byte, error) {
	payload, err := (xmlBody{Message: Message{Text: code, Language: language}}).MarshalText()
	if err != nil {
		return "", nil, fmt.Errorf("starting USSD: encoding XML payload: %w", err)
	}
	boundary := "ussd-" + sip.RandomAlphaNum(12)
	body, err := (multipartBody{Boundary: boundary, Parts: []multipartBodyPart{
		{
			Header: textproto.MIMEHeader{"Content-Type": {sdpContentType}},
			Body:   []byte(s.ussdSDP()),
		},
		{
			Header: textproto.MIMEHeader{
				"Content-Type":        {xmlContentType},
				"Content-Disposition": {renderOptionalDisposition},
			},
			Body: payload,
		},
	}}).MarshalBinary()
	if err != nil {
		return "", nil, fmt.Errorf("starting USSD: building multipart body: %w", err)
	}
	return boundary, body, nil
}

func (s *Service) buildInvite(start startRequest, boundary string, body []byte) sip.Message {
	state := s.reg.State()
	senderIdentity := preferredIdentity(state)
	msg := sip.NewRequest("INVITE", start.target)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, start.branch))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, start.localTag))
	msg.Headers.Add("To", fmt.Sprintf("<%s>", start.target))
	msg.Headers.Add("Call-ID", start.callID)
	msg.Headers.Add("Session-ID", start.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d INVITE", start.inviteSeq))
	msg.Headers.Add("Accept-Contact", "*;"+icsiRefFeatureTag)
	msg.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	msg.Headers.Add("Contact", contactValue(state, s.cfg.NetworkInitiatedSupported))
	msg.Headers.Add("Accept", ussdAcceptHeader)
	msg.Headers.Add("Recv-Info", infoPackage)
	s.reg.RequestPolicy().Apply(&msg)
	msg.Headers.Add("Content-Type", fmt.Sprintf("%s; boundary=%s", mixedMultipartType, boundary))
	msg.Body = body
	return msg
}

func (s *Service) startSession(ctx context.Context, start startRequest, invite, resp sip.Message) (*Session, error) {
	if err := validateInviteOK(resp); err != nil {
		return nil, fmt.Errorf("starting USSD: validating 200 OK: %w", err)
	}
	ussdSession := &Session{
		service:      s,
		callID:       start.callID,
		sessionID:    start.sessionID,
		localURI:     nonEmpty(sip.AddressURI(invite.Header("From")), preferredIdentity(s.reg.State())),
		localTag:     start.localTag,
		remoteTag:    sip.HeaderTag(resp.Header("To")),
		remoteTo:     nonEmpty(resp.Header("To"), invite.Header("To")),
		targetURI:    nonEmpty(sip.AddressURI(resp.Header("Contact")), start.target),
		routeSet:     reverseValues(resp.HeadersByName("Record-Route")),
		inviteSeq:    start.inviteSeq,
		localCSeq:    start.inviteSeq,
		language:     start.language,
		events:       make(chan Message, 16),
		remoteCSeqs:  make(map[string]struct{}),
		responseKind: dialogKindRequest,
	}
	if err := s.storeSession(ussdSession); err != nil {
		if endErr := ussdSession.endDirect(ctx, ""); endErr != nil {
			err = errors.Join(err, endErr)
		}
		ussdSession.finish(false)
		return nil, err
	}
	if err := s.sess.Send(ctx, ussdSession.buildACK()); err != nil {
		s.removeSession(ussdSession.sessionKey())
		ussdSession.closeEvents()
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	s.logger.Info("started USSD session", "code", start.code, "call_id", start.callID, "target_uri", ussdSession.targetURI)
	return ussdSession, nil
}

func (s *Service) cancelInvite(parent context.Context, invite sip.Message) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancel()
	_ = s.sess.Send(ctx, buildCancel(invite))
}

func (s *Service) handleIncomingInvite(ctx context.Context, req session.Request) error {
	if handled, err := s.handleExistingInvite(ctx, req); handled || err != nil {
		return err
	}
	if !s.cfg.NetworkInitiatedSupported {
		return s.sess.WriteStatus(ctx, req, sipStatusNotFound, "Not Found")
	}
	if s.hasActiveSession() {
		return s.sess.WriteStatus(ctx, req, sipStatusBusyHere, "Busy Here")
	}
	payload, err := validateIncomingInvite(req.Message)
	if err != nil {
		if errors.Is(err, errUnsupportedMediaType) {
			return s.writeUnsupportedMediaType(ctx, req)
		}
		return s.sess.WriteStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
	}
	ussdSession := s.newIncomingSession(req.Message, payload)
	if err := s.sess.WriteStatus(ctx, req, sipStatusTrying, "Trying"); err != nil {
		return fmt.Errorf("handling USSD INVITE: sending 100 Trying: %w", err)
	}
	ussdSession.inviteOK = s.buildIncomingInviteOK(req.Message, ussdSession.localURI, ussdSession.localTag)
	if err := s.storeSession(ussdSession); err != nil {
		ussdSession.closeEvents()
		if errors.Is(err, errSessionActive) {
			return s.sess.WriteStatus(ctx, req, sipStatusBusyHere, "Busy Here")
		}
		return err
	}
	ussdSession.emit(payload)
	ussdSession.setDeliveringInvite(true)
	if s.cfg.OnIncoming != nil {
		s.cfg.OnIncoming(ussdSession, payload)
	}
	ussdSession.setDeliveringInvite(false)
	if err := s.sess.WriteResponse(ctx, req, ussdSession.inviteOK); err != nil {
		ussdSession.finish(false)
		return fmt.Errorf("handling USSD INVITE: sending 200 OK: %w", err)
	}
	ussdSession.startInviteOKRetransmit(req, ussdSession.inviteOK)
	s.logger.Info("accepted network-initiated USSD", "call_id", ussdSession.callID, "target_uri", ussdSession.targetURI)
	return nil
}

func (s *Service) handleExistingInvite(ctx context.Context, req session.Request) (bool, error) {
	ussdSession := s.lookupIncomingInviteSession(req.Message)
	if ussdSession == nil {
		return false, nil
	}
	if ussdSession.inviteOK.StartLine != "" {
		return true, s.sess.WriteResponse(ctx, req, ussdSession.inviteOK)
	}
	return true, s.sess.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
}

func (s *Session) startInviteOKRetransmit(req session.Request, resp sip.Message) {
	s.mu.Lock()
	if s.inviteOKStop != nil || s.closed {
		s.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	s.inviteOKStop = stop
	s.mu.Unlock()

	s.service.startBackgroundTask(func() {
		timers := s.service.sess.TransactionTimers()
		interval := timers.T1
		timer := time.NewTimer(interval)
		defer timer.Stop()
		deadline := time.NewTimer(inviteOKTimeoutMultiplier * timers.T1)
		defer deadline.Stop()

		for {
			select {
			case <-stop:
				return
			case <-deadline.C:
				s.service.logger.Warn("USSD INVITE 200 OK ACK timeout", "call_id", s.callID)
				s.finish(false)
				return
			case <-timer.C:
				ctx, cancel := context.WithTimeout(context.Background(), min(inviteOKWriteTimeout, interval))
				if err := s.service.sess.WriteResponse(ctx, req, resp); err != nil {
					s.service.logger.Warn("retransmitting USSD INVITE 200 OK", "call_id", s.callID, "err", err)
				}
				cancel()
				interval = min(interval*2, timers.T2)
				timer.Reset(interval)
			}
		}
	})
}

func (s *Service) newIncomingSession(msg sip.Message, payload Message) *Session {
	state := s.reg.State()
	localTag := sip.RandomAlphaNum(10)
	remoteTo := msg.Header("From")
	targetURI := nonEmpty(sip.AddressURI(msg.Header("Contact")), sip.AddressURI(remoteTo))
	if targetURI == "" {
		targetURI = state.PublicIdentity
	}
	return &Session{
		service:          s,
		incomingInviteID: incomingInviteKey(msg),
		callID:           msg.Header("Call-ID"),
		sessionID:        nonEmpty(msg.Header("Session-ID"), sip.RandomHex(32)),
		localURI:         nonEmpty(sip.AddressURI(msg.Header("To")), preferredIdentity(state)),
		localTag:         localTag,
		remoteTag:        sip.HeaderTag(remoteTo),
		remoteTo:         remoteTo,
		targetURI:        targetURI,
		routeSet:         append([]string(nil), msg.HeadersByName("Record-Route")...),
		inviteSeq:        sip.CSeqNumber(msg.Header("CSeq")),
		localCSeq:        0,
		remoteCSeq:       sip.CSeqNumber(msg.Header("CSeq")),
		language:         defaultValue(payload.Language, defaultValue(s.cfg.Language, defaultLang)),
		networkInitiated: true,
		responseKind:     kindFromPayload(payload),
		ackCh:            make(chan struct{}),
		events:           make(chan Message, 16),
		remoteCSeqs:      map[string]struct{}{"INVITE|" + msg.Header("CSeq"): {}},
	}
}

func (s *Service) buildIncomingInviteOK(msg sip.Message, localURI, localTag string) sip.Message {
	ok := sip.NewResponse(sipStatusOK, "OK")
	ok.Headers = sip.ResponseHeaders(msg, sipStatusOK)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), localURI, localTag))
	ok.Headers.Add("Contact", contactValue(s.reg.State(), s.cfg.NetworkInitiatedSupported))
	ok.Headers.Add("Recv-Info", infoPackage)
	ok.Headers.Add("Accept", ussdAcceptHeader)
	ok.Headers.Add("Content-Type", sdpContentType)
	ok.Body = []byte(s.ussdSDP())
	return ok
}

func validateInviteOK(msg sip.Message) error {
	if !sip.TokenListContains(msg.Header("Recv-Info"), infoPackage) {
		return fmt.Errorf("missing Recv-Info %q", infoPackage)
	}
	if err := validateMessageSDP(msg); err != nil {
		return fmt.Errorf("validating SDP answer: %w", err)
	}
	return nil
}

func validateIncomingInvite(msg sip.Message) (Message, error) {
	if !sip.TokenListContains(msg.Header("Recv-Info"), infoPackage) {
		return Message{}, fmt.Errorf("missing Recv-Info %q", infoPackage)
	}
	if !acceptsMedia(msg.Header("Accept")) {
		return Message{}, errors.New("missing required Accept media types")
	}
	payload, hasSDP, err := decodeInvitePayload(msg)
	if err != nil {
		return Message{}, err
	}
	if !hasSDP {
		return Message{}, errors.New("missing SDP offer")
	}
	if !payload.Request && !payload.Notify {
		return Message{}, errors.New("missing network initiated USSD marker")
	}
	return payload, nil
}

func decodeInvitePayload(msg sip.Message) (Message, bool, error) {
	mediaType, params, err := splitContentTypeHeader("parsing USSD INVITE", msg.Header("Content-Type"))
	if err != nil {
		return Message{}, false, err
	}
	if mediaType != mixedMultipartType {
		return Message{}, false, fmt.Errorf("%w: parsing USSD INVITE: unsupported content type %q", errUnsupportedMediaType, mediaType)
	}
	body, err := readMultipartMessageBody("parsing USSD INVITE", params, msg.Body)
	if err != nil {
		return Message{}, false, err
	}
	if err := body.rejectUnsupportedRequiredParts("parsing USSD INVITE", xmlContentType, sdpContentType); err != nil {
		return Message{}, false, err
	}
	payload, err := decodeMultipartPayload("parsing USSD INVITE", body)
	if err != nil {
		return Message{}, false, err
	}
	hasSDP, err := validateOptionalMultipartSDP(body)
	if err != nil {
		return Message{}, false, err
	}
	return payload, hasSDP, nil
}

func looksLikeInvite(msg sip.Message) bool {
	if !strings.EqualFold(msg.Method(), "INVITE") {
		return false
	}
	return sip.TokenListContains(msg.Header("Recv-Info"), infoPackage) || acceptsMedia(msg.Header("Accept"))
}
