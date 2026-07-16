package ussd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

var ErrIMSDomainNotAllowed = errors.New("ims ussd is not allowed by domain policy")

func New(cfg Config, sess *session.Session, reg *registration.Registrar) (*Endpoint, error) {
	endpointCfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	endpoint := &Endpoint{
		cfg:           endpointCfg,
		sess:          sess,
		reg:           reg,
		logger:        endpointCfg.Logger.With("component", "ims-ussd"),
		sessions:      make(map[string]*Session),
		incomingIndex: make(map[string]string),
		done:          make(chan struct{}),
	}
	attachment, err := sess.Attach(endpoint)
	if err != nil {
		return nil, fmt.Errorf("creating USSD endpoint: %w", err)
	}
	endpoint.attachment = attachment
	return endpoint, nil
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.Language = strings.TrimSpace(cfg.Language)
	cfg.PhoneContextDomain = strings.TrimSpace(cfg.PhoneContextDomain)
	cfg.Domain = Domain(strings.ToLower(strings.TrimSpace(string(cfg.Domain))))
	if cfg.Domain == "" {
		cfg.Domain = DomainIMS
	}
	switch cfg.Domain {
	case DomainIMS, DomainCS, DomainDisabled:
	default:
		return Config{}, fmt.Errorf("creating USSD endpoint: unsupported domain %q", cfg.Domain)
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return cfg, nil
}

func (s *Endpoint) Start(ctx context.Context, code string) (*Session, error) {
	if s.cfg.Domain != DomainIMS {
		return nil, fmt.Errorf("starting USSD: %w", ErrIMSDomainNotAllowed)
	}
	if err := s.ensureNoActiveSession(); err != nil {
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	start, invite, err := s.newStart(code)
	if err != nil {
		return nil, err
	}
	resp, err := s.sess.Exchange(ctx, invite)
	if err != nil {
		if ctx.Err() != nil {
			s.cancelInvite(invite)
		}
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	if status := resp.StatusCode(); status == sipStatusNotFound {
		return nil, errors.New("starting USSD: missing network support")
	} else if status != sipStatusOK {
		return nil, fmt.Errorf("starting USSD: unexpected response: %w", sip.NewResponseError(resp))
	}
	return s.startSession(ctx, start, invite, resp)
}

func (s *Endpoint) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	attachment := s.attachment
	s.attachment = nil
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.sessions = make(map[string]*Session)
	s.incomingIndex = make(map[string]string)
	close(s.done)
	s.mu.Unlock()

	var err error
	if attachment != nil {
		err = attachment.Close()
	}

	for _, session := range sessions {
		session.finish(false)
	}
	s.bgWG.Wait()
	return err
}

func (s *Endpoint) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	switch strings.ToUpper(req.Message.Method()) {
	case "INVITE":
		if !looksLikeInvite(req.Message) {
			return false, nil
		}
		return true, s.handleIncomingInvite(ctx, req)
	case "ACK":
		session := s.lookupSessionForMessage(req.Message)
		if session == nil {
			return false, nil
		}
		return true, session.handleRequest(ctx, req)
	case "CANCEL":
		session := s.lookupIncomingInviteSession(req.Message)
		if session == nil {
			return false, nil
		}
		if !session.inviteHasFinalResponse() {
			session.finish(false)
		}
		return true, nil
	case "INFO", "BYE":
		session := s.lookupSessionForMessage(req.Message)
		if session != nil {
			return true, session.handleRequest(ctx, req)
		}
		if looksLikeDialogMessage(req.Message) {
			return true, s.sess.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
		}
		return false, nil
	default:
		return false, nil
	}
}

func (s *Endpoint) HandleError(err error) {
	if err == nil {
		return
	}
	s.logger.Debug("session error", "err", err)
}

func (s *Endpoint) HandleResponse(ctx context.Context, msg sip.Message) (bool, error) {
	if msg.StatusCode() < 200 || msg.StatusCode() >= 300 || !strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), "INVITE") {
		return false, nil
	}
	session := s.lookupSessionByCallID(strings.TrimSpace(msg.Header("Call-ID")))
	if session == nil || sip.CSeqNumber(msg.Header("CSeq")) != session.inviteSeq {
		return false, nil
	}
	remoteTag := sip.HeaderTag(msg.Header("To"))
	if remoteTag != session.remoteTag {
		return true, s.ackAndEndForkedDialog(ctx, session, msg)
	}
	session.mu.Lock()
	ack := session.inviteACK
	session.mu.Unlock()
	if ack.StartLine == "" {
		return false, nil
	}
	if err := s.sess.Send(ctx, ack); err != nil {
		return true, fmt.Errorf("acknowledging retransmitted USSD INVITE 2xx: %w", err)
	}
	return true, nil
}

func (s *Endpoint) ackAndEndForkedDialog(ctx context.Context, base *Session, resp sip.Message) error {
	base.mu.Lock()
	fork := &Session{
		endpoint:     s,
		callID:       base.callID,
		sessionID:    base.sessionID,
		localURI:     base.localURI,
		localTag:     base.localTag,
		remoteTag:    sip.HeaderTag(resp.Header("To")),
		remoteTo:     resp.Header("To"),
		targetURI:    nonEmpty(sip.AddressURI(resp.Header("Contact")), base.targetURI),
		routeSet:     reverseValues(resp.HeaderList("Record-Route")),
		inviteSeq:    base.inviteSeq,
		localCSeq:    base.inviteSeq,
		language:     base.language,
		events:       make(chan Message),
		remoteCSeqs:  make(map[string]struct{}),
		responseKind: dialogKindRequest,
	}
	base.mu.Unlock()
	if fork.remoteTag == "" {
		return errors.New("acknowledging forked USSD INVITE 2xx: missing To tag")
	}
	if err := s.sess.Send(ctx, fork.buildACK()); err != nil {
		return fmt.Errorf("acknowledging forked USSD INVITE 2xx: %w", err)
	}
	s.startBackgroundTask(func(done <-chan struct{}) {
		endCtx, cancel := contextWithDoneTimeout(done, defaultQueuedRequestTimeout)
		defer cancel()
		if err := fork.endDirect(endCtx, ""); err != nil {
			s.logger.Warn("ending forked USSD dialog", "call_id", fork.callID, "remote_tag", fork.remoteTag, "err", err)
		}
	})
	return nil
}

func (s *Endpoint) writeUnsupportedMediaType(ctx context.Context, req session.Request) error {
	resp := sip.NewResponse(sipStatusUnsupportedMediaType, "Unsupported Media Type")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusUnsupportedMediaType)
	resp.Headers.Add("Accept", acceptHeader)
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Endpoint) startBackgroundTask(task func(done <-chan struct{})) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	done := s.done
	s.bgWG.Go(func() {
		task(done)
	})
	s.mu.Unlock()
}

func (s *Endpoint) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	return contextWithDoneTimeout(done, timeout)
}

func contextWithDoneTimeout(done <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-done:
			cancel()
		case <-stop:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			cancel()
		})
	}
}

func (s *Endpoint) handleIncomingInvite(ctx context.Context, req session.Request) error {
	if handled, err := s.handleExistingInvite(ctx, req); handled || err != nil {
		return err
	}
	if !s.cfg.NetworkInitiatedSupported {
		return s.sess.WriteStatus(ctx, req, sipStatusNotFound, "Not Found")
	}
	if s.hasActiveSession() {
		return s.sess.WriteStatus(ctx, req, sipStatusBusyHere, "Busy Here")
	}
	payload, offerSDP, err := validateIncomingInvite(req.Message)
	if err != nil {
		if errors.Is(err, errUnsupportedMediaType) {
			return s.writeUnsupportedMediaType(ctx, req)
		}
		return s.sess.WriteStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
	}
	session := s.newIncomingSession(req.Message, payload)
	if err := s.sess.WriteStatus(ctx, req, sipStatusTrying, "Trying"); err != nil {
		return fmt.Errorf("handling USSD INVITE: sending 100 Trying: %w", err)
	}
	answerSDP, err := s.sdpAnswer(offerSDP)
	if err != nil {
		session.closeEvents()
		return s.sess.WriteStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
	}
	session.inviteOK = s.buildIncomingInviteOK(req.Message, session.localURI, session.localTag, answerSDP)
	if err := s.storeSession(session); err != nil {
		session.closeEvents()
		if errors.Is(err, errSessionActive) {
			return s.sess.WriteStatus(ctx, req, sipStatusBusyHere, "Busy Here")
		}
		return err
	}
	session.emit(payload)
	session.setDeliveringInvite(true)
	if s.cfg.OnIncoming != nil {
		s.cfg.OnIncoming(session, payload)
	}
	session.setDeliveringInvite(false)
	if err := s.sess.WriteResponse(ctx, req, session.inviteOK); err != nil {
		session.finish(false)
		return fmt.Errorf("handling USSD INVITE: sending 200 OK: %w", err)
	}
	session.markInviteFinalResponseSent()
	session.startInviteOKRetransmit(req, session.inviteOK)
	s.logger.Info("accepted network-initiated USSD", "call_id", session.callID, "target_uri", session.targetURI)
	return nil
}

func (s *Endpoint) handleExistingInvite(ctx context.Context, req session.Request) (bool, error) {
	session := s.lookupIncomingInviteSession(req.Message)
	if session == nil {
		return false, nil
	}
	if session.inviteOK.StartLine != "" {
		return true, s.sess.WriteResponse(ctx, req, session.inviteOK)
	}
	return true, s.sess.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
}

func (s *Endpoint) newIncomingSession(msg sip.Message, payload Message) *Session {
	state := s.reg.State()
	localTag := sip.RandomAlphaNum(10)
	remoteTo := msg.Header("From")
	targetURI := nonEmpty(sip.AddressURI(msg.Header("Contact")), sip.AddressURI(remoteTo))
	if targetURI == "" {
		targetURI = state.PublicIdentity
	}
	return &Session{
		endpoint:         s,
		incomingInviteID: incomingInviteKey(msg),
		callID:           msg.Header("Call-ID"),
		sessionID:        nonEmpty(msg.Header("Session-ID"), sip.RandomHex(32)),
		localURI:         nonEmpty(sip.AddressURI(msg.Header("To")), preferredIdentity(state)),
		localTag:         localTag,
		remoteTag:        sip.HeaderTag(remoteTo),
		remoteTo:         remoteTo,
		targetURI:        targetURI,
		routeSet:         msg.HeaderList("Record-Route"),
		inviteSeq:        sip.CSeqNumber(msg.Header("CSeq")),
		localCSeq:        0,
		remoteCSeq:       sip.CSeqNumber(msg.Header("CSeq")),
		language:         defaultValue(payload.Language, defaultValue(s.cfg.Language, defaultLang)),
		networkInitiated: true,
		responseKind:     kindFromPayload(payload),
		ackCh:            make(chan struct{}),
		state:            sessionStateWaitingACK,
		events:           make(chan Message, 16),
		remoteCSeqs:      map[string]struct{}{"INVITE|" + msg.Header("CSeq"): {}},
	}
}

func (s *Endpoint) buildIncomingInviteOK(msg sip.Message, localURI, localTag string, answerSDP []byte) sip.Message {
	ok := sip.NewResponse(sipStatusOK, "OK")
	ok.Headers = sip.ResponseHeaders(msg, sipStatusOK)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), localURI, localTag))
	for _, recordRoute := range msg.HeadersByName("Record-Route") {
		ok.Headers.Add("Record-Route", recordRoute)
	}
	ok.Headers.Add("Contact", contactValue(s.reg.State(), s.cfg.NetworkInitiatedSupported))
	ok.Headers.Add("Recv-Info", infoPackage)
	ok.Headers.Add("Accept", acceptHeader)
	ok.Headers.Add("Content-Type", sdpContentType)
	ok.Body = answerSDP
	return ok
}

func (s *Endpoint) newStart(code string) (startRequest, sip.Message, error) {
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
	start.target = s.targetURI(start.code)
	boundary, body, err := s.buildInviteBody(start.code, start.language)
	if err != nil {
		return startRequest{}, sip.Message{}, err
	}
	return start, s.buildInvite(start, boundary, body), nil
}

func (s *Endpoint) buildInviteBody(code, language string) (string, []byte, error) {
	payload, err := (xmlBody{Message: Message{Text: code, Language: language}}).MarshalText()
	if err != nil {
		return "", nil, fmt.Errorf("starting USSD: encoding XML payload: %w", err)
	}
	boundary := "ussd-" + sip.RandomAlphaNum(12)
	body, err := (multipartBody{Boundary: boundary, Parts: []multipartBodyPart{
		{
			Header: textproto.MIMEHeader{"Content-Type": {sdpContentType}},
			Body:   []byte(s.sdp()),
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

func (s *Endpoint) buildInvite(start startRequest, boundary string, body []byte) sip.Message {
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
	msg.Headers.Add("Accept", acceptHeader)
	msg.Headers.Add("Recv-Info", infoPackage)
	s.reg.RequestPolicy().Apply(&msg)
	msg.Headers.Add("Content-Type", fmt.Sprintf("%s; boundary=%s", mixedMultipartType, boundary))
	msg.Body = body
	return msg
}

func (s *Endpoint) startSession(ctx context.Context, start startRequest, invite, resp sip.Message) (*Session, error) {
	session := &Session{
		endpoint:     s,
		callID:       start.callID,
		sessionID:    start.sessionID,
		localURI:     nonEmpty(sip.AddressURI(invite.Header("From")), preferredIdentity(s.reg.State())),
		localTag:     start.localTag,
		remoteTag:    sip.HeaderTag(resp.Header("To")),
		remoteTo:     nonEmpty(resp.Header("To"), invite.Header("To")),
		targetURI:    nonEmpty(sip.AddressURI(resp.Header("Contact")), start.target),
		routeSet:     reverseValues(resp.HeaderList("Record-Route")),
		inviteSeq:    start.inviteSeq,
		localCSeq:    start.inviteSeq,
		language:     start.language,
		events:       make(chan Message, 16),
		remoteCSeqs:  make(map[string]struct{}),
		responseKind: dialogKindRequest,
	}
	validationErr := validateInviteOK(resp)
	storeErr := s.storeSession(session)

	// RFC 3261 section 13.2.2.4 requires an ACK for every INVITE 2xx,
	// including an unacceptable response or a dialog we cannot retain.
	ack := session.buildACK()
	session.inviteACK = ack
	if err := s.sess.Send(ctx, ack); err != nil {
		session.finish(false)
		return nil, fmt.Errorf("starting USSD: acknowledging 200 OK: %w", err)
	}
	if validationErr != nil {
		validationErr = fmt.Errorf("starting USSD: validating 200 OK: %w", validationErr)
		if storeErr != nil {
			validationErr = errors.Join(validationErr, storeErr)
		}
		if endErr := session.endDirect(ctx, ""); endErr != nil {
			validationErr = errors.Join(validationErr, endErr)
		}
		session.finish(false)
		return nil, validationErr
	}
	if storeErr != nil {
		if endErr := session.endDirect(ctx, ""); endErr != nil {
			storeErr = errors.Join(storeErr, endErr)
		}
		session.finish(false)
		return nil, storeErr
	}
	s.logger.Info("started USSD session", "code", start.code, "call_id", start.callID, "target_uri", session.targetURI)
	return session, nil
}

func (s *Endpoint) cancelInvite(invite sip.Message) {
	ctx, cancel := s.timeoutContext(2 * time.Second)
	defer cancel()
	_ = s.sess.Send(ctx, buildCancel(invite))
}

func (s *Session) startInviteOKRetransmit(req session.Request, resp sip.Message) {
	s.mu.Lock()
	if s.inviteOKStop != nil || s.state == sessionStateClosed {
		s.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	s.inviteOKStop = stop
	s.mu.Unlock()

	s.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		timers := s.endpoint.sess.TransactionTimers()
		interval := timers.T1
		timer := time.NewTimer(interval)
		defer timer.Stop()
		deadline := time.NewTimer(inviteOKTimeoutMultiplier * timers.T1)
		defer deadline.Stop()

		for {
			select {
			case <-done:
				return
			case <-stop:
				return
			case <-deadline.C:
				s.endpoint.logger.Warn("USSD INVITE 200 OK ACK timeout", "call_id", s.callID)
				s.finish(false)
				return
			case <-timer.C:
				ctx, cancel := contextWithDoneTimeout(done, min(inviteOKWriteTimeout, interval))
				if err := s.endpoint.sess.WriteResponse(ctx, req, resp); err != nil {
					s.endpoint.logger.Warn("retransmitting USSD INVITE 200 OK", "call_id", s.callID, "err", err)
				}
				cancel()
				interval = min(interval*2, timers.T2)
				timer.Reset(interval)
			}
		}
	})
}

func validateInviteOK(msg sip.Message) error {
	if sip.HeaderTag(msg.Header("To")) == "" {
		return errors.New("missing To tag")
	}
	if _, err := dialogContactURI(msg); err != nil {
		return fmt.Errorf("invalid Contact: %w", err)
	}
	if !msg.HeaderHasToken("Recv-Info", infoPackage) {
		return fmt.Errorf("missing Recv-Info %q", infoPackage)
	}
	if !acceptsMedia(strings.Join(msg.HeadersByName("Accept"), ",")) {
		return errors.New("missing required Accept media types")
	}
	if err := validateMessageSDP(msg); err != nil {
		return fmt.Errorf("validating SDP answer: %w", err)
	}
	return nil
}

func validateIncomingInvite(msg sip.Message) (Message, []byte, error) {
	if _, err := dialogContactURI(msg); err != nil {
		return Message{}, nil, fmt.Errorf("invalid Contact: %w", err)
	}
	if !msg.HeaderHasToken("Recv-Info", infoPackage) {
		return Message{}, nil, fmt.Errorf("missing Recv-Info %q", infoPackage)
	}
	if !acceptsMedia(strings.Join(msg.HeadersByName("Accept"), ",")) {
		return Message{}, nil, errors.New("missing required Accept media types")
	}
	payload, hasSDP, err := decodeInvitePayload(msg)
	if err != nil {
		return Message{}, nil, err
	}
	if !hasSDP {
		return Message{}, nil, errors.New("missing SDP offer")
	}
	if !payload.Request || payload.Notify {
		return Message{}, nil, errors.New("invalid network initiated USSD request marker")
	}
	xmlData, err := messageBodyPart(msg, xmlContentType)
	if err != nil {
		return Message{}, nil, err
	}
	_, presence, err := decodeXMLWithPresence(xmlData)
	if err != nil {
		return Message{}, nil, err
	}
	if !presence.text {
		return Message{}, nil, errors.New("missing ussd-string element")
	}
	if presence.error {
		return Message{}, nil, errors.New("unexpected error-code in network initiated INVITE")
	}
	offerSDP, err := messageSDPBody(msg)
	if err != nil {
		return Message{}, nil, err
	}
	return payload, offerSDP, nil
}

func decodeInvitePayload(msg sip.Message) (Message, bool, error) {
	mediaType, params, err := splitContentTypeHeader(payloadContextUSSDInvite, msg.Header("Content-Type"))
	if err != nil {
		return Message{}, false, err
	}
	if mediaType != mixedMultipartType {
		return Message{}, false, fmt.Errorf("%w: parsing USSD INVITE: unsupported content type %q", errUnsupportedMediaType, mediaType)
	}
	body, err := readMultipartMessageBody(payloadContextUSSDInvite, params, msg.Body)
	if err != nil {
		return Message{}, false, err
	}
	if err := body.rejectUnsupportedRequiredParts(payloadContextUSSDInvite, xmlContentType, sdpContentType); err != nil {
		return Message{}, false, err
	}
	payload, err := decodeMultipartPayload(payloadContextUSSDInvite, body)
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
	return msg.HeaderHasToken("Recv-Info", infoPackage) || acceptsMedia(strings.Join(msg.HeadersByName("Accept"), ","))
}
