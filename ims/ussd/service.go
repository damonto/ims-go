package ussd

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
)

const (
	infoPackage                 = "g.3gpp.ussd"
	xmlContentType              = "application/vnd.3gpp.ussd+xml"
	mixedMultipartType          = "multipart/mixed"
	defaultLang                 = "en"
	defaultQueuedRequestTimeout = 30 * time.Second
)

type Config struct {
	Language           string
	PhoneContextDomain string
	OnIncoming         func(*Session, Message)
}

type Message struct {
	Text      string
	Language  string
	ErrorCode int
	Final     bool
	Notify    bool
	Request   bool
}

type USSDMessage = Message

type Service struct {
	cfg           Config
	sess          *session.Session
	reg           *registration.Service
	logger        *slog.Logger
	attachment    session.Attachment
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc

	mu            sync.Mutex
	sessions      map[string]*Session
	incomingIndex map[string]string
	closed        bool
	cseq          int64
	bgWG          sync.WaitGroup
}

type Session struct {
	service          *Service
	dialogAttachment session.Attachment
	incomingInviteID string
	callID           string
	sessionID        string
	localURI         string
	localTag         string
	remoteTag        string
	remoteTo         string
	targetURI        string
	routeSet         []string
	inviteSeq        int64
	language         string
	networkInitiated bool
	responseKind     dialogKind
	inviteOK         sip.Message
	ackCh            chan struct{}
	acked            bool
	awaitingInfo     bool
	events           chan Message
	remoteCSeqs      map[string]struct{}
	pendingInitial   *queuedRequest
	deliveringInvite bool

	mu     sync.Mutex
	closed bool
}

type USSDSession = Session

type dialogKind uint8

const (
	dialogKindNone dialogKind = iota
	dialogKindRequest
	dialogKindNotify
)

type xmlPayload struct {
	XMLName   xml.Name `xml:"ussd-data"`
	Language  string   `xml:"language,omitempty"`
	String    string   `xml:"ussd-string,omitempty"`
	ErrorCode int      `xml:"error-code,omitempty"`
	AnyExt    *anyExt  `xml:"anyExt,omitempty"`
}

type anyExt struct {
	Request *struct{} `xml:"UnstructuredSS-Request,omitempty"`
	Notify  *struct{} `xml:"UnstructuredSS-Notify,omitempty"`
}

type multipartBodyPart struct {
	Header textproto.MIMEHeader
	Body   []byte
}

type queuedRequest struct {
	msg     sip.Message
	action  string
	final   bool
	timeout time.Duration
}

type startRequest struct {
	code      string
	target    string
	callID    string
	sessionID string
	localTag  string
	branch    string
	inviteSeq int64
	language  string
}

func New(cfg Config, sess *session.Session, reg *registration.Service) (*Service, error) {
	if sess == nil {
		return nil, errors.New("creating ussd service: session is nil")
	}
	if reg == nil {
		return nil, errors.New("creating ussd service: registration service is nil")
	}
	cfg.Language = strings.TrimSpace(cfg.Language)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	s := &Service{
		cfg:           cfg,
		sess:          sess,
		reg:           reg,
		logger:        slog.Default().With("component", "ims-ussd"),
		sessions:      make(map[string]*Session),
		incomingIndex: make(map[string]string),
		cleanupCtx:    cleanupCtx,
		cleanupCancel: cleanupCancel,
	}
	attachment, err := sess.Attach(s)
	if err != nil {
		return nil, fmt.Errorf("creating ussd service: %w", err)
	}
	s.attachment = attachment
	return s, nil
}

func (s *Service) Start(ctx context.Context, code string) (*Session, error) {
	ctx = normalizeContext(ctx)
	start, invite, err := s.newStart(code)
	if err != nil {
		return nil, err
	}
	resp, err := s.sess.Exchange(ctx, invite)
	if err != nil {
		if ctx.Err() != nil {
			s.cancelInvite(ctx, invite)
		}
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	if status := resp.StatusCode(); status == 404 {
		return nil, errors.New("starting USSD: missing network support")
	} else if status != 200 {
		return nil, fmt.Errorf("starting USSD: unexpected status %d", status)
	}
	return s.startSession(ctx, start, invite, resp)
}

func (s *Service) CloseContext(ctx context.Context) error {
	ctx = normalizeContext(ctx)
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.sessions = make(map[string]*Session)
	s.incomingIndex = make(map[string]string)
	s.mu.Unlock()

	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
	if s.attachment != nil {
		_ = s.attachment.Close()
	}

	var err error
	for _, ussdSession := range sessions {
		if !ussdSession.isClosed() {
			err = errors.Join(err, ussdSession.endDirect(ctx, ""))
		}
		ussdSession.finish(false)
	}
	s.bgWG.Wait()
	return err
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	switch strings.ToUpper(req.Message.Method()) {
	case "INVITE":
		if !looksLikeInvite(req.Message) {
			return false, nil
		}
		return true, s.handleIncomingInvite(ctx, req)
	case "ACK":
		ussdSession := s.lookupSessionForMessage(req.Message)
		if ussdSession == nil {
			return false, nil
		}
		return true, ussdSession.handleRequest(ctx, req)
	case "INFO", "BYE":
		ussdSession := s.lookupSessionForMessage(req.Message)
		if ussdSession != nil {
			return true, ussdSession.handleRequest(ctx, req)
		}
		if looksLikeDialogMessage(req.Message) {
			return true, s.sess.WriteStatus(ctx, req, 481, "Call/Transaction Does Not Exist")
		}
		return false, nil
	default:
		return false, nil
	}
}

func (s *Service) HandleError(err error) {
	if err == nil {
		return
	}
	s.logger.Debug("session error", "err", err)
}

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
			Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}},
			Body:   []byte(s.ussdSDP()),
		},
		{
			Header: textproto.MIMEHeader{
				"Content-Type":        {xmlContentType},
				"Content-Disposition": {"render;handling=optional"},
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
	msg.Headers.Add("Accept-Contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`)
	msg.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	msg.Headers.Add("Contact", contactValue(state))
	msg.Headers.Add("Accept", "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed")
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
		language:     start.language,
		events:       make(chan Message, 16),
		remoteCSeqs:  make(map[string]struct{}),
		responseKind: dialogKindRequest,
	}
	if err := s.storeSession(ussdSession); err != nil {
		return nil, err
	}
	if err := s.sess.Send(ctx, ussdSession.buildACK()); err != nil {
		s.removeSession(ussdSession.sessionKey())
		ussdSession.closeEvents()
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	s.logger.Debug("started USSD session", "code", start.code, "call_id", start.callID, "target_uri", ussdSession.targetURI)
	return ussdSession, nil
}

func (s *Service) cancelInvite(parent context.Context, invite sip.Message) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancel()
	_ = s.sess.Send(ctx, buildCancel(invite))
}

func (s *Service) handleIncomingInvite(ctx context.Context, req session.Request) error {
	if handled, err := s.handleExistingInvite(ctx, req); handled || err != nil {
		return err
	}
	payload, err := validateIncomingInvite(req.Message)
	if err != nil {
		return s.sess.WriteStatus(ctx, req, 488, "Not Acceptable Here")
	}
	ussdSession := s.newIncomingSession(req.Message, payload)
	if err := s.sess.WriteStatus(ctx, req, 100, "Trying"); err != nil {
		return fmt.Errorf("handling USSD INVITE: sending 100 Trying: %w", err)
	}
	ussdSession.inviteOK = s.buildIncomingInviteOK(req.Message, ussdSession.localURI, ussdSession.localTag)
	if err := s.storeSession(ussdSession); err != nil {
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
	s.logger.Debug("accepted network-initiated USSD", "call_id", ussdSession.callID, "target_uri", ussdSession.targetURI)
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
	return true, s.sess.WriteStatus(ctx, req, 481, "Call/Transaction Does Not Exist")
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
		language:         defaultValue(payload.Language, defaultValue(s.cfg.Language, defaultLang)),
		networkInitiated: true,
		responseKind:     kindFromPayload(payload),
		ackCh:            make(chan struct{}),
		events:           make(chan Message, 16),
		remoteCSeqs:      map[string]struct{}{"INVITE|" + msg.Header("CSeq"): {}},
	}
}

func (s *Service) buildIncomingInviteOK(msg sip.Message, localURI, localTag string) sip.Message {
	ok := sip.NewResponse(200, "OK")
	ok.Headers = sip.ResponseHeaders(msg, 200)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), localURI, localTag))
	ok.Headers.Add("Contact", contactValue(s.reg.State()))
	ok.Headers.Add("Recv-Info", infoPackage)
	ok.Headers.Add("Accept", "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed")
	ok.Headers.Add("Content-Type", "application/sdp")
	ok.Body = []byte(s.ussdSDP())
	return ok
}

func (s *Service) storeSession(ussdSession *Session) error {
	key := ussdSession.sessionKey()
	attachment, err := s.sess.RegisterDialog(sip.DialogID{
		CallID:    ussdSession.callID,
		LocalTag:  ussdSession.localTag,
		RemoteTag: ussdSession.remoteTag,
	}, key)
	if err != nil {
		return fmt.Errorf("storing USSD session: %w", err)
	}
	ussdSession.dialogAttachment = attachment
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[key] = ussdSession
	if inviteKey := ussdSession.inviteRequestKey(); inviteKey != "" {
		s.incomingIndex[inviteKey] = key
	}
	return nil
}

func (s *Service) lookupSessionByCallID(callID string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ussdSession := range s.sessions {
		if ussdSession.callID == callID {
			return ussdSession
		}
	}
	return nil
}

func (s *Service) lookupIncomingInviteSession(msg sip.Message) *Session {
	inviteKey := incomingInviteKey(msg)
	if inviteKey == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key, ok := s.incomingIndex[inviteKey]
	if !ok {
		return nil
	}
	return s.sessions[key]
}

func (s *Service) lookupSessionForMessage(msg sip.Message) *Session {
	key, ok := s.sess.LookupDialogKey(msg)
	if !ok {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[key]
}

func (s *Service) removeSession(key string) {
	s.mu.Lock()
	ussdSession := s.sessions[key]
	if ussdSession != nil {
		delete(s.sessions, key)
		if inviteKey := ussdSession.inviteRequestKey(); inviteKey != "" {
			delete(s.incomingIndex, inviteKey)
		}
	}
	s.mu.Unlock()
	if ussdSession != nil && ussdSession.dialogAttachment != nil {
		_ = ussdSession.dialogAttachment.Close()
		ussdSession.dialogAttachment = nil
	}
}

func (s *Service) ussdTargetURI(code string) string {
	realm := strings.TrimPrefix(s.reg.State().RegisterURI, "sip:")
	phoneContext := strings.TrimSpace(s.cfg.PhoneContextDomain)
	if phoneContext == "" {
		phoneContext = realm
	}
	dial := strings.ReplaceAll(code, "#", "%23")
	return fmt.Sprintf("sip:%s;phone-context=%s@%s;user=dialstring", dial, phoneContext, realm)
}

func (s *Service) ussdSDP() string {
	host := s.reg.State().ContactHost
	network := "IP4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "IP6"
	}
	sessionID := sip.RandomUint32()
	return fmt.Sprintf("v=0\r\no=- %d %d IN %s %s\r\ns=-\r\nc=IN %s %s\r\nt=0 0\r\nm=audio 0 RTP/AVP 97 96\r\na=rtpmap:97 AMR\r\na=fmtp:97 mode-set=0,2,5,7; maxframes=2\r\na=rtpmap:96 telephone-event\r\n", sessionID, sessionID, network, host, network, host)
}

func (s *Service) startBackgroundTask(task func()) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.bgWG.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.bgWG.Done()
		task()
	}()
}

func (s *Session) Events() <-chan Message {
	return s.events
}

func (s *Session) Reply(ctx context.Context, text string) error {
	if err := s.ensureActive("replying USSD"); err != nil {
		return err
	}
	payload, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage()})
	if err != nil {
		return fmt.Errorf("replying USSD: encoding XML payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.Headers.Add("Info-Package", infoPackage)
	msg.Headers.Add("Content-Disposition", "info-package")
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, "replying USSD", false); queued || err != nil {
		return err
	}
	return s.exchange(ctx, msg, "replying USSD")
}

func (s *Session) ReplyError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive("replying USSD"); err != nil {
		return err
	}
	payload, err := (xmlBody{Message: Message{Language: s.currentLanguage(), ErrorCode: normalizeErrorCode(errorCode)}}).MarshalText()
	if err != nil {
		return fmt.Errorf("replying USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.Headers.Add("Info-Package", infoPackage)
	msg.Headers.Add("Content-Disposition", "info-package")
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, "replying USSD", false); queued || err != nil {
		return err
	}
	return s.exchange(ctx, msg, "replying USSD")
}

func (s *Session) End(ctx context.Context, text string) error {
	if err := s.ensureActive("ending USSD"); err != nil {
		return err
	}
	var payload []byte
	if strings.TrimSpace(text) != "" {
		encoded, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage(), Final: true})
		if err != nil {
			return fmt.Errorf("ending USSD: encoding XML payload: %w", err)
		}
		payload = encoded
	}
	msg := s.buildDialogRequest("BYE", payload)
	if len(payload) > 0 {
		msg.Headers.Add("Content-Type", xmlContentType)
	}
	if queued, err := s.queueInitialRequest(ctx, msg, "ending USSD", true); queued || err != nil {
		return err
	}
	if err := s.exchange(ctx, msg, "ending USSD"); err != nil {
		return err
	}
	s.finish(false)
	return nil
}

func (s *Session) EndError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive("ending USSD"); err != nil {
		return err
	}
	payload, err := (xmlBody{Message: Message{Language: s.currentLanguage(), ErrorCode: normalizeErrorCode(errorCode), Final: true}}).MarshalText()
	if err != nil {
		return fmt.Errorf("ending USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("BYE", payload)
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, "ending USSD", true); queued || err != nil {
		return err
	}
	if err := s.exchange(ctx, msg, "ending USSD"); err != nil {
		return err
	}
	s.finish(false)
	return nil
}

func (s *Session) endDirect(ctx context.Context, text string) error {
	var payload []byte
	if strings.TrimSpace(text) != "" {
		encoded, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage(), Final: true})
		if err != nil {
			return fmt.Errorf("ending USSD: encoding XML payload: %w", err)
		}
		payload = encoded
	}
	msg := s.buildDialogRequest("BYE", payload)
	if len(payload) > 0 {
		msg.Headers.Add("Content-Type", xmlContentType)
	}
	resp, err := s.service.sess.Exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("ending USSD: %w", err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("ending USSD: unexpected status %d", resp.StatusCode())
	}
	return nil
}

func (s *Session) marshalDialogPayload(msg Message) ([]byte, error) {
	if s.networkInitiated {
		switch s.dialogKind() {
		case dialogKindRequest:
			msg.Request = true
		case dialogKindNotify:
			msg.Notify = true
		}
	}
	return (xmlBody{Message: msg}).MarshalText()
}

func (s *Session) dialogKind() dialogKind {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.responseKind
}

func (s *Session) currentLanguage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.language
}

func (s *Session) setLanguage(language string) {
	if strings.TrimSpace(language) == "" {
		return
	}
	s.mu.Lock()
	s.language = language
	s.mu.Unlock()
}

func (s *Session) ensureActive(action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%s: session is closed", action)
	}
	return nil
}

func (s *Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *Session) waitForACK(ctx context.Context, action string) error {
	s.mu.Lock()
	if !s.networkInitiated || s.acked || s.ackCh == nil {
		s.mu.Unlock()
		return nil
	}
	ackCh := s.ackCh
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return fmt.Errorf("%s: %w", action, ctx.Err())
	case <-ackCh:
		return nil
	}
}

func (s *Session) exchange(ctx context.Context, msg sip.Message, action string) error {
	releaseInfo := false
	if strings.EqualFold(msg.Method(), "INFO") {
		if err := s.beginInfoExchange(action); err != nil {
			return err
		}
		releaseInfo = true
		defer func() {
			if releaseInfo {
				s.releaseInfoExchange()
			}
		}()
	}
	if err := s.waitForACK(ctx, action); err != nil {
		return err
	}
	resp, err := s.service.sess.Exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("%s: unexpected status %d", action, resp.StatusCode())
	}
	releaseInfo = false
	return nil
}

func (s *Session) buildACK() sip.Message {
	state := s.service.reg.State()
	senderIdentity := s.localDialogURI()
	msg := sip.NewRequest("ACK", s.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("Max-Forwards", "70")
	sip.ApplyRouteSet(&msg, s.routeSet)
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d ACK", s.inviteSeq))
	return msg
}

func (s *Session) buildDialogRequest(method string, body []byte) sip.Message {
	state := s.service.reg.State()
	senderIdentity := s.localDialogURI()
	msg := sip.NewRequest(method, s.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("Session-ID", s.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", atomic.AddInt64(&s.service.cseq, 1), method))
	msg.Headers.Add("Contact", contactValue(state))
	s.service.reg.DialogRequestPolicy(s.routeSet).Apply(&msg)
	msg.Body = body
	return msg
}

func (s *Session) handleRequest(ctx context.Context, req session.Request) error {
	switch strings.ToUpper(req.Message.Method()) {
	case "ACK":
		s.handleACK()
		return nil
	case "INFO":
		return s.handleInfo(ctx, req)
	case "BYE":
		return s.handleBye(ctx, req)
	default:
		return nil
	}
}

func (s *Session) handleACK() {
	pending := s.markACK()
	if pending == nil {
		return
	}
	s.service.startBackgroundTask(func() {
		ctx, cancel := context.WithTimeout(s.service.cleanupCtx, pending.timeout)
		defer cancel()
		if err := s.exchange(ctx, pending.msg, pending.action); err != nil {
			s.service.logger.Warn("sending queued ussd response", "call_id", s.callID, "method", pending.msg.Method(), "err", err)
			return
		}
		if pending.final {
			s.finish(false)
		}
	})
}

func (s *Session) handleInfo(ctx context.Context, req session.Request) error {
	payload, err := validateInboundInfo(req.Message, s.networkInitiated)
	if err != nil {
		return s.service.sess.WriteStatus(ctx, req, 415, "Unsupported Media Type")
	}
	if err := s.service.sess.WriteStatus(ctx, req, 200, "OK"); err != nil {
		return err
	}
	s.releaseInfoExchange()
	if s.isDuplicateRemote(req.Message) {
		s.service.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", req.Message.Header("CSeq"))
		return nil
	}
	s.setLanguage(payload.Language)
	s.setDialogKind(payload)
	s.emit(payload)
	return nil
}

func (s *Session) handleBye(ctx context.Context, req session.Request) error {
	s.releaseInfoExchange()
	var payload Message
	hasPayload := len(req.Message.Body) > 0 || strings.TrimSpace(req.Message.Header("Content-Type")) != ""
	if hasPayload {
		decoded, err := decodeSinglePayload("parsing USSD BYE", req.Message)
		if err != nil {
			return s.service.sess.WriteStatus(ctx, req, 415, "Unsupported Media Type")
		}
		payload = decoded
	}
	if s.isDuplicateRemote(req.Message) {
		if err := s.service.sess.WriteStatus(ctx, req, 200, "OK"); err != nil {
			return err
		}
		s.service.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", req.Message.Header("CSeq"))
		return nil
	}
	if err := s.service.sess.WriteStatus(ctx, req, 200, "OK"); err != nil {
		return err
	}
	payload.Final = true
	s.setLanguage(payload.Language)
	s.setDialogKind(payload)
	if hasPayload {
		s.emit(payload)
	}
	s.finish(true)
	return nil
}

func (s *Session) emit(msg Message) {
	defer func() { _ = recover() }()
	select {
	case s.events <- msg:
	default:
		s.service.logger.Debug("dropping USSD event", "call_id", s.callID, "text", msg.Text)
	}
}

func (s *Session) isDuplicateRemote(msg sip.Message) bool {
	key := msg.Method() + "|" + msg.Header("CSeq")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.remoteCSeqs[key]; ok {
		return true
	}
	s.remoteCSeqs[key] = struct{}{}
	return false
}

func (s *Session) markACK() *queuedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acked {
		return nil
	}
	s.acked = true
	pending := s.pendingInitial
	s.pendingInitial = nil
	if s.ackCh != nil {
		close(s.ackCh)
	}
	return pending
}

func (s *Session) setDialogKind(payload Message) {
	kind := kindFromPayload(payload)
	if kind == dialogKindNone {
		return
	}
	s.mu.Lock()
	s.responseKind = kind
	s.mu.Unlock()
}

func (s *Session) beginInfoExchange(action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.awaitingInfo {
		return fmt.Errorf("%s: awaiting remote INFO", action)
	}
	s.awaitingInfo = true
	return nil
}

func (s *Session) releaseInfoExchange() {
	s.mu.Lock()
	s.awaitingInfo = false
	s.mu.Unlock()
}

func (s *Session) finish(fromNetwork bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.deliveringInvite = false
	s.pendingInitial = nil
	if !s.acked && s.ackCh != nil {
		close(s.ackCh)
		s.acked = true
	}
	s.mu.Unlock()
	if s.dialogAttachment != nil {
		_ = s.dialogAttachment.Close()
		s.dialogAttachment = nil
	}
	s.service.removeSession(s.sessionKey())
	s.closeEvents()
	s.service.logger.Debug("ended USSD session", "call_id", s.callID, "from_network", fromNetwork)
}

func (s *Session) closeEvents() {
	defer func() { _ = recover() }()
	close(s.events)
}

func (s *Session) setDeliveringInvite(active bool) {
	s.mu.Lock()
	s.deliveringInvite = active
	s.mu.Unlock()
}

func (s *Session) queueInitialRequest(ctx context.Context, msg sip.Message, action string, final bool) (bool, error) {
	ctx = normalizeContext(ctx)
	timeout, err := queuedRequestTimeout(ctx)
	if err != nil {
		return false, fmt.Errorf("%s: %w", action, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.networkInitiated || s.acked || s.ackCh == nil {
		return false, nil
	}
	if s.pendingInitial != nil {
		return false, fmt.Errorf("%s: initial response already queued", action)
	}
	if !s.deliveringInvite {
		return false, nil
	}
	s.pendingInitial = &queuedRequest{
		msg:     msg,
		action:  action,
		final:   final,
		timeout: timeout,
	}
	return true, nil
}

func (s *Session) localDialogURI() string {
	if uri := strings.TrimSpace(s.localURI); uri != "" {
		return uri
	}
	return preferredIdentity(s.service.reg.State())
}

func (s *Session) sessionKey() string {
	return dialogSessionKey(sip.DialogID{
		CallID:    s.callID,
		LocalTag:  s.localTag,
		RemoteTag: s.remoteTag,
	})
}

func (s *Session) inviteRequestKey() string {
	if !s.networkInitiated {
		return ""
	}
	return strings.TrimSpace(s.incomingInviteID)
}

func dialogSessionKey(id sip.DialogID) string {
	return id.CallID + "|" + id.LocalTag + "|" + id.RemoteTag
}

func incomingInviteKey(msg sip.Message) string {
	method := strings.ToUpper(strings.TrimSpace(msg.Method()))
	if method == "" {
		return ""
	}
	if method == "ACK" {
		method = "INVITE"
	}

	via := strings.TrimSpace(msg.Header("Via"))
	branch := strings.TrimSpace(sip.TopViaBranch(via))
	if strings.HasPrefix(branch, "z9hG4bK") {
		sentBy := strings.TrimSpace(sip.TopViaSentBy(via))
		if sentBy == "" {
			return ""
		}
		return branch + "|" + sentBy + "|" + method
	}

	requestURI := strings.TrimSpace(sip.RequestURI(msg))
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	fromTag := strings.TrimSpace(sip.HeaderTag(msg.Header("From")))
	toTag := strings.TrimSpace(sip.HeaderTag(msg.Header("To")))
	if requestURI == "" || via == "" || callID == "" || cseq == "" || fromTag == "" {
		return ""
	}
	return requestURI + "|" + toTag + "|" + fromTag + "|" + callID + "|" + cseq + "|" + via
}

func validateInviteOK(msg sip.Message) error {
	if !sip.TokenListContains(msg.Header("Recv-Info"), infoPackage) {
		return fmt.Errorf("missing Recv-Info %q", infoPackage)
	}
	if !acceptsMedia(msg.Header("Accept")) {
		return errors.New("missing required Accept media types")
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

func validateInboundInfo(msg sip.Message, requireRequestMarker bool) (Message, error) {
	if !sip.TokenListContains(msg.Header("Info-Package"), infoPackage) {
		return Message{}, fmt.Errorf("missing Info-Package %q", infoPackage)
	}
	if !strings.EqualFold(contentDispositionType(msg.Header("Content-Disposition")), "info-package") {
		return Message{}, errors.New("missing Content-Disposition info-package")
	}
	payload, err := decodeSinglePayload("parsing USSD INFO", msg)
	if err != nil {
		return Message{}, err
	}
	if requireRequestMarker && !payload.Request && !payload.Notify {
		return Message{}, errors.New("missing network initiated USSD marker")
	}
	return payload, nil
}

func splitContentTypeHeader(action, rawContentType string) (string, map[string]string, error) {
	rawContentType = strings.TrimSpace(rawContentType)
	if rawContentType == "" {
		return "", nil, fmt.Errorf("%s: content type is empty", action)
	}
	mediaType, params, err := mime.ParseMediaType(rawContentType)
	if err != nil {
		return "", nil, fmt.Errorf("%s: content type: %w", action, err)
	}
	return strings.ToLower(mediaType), params, nil
}

func readMultipartMessageBody(action string, params map[string]string, data []byte) (multipartBody, error) {
	boundary := params["boundary"]
	if boundary == "" {
		return multipartBody{}, fmt.Errorf("%s: multipart boundary is empty", action)
	}
	body := multipartBody{Boundary: boundary}
	if err := body.UnmarshalBinary(data); err != nil {
		return multipartBody{}, err
	}
	return body, nil
}

func decodeMultipartPayload(action string, body multipartBody) (Message, error) {
	payload, ok, err := body.ussdPayload()
	if err != nil {
		return Message{}, err
	}
	if !ok {
		return Message{}, fmt.Errorf("%s: %s part not found", action, xmlContentType)
	}
	return payload, nil
}

func validateOptionalMultipartSDP(body multipartBody) (bool, error) {
	part, ok := body.part("application/sdp")
	if !ok {
		return false, nil
	}
	if err := validateSDPBody(part.Body); err != nil {
		return true, err
	}
	return true, nil
}

func validateMultipartMessageSDP(action string, body multipartBody) error {
	part, ok := body.part("application/sdp")
	if !ok {
		return fmt.Errorf("%s: application/sdp part not found", action)
	}
	return validateSDPBody(part.Body)
}

func decodeInvitePayload(msg sip.Message) (Message, bool, error) {
	mediaType, params, err := splitContentTypeHeader("parsing USSD INVITE", msg.Header("Content-Type"))
	if err != nil {
		return Message{}, false, err
	}
	if mediaType != mixedMultipartType {
		return Message{}, false, fmt.Errorf("parsing USSD INVITE: unsupported content type %q", mediaType)
	}
	body, err := readMultipartMessageBody("parsing USSD INVITE", params, msg.Body)
	if err != nil {
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

func validateMessageSDP(msg sip.Message) error {
	mediaType, params, err := splitContentTypeHeader("validating SDP", msg.Header("Content-Type"))
	if err != nil {
		return err
	}
	switch mediaType {
	case "application/sdp":
		return validateSDPBody(msg.Body)
	case mixedMultipartType:
		body, err := readMultipartMessageBody("validating SDP", params, msg.Body)
		if err != nil {
			return err
		}
		return validateMultipartMessageSDP("validating SDP", body)
	default:
		return fmt.Errorf("unsupported content type %q", mediaType)
	}
}

func validateSDPBody(body []byte) error {
	lines := strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n")
	mediaCount := 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "m=") {
			continue
		}
		mediaCount++
		fields := strings.Fields(strings.TrimPrefix(line, "m="))
		if len(fields) < 2 {
			return errors.New("malformed media description")
		}
		if fields[1] != "0" {
			return fmt.Errorf("media port %q is not zero", fields[1])
		}
	}
	switch mediaCount {
	case 0:
		return errors.New("missing media description")
	case 1:
		return nil
	default:
		return fmt.Errorf("expected one media description, got %d", mediaCount)
	}
}

func decodePayload(msg sip.Message) (Message, error) {
	rawContentType := strings.TrimSpace(msg.Header("Content-Type"))
	if rawContentType == "" {
		if len(msg.Body) == 0 {
			return Message{}, nil
		}
		return Message{}, errors.New("parsing USSD payload: content type is empty")
	}
	mediaType, params, err := splitContentTypeHeader("parsing USSD payload", rawContentType)
	if err != nil {
		return Message{}, err
	}
	switch mediaType {
	case xmlContentType:
		return decodeXML(msg.Body)
	case mixedMultipartType:
		body, err := readMultipartMessageBody("parsing USSD payload", params, msg.Body)
		if err != nil {
			return Message{}, err
		}
		return decodeMultipartPayload("parsing USSD payload", body)
	default:
		return Message{}, fmt.Errorf("parsing USSD payload: unsupported content type %q", mediaType)
	}
}

func decodeSinglePayload(action string, msg sip.Message) (Message, error) {
	mediaType, _, err := splitContentTypeHeader(action, msg.Header("Content-Type"))
	if err != nil {
		return Message{}, err
	}
	if mediaType != xmlContentType {
		return Message{}, fmt.Errorf("%s: unsupported content type %q", action, mediaType)
	}
	return decodeXML(msg.Body)
}

func decodeXML(data []byte) (Message, error) {
	var payload xmlBody
	if err := payload.UnmarshalText(data); err != nil {
		return Message{}, err
	}
	return payload.Message, nil
}

func normalizeErrorCode(code int) int {
	switch code {
	case 0, 1, 2, 3:
		return code
	default:
		return 1
	}
}

func buildCancel(invite sip.Message) sip.Message {
	cancelMsg := sip.NewRequest("CANCEL", sip.RequestURI(invite))
	cancelMsg.Headers.Add("Via", invite.Header("Via"))
	cancelMsg.Headers.Add("Max-Forwards", nonEmpty(invite.Header("Max-Forwards"), "70"))
	for _, route := range invite.HeadersByName("Route") {
		cancelMsg.Headers.Add("Route", route)
	}
	cancelMsg.Headers.Add("From", invite.Header("From"))
	cancelMsg.Headers.Add("To", invite.Header("To"))
	cancelMsg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	cancelMsg.Headers.Add("CSeq", fmt.Sprintf("%d CANCEL", sip.CSeqNumber(invite.Header("CSeq"))))
	return cancelMsg
}

func contentDispositionType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ";")
	return strings.TrimSpace(parts[0])
}

func acceptsMedia(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, xmlContentType) && strings.Contains(lower, "application/sdp") && strings.Contains(lower, mixedMultipartType)
}

func looksLikeInvite(msg sip.Message) bool {
	if !strings.EqualFold(msg.Method(), "INVITE") {
		return false
	}
	return sip.TokenListContains(msg.Header("Recv-Info"), infoPackage) || acceptsMedia(msg.Header("Accept"))
}

func looksLikeDialogMessage(msg sip.Message) bool {
	if strings.EqualFold(msg.Method(), "INFO") {
		return sip.TokenListContains(msg.Header("Info-Package"), infoPackage) || strings.Contains(strings.ToLower(msg.Header("Content-Type")), xmlContentType)
	}
	if strings.EqualFold(msg.Method(), "BYE") {
		return strings.Contains(strings.ToLower(msg.Header("Content-Type")), xmlContentType)
	}
	return false
}

func reverseValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for i := len(values) - 1; i >= 0; i-- {
		out = append(out, values[i])
	}
	return out
}

func kindFromPayload(payload Message) dialogKind {
	if payload.Request {
		return dialogKindRequest
	}
	if payload.Notify {
		return dialogKindNotify
	}
	return dialogKindNone
}

func nonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func ioReadAll(part *multipart.Part) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(part); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func contactValue(state registration.State) string {
	params := []string{
		`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
		`+g.3gpp.mid-call`,
		`+g.3gpp.nw-init-ussi`,
		`+g.3gpp.ps2cs-srvcc-orig-pre-alerting`,
		`+g.3gpp.smsip`,
		`+g.3gpp.srvcc-alerting`,
	}
	if state.IMEI != "" {
		params = append(params, fmt.Sprintf(`+sip.instance="<urn:gsma:imei:%s>"`, state.IMEI))
	}
	params = append(params, "text")
	return fmt.Sprintf("<%s>;%s", sipContactURI(state.ContactHost, state.MessagePort), strings.Join(params, ";"))
}

func sipContactURI(host string, port int) string {
	return "sip:" + net.JoinHostPort(host, strconv.Itoa(port))
}

func preferredIdentity(state registration.State) string {
	if identity := strings.TrimSpace(state.DefaultPublicID); identity != "" {
		return identity
	}
	return state.PublicIdentity
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func queuedRequestTimeout(ctx context.Context) (time.Duration, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return defaultQueuedRequestTimeout, nil
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return 0, context.DeadlineExceeded
	}
	return timeout, nil
}
