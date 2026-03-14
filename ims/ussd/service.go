package ussd

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
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
	ussdInfoPackage   = "g.3gpp.ussd"
	ussdContentType   = "application/vnd.3gpp.ussd+xml"
	ussdMultipartType = "multipart/mixed"
	defaultUSSDLang   = "en"
)

type Config struct {
	Language   string
	OnIncoming func(*Session, Message)
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
	cfg        Config
	sess       *session.Session
	reg        *registration.Service
	logger     *slog.Logger
	attachment session.Attachment

	mu       sync.Mutex
	sessions map[string]*Session
	closed   bool
	cseq     int64
	bgWG     sync.WaitGroup
}

type Session struct {
	service          *Service
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
	responseKind     ussdDialogKind
	inviteOK         sip.Message
	ackCh            chan struct{}
	acked            bool
	awaitingInfo     bool
	events           chan Message
	remoteCSeqs      map[string]struct{}
	pendingInitial   *queuedUSSDRequest
	deliveringInvite bool

	mu     sync.Mutex
	closed bool
}

type USSDSession = Session

type ussdDialogKind uint8

const (
	ussdDialogKindNone ussdDialogKind = iota
	ussdDialogKindRequest
	ussdDialogKindNotify
)

type ussdXML struct {
	XMLName   xml.Name    `xml:"ussd-data"`
	Language  string      `xml:"language,omitempty"`
	String    string      `xml:"ussd-string,omitempty"`
	ErrorCode int         `xml:"error-code,omitempty"`
	AnyExt    *ussdAnyExt `xml:"anyExt,omitempty"`
}

type ussdAnyExt struct {
	Request *struct{} `xml:"UnstructuredSS-Request,omitempty"`
	Notify  *struct{} `xml:"UnstructuredSS-Notify,omitempty"`
}

type multipartBodyPart struct {
	Header textproto.MIMEHeader
	Body   []byte
}

type queuedUSSDRequest struct {
	ctx    context.Context
	msg    sip.Message
	action string
	final  bool
}

type ussdStart struct {
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
		return nil, fmt.Errorf("creating ussd service: session is nil")
	}
	if reg == nil {
		return nil, fmt.Errorf("creating ussd service: registration service is nil")
	}
	cfg.Language = strings.TrimSpace(cfg.Language)
	s := &Service{
		cfg:      cfg,
		sess:     sess,
		reg:      reg,
		logger:   slog.Default().With("component", "ims-ussd"),
		sessions: make(map[string]*Session),
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
	start, invite, err := s.newUSSDStart(code)
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
		return nil, fmt.Errorf("starting USSD: missing network support")
	} else if status != 200 {
		return nil, fmt.Errorf("starting USSD: unexpected status %d", status)
	}
	return s.startUSSDSession(ctx, start, invite, resp)
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
	s.mu.Unlock()

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
		if !looksLikeUSSDInvite(req.Message) {
			return false, nil
		}
		return true, s.handleIncomingUSSDInvite(ctx, req)
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
		if looksLikeUSSDDialogMessage(req.Message) {
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

func (s *Service) newUSSDStart(code string) (ussdStart, sip.Message, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return ussdStart{}, sip.Message{}, fmt.Errorf("starting USSD: code is empty")
	}
	start := ussdStart{
		code:      code,
		callID:    randomAlphaNum(24),
		sessionID: randomHex(32),
		localTag:  randomAlphaNum(10),
		branch:    randomAlphaNum(15),
		inviteSeq: atomic.AddInt64(&s.cseq, 1),
		language:  defaultValue(s.cfg.Language, defaultUSSDLang),
	}
	start.target = s.ussdTargetURI(start.code)
	boundary, body, err := s.buildUSSDInviteBody(start.code, start.language)
	if err != nil {
		return ussdStart{}, sip.Message{}, err
	}
	return start, s.buildUSSDInvite(start, boundary, body), nil
}

func (s *Service) buildUSSDInviteBody(code, language string) (string, []byte, error) {
	payload, err := (ussdXMLBody{Message: Message{Text: code, Language: language}}).MarshalText()
	if err != nil {
		return "", nil, fmt.Errorf("starting USSD: encoding XML payload: %w", err)
	}
	boundary := "ussd-" + randomAlphaNum(12)
	body, err := (multipartBody{Boundary: boundary, Parts: []multipartBodyPart{
		{
			Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}},
			Body:   []byte(s.ussdSDP()),
		},
		{
			Header: textproto.MIMEHeader{
				"Content-Type":        {ussdContentType},
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

func (s *Service) buildUSSDInvite(start ussdStart, boundary string, body []byte) sip.Message {
	state := s.reg.State()
	senderIdentity := ussdPreferredIdentity(state)
	msg := sip.NewRequest("INVITE", start.target)
	msg.Headers.Add("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", transportToken(s.sess.LocalAddr()), net.JoinHostPort(state.ContactHost, strconv.Itoa(state.MessagePort)), start.branch))
	msg.Headers.Add("Max-Forwards", "70")
	for _, route := range state.ServiceRoutes {
		msg.Headers.Add("Route", route)
	}
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, start.localTag))
	msg.Headers.Add("To", fmt.Sprintf("<%s>", start.target))
	msg.Headers.Add("Call-ID", start.callID)
	msg.Headers.Add("Session-ID", start.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d INVITE", start.inviteSeq))
	msg.Headers.Add("Accept-Contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`)
	msg.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	msg.Headers.Add("Contact", contactValue(state))
	msg.Headers.Add("Allow", "INVITE,ACK,CANCEL,BYE,PRACK,UPDATE,REFER,MESSAGE,INFO")
	msg.Headers.Add("Accept", "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed")
	msg.Headers.Add("Recv-Info", ussdInfoPackage)
	msg.Headers.Add("Supported", "100rel,path,replaces")
	msg.Headers.Add("User-Agent", state.UserAgent)
	if state.AccessNetworkInfo != "" {
		msg.Headers.Add("P-Access-Network-Info", state.AccessNetworkInfo)
	}
	if state.SecurityVerify != nil {
		msg.Headers.Add("Security-Verify", state.SecurityVerify.String())
		msg.Headers.Add("Require", "sec-agree")
		msg.Headers.Add("Proxy-Require", "sec-agree")
	}
	msg.Headers.Add("Content-Type", fmt.Sprintf("%s; boundary=%s", ussdMultipartType, boundary))
	msg.Body = body
	return msg
}

func (s *Service) startUSSDSession(ctx context.Context, start ussdStart, invite, resp sip.Message) (*Session, error) {
	if err := validateUSSDInviteOK(resp); err != nil {
		return nil, fmt.Errorf("starting USSD: validating 200 OK: %w", err)
	}
	ussdSession := &Session{
		service:      s,
		callID:       start.callID,
		sessionID:    start.sessionID,
		localURI:     nonEmpty(sip.AddressURI(invite.Header("From")), ussdPreferredIdentity(s.reg.State())),
		localTag:     start.localTag,
		remoteTag:    sip.HeaderTag(resp.Header("To")),
		remoteTo:     nonEmpty(resp.Header("To"), invite.Header("To")),
		targetURI:    nonEmpty(sip.AddressURI(resp.Header("Contact")), start.target),
		routeSet:     reverseValues(resp.HeadersByName("Record-Route")),
		inviteSeq:    start.inviteSeq,
		language:     start.language,
		events:       make(chan Message, 16),
		remoteCSeqs:  make(map[string]struct{}),
		responseKind: ussdDialogKindRequest,
	}
	s.storeSession(ussdSession)
	if err := s.sess.Send(ctx, ussdSession.buildACK()); err != nil {
		s.removeSession(start.callID)
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

func (s *Service) handleIncomingUSSDInvite(ctx context.Context, req session.Request) error {
	if handled, err := s.handleExistingUSSDInvite(ctx, req); handled || err != nil {
		return err
	}
	payload, err := validateIncomingUSSDInvite(req.Message)
	if err != nil {
		return s.sess.WriteStatus(ctx, req, 488, "Not Acceptable Here")
	}
	ussdSession := s.newIncomingUSSDSession(req.Message, payload)
	ussdSession.inviteOK = s.buildIncomingUSSDInviteOK(req.Message, ussdSession.localURI, ussdSession.localTag)
	s.storeSession(ussdSession)
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

func (s *Service) handleExistingUSSDInvite(ctx context.Context, req session.Request) (bool, error) {
	ussdSession := s.lookupSessionByCallID(req.Message.Header("Call-ID"))
	if ussdSession == nil {
		return false, nil
	}
	if ussdSession.inviteOK.StartLine != "" {
		return true, s.sess.WriteResponse(ctx, req, ussdSession.inviteOK)
	}
	return true, s.sess.WriteStatus(ctx, req, 481, "Call/Transaction Does Not Exist")
}

func (s *Service) newIncomingUSSDSession(msg sip.Message, payload Message) *Session {
	state := s.reg.State()
	localTag := randomAlphaNum(10)
	remoteTo := msg.Header("From")
	targetURI := nonEmpty(sip.AddressURI(msg.Header("Contact")), sip.AddressURI(remoteTo))
	if targetURI == "" {
		targetURI = state.PublicIdentity
	}
	return &Session{
		service:          s,
		callID:           msg.Header("Call-ID"),
		sessionID:        nonEmpty(msg.Header("Session-ID"), randomHex(32)),
		localURI:         nonEmpty(sip.AddressURI(msg.Header("To")), ussdPreferredIdentity(state)),
		localTag:         localTag,
		remoteTag:        sip.HeaderTag(remoteTo),
		remoteTo:         remoteTo,
		targetURI:        targetURI,
		routeSet:         append([]string(nil), msg.HeadersByName("Record-Route")...),
		inviteSeq:        sip.CSeqNumber(msg.Header("CSeq")),
		language:         defaultValue(payload.Language, defaultValue(s.cfg.Language, defaultUSSDLang)),
		networkInitiated: true,
		responseKind:     kindFromPayload(payload),
		ackCh:            make(chan struct{}),
		events:           make(chan Message, 16),
		remoteCSeqs:      map[string]struct{}{"INVITE|" + msg.Header("CSeq"): {}},
	}
}

func (s *Service) buildIncomingUSSDInviteOK(msg sip.Message, localURI, localTag string) sip.Message {
	ok := sip.NewResponse(200, "OK")
	ok.Headers = sip.ResponseHeaders(msg, 200)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), localURI, localTag))
	ok.Headers.Add("Contact", contactValue(s.reg.State()))
	ok.Headers.Add("Recv-Info", ussdInfoPackage)
	ok.Headers.Add("Accept", "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed")
	ok.Headers.Add("Content-Type", "application/sdp")
	ok.Body = []byte(s.ussdSDP())
	return ok
}

func (s *Service) storeSession(ussdSession *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[ussdSession.callID] = ussdSession
}

func (s *Service) lookupSessionByCallID(callID string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sessions[callID]
}

func (s *Service) lookupSessionForMessage(msg sip.Message) *Session {
	ussdSession := s.lookupSessionByCallID(msg.Header("Call-ID"))
	if ussdSession == nil {
		return nil
	}
	if !ussdSession.matchesDialog(msg) {
		return nil
	}
	return ussdSession
}

func (s *Service) removeSession(callID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, callID)
}

func (s *Service) ussdTargetURI(code string) string {
	realm := strings.TrimPrefix(s.reg.State().RegisterURI, "sip:")
	dial := strings.ReplaceAll(code, "#", "%23")
	return fmt.Sprintf("sip:%s;phone-context=%s@%s;user=dialstring", dial, realm, realm)
}

func (s *Service) ussdSDP() string {
	host := s.reg.State().ContactHost
	network := "IP4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "IP6"
	}
	sessionID := randomUint32()
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
	payload, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage(), Request: !s.networkInitiated})
	if err != nil {
		return fmt.Errorf("replying USSD: encoding XML payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.Headers.Add("Info-Package", ussdInfoPackage)
	msg.Headers.Add("Content-Disposition", "info-package")
	msg.Headers.Add("Content-Type", ussdContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, "replying USSD", false); queued || err != nil {
		return err
	}
	return s.exchange(ctx, msg, "replying USSD")
}

func (s *Session) ReplyError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive("replying USSD"); err != nil {
		return err
	}
	payload, err := (ussdXMLBody{Message: Message{Language: s.currentLanguage(), ErrorCode: normalizeUSSDErrorCode(errorCode)}}).MarshalText()
	if err != nil {
		return fmt.Errorf("replying USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.Headers.Add("Info-Package", ussdInfoPackage)
	msg.Headers.Add("Content-Disposition", "info-package")
	msg.Headers.Add("Content-Type", ussdContentType)
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
		msg.Headers.Add("Content-Type", ussdContentType)
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
	payload, err := (ussdXMLBody{Message: Message{Language: s.currentLanguage(), ErrorCode: normalizeUSSDErrorCode(errorCode), Final: true}}).MarshalText()
	if err != nil {
		return fmt.Errorf("ending USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("BYE", payload)
	msg.Headers.Add("Content-Type", ussdContentType)
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
		msg.Headers.Add("Content-Type", ussdContentType)
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
	if !s.networkInitiated && !msg.Final && !msg.Notify && msg.ErrorCode == 0 {
		msg.Request = true
	}
	if s.networkInitiated {
		switch s.dialogKind() {
		case ussdDialogKindRequest:
			msg.Request = true
		case ussdDialogKindNotify:
			msg.Notify = true
		}
	}
	return (ussdXMLBody{Message: msg}).MarshalText()
}

func (s *Session) dialogKind() ussdDialogKind {
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
	msg.Headers.Add("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", transportToken(s.service.sess.LocalAddr()), net.JoinHostPort(state.ContactHost, strconv.Itoa(state.MessagePort)), randomAlphaNum(15)))
	msg.Headers.Add("Max-Forwards", "70")
	for _, route := range s.routeSet {
		msg.Headers.Add("Route", route)
	}
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
	msg.Headers.Add("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", transportToken(s.service.sess.LocalAddr()), net.JoinHostPort(state.ContactHost, strconv.Itoa(state.MessagePort)), randomAlphaNum(15)))
	msg.Headers.Add("Max-Forwards", "70")
	for _, route := range s.routeSet {
		msg.Headers.Add("Route", route)
	}
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("Session-ID", s.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", atomic.AddInt64(&s.service.cseq, 1), method))
	msg.Headers.Add("Contact", contactValue(state))
	msg.Headers.Add("Allow", "INVITE,ACK,CANCEL,BYE,PRACK,UPDATE,REFER,MESSAGE,INFO")
	msg.Headers.Add("Supported", "100rel,path,replaces")
	msg.Headers.Add("User-Agent", state.UserAgent)
	if state.AccessNetworkInfo != "" {
		msg.Headers.Add("P-Access-Network-Info", state.AccessNetworkInfo)
	}
	if state.SecurityVerify != nil {
		msg.Headers.Add("Security-Verify", state.SecurityVerify.String())
	}
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
		if err := s.exchange(pending.ctx, pending.msg, pending.action); err != nil {
			s.service.logger.Warn("sending queued ussd response", "call_id", s.callID, "method", pending.msg.Method(), "err", err)
			return
		}
		if pending.final {
			s.finish(false)
		}
	})
}

func (s *Session) handleInfo(ctx context.Context, req session.Request) error {
	payload, err := validateInboundUSSDInfo(req.Message, s.networkInitiated)
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
	if err := s.service.sess.WriteStatus(ctx, req, 200, "OK"); err != nil {
		return err
	}
	if s.isDuplicateRemote(req.Message) {
		s.service.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", req.Message.Header("CSeq"))
		return nil
	}
	payload, err := decodeUSSDPayload(req.Message)
	if err != nil {
		s.finish(true)
		return nil
	}
	payload.Final = true
	s.setLanguage(payload.Language)
	s.setDialogKind(payload)
	if len(req.Message.Body) > 0 {
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

func (s *Session) markACK() *queuedUSSDRequest {
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
	if kind == ussdDialogKindNone {
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
	s.service.removeSession(s.callID)
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
	s.pendingInitial = &queuedUSSDRequest{
		ctx:    ctx,
		msg:    msg,
		action: action,
		final:  final,
	}
	return true, nil
}

func (s *Session) localDialogURI() string {
	if uri := strings.TrimSpace(s.localURI); uri != "" {
		return uri
	}
	return ussdPreferredIdentity(s.service.reg.State())
}

func (s *Session) matchesDialog(msg sip.Message) bool {
	if msg.Header("Call-ID") != s.callID {
		return false
	}
	if tag := sip.HeaderTag(msg.Header("To")); tag != "" && s.localTag != "" && tag != s.localTag {
		return false
	}
	if tag := sip.HeaderTag(msg.Header("From")); tag != "" && s.remoteTag != "" && tag != s.remoteTag {
		return false
	}
	return true
}

func validateUSSDInviteOK(msg sip.Message) error {
	if !sip.TokenListContains(msg.Header("Recv-Info"), ussdInfoPackage) {
		return fmt.Errorf("missing Recv-Info %q", ussdInfoPackage)
	}
	if !acceptsUSSDMedia(msg.Header("Accept")) {
		return fmt.Errorf("missing required Accept media types")
	}
	if err := validateMessageSDP(msg); err != nil {
		return fmt.Errorf("validating SDP answer: %w", err)
	}
	return nil
}

func validateIncomingUSSDInvite(msg sip.Message) (Message, error) {
	if !sip.TokenListContains(msg.Header("Recv-Info"), ussdInfoPackage) {
		return Message{}, fmt.Errorf("missing Recv-Info %q", ussdInfoPackage)
	}
	if !acceptsUSSDMedia(msg.Header("Accept")) {
		return Message{}, fmt.Errorf("missing required Accept media types")
	}
	payload, hasSDP, err := decodeUSSDInvitePayload(msg)
	if err != nil {
		return Message{}, err
	}
	if !hasSDP {
		return Message{}, fmt.Errorf("missing SDP offer")
	}
	if !payload.Request && !payload.Notify {
		return Message{}, fmt.Errorf("missing network initiated USSD marker")
	}
	return payload, nil
}

func validateInboundUSSDInfo(msg sip.Message, requireRequestMarker bool) (Message, error) {
	if !sip.TokenListContains(msg.Header("Info-Package"), ussdInfoPackage) {
		return Message{}, fmt.Errorf("missing Info-Package %q", ussdInfoPackage)
	}
	if !strings.EqualFold(contentDispositionType(msg.Header("Content-Disposition")), "info-package") {
		return Message{}, fmt.Errorf("missing Content-Disposition info-package")
	}
	payload, err := decodeUSSDPayload(msg)
	if err != nil {
		return Message{}, err
	}
	if requireRequestMarker && !payload.Request && !payload.Notify {
		return Message{}, fmt.Errorf("missing network initiated USSD marker")
	}
	return payload, nil
}

func splitContentTypeHeader(action, contentType string) (string, map[string]string, error) {
	contentType = strings.TrimSpace(contentType)
	if contentType == "" {
		return "", nil, fmt.Errorf("%s: content type is empty", action)
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
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

func decodeMultipartUSSDPayload(action string, body multipartBody) (Message, error) {
	payload, ok, err := body.ussdPayload()
	if err != nil {
		return Message{}, err
	}
	if !ok {
		return Message{}, fmt.Errorf("%s: %s part not found", action, ussdContentType)
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

func decodeUSSDInvitePayload(msg sip.Message) (Message, bool, error) {
	mediaType, params, err := splitContentTypeHeader("parsing USSD INVITE", msg.Header("Content-Type"))
	if err != nil {
		return Message{}, false, err
	}
	if mediaType != ussdMultipartType {
		return Message{}, false, fmt.Errorf("parsing USSD INVITE: unsupported content type %q", mediaType)
	}
	body, err := readMultipartMessageBody("parsing USSD INVITE", params, msg.Body)
	if err != nil {
		return Message{}, false, err
	}
	payload, err := decodeMultipartUSSDPayload("parsing USSD INVITE", body)
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
	case ussdMultipartType:
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
	haveMedia := false
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "m=") {
			continue
		}
		haveMedia = true
		fields := strings.Fields(strings.TrimPrefix(line, "m="))
		if len(fields) < 2 {
			return fmt.Errorf("malformed media description")
		}
		if fields[1] != "0" {
			return fmt.Errorf("media port %q is not zero", fields[1])
		}
	}
	if !haveMedia {
		return fmt.Errorf("missing media description")
	}
	return nil
}

func decodeUSSDPayload(msg sip.Message) (Message, error) {
	contentType := strings.TrimSpace(msg.Header("Content-Type"))
	if contentType == "" {
		if len(msg.Body) == 0 {
			return Message{}, nil
		}
		return Message{}, fmt.Errorf("parsing USSD payload: content type is empty")
	}
	mediaType, params, err := splitContentTypeHeader("parsing USSD payload", contentType)
	if err != nil {
		return Message{}, err
	}
	switch mediaType {
	case ussdContentType:
		return decodeUSSDXML(msg.Body)
	case ussdMultipartType:
		body, err := readMultipartMessageBody("parsing USSD payload", params, msg.Body)
		if err != nil {
			return Message{}, err
		}
		return decodeMultipartUSSDPayload("parsing USSD payload", body)
	default:
		return Message{}, fmt.Errorf("parsing USSD payload: unsupported content type %q", mediaType)
	}
}

func decodeUSSDXML(data []byte) (Message, error) {
	var payload ussdXMLBody
	if err := payload.UnmarshalText(data); err != nil {
		return Message{}, err
	}
	return payload.Message, nil
}

func normalizeUSSDErrorCode(code int) int {
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

func acceptsUSSDMedia(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, ussdContentType) && strings.Contains(lower, "application/sdp") && strings.Contains(lower, ussdMultipartType)
}

func looksLikeUSSDInvite(msg sip.Message) bool {
	if !strings.EqualFold(msg.Method(), "INVITE") {
		return false
	}
	return sip.TokenListContains(msg.Header("Recv-Info"), ussdInfoPackage) || acceptsUSSDMedia(msg.Header("Accept"))
}

func looksLikeUSSDDialogMessage(msg sip.Message) bool {
	if strings.EqualFold(msg.Method(), "INFO") {
		return sip.TokenListContains(msg.Header("Info-Package"), ussdInfoPackage) || strings.Contains(strings.ToLower(msg.Header("Content-Type")), ussdContentType)
	}
	if strings.EqualFold(msg.Method(), "BYE") {
		return strings.Contains(strings.ToLower(msg.Header("Content-Type")), ussdContentType)
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

func kindFromPayload(payload Message) ussdDialogKind {
	if payload.Request {
		return ussdDialogKindRequest
	}
	if payload.Notify {
		return ussdDialogKindNotify
	}
	return ussdDialogKindNone
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
	return fmt.Sprintf("<sip:%s:%d>;%s", state.ContactHost, state.MessagePort, strings.Join(params, ";"))
}

func ussdPreferredIdentity(state registration.State) string {
	if identity := strings.TrimSpace(state.DefaultPublicID); identity != "" {
		return identity
	}
	return state.PublicIdentity
}

func transportToken(addr net.Addr) string {
	switch addr.(type) {
	case *net.TCPAddr:
		return "TCP"
	default:
		return "UDP"
	}
}

func randomAlphaNum(length int) string {
	return randomString(length, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func randomHex(length int) string {
	return randomString(length, "0123456789abcdef")
}

func randomString(length int, alphabet string) string {
	buf := make([]byte, length)
	rnd := make([]byte, length)
	_, _ = rand.Read(rnd)
	for i, b := range rnd {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(buf)
}

func randomUint32() uint32 {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
