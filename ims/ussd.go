package ims

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"mime"
	"mime/multipart"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	ussdInfoPackage   = "g.3gpp.ussd"
	ussdContentType   = "application/vnd.3gpp.ussd+xml"
	ussdMultipartType = "multipart/mixed"
	defaultUSSDLang   = "en"
)

type USSDMessage struct {
	Text      string
	Language  string
	ErrorCode int
	Final     bool
	Notify    bool
	Request   bool
}

type ussdDialogKind uint8

const (
	ussdDialogKindNone ussdDialogKind = iota
	ussdDialogKindRequest
	ussdDialogKindNotify
)

type USSDSession struct {
	client           *Client
	callID           string
	sessionID        string
	localTag         string
	remoteTag        string
	remoteTo         string
	targetURI        string
	routeSet         []string
	inviteSeq        int64
	language         string
	networkInitiated bool
	responseKind     ussdDialogKind
	inviteOK         []byte
	ackCh            chan struct{}
	acked            bool
	events           chan USSDMessage
	remoteCSeqs      map[string]struct{}

	mu     sync.Mutex
	closed bool
}

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

func (c *Client) StartUSSD(ctx context.Context, code string) (*USSDSession, error) {
	start, invite, err := c.newUSSDStart(code)
	if err != nil {
		return nil, err
	}
	respCh := c.registerPending(invite)
	defer c.removePending(invite)
	if err := c.transport.WritePacket(ctx, invite.Bytes()); err != nil {
		return nil, fmt.Errorf("starting USSD: sending INVITE: %w", err)
	}
	return c.awaitUSSDStart(ctx, start, invite, respCh)
}

func (c *Client) newUSSDStart(code string) (ussdStart, Message, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return ussdStart{}, Message{}, fmt.Errorf("starting USSD: code is empty")
	}
	start := ussdStart{
		code:      code,
		callID:    randomAlphaNum(24),
		sessionID: randomHex(32),
		localTag:  randomAlphaNum(10),
		branch:    randomAlphaNum(15),
		inviteSeq: atomicAddInt64(&c.cseq, 1),
		language:  defaultValue(c.cfg.USSDLanguage, defaultUSSDLang),
	}
	start.target = c.ussdTargetURI(start.code)
	boundary, body, err := c.buildUSSDInviteBody(start.code, start.language)
	if err != nil {
		return ussdStart{}, Message{}, err
	}
	return start, c.buildUSSDInvite(start, boundary, body), nil
}

func (c *Client) buildUSSDInviteBody(code, language string) (string, []byte, error) {
	payload, err := (ussdXMLBody{Message: USSDMessage{Text: code, Language: language, Request: true}}).MarshalText()
	if err != nil {
		return "", nil, fmt.Errorf("starting USSD: encoding XML payload: %w", err)
	}
	boundary := "ussd-" + randomAlphaNum(12)
	body, err := (multipartBody{Boundary: boundary, Parts: []multipartBodyPart{
		{
			Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}},
			Body:   []byte(c.ussdSDP()),
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

func (c *Client) buildUSSDInvite(start ussdStart, boundary string, body []byte) Message {
	msg := NewRequest("INVITE", start.target)
	msg.AddHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", c.transportToken(), net.JoinHostPort(c.contactHost, strconv.Itoa(c.messageViaPort())), start.branch))
	msg.AddHeader("Max-Forwards", "70")
	for _, route := range c.serviceRoutes {
		msg.AddHeader("Route", route)
	}
	msg.AddHeader("From", fmt.Sprintf("<%s>;tag=%s", c.cfg.PublicIdentity, start.localTag))
	msg.AddHeader("To", fmt.Sprintf("<%s>", start.target))
	msg.AddHeader("Call-ID", start.callID)
	msg.AddHeader("Session-ID", start.sessionID)
	msg.AddHeader("CSeq", fmt.Sprintf("%d INVITE", start.inviteSeq))
	msg.AddHeader("Accept-Contact", `*;+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`)
	msg.AddHeader("P-Preferred-Identity", fmt.Sprintf("<%s>", c.cfg.PublicIdentity))
	msg.AddHeader("Contact", c.registerContactValue(c.messageViaPort()))
	msg.AddHeader("Allow", "INVITE,ACK,CANCEL,BYE,PRACK,UPDATE,REFER,MESSAGE,INFO")
	msg.AddHeader("Accept", "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed")
	msg.AddHeader("Recv-Info", ussdInfoPackage)
	msg.AddHeader("Supported", "100rel,path,replaces")
	msg.AddHeader("User-Agent", c.cfg.UserAgent)
	c.addAccessNetworkInfo(&msg)
	if c.addSecurityVerifyHeader(&msg, c.currentSecurityVerify()) {
		msg.AddHeader("Require", "sec-agree")
		msg.AddHeader("Proxy-Require", "sec-agree")
	}
	msg.AddHeader("Content-Type", fmt.Sprintf("%s; boundary=%s", ussdMultipartType, boundary))
	msg.Body = body
	return msg
}

func (c *Client) awaitUSSDStart(ctx context.Context, start ussdStart, invite Message, respCh <-chan Message) (*USSDSession, error) {
	for {
		select {
		case <-ctx.Done():
			c.cancelInvite(ctx, invite)
			return nil, ctx.Err()
		case resp := <-respCh:
			status := resp.StatusCode()
			if status >= 100 && status < 200 {
				continue
			}
			if status == 404 {
				return nil, fmt.Errorf("starting USSD: missing network support")
			}
			if status != 200 {
				return nil, fmt.Errorf("starting USSD: unexpected status %d", status)
			}
			return c.startUSSDSession(ctx, start, invite, resp)
		}
	}
}

func (c *Client) startUSSDSession(ctx context.Context, start ussdStart, invite, resp Message) (*USSDSession, error) {
	if err := validateUSSDInviteOK(resp); err != nil {
		return nil, fmt.Errorf("starting USSD: validating 200 OK: %w", err)
	}
	session := &USSDSession{
		client:      c,
		callID:      start.callID,
		sessionID:   start.sessionID,
		localTag:    start.localTag,
		remoteTag:   headerTag(resp.Header("To")),
		remoteTo:    nonEmpty(resp.Header("To"), invite.Header("To")),
		targetURI:   nonEmpty(addressURI(resp.Header("Contact")), start.target),
		routeSet:    reverseValues(resp.HeadersByName("Record-Route")),
		inviteSeq:   start.inviteSeq,
		language:    start.language,
		events:      make(chan USSDMessage, 16),
		remoteCSeqs: make(map[string]struct{}),
	}
	c.storeUSSDSession(session)
	if err := c.transport.WritePacket(ctx, session.buildACK()); err != nil {
		c.removeUSSDSession(start.callID)
		session.closeEvents()
		return nil, fmt.Errorf("starting USSD: sending ACK: %w", err)
	}
	c.logger.Debug("started USSD session", "code", start.code, "call_id", start.callID, "target_uri", session.targetURI)
	return session, nil
}

func (c *Client) cancelInvite(parent context.Context, invite Message) {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 2*time.Second)
	defer cancel()
	cancelMsg := buildCancel(invite)
	_ = c.transport.WritePacket(ctx, cancelMsg.Bytes())
}

func (s *USSDSession) Events() <-chan USSDMessage {
	return s.events
}

func (s *USSDSession) Reply(ctx context.Context, text string) error {
	if err := s.ensureActive("replying USSD"); err != nil {
		return err
	}
	payload, err := s.marshalDialogPayload(USSDMessage{Text: text, Language: s.language, Request: !s.networkInitiated})
	if err != nil {
		return fmt.Errorf("replying USSD: encoding XML payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.AddHeader("Info-Package", ussdInfoPackage)
	msg.AddHeader("Content-Disposition", "info-package")
	msg.AddHeader("Content-Type", ussdContentType)
	return s.exchange(ctx, msg, "replying USSD")
}

func (s *USSDSession) ReplyError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive("replying USSD"); err != nil {
		return err
	}
	payload, err := (ussdXMLBody{Message: USSDMessage{Language: s.language, ErrorCode: normalizeUSSDErrorCode(errorCode)}}).MarshalText()
	if err != nil {
		return fmt.Errorf("replying USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.AddHeader("Info-Package", ussdInfoPackage)
	msg.AddHeader("Content-Disposition", "info-package")
	msg.AddHeader("Content-Type", ussdContentType)
	return s.exchange(ctx, msg, "replying USSD")
}

func (s *USSDSession) End(ctx context.Context, text string) error {
	if err := s.ensureActive("ending USSD"); err != nil {
		return err
	}
	var payload []byte
	if strings.TrimSpace(text) != "" {
		encoded, err := s.marshalDialogPayload(USSDMessage{Text: text, Language: s.language, Final: true})
		if err != nil {
			return fmt.Errorf("ending USSD: encoding XML payload: %w", err)
		}
		payload = encoded
	}
	msg := s.buildDialogRequest("BYE", payload)
	if len(payload) > 0 {
		msg.AddHeader("Content-Type", ussdContentType)
	}
	if err := s.exchange(ctx, msg, "ending USSD"); err != nil {
		return err
	}
	s.finish(false)
	return nil
}

func (s *USSDSession) EndError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive("ending USSD"); err != nil {
		return err
	}
	payload, err := (ussdXMLBody{Message: USSDMessage{Language: s.language, ErrorCode: normalizeUSSDErrorCode(errorCode), Final: true}}).MarshalText()
	if err != nil {
		return fmt.Errorf("ending USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("BYE", payload)
	msg.AddHeader("Content-Type", ussdContentType)
	if err := s.exchange(ctx, msg, "ending USSD"); err != nil {
		return err
	}
	s.finish(false)
	return nil
}

func (s *USSDSession) endDirect(ctx context.Context, text string) error {
	var payload []byte
	if strings.TrimSpace(text) != "" {
		encoded, err := s.marshalDialogPayload(USSDMessage{Text: text, Language: s.language, Final: true})
		if err != nil {
			return fmt.Errorf("ending USSD: encoding XML payload: %w", err)
		}
		payload = encoded
	}
	msg := s.buildDialogRequest("BYE", payload)
	if len(payload) > 0 {
		msg.AddHeader("Content-Type", ussdContentType)
	}
	resp, err := s.client.exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("ending USSD: %w", err)
	}
	if resp.StatusCode() != 200 {
		return fmt.Errorf("ending USSD: unexpected status %d", resp.StatusCode())
	}
	return nil
}

func (s *USSDSession) marshalDialogPayload(msg USSDMessage) ([]byte, error) {
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

func (s *USSDSession) dialogKind() ussdDialogKind {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.responseKind
}

func (s *USSDSession) ensureActive(action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%s: session is closed", action)
	}
	return nil
}

func (s *USSDSession) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

func (s *USSDSession) waitForACK(ctx context.Context, action string) error {
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

func (s *USSDSession) exchange(ctx context.Context, msg Message, action string) error {
	if err := s.waitForACK(ctx, action); err != nil {
		return err
	}
	respCh := s.client.registerPending(msg)
	defer s.client.removePending(msg)
	if err := s.client.transport.WritePacket(ctx, msg.Bytes()); err != nil {
		return fmt.Errorf("%s: sending %s: %w", action, msg.Method(), err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case resp := <-respCh:
			status := resp.StatusCode()
			if status >= 100 && status < 200 {
				continue
			}
			if status != 200 {
				return fmt.Errorf("%s: unexpected status %d", action, status)
			}
			return nil
		}
	}
}

func (s *USSDSession) buildACK() []byte {
	msg := NewRequest("ACK", s.targetURI)
	msg.AddHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", s.client.transportToken(), net.JoinHostPort(s.client.contactHost, strconv.Itoa(s.client.messageViaPort())), randomAlphaNum(15)))
	msg.AddHeader("Max-Forwards", "70")
	for _, route := range s.routeSet {
		msg.AddHeader("Route", route)
	}
	msg.AddHeader("From", fmt.Sprintf("<%s>;tag=%s", s.client.cfg.PublicIdentity, s.localTag))
	msg.AddHeader("To", s.remoteTo)
	msg.AddHeader("Call-ID", s.callID)
	msg.AddHeader("CSeq", fmt.Sprintf("%d ACK", s.inviteSeq))
	return msg.Bytes()
}

func (s *USSDSession) buildDialogRequest(method string, body []byte) Message {
	msg := NewRequest(method, s.targetURI)
	msg.AddHeader("Via", fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", s.client.transportToken(), net.JoinHostPort(s.client.contactHost, strconv.Itoa(s.client.messageViaPort())), randomAlphaNum(15)))
	msg.AddHeader("Max-Forwards", "70")
	for _, route := range s.routeSet {
		msg.AddHeader("Route", route)
	}
	msg.AddHeader("From", fmt.Sprintf("<%s>;tag=%s", s.client.cfg.PublicIdentity, s.localTag))
	msg.AddHeader("To", s.remoteTo)
	msg.AddHeader("Call-ID", s.callID)
	msg.AddHeader("Session-ID", s.sessionID)
	msg.AddHeader("CSeq", fmt.Sprintf("%d %s", atomicAddInt64(&s.client.cseq, 1), method))
	msg.AddHeader("Contact", s.client.registerContactValue(s.client.messageViaPort()))
	msg.AddHeader("Allow", "INVITE,ACK,CANCEL,BYE,PRACK,UPDATE,REFER,MESSAGE,INFO")
	msg.AddHeader("Supported", "100rel,path,replaces")
	msg.AddHeader("User-Agent", s.client.cfg.UserAgent)
	s.client.addAccessNetworkInfo(&msg)
	s.client.addSecurityVerifyHeader(&msg, s.client.currentSecurityVerify())
	msg.Body = body
	return msg
}

func (s *USSDSession) handleRequest(ctx context.Context, transport Transport, msg Message) error {
	switch strings.ToUpper(msg.Method()) {
	case "ACK":
		s.markACK()
		return nil
	case "INFO":
		return s.handleInfo(ctx, transport, msg)
	case "BYE":
		return s.handleBye(ctx, transport, msg)
	default:
		return nil
	}
}

func (s *USSDSession) handleInfo(ctx context.Context, transport Transport, msg Message) error {
	payload, err := validateInboundUSSDInfo(msg, s.networkInitiated)
	if err != nil {
		return writeUSSDStatus(ctx, transport, msg, 415, "Unsupported Media Type")
	}
	if err := writeUSSDStatus(ctx, transport, msg, 200, "OK"); err != nil {
		return err
	}
	if s.isDuplicateRemote(msg) {
		s.client.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", msg.Header("CSeq"))
		return nil
	}
	if strings.TrimSpace(payload.Language) != "" {
		s.language = payload.Language
	}
	s.setDialogKind(payload)
	s.emit(payload)
	return nil
}

func (s *USSDSession) handleBye(ctx context.Context, transport Transport, msg Message) error {
	payload, err := decodeUSSDPayload(msg)
	if err != nil {
		return writeUSSDStatus(ctx, transport, msg, 415, "Unsupported Media Type")
	}
	if err := writeUSSDStatus(ctx, transport, msg, 200, "OK"); err != nil {
		return err
	}
	if s.isDuplicateRemote(msg) {
		s.client.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", msg.Header("CSeq"))
		return nil
	}
	payload.Final = true
	if strings.TrimSpace(payload.Language) != "" {
		s.language = payload.Language
	}
	s.setDialogKind(payload)
	if len(msg.Body) > 0 {
		s.emit(payload)
	}
	s.finish(true)
	return nil
}

func (s *USSDSession) emit(msg USSDMessage) {
	defer func() {
		_ = recover()
	}()
	select {
	case s.events <- msg:
	default:
		s.client.logger.Debug("dropping USSD event", "call_id", s.callID, "text", msg.Text)
	}
}

func (s *USSDSession) isDuplicateRemote(msg Message) bool {
	key := msg.Method() + "|" + msg.Header("CSeq")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.remoteCSeqs[key]; ok {
		return true
	}
	s.remoteCSeqs[key] = struct{}{}
	return false
}

func (s *USSDSession) markACK() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acked {
		return
	}
	s.acked = true
	if s.ackCh != nil {
		close(s.ackCh)
	}
}

func (s *USSDSession) setDialogKind(payload USSDMessage) {
	kind := ussdDialogKindNone
	if payload.Request {
		kind = ussdDialogKindRequest
	}
	if payload.Notify {
		kind = ussdDialogKindNotify
	}
	if kind == ussdDialogKindNone {
		return
	}
	s.mu.Lock()
	s.responseKind = kind
	s.mu.Unlock()
}

func (s *USSDSession) finish(fromNetwork bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	if !s.acked && s.ackCh != nil {
		close(s.ackCh)
		s.acked = true
	}
	s.mu.Unlock()
	s.client.removeUSSDSession(s.callID)
	s.closeEvents()
	s.client.logger.Debug("ended USSD session", "call_id", s.callID, "from_network", fromNetwork)
}

func (s *USSDSession) closeEvents() {
	defer func() {
		_ = recover()
	}()
	close(s.events)
}

func (c *Client) handleUSSDRequest(ctx context.Context, transport Transport, msg Message) (bool, error) {
	switch strings.ToUpper(msg.Method()) {
	case "INVITE":
		if !looksLikeUSSDInvite(msg) {
			return false, nil
		}
		return true, c.handleIncomingUSSDInvite(ctx, transport, msg)
	case "ACK":
		session := c.lookupUSSDSessionForMessage(msg)
		if session == nil {
			return false, nil
		}
		return true, session.handleRequest(ctx, transport, msg)
	case "INFO", "BYE":
		session := c.lookupUSSDSessionForMessage(msg)
		if session != nil {
			return true, session.handleRequest(ctx, transport, msg)
		}
		if looksLikeUSSDDialogMessage(msg) {
			return true, writeUSSDStatus(ctx, transport, msg, 481, "Call/Transaction Does Not Exist")
		}
		return false, nil
	default:
		return false, nil
	}
}

func (c *Client) handleIncomingUSSDInvite(ctx context.Context, transport Transport, msg Message) error {
	if handled, err := c.handleExistingUSSDInvite(ctx, transport, msg); handled || err != nil {
		return err
	}
	payload, err := validateIncomingUSSDInvite(msg)
	if err != nil {
		return writeUSSDStatus(ctx, transport, msg, 488, "Not Acceptable Here")
	}
	session := c.newIncomingUSSDSession(msg, payload)
	session.inviteOK = c.buildIncomingUSSDInviteOK(msg, session.localTag)
	return c.acceptIncomingUSSDInvite(ctx, transport, session, payload)
}

func (c *Client) handleExistingUSSDInvite(ctx context.Context, transport Transport, msg Message) (bool, error) {
	session := c.lookupUSSDSessionByCallID(msg.Header("Call-ID"))
	if session == nil {
		return false, nil
	}
	if len(session.inviteOK) > 0 {
		return true, transport.WritePacket(ctx, session.inviteOK)
	}
	return true, writeUSSDStatus(ctx, transport, msg, 481, "Call/Transaction Does Not Exist")
}

func (c *Client) newIncomingUSSDSession(msg Message, payload USSDMessage) *USSDSession {
	localTag := randomAlphaNum(10)
	remoteTo := msg.Header("From")
	targetURI := nonEmpty(addressURI(msg.Header("Contact")), addressURI(remoteTo))
	if targetURI == "" {
		targetURI = c.cfg.PublicIdentity
	}
	return &USSDSession{
		client:           c,
		callID:           msg.Header("Call-ID"),
		sessionID:        nonEmpty(msg.Header("Session-ID"), randomHex(32)),
		localTag:         localTag,
		remoteTag:        headerTag(remoteTo),
		remoteTo:         remoteTo,
		targetURI:        targetURI,
		routeSet:         append([]string(nil), msg.HeadersByName("Record-Route")...),
		inviteSeq:        cseqNumber(msg.Header("CSeq")),
		language:         defaultValue(payload.Language, defaultValue(c.cfg.USSDLanguage, defaultUSSDLang)),
		networkInitiated: true,
		responseKind:     kindFromPayload(payload),
		ackCh:            make(chan struct{}),
		events:           make(chan USSDMessage, 16),
		remoteCSeqs:      map[string]struct{}{"INVITE|" + msg.Header("CSeq"): {}},
	}
}

func (c *Client) buildIncomingUSSDInviteOK(msg Message, localTag string) []byte {
	ok := NewResponse(200, "OK")
	ok.Headers = responseHeaders(msg, 200)
	ok.Headers = upsertHeader(ok.Headers, "To", withTag(msg.Header("To"), c.cfg.PublicIdentity, localTag))
	ok.AddHeader("Contact", c.registerContactValue(c.messageViaPort()))
	ok.AddHeader("Recv-Info", ussdInfoPackage)
	ok.AddHeader("Accept", "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed")
	ok.AddHeader("Content-Type", "application/sdp")
	ok.Body = []byte(c.ussdSDP())
	return ok.Bytes()
}

func (c *Client) acceptIncomingUSSDInvite(ctx context.Context, transport Transport, session *USSDSession, payload USSDMessage) error {
	if err := transport.WritePacket(ctx, session.inviteOK); err != nil {
		return fmt.Errorf("handling USSD INVITE: sending 200 OK: %w", err)
	}
	c.storeUSSDSession(session)
	session.emit(payload)
	if c.onUSSD != nil {
		c.onUSSD(session, payload)
	}
	c.logger.Debug("accepted network-initiated USSD", "call_id", session.callID, "target_uri", session.targetURI)
	return nil
}

func (c *Client) storeUSSDSession(session *USSDSession) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ussd[session.callID] = session
}

func (c *Client) lookupUSSDSessionByCallID(callID string) *USSDSession {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ussd[callID]
}

func (c *Client) lookupUSSDSessionForMessage(msg Message) *USSDSession {
	session := c.lookupUSSDSessionByCallID(msg.Header("Call-ID"))
	if session == nil {
		return nil
	}
	if !session.matchesDialog(msg) {
		return nil
	}
	return session
}

func (s *USSDSession) matchesDialog(msg Message) bool {
	if msg.Header("Call-ID") != s.callID {
		return false
	}
	if tag := headerTag(msg.Header("To")); tag != "" && s.localTag != "" && tag != s.localTag {
		return false
	}
	if tag := headerTag(msg.Header("From")); tag != "" && s.remoteTag != "" && tag != s.remoteTag {
		return false
	}
	return true
}

func (c *Client) removeUSSDSession(callID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.ussd, callID)
}

func (c *Client) closeUSSDSessions(ctx context.Context) error {
	c.mu.Lock()
	sessions := make([]*USSDSession, 0, len(c.ussd))
	for _, session := range c.ussd {
		sessions = append(sessions, session)
	}
	c.ussd = make(map[string]*USSDSession)
	c.mu.Unlock()

	var err error
	for _, session := range sessions {
		if !session.isClosed() {
			err = errors.Join(err, session.endDirect(ctx, ""))
		}
		session.finish(false)
	}
	return err
}

func (c *Client) ussdTargetURI(code string) string {
	realm := strings.TrimPrefix(c.registerURI, "sip:")
	dial := strings.ReplaceAll(code, "#", "%23")
	return fmt.Sprintf("sip:%s;phone-context=%s@%s;user=dialstring", dial, realm, realm)
}

func (c *Client) ussdSDP() string {
	network := "IP4"
	host := c.contactHost
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "IP6"
	}
	sessionID := randomUint32()
	return fmt.Sprintf("v=0\r\no=- %d %d IN %s %s\r\ns=-\r\nc=IN %s %s\r\nt=0 0\r\nm=audio 0 RTP/AVP 97 96\r\na=rtpmap:97 AMR\r\na=fmtp:97 mode-set=0,2,5,7; maxframes=2\r\na=rtpmap:96 telephone-event\r\n", sessionID, sessionID, network, host, network, host)
}

func validateUSSDInviteOK(msg Message) error {
	if !tokenListContains(msg.Header("Recv-Info"), ussdInfoPackage) {
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

func validateIncomingUSSDInvite(msg Message) (USSDMessage, error) {
	if !tokenListContains(msg.Header("Recv-Info"), ussdInfoPackage) {
		return USSDMessage{}, fmt.Errorf("missing Recv-Info %q", ussdInfoPackage)
	}
	if !acceptsUSSDMedia(msg.Header("Accept")) {
		return USSDMessage{}, fmt.Errorf("missing required Accept media types")
	}
	payload, hasSDP, err := decodeUSSDInvitePayload(msg)
	if err != nil {
		return USSDMessage{}, err
	}
	if !hasSDP {
		return USSDMessage{}, fmt.Errorf("missing SDP offer")
	}
	if !payload.Request && !payload.Notify {
		return USSDMessage{}, fmt.Errorf("missing network initiated USSD marker")
	}
	return payload, nil
}

func validateInboundUSSDInfo(msg Message, requireRequestMarker bool) (USSDMessage, error) {
	if !tokenListContains(msg.Header("Info-Package"), ussdInfoPackage) {
		return USSDMessage{}, fmt.Errorf("missing Info-Package %q", ussdInfoPackage)
	}
	if !strings.EqualFold(contentDispositionType(msg.Header("Content-Disposition")), "info-package") {
		return USSDMessage{}, fmt.Errorf("missing Content-Disposition info-package")
	}
	payload, err := decodeUSSDPayload(msg)
	if err != nil {
		return USSDMessage{}, err
	}
	if requireRequestMarker && !payload.Request && !payload.Notify {
		return USSDMessage{}, fmt.Errorf("missing network initiated USSD marker")
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

func decodeMultipartUSSDPayload(action string, body multipartBody) (USSDMessage, error) {
	payload, ok, err := body.ussdPayload()
	if err != nil {
		return USSDMessage{}, err
	}
	if !ok {
		return USSDMessage{}, fmt.Errorf("%s: %s part not found", action, ussdContentType)
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

func decodeUSSDInvitePayload(msg Message) (USSDMessage, bool, error) {
	mediaType, params, err := splitContentTypeHeader("parsing USSD INVITE", msg.Header("Content-Type"))
	if err != nil {
		return USSDMessage{}, false, err
	}
	if mediaType != ussdMultipartType {
		return USSDMessage{}, false, fmt.Errorf("parsing USSD INVITE: unsupported content type %q", mediaType)
	}
	body, err := readMultipartMessageBody("parsing USSD INVITE", params, msg.Body)
	if err != nil {
		return USSDMessage{}, false, err
	}
	payload, err := decodeMultipartUSSDPayload("parsing USSD INVITE", body)
	if err != nil {
		return USSDMessage{}, false, err
	}
	hasSDP, err := validateOptionalMultipartSDP(body)
	if err != nil {
		return USSDMessage{}, false, err
	}
	return payload, hasSDP, nil
}

func validateMessageSDP(msg Message) error {
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

func decodeUSSDPayload(msg Message) (USSDMessage, error) {
	contentType := strings.TrimSpace(msg.Header("Content-Type"))
	if contentType == "" {
		if len(msg.Body) == 0 {
			return USSDMessage{}, nil
		}
		return USSDMessage{}, fmt.Errorf("parsing USSD payload: content type is empty")
	}
	mediaType, params, err := splitContentTypeHeader("parsing USSD payload", contentType)
	if err != nil {
		return USSDMessage{}, err
	}
	switch mediaType {
	case ussdContentType:
		return decodeUSSDXML(msg.Body)
	case ussdMultipartType:
		body, err := readMultipartMessageBody("parsing USSD payload", params, msg.Body)
		if err != nil {
			return USSDMessage{}, err
		}
		return decodeMultipartUSSDPayload("parsing USSD payload", body)
	default:
		return USSDMessage{}, fmt.Errorf("parsing USSD payload: unsupported content type %q", mediaType)
	}
}

func decodeUSSDXML(data []byte) (USSDMessage, error) {
	var payload ussdXMLBody
	if err := payload.UnmarshalText(data); err != nil {
		return USSDMessage{}, err
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

func buildCancel(invite Message) Message {
	cancelMsg := NewRequest("CANCEL", requestURI(invite))
	cancelMsg.AddHeader("Via", invite.Header("Via"))
	cancelMsg.AddHeader("Max-Forwards", nonEmpty(invite.Header("Max-Forwards"), "70"))
	for _, route := range invite.HeadersByName("Route") {
		cancelMsg.AddHeader("Route", route)
	}
	cancelMsg.AddHeader("From", invite.Header("From"))
	cancelMsg.AddHeader("To", invite.Header("To"))
	cancelMsg.AddHeader("Call-ID", invite.Header("Call-ID"))
	cancelMsg.AddHeader("CSeq", fmt.Sprintf("%d CANCEL", cseqNumber(invite.Header("CSeq"))))
	return cancelMsg
}

func requestURI(msg Message) string {
	parts := strings.SplitN(msg.StartLine, " ", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[1]
}

func contentDispositionType(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ";")
	return strings.TrimSpace(parts[0])
}

func tokenListContains(value, want string) bool {
	for _, token := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(token), want) {
			return true
		}
	}
	return false
}

func acceptsUSSDMedia(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, ussdContentType) && strings.Contains(lower, "application/sdp") && strings.Contains(lower, ussdMultipartType)
}

func looksLikeUSSDInvite(msg Message) bool {
	if !strings.EqualFold(msg.Method(), "INVITE") {
		return false
	}
	return tokenListContains(msg.Header("Recv-Info"), ussdInfoPackage) || acceptsUSSDMedia(msg.Header("Accept"))
}

func looksLikeUSSDDialogMessage(msg Message) bool {
	if strings.EqualFold(msg.Method(), "INFO") {
		return tokenListContains(msg.Header("Info-Package"), ussdInfoPackage) || strings.Contains(strings.ToLower(msg.Header("Content-Type")), ussdContentType)
	}
	if strings.EqualFold(msg.Method(), "BYE") {
		return strings.Contains(strings.ToLower(msg.Header("Content-Type")), ussdContentType)
	}
	return false
}

func writeUSSDStatus(ctx context.Context, transport Transport, req Message, code int, reason string) error {
	resp := NewResponse(code, reason)
	resp.Headers = responseHeaders(req, code)
	return transport.WritePacket(ctx, resp.Bytes())
}

func upsertHeader(headers []Header, name, value string) []Header {
	for i, header := range headers {
		if strings.EqualFold(header.Name, name) {
			headers[i].Value = value
			return headers
		}
	}
	return append(headers, Header{Name: name, Value: value})
}

func withTag(headerValue, fallbackURI, tag string) string {
	base := strings.TrimSpace(headerValue)
	if base == "" {
		base = fmt.Sprintf("<%s>", fallbackURI)
	}
	if strings.Contains(strings.ToLower(base), ";tag=") {
		return base
	}
	return base + ";tag=" + tag
}

func headerTag(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	for _, part := range strings.Split(value, ";") {
		name, val, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(name, "tag") {
			return strings.Trim(strings.TrimSpace(val), `"`)
		}
	}
	return ""
}

func addressURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if left := strings.IndexByte(value, '<'); left >= 0 {
		right := strings.IndexByte(value[left+1:], '>')
		if right >= 0 {
			return strings.TrimSpace(value[left+1 : left+1+right])
		}
	}
	if idx := strings.IndexByte(value, ';'); idx >= 0 {
		return strings.TrimSpace(value[:idx])
	}
	return value
}

func cseqNumber(value string) int64 {
	fields := strings.Fields(strings.TrimSpace(value))
	if len(fields) == 0 {
		return 0
	}
	n, _ := strconv.ParseInt(fields[0], 10, 64)
	return n
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

func kindFromPayload(payload USSDMessage) ussdDialogKind {
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

func atomicAddInt64(counter *int64, delta int64) int64 {
	return atomic.AddInt64(counter, delta)
}

func ioReadAll(part *multipart.Part) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := buf.ReadFrom(part); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
