package call

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

type Direction string

const (
	DirectionOutgoing Direction = "outgoing"
	DirectionIncoming Direction = "incoming"
)

const (
	mmtelICSI        = "urn:urn-7:3gpp-service.ims.icsi.mmtel"
	mmtelICSIEncoded = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
)

type State string

const (
	StateDialing   State = "dialing"
	StateRinging   State = "ringing"
	StateAnswering State = "answering"
	StateActive    State = "active"
	StateEnding    State = "ending"
	StateEnded     State = "ended"
	StateFailed    State = "failed"
)

type Request struct {
	To    string
	Media MediaOffer
}

type Incoming struct {
	Call     *Call
	From     string
	Offer    MediaOffer
	Received time.Time
}

type Event struct {
	CallID string
	State  State
	Cause  string
	At     time.Time
}

type Service struct {
	cfg        Config
	sess       *session.Session
	reg        *registration.Service
	logger     *slog.Logger
	attachment session.Attachment
	timers     session.TransactionTimers

	mu        sync.Mutex
	cseq      int64
	nextPort  int
	calls     map[string]*Call
	incomings map[string]*Call
	closed    bool
}

type Call struct {
	service *Service

	mu               sync.Mutex
	id               string
	sessionID        string
	direction        Direction
	state            State
	localURI         string
	localTag         string
	remoteURI        string
	remoteTag        string
	remoteTo         string
	targetURI        string
	routeSet         []string
	inviteSeq        int64
	localPort        int
	incomingRequest  *session.Request
	remoteOffer      sdpOffer
	earlyAnswer      sdpOffer
	hasEarlyAnswer   bool
	inviteOK         sip.Message
	inviteOKStop     chan struct{}
	inviteACK        sip.Message
	prackedRSeq      map[string]struct{}
	delayedOffer     bool
	mediaActivity    chan MediaPacket
	mediaWatchStop   chan struct{}
	dialogAttachment session.Attachment
	media            NegotiatedMedia
	transport        MediaTransport
	closed           bool
}

const (
	inviteOKWriteTimeout = 5 * time.Second
	callReleaseTimeout   = 5 * time.Second
)

const (
	reasonUserTriggered       = `RELEASE_CAUSE;cause=1;text="User ends call"`
	reasonMediaBearerReleased = `RELEASE_CAUSE;cause=3;text="Media bearer loss"`
)

func New(cfg Config, sess *session.Session, reg *registration.Service) (*Service, error) {
	if sess == nil {
		return nil, errors.New("creating call service: session is nil")
	}
	if reg == nil {
		return nil, errors.New("creating call service: registration service is nil")
	}
	normalized, err := cfg.Normalized()
	if err != nil {
		return nil, err
	}
	svc := &Service{
		cfg:       normalized,
		sess:      sess,
		reg:       reg,
		logger:    slog.Default().With("component", "ims-call"),
		timers:    sess.TransactionTimers(),
		nextPort:  normalized.LocalRTPPortMin,
		calls:     make(map[string]*Call),
		incomings: make(map[string]*Call),
	}
	attachment, err := sess.Attach(svc)
	if err != nil {
		return nil, fmt.Errorf("creating call service: %w", err)
	}
	svc.attachment = attachment
	return svc, nil
}

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
	if err := setInviteBody(&invite, s.cfg, localURI, offer); err != nil {
		return nil, err
	}

	call := &Call{
		service:   s,
		id:        callID,
		sessionID: sessionID,
		direction: DirectionOutgoing,
		state:     StateDialing,
		localURI:  localURI,
		localTag:  tag,
		remoteURI: target,
		remoteTo:  fmt.Sprintf("<%s>", target),
		targetURI: target,
		inviteSeq: inviteSeq,
		localPort: localPort,
		media:     media,
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

	resp, err := s.sess.Exchange(ctx, invite)
	if err != nil {
		_ = call.closeMedia()
		s.removeCall(callID)
		call.setState(StateFailed, err.Error())
		return nil, fmt.Errorf("dialing call: %w", err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		_ = call.closeMedia()
		s.removeCall(callID)
		err := fmt.Errorf("dialing call: expected 2xx, got %d", resp.StatusCode())
		call.setState(StateFailed, err.Error())
		return nil, err
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
	call.setState(StateActive, "")
	return call, nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	calls := make([]*Call, 0, len(s.calls))
	for _, call := range s.calls {
		calls = append(calls, call)
	}
	s.calls = make(map[string]*Call)
	s.incomings = make(map[string]*Call)
	s.mu.Unlock()

	if s.attachment != nil {
		_ = s.attachment.Close()
	}
	for _, call := range calls {
		call.finish(StateEnded, "")
	}
	return nil
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	switch strings.ToUpper(req.Message.Method()) {
	case "INVITE":
		return true, s.handleIncomingInvite(ctx, req)
	case "ACK", "BYE", "CANCEL":
		call := s.lookupCallForMessage(req.Message)
		if call == nil {
			return false, nil
		}
		return true, call.handleRequest(ctx, req)
	default:
		return false, nil
	}
}

func (s *Service) HandleResponse(ctx context.Context, msg sip.Message) (bool, error) {
	if !strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), "INVITE") {
		return false, nil
	}
	call := s.lookupCall(strings.TrimSpace(msg.Header("Call-ID")))
	if call == nil {
		return false, nil
	}
	if msg.StatusCode() > 100 && msg.StatusCode() < 200 {
		return true, call.handleProvisionalResponse(ctx, msg)
	}
	if msg.StatusCode() < 200 || msg.StatusCode() >= 300 {
		return false, nil
	}
	return true, call.handleResponse(ctx, msg)
}

func (s *Service) HandleError(err error) {
	if err != nil {
		s.emitError(err)
	}
}

func (s *Service) handleIncomingInvite(ctx context.Context, req session.Request) error {
	if existing := s.lookupIncoming(req.Message); existing != nil {
		existing.mu.Lock()
		resp := existing.inviteOK
		existing.mu.Unlock()
		if resp.StartLine != "" {
			return s.sess.WriteResponse(ctx, req, resp)
		}
		return s.writeRinging(ctx, req)
	}

	localPort := s.reserveRTPPort()
	localIP := s.localIP()
	var (
		offer        sdpOffer
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
		_, media, err = buildSDPAnswer(s.cfg, localIP, localPort, offer, MediaOffer{})
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
	}
	if err := s.storeCall(call); err != nil {
		return err
	}
	s.storeIncoming(req.Message, call)

	if err := s.writeStatus(ctx, req, 100, "Trying"); err != nil {
		return fmt.Errorf("handling call INVITE: sending 100 Trying: %w", err)
	}
	if err := s.writeRinging(ctx, req); err != nil {
		return fmt.Errorf("handling call INVITE: sending 180 Ringing: %w", err)
	}
	call.setState(StateRinging, "")
	if s.cfg.OnIncoming != nil {
		var incomingOffer MediaOffer
		if !delayedOffer {
			incomingOffer = mediaOfferFromSDP(offer)
		}
		s.cfg.OnIncoming(Incoming{
			Call:     call,
			From:     call.remoteURI,
			Offer:    incomingOffer,
			Received: time.Now(),
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

func (s *Service) writeRinging(ctx context.Context, req session.Request) error {
	resp := sip.NewResponse(180, "Ringing")
	resp.Headers = sip.ResponseHeaders(req.Message, 180)
	s.addAccessNetworkInfo(&resp)
	resp.Headers.Add("Contact", contactValue(s.reg.State()))
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	resp.Headers.Add("Accept", callAcceptHeader(s.cfg))
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) addAccessNetworkInfo(resp *sip.Message) {
	if value := strings.TrimSpace(s.reg.State().AccessNetworkInfo); value != "" {
		resp.Headers.Add("P-Access-Network-Info", value)
	}
}

func (c *Call) ID() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.id
}

func (c *Call) Direction() Direction {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.direction
}

func (c *Call) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Call) Media() NegotiatedMedia {
	c.mu.Lock()
	defer c.mu.Unlock()
	media := c.media
	media.RemoteIP = append(net.IP(nil), media.RemoteIP...)
	return media
}

func (c *Call) Answer(ctx context.Context, offer MediaOffer) error {
	c.mu.Lock()
	if c.direction != DirectionIncoming {
		c.mu.Unlock()
		return errors.New("answering call: call is not incoming")
	}
	if c.state != StateRinging {
		c.mu.Unlock()
		return fmt.Errorf("answering call: call state is %s", c.state)
	}
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("answering call: incoming request is missing")
	}
	remoteOffer := c.remoteOffer
	localPort := c.localPort
	c.mu.Unlock()

	var (
		answer []byte
		media  NegotiatedMedia
		err    error
	)
	if c.delayedOffer {
		answer, media, err = buildSDPOffer(c.service.cfg, c.service.localIP(), localPort, offer)
	} else {
		answer, media, err = buildSDPAnswer(c.service.cfg, c.service.localIP(), localPort, remoteOffer, offer)
	}
	if err != nil {
		return err
	}
	c.mu.Lock()
	c.media = media
	c.mu.Unlock()
	if c.delayedOffer {
		if err := c.prepareMedia(ctx); err != nil {
			return err
		}
	} else {
		if err := c.openMedia(ctx); err != nil {
			return err
		}
		c.startMediaInactivityWatch()
	}
	return c.writeInviteOK(ctx, answer)
}

func (c *Call) Reject(ctx context.Context, code int, reason string) error {
	if code == 0 {
		code = 486
	}
	if reason == "" {
		reason = "Busy Here"
	}
	c.mu.Lock()
	if c.direction != DirectionIncoming {
		c.mu.Unlock()
		return errors.New("rejecting call: call is not incoming")
	}
	if c.state != StateRinging {
		c.mu.Unlock()
		return fmt.Errorf("rejecting call: call state is %s", c.state)
	}
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("rejecting call: incoming request is missing")
	}
	req := *c.incomingRequest
	c.mu.Unlock()
	if err := c.service.writeStatus(ctx, req, code, reason); err != nil {
		return fmt.Errorf("rejecting call: %w", err)
	}
	c.finish(StateEnded, reason)
	return nil
}

func (c *Call) Hangup(ctx context.Context) error {
	c.mu.Lock()
	state := c.state
	direction := c.direction
	c.mu.Unlock()

	if direction == DirectionIncoming && state == StateRinging {
		return c.Reject(ctx, 486, "Busy Here")
	}
	if state == StateEnding || state == StateEnded {
		return nil
	}
	if state != StateActive {
		return fmt.Errorf("hanging up call: call state is %s", state)
	}
	c.setState(StateEnding, "")
	_ = c.closeMedia()
	resp, err := c.service.sess.Exchange(ctx, c.buildBYE(reasonUserTriggered))
	if err != nil {
		c.finish(StateFailed, err.Error())
		return fmt.Errorf("hanging up call: %w", err)
	}
	if resp.StatusCode() != 200 {
		err := fmt.Errorf("hanging up call: expected 200, got %d", resp.StatusCode())
		c.finish(StateFailed, err.Error())
		return err
	}
	c.finish(StateEnded, "")
	return nil
}

func (c *Call) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	transport, err := c.mediaTransport("reading call media")
	if err != nil {
		return nil, nil, err
	}
	return transport.ReadPacket(ctx)
}

func (c *Call) WritePacket(ctx context.Context, data []byte) error {
	transport, err := c.mediaTransport("writing call media")
	if err != nil {
		return err
	}
	return transport.WritePacket(ctx, data)
}

func (c *Call) ReadRTP(ctx context.Context) ([]byte, net.Addr, error) {
	return c.ReadPacket(ctx)
}

func (c *Call) WriteRTP(ctx context.Context, data []byte) error {
	return c.WritePacket(ctx, data)
}

func (c *Call) ReadRTCP(ctx context.Context) ([]byte, net.Addr, error) {
	transport, err := c.mediaTransport("reading call rtcp")
	if err != nil {
		return nil, nil, err
	}
	if rtcp, ok := transport.(interface {
		ReadRTCP(context.Context) ([]byte, net.Addr, error)
	}); ok {
		return rtcp.ReadRTCP(ctx)
	}
	return transport.ReadPacket(ctx)
}

func (c *Call) WriteRTCP(ctx context.Context, data []byte) error {
	transport, err := c.mediaTransport("writing call rtcp")
	if err != nil {
		return err
	}
	if rtcp, ok := transport.(interface {
		WriteRTCP(context.Context, []byte) error
	}); ok {
		return rtcp.WriteRTCP(ctx, data)
	}
	return transport.WritePacket(ctx, data)
}

func (c *Call) handleRequest(ctx context.Context, req session.Request) error {
	switch strings.ToUpper(req.Message.Method()) {
	case "ACK":
		if err := c.handleACK(ctx, req); err != nil {
			return err
		}
		c.stopInviteOKRetransmit()
		return nil
	case "BYE":
		if err := c.service.writeStatus(ctx, req, 200, "OK"); err != nil {
			return err
		}
		c.finish(StateEnded, "remote bye")
		return nil
	case "CANCEL":
		c.finish(StateEnded, "remote cancel")
		return nil
	default:
		return nil
	}
}

func (c *Call) handleACK(ctx context.Context, req session.Request) error {
	c.mu.Lock()
	delayedOffer := c.delayedOffer
	state := c.state
	media := c.media
	c.mu.Unlock()
	if !delayedOffer {
		c.setState(StateActive, "")
		return nil
	}
	if state != StateAnswering {
		return nil
	}
	body, ok := sdpBody(req.Message)
	if !ok {
		c.finish(StateFailed, "missing delayed-offer sdp answer")
		return nil
	}
	answer, err := parseSDP(body)
	if err != nil {
		c.finish(StateFailed, err.Error())
		return nil
	}
	negotiated, ok := chooseCodec(answer, c.service.cfg.Codecs)
	if !ok {
		c.finish(StateFailed, "no compatible delayed-offer answer codec")
		return nil
	}
	dtmf, hasDTMF := chooseTelephoneEvent(answer, c.service.cfg.Codecs)
	answerMedia := negotiatedMedia(answer, negotiated, nonZeroDuration(answer.PTime, media.PTime), dtmf, hasDTMF)
	c.mu.Lock()
	c.media = answerMedia
	c.mu.Unlock()
	if err := c.openMedia(ctx); err != nil {
		c.finish(StateFailed, err.Error())
		return nil
	}
	c.startMediaInactivityWatch()
	c.setState(StateActive, "")
	return nil
}

func (c *Call) handleResponse(ctx context.Context, msg sip.Message) error {
	c.mu.Lock()
	if c.direction != DirectionOutgoing || sip.CSeqNumber(msg.Header("CSeq")) != c.inviteSeq {
		c.mu.Unlock()
		return nil
	}
	tag := sip.HeaderTag(msg.Header("To"))
	if tag != "" && c.remoteTag != "" && tag != c.remoteTag {
		ack := c.buildACKForResponseLocked(msg)
		bye := c.buildBYEForResponseLocked(msg, reasonUserTriggered)
		c.mu.Unlock()
		if err := c.service.sess.Send(ctx, ack); err != nil {
			return fmt.Errorf("acknowledging forked call 2xx: %w", err)
		}
		resp, err := c.service.sess.Exchange(ctx, bye)
		if err != nil {
			return fmt.Errorf("releasing forked call 2xx: %w", err)
		}
		if resp.StatusCode() != 200 {
			return fmt.Errorf("releasing forked call 2xx: expected 200, got %d", resp.StatusCode())
		}
		return nil
	}
	ack := c.inviteACK
	c.mu.Unlock()
	if ack.StartLine == "" {
		return nil
	}
	if err := c.service.sess.Send(ctx, ack); err != nil {
		return fmt.Errorf("acknowledging retransmitted call 2xx: %w", err)
	}
	return nil
}

func (c *Call) handleProvisionalResponse(_ context.Context, msg sip.Message) error {
	c.mu.Lock()
	if c.direction != DirectionOutgoing || sip.CSeqNumber(msg.Header("CSeq")) != c.inviteSeq {
		c.mu.Unlock()
		return nil
	}
	c.mu.Unlock()

	if body, ok := sdpBody(msg); ok {
		answer, err := parseSDP(body)
		if err != nil {
			return fmt.Errorf("handling provisional call answer: %w", err)
		}
		c.mu.Lock()
		c.earlyAnswer = answer
		c.hasEarlyAnswer = true
		c.mu.Unlock()
	}

	if !isReliableProvisional(msg) {
		return nil
	}
	c.mu.Lock()
	key := provisionalResponseKey(msg)
	if key == "" {
		c.mu.Unlock()
		return nil
	}
	if c.prackedRSeq == nil {
		c.prackedRSeq = make(map[string]struct{})
	}
	if _, ok := c.prackedRSeq[key]; ok {
		c.mu.Unlock()
		return nil
	}
	c.prackedRSeq[key] = struct{}{}
	prack, err := c.buildPRACKForResponseLocked(msg)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	go c.sendPRACK(prack)
	return nil
}

func (c *Call) answerFromFinalResponse(resp sip.Message) (sdpOffer, bool, error) {
	if answerBody, ok := sdpBody(resp); ok {
		answer, err := parseSDP(answerBody)
		if err != nil {
			return sdpOffer{}, false, err
		}
		return answer, true, nil
	}
	c.mu.Lock()
	answer := c.earlyAnswer
	ok := c.hasEarlyAnswer
	c.mu.Unlock()
	return answer, ok, nil
}

func (c *Call) sendPRACK(prack sip.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), callReleaseTimeout)
	defer cancel()
	resp, err := c.service.sess.Exchange(ctx, prack)
	if err != nil {
		c.service.emitError(fmt.Errorf("sending call PRACK: %w", err))
		return
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		c.service.emitError(fmt.Errorf("sending call PRACK: expected 2xx, got %d", resp.StatusCode()))
	}
}

func (c *Call) prepareMedia(ctx context.Context) error {
	c.mu.Lock()
	if c.transport != nil {
		c.mu.Unlock()
		return nil
	}
	localPort := c.localPort
	media := c.media
	c.mu.Unlock()

	if c.service.cfg.PrepareMedia == nil {
		return nil
	}
	transport, err := c.service.cfg.PrepareMedia(ctx, MediaConfig{
		LocalPort: localPort,
		Media:     media,
		OnPacket:  c.recordMediaPacket,
	})
	if err != nil {
		return fmt.Errorf("preparing call media: %w", err)
	}
	if transport == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return transport.Close()
	}
	c.transport = transport
	c.mu.Unlock()
	return nil
}

func (c *Call) openMedia(ctx context.Context) error {
	c.mu.Lock()
	transport := c.transport
	localPort := c.localPort
	media := c.media
	c.mu.Unlock()

	cfg := MediaConfig{
		LocalPort:  localPort,
		RemoteIP:   append(net.IP(nil), media.RemoteIP...),
		RemotePort: media.RemotePort,
		Media:      media,
		OnPacket:   c.recordMediaPacket,
	}
	if transport != nil {
		if configurable, ok := transport.(interface {
			ConfigureRemote(context.Context, MediaConfig) error
		}); ok {
			if err := configurable.ConfigureRemote(ctx, cfg); err != nil {
				return fmt.Errorf("configuring call media remote: %w", err)
			}
			return nil
		}
		if c.service.cfg.OpenMedia == nil {
			return nil
		}
		c.mu.Lock()
		if c.transport == transport {
			c.transport = nil
		}
		c.mu.Unlock()
		if err := transport.Close(); err != nil {
			return fmt.Errorf("closing prepared call media: %w", err)
		}
	}

	if c.service.cfg.OpenMedia == nil {
		return nil
	}
	transport, err := c.service.cfg.OpenMedia(ctx, cfg)
	if err != nil {
		return fmt.Errorf("opening call media: %w", err)
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return transport.Close()
	}
	c.transport = transport
	c.mu.Unlock()
	return nil
}

func (c *Call) recordMediaPacket(packet MediaPacket) {
	c.mu.Lock()
	activity := c.mediaActivity
	c.mu.Unlock()
	if activity == nil {
		return
	}
	select {
	case activity <- packet:
	default:
	}
}

func (c *Call) startMediaInactivityWatch() {
	rtpTimeout := c.service.cfg.RTPInactivityTimeout
	rtcpTimeout := c.service.cfg.RTCPInactivityTimeout
	c.mu.Lock()
	if c.mediaWatchStop != nil || c.closed {
		c.mu.Unlock()
		return
	}
	activity := make(chan MediaPacket, 16)
	stop := make(chan struct{})
	c.mediaActivity = activity
	c.mediaWatchStop = stop
	c.mu.Unlock()

	go func() {
		var rtpTimer *time.Timer
		var rtpC <-chan time.Time
		if rtpTimeout > 0 {
			rtpTimer = time.NewTimer(rtpTimeout)
			rtpC = rtpTimer.C
			defer rtpTimer.Stop()
		}
		var rtcpTimer *time.Timer
		var rtcpC <-chan time.Time
		if rtcpTimeout > 0 {
			rtcpTimer = time.NewTimer(rtcpTimeout)
			rtcpC = rtcpTimer.C
			defer rtcpTimer.Stop()
		}
		for {
			select {
			case <-stop:
				return
			case packet := <-activity:
				if packet.RTCP {
					if packet.RTCPBye {
						c.endAfterMediaEvent("rtcp bye")
						return
					}
					if rtcpTimer != nil {
						resetTimer(rtcpTimer, rtcpTimeout)
					}
				} else if rtpTimer != nil {
					resetTimer(rtpTimer, rtpTimeout)
				}
			case <-rtpC:
				c.endAfterMediaEvent("rtp inactivity timeout")
				return
			case <-rtcpC:
				c.endAfterMediaEvent("rtcp inactivity timeout")
				return
			}
		}
	}()
}

func (c *Call) endAfterMediaEvent(cause string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	state := c.state
	c.mu.Unlock()

	_ = c.closeMedia()
	if state == StateActive {
		c.setState(StateEnding, cause)
		ctx, cancel := context.WithTimeout(context.Background(), callReleaseTimeout)
		resp, err := c.service.sess.Exchange(ctx, c.buildBYE(reasonMediaBearerReleased))
		cancel()
		if err != nil {
			c.service.emitError(fmt.Errorf("ending call after media event: %w", err))
		} else if resp.StatusCode() != 200 {
			c.service.emitError(fmt.Errorf("ending call after media event: expected 200, got %d", resp.StatusCode()))
		}
	}
	c.finish(StateEnded, cause)
}

func (c *Call) closeMedia() error {
	c.mu.Lock()
	transport := c.transport
	c.transport = nil
	c.mu.Unlock()
	if transport == nil {
		return nil
	}
	return transport.Close()
}

func (c *Call) startInviteOKRetransmit(req session.Request, resp sip.Message) {
	c.mu.Lock()
	if c.inviteOKStop != nil || c.closed {
		c.mu.Unlock()
		return
	}
	stop := make(chan struct{})
	c.inviteOKStop = stop
	c.mu.Unlock()

	go func() {
		timers := c.service.timers
		interval := timers.T1
		timer := time.NewTimer(interval)
		defer timer.Stop()
		deadline := time.NewTimer(64 * timers.T1)
		defer deadline.Stop()

		for {
			select {
			case <-stop:
				return
			case <-deadline.C:
				c.finish(StateEnded, "ack timeout")
				return
			case <-timer.C:
				ctx, cancel := context.WithTimeout(context.Background(), min(inviteOKWriteTimeout, interval))
				if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
					c.service.emitError(fmt.Errorf("retransmitting call 200 OK: %w", err))
				}
				cancel()
				interval = min(interval*2, timers.T2)
				timer.Reset(interval)
			}
		}
	}()
}

func (c *Call) stopInviteOKRetransmit() {
	c.mu.Lock()
	stop := c.inviteOKStop
	c.inviteOKStop = nil
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (c *Call) mediaTransport(action string) (MediaTransport, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, fmt.Errorf("%s: call is closed", action)
	}
	if c.transport == nil {
		return nil, fmt.Errorf("%s: media transport is not configured", action)
	}
	return c.transport, nil
}

func (c *Call) buildACK() sip.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buildACKLocked()
}

func (c *Call) buildACKLocked() sip.Message {
	state := c.service.reg.State()
	msg := sip.NewRequest("ACK", c.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", c.remoteTo)
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d ACK", c.inviteSeq))
	c.service.reg.DialogRequestPolicy(c.routeSet).Apply(&msg)
	return msg
}

func (c *Call) buildACKForResponseLocked(resp sip.Message) sip.Message {
	state := c.service.reg.State()
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), c.targetURI)
	msg := sip.NewRequest("ACK", targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", nonEmpty(resp.Header("To"), c.remoteTo))
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d ACK", c.inviteSeq))
	c.service.reg.DialogRequestPolicy(reverseValues(resp.HeadersByName("Record-Route"))).Apply(&msg)
	return msg
}

func (c *Call) buildDialogRequest(method string) sip.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	state := c.service.reg.State()
	msg := sip.NewRequest(method, c.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", c.remoteTo)
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("Session-ID", c.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", atomic.AddInt64(&c.service.cseq, 1), method))
	msg.Headers.Add("Contact", contactValue(state))
	c.service.reg.DialogRequestPolicy(c.routeSet).Apply(&msg)
	return msg
}

func (c *Call) buildBYE(reason string) sip.Message {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buildBYELocked(reason)
}

func (c *Call) buildBYELocked(reason string) sip.Message {
	msg := c.buildDialogRequestLocked("BYE")
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	return msg
}

func (c *Call) buildBYEForResponseLocked(resp sip.Message, reason string) sip.Message {
	state := c.service.reg.State()
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), c.targetURI)
	msg := sip.NewRequest("BYE", targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", nonEmpty(resp.Header("To"), c.remoteTo))
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("Session-ID", c.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d BYE", atomic.AddInt64(&c.service.cseq, 1)))
	msg.Headers.Add("Contact", contactValue(state))
	if reason != "" {
		msg.Headers.Add("Reason", reason)
	}
	c.service.reg.DialogRequestPolicy(reverseValues(resp.HeadersByName("Record-Route"))).Apply(&msg)
	return msg
}

func (c *Call) buildPRACKForResponseLocked(resp sip.Message) (sip.Message, error) {
	rseq, err := parseRSeq(resp.Header("RSeq"))
	if err != nil {
		return sip.Message{}, err
	}
	state := c.service.reg.State()
	targetURI := nonEmpty(sip.AddressURI(resp.Header("Contact")), sip.AddressURI(resp.Header("To")), c.targetURI)
	msg := sip.NewRequest("PRACK", targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", nonEmpty(resp.Header("To"), c.remoteTo))
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("Session-ID", c.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d PRACK", atomic.AddInt64(&c.service.cseq, 1)))
	msg.Headers.Add("RAck", fmt.Sprintf("%d %d INVITE", rseq, c.inviteSeq))
	msg.Headers.Add("Contact", contactValue(state))
	c.service.reg.DialogRequestPolicy(reverseValues(resp.HeadersByName("Record-Route"))).Apply(&msg)
	return msg, nil
}

func (c *Call) buildDialogRequestLocked(method string) sip.Message {
	state := c.service.reg.State()
	msg := sip.NewRequest(method, c.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(c.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", c.localURI, c.localTag))
	msg.Headers.Add("To", c.remoteTo)
	msg.Headers.Add("Call-ID", c.id)
	msg.Headers.Add("Session-ID", c.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", atomic.AddInt64(&c.service.cseq, 1), method))
	msg.Headers.Add("Contact", contactValue(state))
	c.service.reg.DialogRequestPolicy(c.routeSet).Apply(&msg)
	return msg
}

func (c *Call) refreshDialogRegistration() error {
	c.mu.Lock()
	id := sip.DialogID{
		CallID:    c.id,
		LocalTag:  c.localTag,
		RemoteTag: c.remoteTag,
	}
	key := c.id
	c.mu.Unlock()

	attachment, err := c.service.sess.RegisterDialog(id, key)
	if err != nil {
		return fmt.Errorf("refreshing call dialog: %w", err)
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = attachment.Close()
		return errors.New("refreshing call dialog: call is closed")
	}
	old := c.dialogAttachment
	c.dialogAttachment = attachment
	c.mu.Unlock()

	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (c *Call) writeInviteOK(ctx context.Context, body []byte) error {
	c.mu.Lock()
	if c.incomingRequest == nil {
		c.mu.Unlock()
		return errors.New("answering call: incoming request is missing")
	}
	req := *c.incomingRequest
	c.mu.Unlock()
	resp, err := c.buildInviteOK(req.Message, body)
	if err != nil {
		return err
	}
	if err := c.service.sess.WriteResponse(ctx, req, resp); err != nil {
		c.finish(StateFailed, err.Error())
		return fmt.Errorf("answering call: %w", err)
	}
	c.mu.Lock()
	c.inviteOK = resp
	c.mu.Unlock()
	c.setState(StateAnswering, "")
	c.startInviteOKRetransmit(req, resp)
	return nil
}

func (c *Call) buildInviteOK(msg sip.Message, body []byte) (sip.Message, error) {
	ok := sip.NewResponse(200, "OK")
	ok.Headers = sip.ResponseHeaders(msg, 200)
	c.service.addAccessNetworkInfo(&ok)
	ok.Headers = sip.UpsertHeader(ok.Headers, "To", sip.WithTag(msg.Header("To"), c.localURI, c.localTag))
	ok.Headers.Add("Session-ID", c.sessionID)
	ok.Headers.Add("Contact", contactValue(c.service.reg.State()))
	ok.Headers.Add("Allow", sip.DefaultClientAllow)
	ok.Headers.Add("Accept", callAcceptHeader(c.service.cfg))
	addInviteOKSessionTimer(&ok, msg, c.service.cfg)
	if len(body) != 0 {
		if err := setInviteResponseBody(&ok, c.service.cfg, c.localURI, body); err != nil {
			return sip.Message{}, err
		}
	}
	return ok, nil
}

func (c *Call) setState(state State, cause string) {
	c.mu.Lock()
	if c.state == state && cause == "" {
		c.mu.Unlock()
		return
	}
	c.state = state
	id := c.id
	c.mu.Unlock()
	c.service.emit(Event{CallID: id, State: state, Cause: cause, At: time.Now()})
}

func (c *Call) finish(state State, cause string) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	id := c.id
	attachment := c.dialogAttachment
	stop := c.inviteOKStop
	mediaStop := c.mediaWatchStop
	c.inviteOKStop = nil
	c.mediaActivity = nil
	c.mediaWatchStop = nil
	c.dialogAttachment = nil
	c.mu.Unlock()

	if stop != nil {
		close(stop)
	}
	if mediaStop != nil {
		close(mediaStop)
	}
	if attachment != nil {
		_ = attachment.Close()
	}
	_ = c.closeMedia()
	c.service.removeCall(id)
	c.setState(state, cause)
}

func (s *Service) storeCall(call *Call) error {
	attachment, err := s.sess.RegisterDialog(sip.DialogID{
		CallID:    call.id,
		LocalTag:  call.localTag,
		RemoteTag: call.remoteTag,
	}, call.id)
	if err != nil {
		return fmt.Errorf("storing call: %w", err)
	}
	call.dialogAttachment = attachment
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = attachment.Close()
		return errors.New("storing call: service is closed")
	}
	s.calls[call.id] = call
	return nil
}

func (s *Service) removeCall(callID string) {
	s.mu.Lock()
	call := s.calls[callID]
	if call != nil {
		delete(s.calls, callID)
		for key, incoming := range s.incomings {
			if incoming == call {
				delete(s.incomings, key)
			}
		}
	}
	s.mu.Unlock()
	if call != nil && call.dialogAttachment != nil {
		_ = call.dialogAttachment.Close()
		call.dialogAttachment = nil
	}
}

func (s *Service) lookupCallForMessage(msg sip.Message) *Call {
	key, ok := s.sess.LookupDialogKey(msg)
	if !ok {
		return nil
	}
	return s.lookupCall(key)
}

func (s *Service) lookupCall(callID string) *Call {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[callID]
}

func (s *Service) storeIncoming(msg sip.Message, call *Call) {
	key := incomingInviteKey(msg)
	if key == "" {
		return
	}
	s.mu.Lock()
	s.incomings[key] = call
	s.mu.Unlock()
}

func (s *Service) lookupIncoming(msg sip.Message) *Call {
	key := incomingInviteKey(msg)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.incomings[key]
}

func (s *Service) targetURI(to string) string {
	to = strings.TrimSpace(to)
	if to == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToLower(to), "sip:") || strings.HasPrefix(strings.ToLower(to), "tel:") {
		return to
	}
	realm := strings.TrimPrefix(s.reg.State().RegisterURI, "sip:")
	if strings.HasPrefix(to, "+") {
		return fmt.Sprintf("sip:%s@%s;user=phone", to, realm)
	}
	return fmt.Sprintf("sip:%s;phone-context=%s@%s;user=phone", to, realm, realm)
}

func (s *Service) reserveRTPPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	port := s.nextPort
	if port%2 != 0 {
		port++
	}
	s.nextPort = port + 2
	if s.nextPort > s.cfg.LocalRTPPortMax {
		s.nextPort = s.cfg.LocalRTPPortMin
	}
	return port
}

func (s *Service) localIP() net.IP {
	ip := net.ParseIP(s.reg.State().ContactHost)
	if ip == nil || ip.IsUnspecified() {
		return net.IPv4(0, 0, 0, 0)
	}
	return ip
}

func (s *Service) emit(event Event) {
	if s.cfg.OnEvent != nil {
		s.cfg.OnEvent(event)
	}
}

func (s *Service) emitError(err error) {
	if err == nil {
		return
	}
	if s.cfg.OnError != nil {
		s.cfg.OnError(err)
		return
	}
	s.logger.Debug("call service error", "err", err)
}

func mediaOfferFromSDP(offer sdpOffer) MediaOffer {
	seen := make(map[AudioCodec]struct{}, len(offer.Codecs))
	codecs := make([]AudioCodec, 0, len(offer.Codecs))
	for _, payload := range offer.Payloads {
		codec := offer.Codecs[payload]
		if codec.Name == "" {
			continue
		}
		if _, ok := seen[codec.Name]; ok {
			continue
		}
		seen[codec.Name] = struct{}{}
		codecs = append(codecs, codec.Name)
	}
	return MediaOffer{Codecs: codecs, PTime: offer.PTime}
}

func callAcceptHeader(cfg Config) string {
	if cfg.IncludeGeolocationPIDF {
		return "application/sdp, application/pidf+xml, multipart/mixed"
	}
	return "application/sdp"
}

func addInviteOKSessionTimer(resp *sip.Message, invite sip.Message, cfg Config) {
	if !cfg.SessionTimer || !tokenHeaderContains(invite, "Supported", "timer") {
		return
	}
	sessionExpires := strings.TrimSpace(invite.Header("Session-Expires"))
	if sessionExpires == "" {
		seconds := int(defaultSessionExpires / time.Second)
		if minSE, ok := parseSessionSeconds(invite.Header("Min-SE")); ok && minSE > seconds {
			seconds = minSE
		}
		resp.Headers.Set("Session-Expires", fmt.Sprintf("%d;refresher=uac", seconds))
		return
	}
	if sessionExpiresHasRefresher(sessionExpires) {
		resp.Headers.Set("Session-Expires", sessionExpires)
		return
	}
	resp.Headers.Set("Session-Expires", strings.TrimSpace(sessionExpires)+";refresher=uac")
}

func parseSessionSeconds(value string) (int, bool) {
	value, _, _ = strings.Cut(strings.TrimSpace(value), ";")
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return seconds, true
}

func sessionExpiresHasRefresher(value string) bool {
	for _, part := range strings.Split(value, ";")[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(name, "refresher") {
			return true
		}
	}
	return false
}

func setInviteBody(msg *sip.Message, cfg Config, localURI string, sdp []byte) error {
	if !cfg.IncludeGeolocationPIDF {
		msg.Headers.Add("Content-Type", "application/sdp")
		msg.Body = sdp
		return nil
	}
	boundary := "call-" + sip.RandomAlphaNum(18)
	locationID := "pidf-" + sip.RandomAlphaNum(16)
	body, err := buildMultipartInviteBody(boundary, locationID, sdp, buildPIDF(localURI, cfg.GeolocationCountry))
	if err != nil {
		return fmt.Errorf("building call INVITE body: %w", err)
	}
	msg.Headers.Add("Geolocation", "<cid:"+locationID+">")
	msg.Headers.Add("Geolocation-Routing", "yes")
	msg.Headers.Add("Content-Type", `multipart/mixed; boundary=`+boundary)
	msg.Body = body
	return nil
}

func setInviteResponseBody(msg *sip.Message, cfg Config, localURI string, sdp []byte) error {
	if !cfg.IncludeGeolocationPIDF {
		msg.Headers.Add("Content-Type", "application/sdp")
		msg.Body = sdp
		return nil
	}
	boundary := "call-" + sip.RandomAlphaNum(18)
	locationID := "pidf-" + sip.RandomAlphaNum(16)
	body, err := buildMultipartInviteBody(boundary, locationID, sdp, buildPIDF(localURI, cfg.GeolocationCountry))
	if err != nil {
		return fmt.Errorf("building call INVITE response body: %w", err)
	}
	msg.Headers.Add("Geolocation", "<cid:"+locationID+">")
	msg.Headers.Add("Geolocation-Routing", "yes")
	msg.Headers.Add("Content-Type", `multipart/mixed; boundary=`+boundary)
	msg.Body = body
	return nil
}

func buildMultipartInviteBody(boundary string, locationID string, sdp []byte, pidf []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, err
	}
	sdpHeader := textproto.MIMEHeader{}
	sdpHeader.Set("Content-Type", "application/sdp")
	sdpHeader.Set("Content-Disposition", "session")
	part, err := writer.CreatePart(sdpHeader)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(sdp); err != nil {
		return nil, err
	}
	pidfHeader := textproto.MIMEHeader{}
	pidfHeader.Set("Content-Type", "application/pidf+xml")
	pidfHeader.Set("Content-ID", "<"+locationID+">")
	pidfHeader.Set("Content-Disposition", "render;handling=optional")
	part, err = writer.CreatePart(pidfHeader)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(pidf); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sdpBody(msg sip.Message) ([]byte, bool) {
	if len(msg.Body) == 0 {
		return nil, false
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header("Content-Type"))
	if err != nil {
		return nil, false
	}
	switch strings.ToLower(mediaType) {
	case "application/sdp":
		return msg.Body, true
	case "multipart/mixed":
		boundary := strings.TrimSpace(params["boundary"])
		if boundary == "" {
			return nil, false
		}
		reader := multipart.NewReader(bytes.NewReader(msg.Body), boundary)
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				return nil, false
			}
			if err != nil {
				return nil, false
			}
			partType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if err != nil || !strings.EqualFold(partType, "application/sdp") {
				continue
			}
			body, err := io.ReadAll(part)
			return body, err == nil && len(body) > 0
		}
	default:
		return nil, false
	}
}

func incomingInviteKey(msg sip.Message) string {
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	if callID == "" || cseq == "" {
		return ""
	}
	return callID + "|" + cseq
}

func contactValue(state registration.State) string {
	params := []string{
		fmt.Sprintf(`+g.3gpp.icsi-ref="%s"`, mmtelICSIEncoded),
		`+g.3gpp.mid-call`,
		`+g.3gpp.ps2cs-srvcc-orig-pre-alerting`,
		`+g.3gpp.srvcc-alerting`,
	}
	if state.IMEI != "" {
		params = append(params, fmt.Sprintf(`+sip.instance="<urn:gsma:imei:%s>"`, state.IMEI))
	}
	return fmt.Sprintf("<%s>;%s", sipContactURI(state.ContactHost, state.MessagePort), strings.Join(params, ";"))
}

func sipContactURI(host string, port int) string {
	return "sip:" + net.JoinHostPort(host, strconv.Itoa(port))
}

func preferredIdentity(state registration.State) string {
	if identity := strings.TrimSpace(state.SIPPublicID); identity != "" {
		return identity
	}
	if identity := strings.TrimSpace(state.DefaultPublicID); identity != "" {
		return identity
	}
	return state.PublicIdentity
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

func nonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nonZeroDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func isReliableProvisional(msg sip.Message) bool {
	if strings.TrimSpace(msg.Header("RSeq")) == "" {
		return false
	}
	return tokenHeaderContains(msg, "Require", "100rel")
}

func provisionalResponseKey(msg sip.Message) string {
	rseq := strings.TrimSpace(msg.Header("RSeq"))
	if rseq == "" {
		return ""
	}
	return sip.HeaderTag(msg.Header("To")) + "|" + rseq
}

func parseRSeq(value string) (int64, error) {
	rseq, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
	if err != nil || rseq <= 0 {
		return 0, fmt.Errorf("building PRACK: invalid RSeq %q", value)
	}
	return rseq, nil
}

func tokenHeaderContains(msg sip.Message, name string, want string) bool {
	for _, value := range msg.HeadersByName(name) {
		if sip.TokenListContains(value, want) {
			return true
		}
	}
	return false
}

func resetTimer(timer *time.Timer, timeout time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(timeout)
}
