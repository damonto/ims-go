package session

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damonto/ims-go/ims/sip"
)

const (
	sipStatusOK                          = 200
	sipStatusTrying                      = 100
	sipStatusBadRequest                  = 400
	sipStatusMethodNotAllowed            = 405
	sipStatusBadExtension                = 420
	sipStatusLoopDetected                = 482
	sipStatusCallTransactionDoesNotExist = 481
	sipStatusRequestTerminated           = 487
)

type Config struct {
	Transport         string
	Logger            *slog.Logger
	TransactionTimers TransactionTimers
	ResponseDecorator func(*sip.Message)
}

func (cfg Config) Normalized() (Config, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	timers, err := cfg.TransactionTimers.Normalized()
	if err != nil {
		return Config{}, err
	}
	cfg.TransactionTimers = timers
	return cfg, nil
}

type Session struct {
	cfg    Config
	logger *slog.Logger

	mu             sync.Mutex
	sendMu         sync.Mutex
	readWG         sync.WaitGroup
	transportErrs  chan struct{}
	transportQueue []inboundMessage
	primary        Transport
	aux            []Transport
	active         map[Transport]struct{}
	responseRoutes map[Transport]Transport
	run            *runState
	dialogs        map[string][]*dialogEntry
	transactions   map[string]*clientTransaction
	serverTxs      map[string]*serverTransaction
	stunPending    map[[12]byte]stunPendingTransaction
	stunMapped     map[Transport]string
	crlfPending    map[Transport]chan error
	txChanged      chan struct{}
	inboundWatches map[*InboundWatch]struct{}
	handlers       []*handlerEntry
	startedCh      chan struct{}
	closedCh       chan struct{}
	closed         bool
	started        bool
	ready          bool
	running        bool

	responseDecorator func(*sip.Message)
	notifyOnce        sync.Once
}

func Open(cfg Config, primary Transport) (*Session, error) {
	if primary == nil {
		return nil, errors.New("opening session: primary transport is nil")
	}
	cfg, err := cfg.Normalized()
	if err != nil {
		return nil, fmt.Errorf("opening session: %w", err)
	}
	return &Session{
		cfg:            cfg,
		logger:         cfg.Logger.With("component", "ims-session"),
		transportErrs:  make(chan struct{}, 1),
		primary:        primary,
		active:         map[Transport]struct{}{primary: {}},
		responseRoutes: make(map[Transport]Transport),
		dialogs:        make(map[string][]*dialogEntry),
		transactions:   make(map[string]*clientTransaction),
		serverTxs:      make(map[string]*serverTransaction),
		stunPending:    make(map[[12]byte]stunPendingTransaction),
		stunMapped:     make(map[Transport]string),
		crlfPending:    make(map[Transport]chan error),
		txChanged:      make(chan struct{}),
		inboundWatches: make(map[*InboundWatch]struct{}),
		startedCh:      make(chan struct{}),
		closedCh:       make(chan struct{}),
	}, nil
}

func (s *Session) TransactionTimers() TransactionTimers {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.TransactionTimers
}

type runState struct {
	ctx     context.Context
	inbound chan<- inboundMessage
}

type inboundMessage struct {
	msg       sip.Message
	packet    []byte
	parseErr  error
	transport Transport
	peer      net.Addr
	err       error
}

type usableTransportError interface {
	error
	TransportUsable() bool
}

func (s *Session) Run(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("running session: session is closed")
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("running session: already started")
	}
	s.started = true
	s.running = true
	primary := s.primary
	aux := append([]Transport(nil), s.aux...)
	inboundCh := make(chan inboundMessage, 16)
	s.run = &runState{ctx: ctx, inbound: inboundCh}
	s.mu.Unlock()
	defer s.finishRunning()

	s.startReadLoop(ctx, primary, inboundCh)
	for _, transport := range aux {
		s.startReadLoop(ctx, transport, inboundCh)
	}
	s.markReady()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.transportErrs:
			for {
				failure, ok := s.nextTransportFailure()
				if !ok {
					break
				}
				if err := s.handleTransportError(ctx, failure, inboundCh); err != nil {
					return err
				}
			}
		case inbound := <-inboundCh:
			if inbound.err != nil {
				if err := s.handleTransportError(ctx, inbound, inboundCh); err != nil {
					return err
				}
				continue
			}
			if err := s.dispatchInbound(ctx, inbound); err != nil {
				return err
			}
		}
	}
}

func (s *Session) handleTransportError(ctx context.Context, inbound inboundMessage, inboundCh chan<- inboundMessage) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if !s.isTransportActive(inbound.transport) {
		return nil
	}
	if transportRemainsUsable(inbound.err) {
		s.logger.Warn("SIP transport connection lost; transport remains active", "local_addr", inbound.transport.LocalAddr(), "err", inbound.err)
		s.abortTransportTransactions(inbound.transport, inbound.err)
		s.startReadLoop(ctx, inbound.transport, inboundCh)
		return nil
	}
	if s.removeFailedAuxTransport(inbound.transport) {
		s.logger.Warn("removed failed auxiliary SIP transport", "local_addr", inbound.transport.LocalAddr(), "err", inbound.err)
		s.abortTransportTransactions(inbound.transport, inbound.err)
		return nil
	}
	return markTransportFailed(inbound.err)
}

func transportRemainsUsable(err error) bool {
	var usable usableTransportError
	return errors.As(err, &usable) && usable.TransportUsable()
}

func (s *Session) handleInboundRequest(ctx context.Context, req Request) error {
	if err := validateInboundRequest(req.Message); err != nil {
		s.logger.Debug("dropping malformed SIP request", "start_line", req.Message.StartLine, "err", err)
		if !canRespondToRequest(req.Message) || strings.EqualFold(req.Message.Method(), "ACK") {
			return nil
		}
		return s.WriteStatus(ctx, req, sipStatusBadRequest, "Bad Request")
	}
	s.markTransportInbound(req.Transport, req.Message)
	handled, err := s.processServerTransaction(ctx, req)
	if handled || err != nil {
		return err
	}
	if unsupported := unsupportedRequireOptions(req.Message); len(unsupported) != 0 {
		resp := sip.NewResponse(sipStatusBadExtension, "Bad Extension")
		resp.Headers = sip.ResponseHeaders(req.Message, sipStatusBadExtension)
		resp.Headers.Add("Unsupported", strings.Join(unsupported, ","))
		return s.WriteResponse(ctx, req, resp)
	}
	return s.handleRequest(ctx, req)
}

func unsupportedRequireOptions(msg sip.Message) []string {
	method := strings.ToUpper(strings.TrimSpace(msg.Method()))
	if method == "ACK" || method == "CANCEL" {
		return nil
	}
	supported := sip.SplitHeaderList(sip.DefaultClientSupported)
	supported = append(supported, "100rel", "precondition", "timer")
	unsupported := make([]string, 0)
	seen := make(map[string]struct{})
	for _, value := range msg.HeadersByName("Require") {
		for _, option := range sip.SplitHeaderList(value) {
			option = strings.TrimSpace(option)
			if option == "" || slices.ContainsFunc(supported, func(candidate string) bool { return strings.EqualFold(candidate, option) }) {
				continue
			}
			key := strings.ToLower(option)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			unsupported = append(unsupported, option)
		}
	}
	return unsupported
}

func (s *Session) WaitStarted(ctx context.Context) error {
	s.mu.Lock()
	if s.ready {
		s.mu.Unlock()
		return nil
	}
	startedCh := s.startedCh
	closedCh := s.closedCh
	s.mu.Unlock()

	select {
	case <-startedCh:
		return nil
	case <-closedCh:
		s.mu.Lock()
		ready := s.ready
		s.mu.Unlock()
		if ready {
			return nil
		}
		return errors.New("waiting for session start: session is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *Session) markReady() {
	s.mu.Lock()
	if s.ready {
		s.mu.Unlock()
		return
	}
	s.ready = true
	startedCh := s.startedCh
	s.mu.Unlock()
	close(startedCh)
}

func (s *Session) finishRunning() {
	s.mu.Lock()
	s.running = false
	s.run = nil
	s.transportQueue = nil
	s.mu.Unlock()
}

func (s *Session) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	s.mu.Lock()
	closedCh := s.closedCh
	s.mu.Unlock()
	return contextWithDoneTimeout(closedCh, timeout)
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

var errSessionClosed = errors.New("session is closed")

func (s *Session) Close() error {
	state, ok := s.beginClose()
	if !ok {
		return nil
	}

	closeErr := closeTransports(state.transports)
	notifyErr := closeErr
	if notifyErr == nil {
		notifyErr = errSessionClosed
	}
	s.finishClose(state.handlers, notifyErr)
	return errors.Join(closeErr, s.waitReadLoops())
}

type closeState struct {
	transports []Transport
	handlers   []*handlerEntry
}

func (s *Session) beginClose() (closeState, bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return closeState{}, false
	}
	s.closed = true
	primary := s.primary
	aux := append([]Transport(nil), s.aux...)
	transports := uniqueTransports(append(aux, primary))
	handlers := s.handlerSnapshotCopy()
	closedCh := s.closedCh
	s.active = make(map[Transport]struct{})
	s.responseRoutes = make(map[Transport]Transport)
	s.mu.Unlock()
	close(closedCh)

	return closeState{
		transports: transports,
		handlers:   handlers,
	}, true
}

func closeTransports(transports []Transport) error {
	var err error
	for _, transport := range transports {
		err = errors.Join(err, transport.Close())
	}
	return err
}

func (s *Session) finishClose(handlers []*handlerEntry, notifyErr error) {
	s.abortTransactions(notifyErr)
	s.clearServerTransactions()
	s.notifyHandlersOnce(handlers, notifyErr)
}

func (s *Session) waitReadLoops() error {
	done := make(chan struct{})
	go func() {
		s.readWG.Wait()
		close(done)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return context.DeadlineExceeded
	}
}

func readTransportMessage(ctx context.Context, transport Transport) (inboundMessage, error) {
	for {
		packet, peer, err := transport.ReadPacket(ctx)
		if err != nil {
			return inboundMessage{}, err
		}
		if isKeepAlivePacket(packet) {
			return inboundMessage{packet: packet, transport: transport, peer: peer}, nil
		}
		msg, err := sip.ParseMessage(packet)
		if err != nil {
			if !transportIsReliable(transport) {
				partial, partialErr := sip.ParseMessagePartial(packet)
				if partialErr != nil && partial.StartLine != "" {
					return inboundMessage{msg: partial, parseErr: partialErr, transport: transport, peer: peer}, nil
				}
				continue
			}
			return inboundMessage{}, err
		}
		return inboundMessage{msg: msg, transport: transport, peer: peer}, nil
	}
}

func (s *Session) startBootstrapReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage) {
	go func() {
		runTransportReadLoop(ctx, transport, out, true)
	}()
}

func (s *Session) startReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage) {
	s.readWG.Go(func() {
		runTransportReadLoop(ctx, transport, out, false)
	})
}

func runTransportReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage, reportContextError bool) {
	for {
		inbound, err := readTransportMessage(ctx, transport)
		if err != nil {
			if ctx.Err() != nil && !reportContextError {
				return
			}
			_ = sendInbound(ctx, out, inboundMessage{transport: transport, err: err})
			return
		}
		if !sendInbound(ctx, out, inbound) {
			return
		}
	}
}

func sendInbound(ctx context.Context, out chan<- inboundMessage, inbound inboundMessage) bool {
	select {
	case out <- inbound:
		return true
	case <-ctx.Done():
		return false
	}
}

type Request struct {
	Message   sip.Message
	Transport Transport
	PeerAddr  net.Addr
}

type Handler interface {
	HandleRequest(ctx context.Context, req Request) (bool, error)
}

type ErrorHandler interface {
	HandleError(err error)
}

type ResponseHandler interface {
	HandleResponse(ctx context.Context, msg sip.Message) (bool, error)
}

func (s *Session) dispatchInbound(ctx context.Context, inbound inboundMessage) error {
	if len(inbound.packet) != 0 {
		return s.handleKeepAlivePacket(ctx, inbound)
	}
	if inbound.parseErr != nil {
		s.logger.Debug("dropping malformed SIP datagram", "start_line", inbound.msg.StartLine, "err", inbound.parseErr)
		if inbound.msg.IsRequest() && canRespondToRequest(inbound.msg) && !strings.EqualFold(inbound.msg.Method(), "ACK") {
			return s.WriteStatus(ctx, Request{Message: inbound.msg, Transport: inbound.transport, PeerAddr: inbound.peer}, sipStatusBadRequest, "Bad Request")
		}
		return nil
	}
	text, err := inbound.msg.MarshalText()
	if err != nil {
		s.logger.Debug("sip message", "direction", "recv", "start_line", inbound.msg.StartLine, "marshal_error", err)
	} else {
		s.logger.Debug("sip message", "direction", "recv", "start_line", inbound.msg.StartLine, "sip_message", string(text))
	}
	if inbound.msg.IsRequest() {
		return s.handleInboundRequest(ctx, Request{Message: inbound.msg, Transport: inbound.transport, PeerAddr: inbound.peer})
	}
	if err := validateInboundResponse(inbound.msg); err != nil {
		s.logger.Debug("dropping malformed SIP response", "start_line", inbound.msg.StartLine, "err", err)
		return nil
	}
	s.markTransportInbound(inbound.transport, inbound.msg)
	if !s.dispatchResponse(inbound) {
		return s.handleInboundResponse(ctx, inbound.msg)
	}
	return nil
}

func validateInboundRequest(msg sip.Message) error {
	validated := msg
	if strings.TrimSpace(validated.Header("Max-Forwards")) == "" {
		validated.Headers = validated.Headers.Clone()
		validated.Headers.Add("Max-Forwards", strconv.Itoa(sip.DefaultMaxForwards))
	}
	if err := validated.Validate(); err != nil {
		return fmt.Errorf("validating inbound SIP request: %w", err)
	}
	return validateTopViaSentBy(msg)
}

func validateInboundResponse(msg sip.Message) error {
	if err := msg.Validate(); err != nil {
		return fmt.Errorf("validating inbound SIP response: %w", err)
	}
	return validateTopViaSentBy(msg)
}

func validateTopViaSentBy(msg sip.Message) error {
	if strings.TrimSpace(sip.TopViaSentBy(msg.Header("Via"))) == "" {
		return errors.New("validating inbound SIP message: top Via is missing sent-by")
	}
	return nil
}

func validateInboundCoreFields(msg sip.Message) error {
	for _, name := range []string{"Via", "From", "To", "Call-ID", "CSeq"} {
		if strings.TrimSpace(msg.Header(name)) == "" {
			return fmt.Errorf("validating inbound SIP message: missing %s header", name)
		}
	}
	if strings.TrimSpace(sip.TopViaSentBy(msg.Header("Via"))) == "" {
		return errors.New("validating inbound SIP message: top Via is missing sent-by")
	}
	return nil
}

func canRespondToRequest(msg sip.Message) bool {
	return validateInboundCoreFields(msg) == nil
}

func (s *Session) handleRequest(ctx context.Context, req Request) error {
	handled, err := s.dispatchRequest(ctx, req)
	if err != nil {
		return err
	}
	if handled {
		return nil
	}
	if strings.EqualFold(req.Message.Method(), "OPTIONS") {
		resp := sip.NewResponse(sipStatusOK, "OK")
		resp.Headers = sip.ResponseHeaders(req.Message, sipStatusOK)
		resp.Headers.Add("Allow", sip.DefaultClientAllow)
		resp.Headers.Add("Supported", sip.DefaultClientSupported)
		return s.WriteResponse(ctx, req, resp)
	}
	if req.Message.Method() == "ACK" {
		return nil
	}
	if strings.EqualFold(req.Message.Method(), "BYE") {
		return s.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
	}
	resp := sip.NewResponse(sipStatusMethodNotAllowed, "Method Not Allowed")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusMethodNotAllowed)
	resp.Headers.Add("Allow", sip.DefaultClientAllow)
	return s.WriteResponse(ctx, req, resp)
}

func (s *Session) dispatchRequest(ctx context.Context, req Request) (bool, error) {
	for _, entry := range s.handlerSnapshot() {
		handler, ok := entry.handlerIfOpen()
		if !ok {
			continue
		}
		handled, err := handler.HandleRequest(ctx, req)
		if err != nil {
			return false, err
		}
		if handled {
			return true, nil
		}
	}
	return false, nil
}

func (s *Session) handleInboundResponse(ctx context.Context, msg sip.Message) error {
	for _, entry := range s.handlerSnapshot() {
		handler, ok := entry.handlerIfOpen()
		if !ok {
			continue
		}
		responseHandler, ok := handler.(ResponseHandler)
		if !ok {
			continue
		}
		handled, err := responseHandler.HandleResponse(ctx, msg)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
	}
	return nil
}

func isProvisionalResponse(msg sip.Message) bool {
	status := msg.StatusCode()
	return status >= 100 && status < 200
}

type ExchangeOptions struct {
	OnProvisional           func(sip.Message)
	AcceptResponseTransport func(Transport) bool
	ResponseTransports      []Transport
}

func (s *Session) Exchange(ctx context.Context, req sip.Message) (sip.Message, error) {
	return s.ExchangeWithOptions(ctx, req, ExchangeOptions{})
}

// PrimaryTransport returns the transport used for new client transactions.
func (s *Session) PrimaryTransport() Transport {
	return s.primaryTransport()
}

func (s *Session) ExchangeWithOptions(ctx context.Context, req sip.Message, opts ExchangeOptions) (sip.Message, error) {
	return s.ExchangeWithTransport(ctx, s.primaryTransport(), req, opts)
}

func (s *Session) ExchangeWithTransport(ctx context.Context, transport Transport, req sip.Message, opts ExchangeOptions) (sip.Message, error) {
	if err := s.ensureOpen(); err != nil {
		return sip.Message{}, fmt.Errorf("exchanging request: %w", err)
	}
	if err := s.ensureActiveTransport(transport); err != nil {
		return sip.Message{}, fmt.Errorf("exchanging request: %w", err)
	}
	for _, responseTransport := range opts.ResponseTransports {
		if err := s.ensureActiveTransport(responseTransport); err != nil {
			return sip.Message{}, fmt.Errorf("exchanging request: %w", err)
		}
	}
	tx := newClientTransaction(s, transport, req, opts)
	if !s.isRunning() {
		return s.exchangeWithBootstrapReader(ctx, tx)
	}
	if err := tx.start(ctx); err != nil {
		return sip.Message{}, err
	}
	return tx.await(ctx)
}

func (s *Session) exchangeWithBootstrapReader(ctx context.Context, tx *clientTransaction) (sip.Message, error) {
	if err := tx.start(ctx); err != nil {
		return sip.Message{}, err
	}

	readCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	readTransports := exchangeReadTransports(tx.transport, tx.opts.ResponseTransports)
	inboundCh := make(chan inboundMessage, len(readTransports))
	for _, transport := range readTransports {
		s.startBootstrapReadLoop(readCtx, transport, inboundCh)
	}

	resultCh := make(chan transactionResult, 1)
	go func() {
		msg, err := tx.await(ctx)
		resultCh <- transactionResult{msg: msg, err: err}
	}()

	for {
		select {
		case result := <-resultCh:
			if result.err != nil {
				return sip.Message{}, result.err
			}
			return result.msg, nil
		case inbound := <-inboundCh:
			if inbound.err != nil {
				if ctx.Err() != nil {
					tx.abort(ctx.Err())
					continue
				}
				err := fmt.Errorf("receiving %s response: %w", tx.method, inbound.err)
				tx.abort(err)
				return sip.Message{}, err
			}
			if err := s.dispatchInbound(readCtx, inbound); err != nil {
				tx.abort(err)
				return sip.Message{}, err
			}
		}
	}
}

func (s *Session) Send(ctx context.Context, req sip.Message) error {
	if err := s.ensureOpen(); err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	return s.writeRequest(ctx, s.primaryTransport(), req)
}

func (s *Session) writeRequest(ctx context.Context, transport Transport, req sip.Message) error {
	packet, err := messagePacket(req)
	if err != nil {
		return fmt.Errorf("encoding %s request: %w", req.Method(), err)
	}
	s.logger.Debug("sip message", "direction", "send", "start_line", req.StartLine, "sip_message", string(packet))
	if err := s.writePacket(ctx, transport, packet); err != nil {
		return fmt.Errorf("sending %s: %w", req.Method(), err)
	}
	return nil
}

func responseMatchesRequestTransaction(req, resp sip.Message) bool {
	if got, want := sip.PendingKey(resp), sip.PendingKey(req); want != "" && got != want {
		return false
	}
	if want := strings.TrimSpace(sip.TopViaSentBy(req.Header("Via"))); want != "" {
		got := strings.TrimSpace(sip.TopViaSentBy(resp.Header("Via")))
		return sameSIPSentBy(got, want)
	}
	return true
}

func sameSIPSentBy(left, right string) bool {
	if strings.EqualFold(left, right) {
		return true
	}
	leftAddr, leftErr := netip.ParseAddrPort(left)
	rightAddr, rightErr := netip.ParseAddrPort(right)
	return leftErr == nil && rightErr == nil && leftAddr == rightAddr
}

func canonicalSIPSentBy(sentBy string) string {
	if addr, err := netip.ParseAddrPort(sentBy); err == nil {
		return addr.String()
	}
	return strings.ToLower(sentBy)
}

func exchangeReadTransports(requestTransport Transport, responseTransports []Transport) []Transport {
	if len(responseTransports) == 0 {
		return []Transport{requestTransport}
	}
	return uniqueTransports(responseTransports)
}

type Transport interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	WritePacket(ctx context.Context, data []byte) error
	ReadPacket(ctx context.Context) ([]byte, net.Addr, error)
	Close() error
}

type keepAliveTransport interface {
	SupportsSIPKeepAlive() bool
}

type SecureTCPConfig struct {
	LocalPort     int
	RemotePort    int
	OutboundSPI   uint32
	InboundSPI    uint32
	Encryption    string
	EncryptionKey []byte
	Integrity     string
	IntegrityKey  []byte
	Mode          string
	Salt          [4]byte
}

type SecureUDPConfig struct {
	LocalPort     int
	RemotePort    int
	OutboundSPI   uint32
	InboundSPI    uint32
	Encryption    string
	EncryptionKey []byte
	Integrity     string
	IntegrityKey  []byte
	Mode          string
	Salt          [4]byte
}

type targetedPacketWriter interface {
	WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error
}

func (s *Session) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.primary.LocalAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.primary.RemoteAddr()
}

// SupportsKeepAlive reports whether the primary transport permits the SIP
// keep-alive mechanisms negotiated through RFC 6223.
func (s *Session) SupportsKeepAlive() bool {
	transport := s.primaryTransport()
	capability, ok := transport.(keepAliveTransport)
	return !ok || capability.SupportsSIPKeepAlive()
}

func (s *Session) WaitTransportsIdle(ctx context.Context, transports ...Transport) error {
	watched, err := transportSet(transports)
	if err != nil {
		return err
	}
	if len(watched) == 0 {
		return nil
	}
	for {
		s.mu.Lock()
		if s.transportsIdle(watched) {
			s.mu.Unlock()
			return nil
		}
		if s.closed {
			s.mu.Unlock()
			return errors.New("waiting for transport transactions: session is closed")
		}
		changed := s.txChanged
		closed := s.closedCh
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-closed:
			return errors.New("waiting for transport transactions: session is closed")
		case <-changed:
		}
	}
}

type InboundWatch struct {
	session    *Session
	transports map[Transport]struct{}
	excluded   string
	done       chan struct{}
}

// WatchTransportsInbound snapshots the supplied transports so a later Wait
// observes messages arriving immediately after this call.
func (s *Session) WatchTransportsInbound(transports ...Transport) (*InboundWatch, error) {
	return s.watchTransportsInbound("", transports...)
}

// WatchTransportsInboundExcept ignores retransmissions of excluded while
// waiting for a later SIP message.
func (s *Session) WatchTransportsInboundExcept(excluded sip.Message, transports ...Transport) (*InboundWatch, error) {
	return s.watchTransportsInbound(inboundMessageKey(excluded), transports...)
}

func (s *Session) watchTransportsInbound(excluded string, transports ...Transport) (*InboundWatch, error) {
	watched, err := transportSet(transports)
	if err != nil {
		return nil, err
	}
	if len(watched) == 0 {
		return nil, errors.New("watching inbound transport message: no transports")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("watching inbound transport message: session is closed")
	}
	watch := &InboundWatch{
		session:    s,
		transports: watched,
		excluded:   excluded,
		done:       make(chan struct{}),
	}
	s.inboundWatches[watch] = struct{}{}
	return watch, nil
}

func (w *InboundWatch) Wait(ctx context.Context) error {
	s := w.session
	select {
	case <-ctx.Done():
		s.removeInboundWatch(w)
		return ctx.Err()
	case <-s.closedCh:
		s.removeInboundWatch(w)
		return errors.New("waiting for inbound transport message: session is closed")
	case <-w.done:
		return nil
	}
}

func (w *InboundWatch) Close() {
	w.session.removeInboundWatch(w)
}

// WaitTransportsInbound waits for the next valid SIP message received after
// this call on one of the supplied transports.
func (s *Session) WaitTransportsInbound(ctx context.Context, transports ...Transport) error {
	watch, err := s.WatchTransportsInbound(transports...)
	if err != nil {
		return err
	}
	return watch.Wait(ctx)
}

func (s *Session) markTransportInbound(transport Transport, msg sip.Message) {
	key := inboundMessageKey(msg)
	s.mu.Lock()
	for watch := range s.inboundWatches {
		if _, ok := watch.transports[transport]; !ok || key == watch.excluded {
			continue
		}
		delete(s.inboundWatches, watch)
		close(watch.done)
	}
	s.mu.Unlock()
}

func (s *Session) removeInboundWatch(watch *InboundWatch) {
	s.mu.Lock()
	delete(s.inboundWatches, watch)
	s.mu.Unlock()
}

func inboundMessageKey(msg sip.Message) string {
	if msg.StartLine == "" || msg.Header("Call-ID") == "" || msg.Header("CSeq") == "" {
		return ""
	}
	return strings.Join([]string{
		msg.Header("Call-ID"),
		msg.Header("CSeq"),
		sip.HeaderParam(msg.Header("Via"), "branch"),
	}, "\x00")
}

func (s *Session) ensureOpen() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("session is closed")
	}
	return nil
}

func (s *Session) ensureActiveTransport(transport Transport) error {
	if transport == nil {
		return errors.New("transport is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.active[transport]; !ok {
		return errors.New("transport is not active")
	}
	return nil
}

func (s *Session) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Session) primaryTransport() Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.primary
}

func (s *Session) isTransportActive(transport Transport) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.active[transport]
	return ok
}

func (s *Session) removeFailedAuxTransport(transport Transport) bool {
	s.mu.Lock()
	if s.closed || transport == s.primary {
		s.mu.Unlock()
		return false
	}
	if _, ok := s.active[transport]; !ok {
		s.mu.Unlock()
		return true
	}
	delete(s.active, transport)
	s.removeResponseRoutesFor(transport)
	s.aux = removeTransport(s.aux, transport)
	s.notifyTransactionsChanged()
	s.mu.Unlock()
	s.abortTransportKeepAlives(transport, errors.New("waiting for keepalive: transport failed"))
	_ = transport.Close()
	return true
}

func (s *Session) transportsIdle(transports map[Transport]struct{}) bool {
	for _, tx := range s.transactions {
		if _, ok := transports[tx.transport]; ok {
			return false
		}
	}
	for _, tx := range s.serverTxs {
		if _, ok := transports[tx.transport]; ok {
			return false
		}
	}
	return true
}

func (s *Session) notifyTransactionsChanged() {
	close(s.txChanged)
	s.txChanged = make(chan struct{})
}

func transportSet(transports []Transport) (map[Transport]struct{}, error) {
	set := make(map[Transport]struct{}, len(transports))
	for _, transport := range transports {
		if transport == nil {
			return nil, errors.New("waiting for transport transactions: transport is nil")
		}
		set[transport] = struct{}{}
	}
	return set, nil
}

func removeTransport(transports []Transport, target Transport) []Transport {
	next := transports[:0]
	for _, transport := range transports {
		if transport == target {
			continue
		}
		next = append(next, transport)
	}
	return next
}

func uniqueTransports(transports []Transport) []Transport {
	seen := make(map[Transport]struct{}, len(transports))
	unique := make([]Transport, 0, len(transports))
	for _, transport := range transports {
		if _, ok := seen[transport]; ok {
			continue
		}
		seen[transport] = struct{}{}
		unique = append(unique, transport)
	}
	return unique
}

func (s *Session) WriteResponse(ctx context.Context, req Request, resp sip.Message) error {
	if err := s.ensureOpen(); err != nil {
		return fmt.Errorf("writing response: %w", err)
	}
	s.applyResponseDecorator(&resp)
	sip.SetResponseViaPeer(&resp, req.PeerAddr)
	// Record the response before writing it so the INVITE transaction's
	// automatic 100 Trying timer cannot race a response already in flight.
	tx := s.recordServerTransactionResponse(req, resp)
	if err := s.writeResponse(ctx, req.Transport, req.PeerAddr, req.Message, resp); err != nil {
		if tx != nil {
			tx.terminate()
		}
		return err
	}
	return nil
}

func (s *Session) WriteStatus(ctx context.Context, req Request, code int, reason string) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	return s.WriteResponse(ctx, req, resp)
}

func (s *Session) SetResponseDecorator(fn func(*sip.Message)) {
	s.mu.Lock()
	s.responseDecorator = fn
	s.mu.Unlock()
}

func (s *Session) applyResponseDecorator(resp *sip.Message) {
	s.mu.Lock()
	fn := s.responseDecorator
	s.mu.Unlock()
	if fn == nil {
		fn = s.cfg.ResponseDecorator
	}
	if fn != nil {
		fn(resp)
	}
}

func (s *Session) writePacket(ctx context.Context, transport Transport, data []byte) error {
	return s.writePacketTo(ctx, transport, data, nil)
}

func (s *Session) writePacketTo(ctx context.Context, transport Transport, data []byte, addr net.Addr) error {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if s.sendMu.TryLock() {
			defer s.sendMu.Unlock()
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	if addr == nil {
		return transport.WritePacket(ctx, data)
	}
	writer, ok := transport.(targetedPacketWriter)
	if !ok {
		return transport.WritePacket(ctx, data)
	}
	return writer.WritePacketTo(ctx, data, addr)
}

func (s *Session) writeResponse(ctx context.Context, transport Transport, peer net.Addr, req sip.Message, resp sip.Message) error {
	data, err := messagePacket(resp)
	if err != nil {
		return fmt.Errorf("encoding %d response: %w", resp.StatusCode(), err)
	}
	remote := peer
	if remote == nil {
		remote = transport.RemoteAddr()
	}
	target := responseDestination(remote, resp.Header("Via"))
	if peer != nil {
		transport = s.responseTransport(transport, target)
	}
	s.logger.Debug("sip message", "direction", "send", "start_line", resp.StartLine, "sip_message", string(data), "target_addr", target)
	return s.writePacketTo(ctx, transport, data, target)
}

func (s *Session) responseTransport(fallback Transport, target net.Addr) Transport {
	if fallback != nil {
		s.mu.Lock()
		routed := s.responseRoutes[fallback]
		_, active := s.active[routed]
		s.mu.Unlock()
		if active && (target == nil || sameAddr(routed.RemoteAddr(), target)) {
			return routed
		}
	}
	if target == nil {
		return fallback
	}
	if fallback != nil && sameAddr(fallback.RemoteAddr(), target) {
		return fallback
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for transport := range s.active {
		if sameAddr(transport.RemoteAddr(), target) {
			return transport
		}
	}
	return fallback
}

func sameAddr(left, right net.Addr) bool {
	if left == nil || right == nil {
		return left == right
	}
	return left.Network() == right.Network() && left.String() == right.String()
}

func messagePacket(msg sip.Message) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := msg.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func responseDestination(remote net.Addr, via string) net.Addr {
	udpRemote, ok := remote.(*net.UDPAddr)
	if !ok || udpRemote == nil {
		return nil
	}
	target := &net.UDPAddr{IP: append(net.IP(nil), udpRemote.IP...), Port: topViaResponsePort(via, udpRemote.Port), Zone: udpRemote.Zone}
	if received := sip.TopViaReceived(via); received != "" {
		if ip := net.ParseIP(stripHostBrackets(received)); ip != nil {
			target.IP = ip
		}
		return target
	}
	if host := topViaSentByHost(via); host != "" {
		if ip := net.ParseIP(stripHostBrackets(host)); ip != nil {
			target.IP = ip
		}
	}
	return target
}

func (s *Session) dispatchResponse(inbound inboundMessage) bool {
	key := sip.PendingKey(inbound.msg)
	s.mu.Lock()
	tx, ok := s.transactions[key]
	s.mu.Unlock()
	if !ok {
		return false
	}
	if !tx.acceptsResponse(inbound.msg) {
		return true
	}
	tx.handleResponse(inbound)
	return true
}

func topViaResponsePort(via string, remotePort int) int {
	if rport := sip.TopViaRPort(via); rport != "" {
		if port, err := strconv.Atoi(rport); err == nil && port > 0 {
			return port
		}
	}
	if sip.TopViaHasRPort(via) && remotePort > 0 {
		return remotePort
	}
	sentBy := sip.TopViaSentBy(via)
	if sentBy == "" {
		return 5060
	}
	_, portText, err := net.SplitHostPort(sentBy)
	if err != nil {
		return 5060
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port <= 0 {
		return 5060
	}
	return port
}

func topViaSentByHost(via string) string {
	sentBy := sip.TopViaSentBy(via)
	if sentBy == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(sentBy)
	if err == nil {
		return host
	}
	return strings.TrimSpace(strings.Trim(sentBy, "[]"))
}

func stripHostBrackets(host string) string {
	host = strings.TrimPrefix(host, "[")
	return strings.TrimSuffix(host, "]")
}

var sipCRLFKeepAlive = []byte("\r\n\r\n")

func (s *Session) SendKeepAlive(ctx context.Context) error {
	if err := s.ensureOpen(); err != nil {
		return fmt.Errorf("sending SIP keepalive: %w", err)
	}
	if !s.SupportsKeepAlive() {
		return errors.New("sending SIP keepalive: primary transport disables SIP keepalive")
	}
	transport := s.primaryTransport()
	switch transport.LocalAddr().(type) {
	case *net.TCPAddr:
		return s.sendCRLFKeepAlive(ctx, transport)
	default:
		return s.sendSTUNBindingRequest(ctx, transport)
	}
}

func isKeepAlivePacket(packet []byte) bool {
	return isCRLFKeepAlivePacket(packet) || isSTUNPacket(packet)
}

func isCRLFKeepAlivePacket(packet []byte) bool {
	return bytes.Equal(packet, []byte("\r\n")) || bytes.Equal(packet, sipCRLFKeepAlive)
}

func isSTUNPacket(packet []byte) bool {
	if len(packet) < stunHeaderBytes {
		return false
	}
	if packet[0]&0xc0 != 0 {
		return false
	}
	if binary.BigEndian.Uint32(packet[4:8]) != stunMagicCookie {
		return false
	}
	length := int(binary.BigEndian.Uint16(packet[2:4]))
	return length%4 == 0 && stunHeaderBytes+length == len(packet)
}
