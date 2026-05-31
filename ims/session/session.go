package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

type Transport interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	WritePacket(ctx context.Context, data []byte) error
	ReadPacket(ctx context.Context) ([]byte, net.Addr, error)
	Close() error
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
}

type SecureUDPConfig = SecureTCPConfig

type Config struct {
	Transport         string
	Logger            *slog.Logger
	TransactionTimers TransactionTimers
	ResponseDecorator func(*sip.Message)
}

type Request struct {
	Message   sip.Message
	Transport Transport
}

const (
	sipStatusOK                          = 200
	sipStatusTrying                      = 100
	sipStatusMethodNotAllowed            = 405
	sipStatusCallTransactionDoesNotExist = 481
	sipStatusRequestTerminated           = 487
)

type Handler interface {
	HandleRequest(ctx context.Context, req Request) (bool, error)
	HandleError(err error)
}

type ResponseHandler interface {
	HandleResponse(ctx context.Context, msg sip.Message) (bool, error)
}

type ExchangeOptions struct {
	OnProvisional           func(sip.Message)
	AcceptResponseTransport func(Transport) bool
	ResponseTransports      []Transport
}

type Attachment interface {
	Close() error
}

type TransportAttachment interface {
	Attachment
	Transport() Transport
}

type Session struct {
	cfg    Config
	logger *slog.Logger

	mu           sync.Mutex
	sendMu       sync.Mutex
	readWG       sync.WaitGroup
	primary      Transport
	aux          []Transport
	active       map[Transport]struct{}
	runCtx       context.Context
	inboundCh    chan<- inboundMessage
	dialogs      map[string][]*dialogEntry
	transactions map[string]*clientTransaction
	serverTxs    map[string]*serverTransaction
	txChanged    chan struct{}
	handlers     []*handlerEntry
	startedCh    chan struct{}
	closedCh     chan struct{}
	closed       bool
	started      bool
	ready        bool
	running      bool

	responseDecorator func(*sip.Message)
	notifyOnce        sync.Once
}

type handlerEntry struct {
	session *Session
	handler Handler
	closed  bool
}

type transportAttachment struct {
	session   *Session
	transport Transport
	closed    bool
}

type inboundMessage struct {
	msg       sip.Message
	transport Transport
	err       error
}

type targetedPacketWriter interface {
	WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error
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
		cfg:          cfg,
		logger:       cfg.Logger.With("component", "ims-session"),
		primary:      primary,
		active:       map[Transport]struct{}{primary: {}},
		dialogs:      make(map[string][]*dialogEntry),
		transactions: make(map[string]*clientTransaction),
		serverTxs:    make(map[string]*serverTransaction),
		txChanged:    make(chan struct{}),
		startedCh:    make(chan struct{}),
		closedCh:     make(chan struct{}),
	}, nil
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

func (s *Session) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.primary == nil {
		return nil
	}
	return s.primary.LocalAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.primary == nil {
		return nil
	}
	return s.primary.RemoteAddr()
}

func (s *Session) TransactionTimers() TransactionTimers {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.TransactionTimers
}

func (s *Session) WaitTransportsIdle(ctx context.Context, transports ...Transport) error {
	watched := transportSet(transports)
	if len(watched) == 0 {
		return nil
	}
	for {
		s.mu.Lock()
		if s.transportsIdleLocked(watched) {
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

func (s *Session) Attach(h Handler) (Attachment, error) {
	if h == nil {
		return nil, errors.New("attaching handler: handler is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("attaching handler: session is closed")
	}
	entry := &handlerEntry{session: s, handler: h}
	s.handlers = append(s.handlers, entry)
	return entry, nil
}

func (s *Session) AddTransport(t Transport) (Attachment, error) {
	if t == nil {
		return nil, errors.New("adding transport: transport is nil")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("adding transport: session is closed")
	}
	if s.started && !s.running {
		s.mu.Unlock()
		return nil, errors.New("adding transport: session has stopped")
	}
	s.aux = append(s.aux, t)
	s.active[t] = struct{}{}
	runCtx := s.runCtx
	inboundCh := s.inboundCh
	running := s.running
	s.mu.Unlock()

	if running {
		s.startReadLoop(runCtx, t, inboundCh)
	}
	return &transportAttachment{session: s, transport: t}, nil
}

func (s *Session) ReplacePrimary(t Transport) error {
	if t == nil {
		return errors.New("replacing primary transport: transport is nil")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("replacing primary transport: session is closed")
	}
	if s.started {
		s.mu.Unlock()
		return errors.New("replacing primary transport: session has already started")
	}
	old := s.primary
	s.primary = t
	delete(s.active, old)
	s.active[t] = struct{}{}
	s.mu.Unlock()
	if old != nil && old != t {
		if err := old.Close(); err != nil {
			return fmt.Errorf("replacing primary transport: %w", err)
		}
	}
	return nil
}

func (s *Session) PromotePrimary(t Transport) (Attachment, error) {
	if t == nil {
		return nil, errors.New("promoting primary transport: transport is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("promoting primary transport: session is closed")
	}
	if s.started && !s.running {
		return nil, errors.New("promoting primary transport: session has stopped")
	}
	if _, ok := s.active[t]; !ok {
		return nil, errors.New("promoting primary transport: transport is not active")
	}
	old := s.primary
	if old == t {
		return nil, nil
	}
	s.primary = t
	s.aux = removeTransport(s.aux, t)
	if old != nil {
		s.aux = append(s.aux, old)
	}
	return &transportAttachment{session: s, transport: old}, nil
}

func (s *Session) Exchange(ctx context.Context, req sip.Message) (sip.Message, error) {
	return s.ExchangeWithOptions(ctx, req, ExchangeOptions{})
}

func (s *Session) ExchangeWithOptions(ctx context.Context, req sip.Message, opts ExchangeOptions) (sip.Message, error) {
	return s.ExchangeWithTransport(ctx, s.primaryTransport(), req, opts)
}

func (s *Session) ExchangeWithTransport(ctx context.Context, transport Transport, req sip.Message, opts ExchangeOptions) (sip.Message, error) {
	if err := s.ensureOpen("exchanging request"); err != nil {
		return sip.Message{}, err
	}
	if err := s.ensureActiveTransport("exchanging request", transport); err != nil {
		return sip.Message{}, err
	}
	for _, responseTransport := range opts.ResponseTransports {
		if err := s.ensureActiveTransport("exchanging request", responseTransport); err != nil {
			return sip.Message{}, err
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
			if err := s.dispatchBootstrapInbound(readCtx, inbound); err != nil {
				tx.abort(err)
				return sip.Message{}, err
			}
		}
	}
}

func (s *Session) Send(ctx context.Context, req sip.Message) error {
	if err := s.ensureOpen("sending request"); err != nil {
		return err
	}
	return s.writeRequest(ctx, s.primaryTransport(), req)
}

func (s *Session) WriteResponse(ctx context.Context, req Request, resp sip.Message) error {
	if err := s.ensureOpen("writing response"); err != nil {
		return err
	}
	s.applyResponseDecorator(&resp)
	if err := s.writeResponse(ctx, req.Transport, req.Message, resp); err != nil {
		return err
	}
	s.recordServerTransactionResponse(req, resp)
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
	s.runCtx = ctx
	s.inboundCh = inboundCh
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
		case inbound := <-inboundCh:
			if inbound.err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				if inbound.transport != nil && !s.isTransportActive(inbound.transport) {
					continue
				}
				if inbound.transport != nil && s.removeFailedAuxTransport(inbound.transport) {
					s.logger.Warn("removed failed auxiliary SIP transport", "local_addr", inbound.transport.LocalAddr(), "err", inbound.err)
					s.abortTransportTransactions(inbound.transport, inbound.err)
					continue
				}
				return inbound.err
			}
			s.logger.Debug("sip message", "direction", "recv", "start_line", inbound.msg.StartLine, "sip_message", string(inbound.msg.Bytes()))
			if inbound.msg.IsRequest() {
				if err := s.handleInboundRequest(ctx, Request{Message: inbound.msg, Transport: inbound.transport}); err != nil {
					return err
				}
				continue
			}
			if !s.dispatchResponse(inbound) {
				if err := s.handleInboundResponse(ctx, inbound.msg); err != nil {
					return err
				}
			}
		}
	}
}

func (s *Session) handleInboundRequest(ctx context.Context, req Request) error {
	handled, err := s.processServerTransaction(ctx, req)
	if handled || err != nil {
		return err
	}
	return s.handleRequest(ctx, req)
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

func (s *Session) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.CloseContext(ctx)
}

func (s *Session) CloseContext(ctx context.Context) error {
	var closeErr error
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	primary := s.primary
	aux := append([]Transport(nil), s.aux...)
	transports := uniqueTransports(append(aux, primary))
	handlers := s.handlerSnapshotLocked()
	closedCh := s.closedCh
	s.active = make(map[Transport]struct{})
	s.mu.Unlock()
	close(closedCh)

	for _, transport := range transports {
		closeErr = errors.Join(closeErr, transport.Close())
	}
	notifyErr := closeErr
	if notifyErr == nil {
		notifyErr = errors.New("session is closed")
	}
	s.abortTransactions(notifyErr)
	s.clearServerTransactions()
	s.notifyHandlersOnce(handlers, notifyErr)

	done := make(chan struct{})
	go func() {
		s.readWG.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		closeErr = errors.Join(closeErr, ctx.Err())
	}
	return closeErr
}

func (s *Session) ensureOpen(action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%s: session is closed", action)
	}
	if s.primary == nil {
		return fmt.Errorf("%s: primary transport is nil", action)
	}
	return nil
}

func (s *Session) ensureActiveTransport(action string, transport Transport) error {
	if transport == nil {
		return fmt.Errorf("%s: transport is nil", action)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.active[transport]; !ok {
		return fmt.Errorf("%s: transport is not active", action)
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
		return strings.EqualFold(got, want)
	}
	return true
}

func readTransportMessage(ctx context.Context, transport Transport) (inboundMessage, error) {
	packet, _, err := transport.ReadPacket(ctx)
	if err != nil {
		return inboundMessage{}, err
	}
	msg, err := sip.ParseMessage(packet)
	if err != nil {
		return inboundMessage{}, err
	}
	return inboundMessage{msg: msg, transport: transport}, nil
}

func exchangeReadTransports(requestTransport Transport, responseTransports []Transport) []Transport {
	if len(responseTransports) == 0 {
		return []Transport{requestTransport}
	}
	return uniqueTransports(responseTransports)
}

func (s *Session) startBootstrapReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage) {
	go func() {
		for {
			inbound, err := readTransportMessage(ctx, transport)
			if err != nil {
				inbound = inboundMessage{transport: transport, err: err}
			}
			select {
			case out <- inbound:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
}

func (s *Session) dispatchBootstrapInbound(ctx context.Context, inbound inboundMessage) error {
	s.logger.Debug("sip message", "direction", "recv", "start_line", inbound.msg.StartLine, "sip_message", string(inbound.msg.Bytes()))
	if inbound.msg.IsRequest() {
		return s.handleInboundRequest(ctx, Request{Message: inbound.msg, Transport: inbound.transport})
	}
	if !s.dispatchResponse(inbound) {
		return s.handleInboundResponse(ctx, inbound.msg)
	}
	return nil
}

func (s *Session) startReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage) {
	s.readWG.Add(1)
	go func() {
		defer s.readWG.Done()
		for {
			inbound, err := readTransportMessage(ctx, transport)
			if err != nil {
				select {
				case out <- inboundMessage{transport: transport, err: err}:
				case <-ctx.Done():
				}
				return
			}
			select {
			case out <- inbound:
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (s *Session) handleRequest(ctx context.Context, req Request) error {
	handled, err := s.dispatchRequest(ctx, req)
	if err != nil {
		return err
	}
	if handled {
		return nil
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
		if entry.closed {
			continue
		}
		handled, err := entry.handler.HandleRequest(ctx, req)
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
		if entry.closed {
			continue
		}
		handler, ok := entry.handler.(ResponseHandler)
		if !ok {
			continue
		}
		handled, err := handler.HandleResponse(ctx, msg)
		if err != nil {
			return err
		}
		if handled {
			return nil
		}
	}
	return nil
}

func (s *Session) writePacket(ctx context.Context, transport Transport, data []byte) error {
	return s.writePacketTo(ctx, transport, data, nil)
}

func (s *Session) writePacketTo(ctx context.Context, transport Transport, data []byte, addr net.Addr) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if addr == nil {
		return transport.WritePacket(ctx, data)
	}
	writer, ok := transport.(targetedPacketWriter)
	if !ok {
		return transport.WritePacket(ctx, data)
	}
	return writer.WritePacketTo(ctx, data, addr)
}

func (s *Session) writeResponse(ctx context.Context, transport Transport, req sip.Message, resp sip.Message) error {
	data, err := messagePacket(resp)
	if err != nil {
		return fmt.Errorf("encoding %d response: %w", resp.StatusCode(), err)
	}
	target := responseDestination(transport.RemoteAddr(), req.Header("Via"))
	s.logger.Debug("sip message", "direction", "send", "start_line", resp.StartLine, "sip_message", string(data), "target_addr", target)
	return s.writePacketTo(ctx, transport, data, target)
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

func (s *Session) handlerSnapshot() []*handlerEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.handlerSnapshotLocked()
}

func (s *Session) handlerSnapshotLocked() []*handlerEntry {
	snapshot := make([]*handlerEntry, 0, len(s.handlers))
	for _, entry := range s.handlers {
		if entry.closed {
			continue
		}
		snapshot = append(snapshot, entry)
	}
	return snapshot
}

func (s *Session) notifyHandlersOnce(handlers []*handlerEntry, err error) {
	s.notifyOnce.Do(func() {
		for _, entry := range handlers {
			if entry.closed {
				continue
			}
			entry.handler.HandleError(err)
		}
	})
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
	s.runCtx = nil
	s.inboundCh = nil
	s.mu.Unlock()
}

func (s *Session) isTransportActive(transport Transport) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.active[transport]
	return ok
}

func (s *Session) removeFailedAuxTransport(transport Transport) bool {
	s.mu.Lock()
	if s.closed || transport == nil || transport == s.primary {
		s.mu.Unlock()
		return false
	}
	if _, ok := s.active[transport]; !ok {
		s.mu.Unlock()
		return true
	}
	delete(s.active, transport)
	s.aux = removeTransport(s.aux, transport)
	s.notifyTransactionsChangedLocked()
	s.mu.Unlock()
	_ = transport.Close()
	return true
}

func (s *Session) transportsIdleLocked(transports map[Transport]struct{}) bool {
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

func (s *Session) notifyTransactionsChangedLocked() {
	close(s.txChanged)
	s.txChanged = make(chan struct{})
}

func transportSet(transports []Transport) map[Transport]struct{} {
	set := make(map[Transport]struct{}, len(transports))
	for _, transport := range transports {
		if transport != nil {
			set[transport] = struct{}{}
		}
	}
	return set
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
		if transport == nil {
			continue
		}
		if _, ok := seen[transport]; ok {
			continue
		}
		seen[transport] = struct{}{}
		unique = append(unique, transport)
	}
	return unique
}

func isProvisionalResponse(msg sip.Message) bool {
	status := msg.StatusCode()
	return status >= 100 && status < 200
}

func (a *handlerEntry) Close() error {
	a.session.mu.Lock()
	defer a.session.mu.Unlock()
	a.closed = true
	return nil
}

func (a *transportAttachment) Close() error {
	a.session.mu.Lock()
	if a.closed {
		a.session.mu.Unlock()
		return nil
	}
	a.closed = true
	delete(a.session.active, a.transport)
	a.session.aux = removeTransport(a.session.aux, a.transport)
	a.session.mu.Unlock()
	return a.transport.Close()
}

func (a *transportAttachment) Transport() Transport {
	return a.transport
}
