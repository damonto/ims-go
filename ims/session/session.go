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

type Handler interface {
	HandleRequest(ctx context.Context, req Request) (bool, error)
	HandleError(err error)
}

type ResponseHandler interface {
	HandleResponse(ctx context.Context, msg sip.Message) (bool, error)
}

type ExchangeOptions struct {
	OnProvisional func(sip.Message)
}

type Attachment interface {
	Close() error
}

type Session struct {
	cfg    Config
	logger *slog.Logger

	mu           sync.Mutex
	sendMu       sync.Mutex
	readWG       sync.WaitGroup
	primary      Transport
	aux          []Transport
	dialogs      map[string][]*dialogEntry
	transactions map[string]*clientTransaction
	serverTxs    map[string]*serverTransaction
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
		dialogs:      make(map[string][]*dialogEntry),
		transactions: make(map[string]*clientTransaction),
		serverTxs:    make(map[string]*serverTransaction),
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
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("adding transport: session is closed")
	}
	if s.started {
		return nil, errors.New("adding transport: session has already started")
	}
	s.aux = append(s.aux, t)
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
	s.mu.Unlock()
	if old != nil && old != t {
		if err := old.Close(); err != nil {
			return fmt.Errorf("replacing primary transport: %w", err)
		}
	}
	return nil
}

func (s *Session) Exchange(ctx context.Context, req sip.Message) (sip.Message, error) {
	return s.ExchangeWithOptions(ctx, req, ExchangeOptions{})
}

func (s *Session) ExchangeWithOptions(ctx context.Context, req sip.Message, opts ExchangeOptions) (sip.Message, error) {
	if err := s.ensureOpen("exchanging request"); err != nil {
		return sip.Message{}, err
	}
	if !s.isRunning() {
		if err := s.writeRequest(ctx, s.primaryTransport(), req); err != nil {
			return sip.Message{}, err
		}
		resp, err := s.readFinalTransportResponse(ctx, s.primaryTransport(), opts)
		if err != nil {
			return sip.Message{}, fmt.Errorf("receiving %s response: %w", req.Method(), err)
		}
		return resp, nil
	}
	tx := newClientTransaction(s, s.primaryTransport(), req, opts)
	if err := tx.start(ctx); err != nil {
		return sip.Message{}, err
	}
	return tx.await(ctx)
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
	s.mu.Unlock()
	defer s.setRunning(false)

	inboundCh := make(chan inboundMessage, 16)
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
				return inbound.err
			}
			s.logger.Debug("sip message", "direction", "recv", "start_line", inbound.msg.StartLine, "sip_message", string(inbound.msg.Bytes()))
			if inbound.msg.IsRequest() {
				if err := s.handleInboundRequest(ctx, Request{Message: inbound.msg, Transport: inbound.transport}); err != nil {
					return err
				}
				continue
			}
			if !s.dispatchResponse(inbound.msg) {
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
	handlers := s.handlerSnapshotLocked()
	closedCh := s.closedCh
	s.mu.Unlock()
	close(closedCh)

	if primary != nil {
		closeErr = errors.Join(closeErr, primary.Close())
	}
	for _, transport := range aux {
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

func (s *Session) readFinalTransportResponse(ctx context.Context, transport Transport, opts ExchangeOptions) (sip.Message, error) {
	for {
		inbound, err := readTransportMessage(ctx, transport)
		if err != nil {
			return sip.Message{}, err
		}
		if inbound.msg.IsRequest() {
			continue
		}
		s.logger.Debug("sip message", "direction", "recv", "start_line", inbound.msg.StartLine, "sip_message", string(inbound.msg.Bytes()))
		if isProvisionalResponse(inbound.msg) {
			if opts.OnProvisional != nil {
				opts.OnProvisional(inbound.msg)
			}
			continue
		}
		return inbound.msg, nil
	}
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

func (s *Session) startReadLoop(ctx context.Context, transport Transport, out chan<- inboundMessage) {
	s.readWG.Add(1)
	go func() {
		defer s.readWG.Done()
		for {
			inbound, err := readTransportMessage(ctx, transport)
			if err != nil {
				select {
				case out <- inboundMessage{err: err}:
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
		return s.WriteStatus(ctx, req, 481, "Call/Transaction Does Not Exist")
	}
	return s.WriteStatus(ctx, req, 405, "Method Not Allowed")
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
	return s.writePacketTo(ctx, transport, data, responseDestination(transport.RemoteAddr(), req.Header("Via")))
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

func (s *Session) dispatchResponse(msg sip.Message) bool {
	key := sip.PendingKey(msg)
	s.mu.Lock()
	tx, ok := s.transactions[key]
	s.mu.Unlock()
	if !ok {
		return false
	}
	tx.handleResponse(msg)
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

func (s *Session) setRunning(running bool) {
	s.mu.Lock()
	s.running = running
	s.mu.Unlock()
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
	defer a.session.mu.Unlock()
	if a.closed {
		return nil
	}
	if a.session.started {
		return errors.New("closing transport attachment: session has already started")
	}
	a.closed = true
	filtered := a.session.aux[:0]
	for _, transport := range a.session.aux {
		if transport == a.transport {
			continue
		}
		filtered = append(filtered, transport)
	}
	a.session.aux = filtered
	return a.transport.Close()
}
