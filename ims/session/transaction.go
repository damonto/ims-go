package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

type TransactionTimers struct {
	T1 time.Duration
	T2 time.Duration
	T4 time.Duration
	TB time.Duration
	TD time.Duration
	TF time.Duration
	TH time.Duration
	TJ time.Duration
}

type clientTransaction struct {
	session   *Session
	transport Transport
	request   sip.Message
	key       string
	method    string
	reliable  bool
	timers    TransactionTimers

	responseCh chan inboundMessage
	resultCh   chan transactionResult
	cancelCh   chan struct{}

	cancelOnce sync.Once
	opts       ExchangeOptions
}

type clientTransactionState uint8

const (
	clientTransactionCalling clientTransactionState = iota
	clientTransactionTrying
	clientTransactionProceeding
	clientTransactionCompleted
	clientTransactionTerminated
)

type transactionResult struct {
	msg sip.Message
	err error
}

type TransactionTimeoutError struct {
	Method string
	Timer  string
}

func (e *TransactionTimeoutError) Error() string {
	return fmt.Sprintf("waiting for %s response: transaction timeout", e.Method)
}

func TransactionTimerExpired(err error, timer string) bool {
	var timeout *TransactionTimeoutError
	if !errors.As(err, &timeout) {
		return false
	}
	return strings.EqualFold(timeout.Timer, timer)
}

type transactionSendError struct {
	err      error
	reliable bool
}

func (e *transactionSendError) Error() string {
	return e.err.Error()
}

func (e *transactionSendError) Unwrap() error {
	return e.err
}

var defaultTransactionTimers = TransactionTimers{
	T1: 500 * time.Millisecond,
	T2: 4 * time.Second,
	T4: 5 * time.Second,
	TB: 32 * time.Second,
	TD: 32 * time.Second,
	TF: 32 * time.Second,
	TH: 32 * time.Second,
	TJ: 32 * time.Second,
}

func DefaultTransactionTimers() TransactionTimers {
	return defaultTransactionTimers
}

func (timers TransactionTimers) Normalized() (TransactionTimers, error) {
	if timers.T1 < 0 {
		return TransactionTimers{}, errors.New("normalizing transaction timers: T1 must be >= 0")
	}
	if timers.T2 < 0 {
		return TransactionTimers{}, errors.New("normalizing transaction timers: T2 must be >= 0")
	}
	if timers.T4 < 0 {
		return TransactionTimers{}, errors.New("normalizing transaction timers: T4 must be >= 0")
	}
	if timers.TB < 0 {
		return TransactionTimers{}, errors.New("normalizing transaction timers: Timer B must be >= 0")
	}
	if timers.TD < 0 {
		return TransactionTimers{}, errors.New("normalizing transaction timers: Timer D must be >= 0")
	}
	if timers.TF < 0 {
		return TransactionTimers{}, errors.New("normalizing transaction timers: Timer F must be >= 0")
	}
	if timers.TH < 0 {
		return TransactionTimers{}, errors.New("normalizing transaction timers: Timer H must be >= 0")
	}
	if timers.TJ < 0 {
		return TransactionTimers{}, errors.New("normalizing transaction timers: Timer J must be >= 0")
	}
	defaults := DefaultTransactionTimers()
	if timers.T1 == 0 {
		timers.T1 = defaults.T1
	}
	if timers.T2 == 0 {
		timers.T2 = defaults.T2
	}
	if timers.T4 == 0 {
		timers.T4 = defaults.T4
	}
	if timers.TB == 0 {
		timers.TB = 64 * timers.T1
	}
	if timers.TD == 0 {
		timers.TD = defaults.TD
	}
	if timers.TF == 0 {
		timers.TF = 64 * timers.T1
	}
	if timers.TH == 0 {
		timers.TH = 64 * timers.T1
	}
	if timers.TJ == 0 {
		timers.TJ = 64 * timers.T1
	}
	return timers, nil
}

func newClientTransaction(s *Session, transport Transport, req sip.Message, opts ExchangeOptions) *clientTransaction {
	return &clientTransaction{
		session:    s,
		transport:  transport,
		request:    req,
		key:        sip.PendingKey(req),
		method:     strings.ToUpper(req.Method()),
		reliable:   transportIsReliable(transport),
		timers:     s.cfg.TransactionTimers,
		responseCh: make(chan inboundMessage, 8),
		resultCh:   make(chan transactionResult, 1),
		cancelCh:   make(chan struct{}),
		opts:       opts,
	}
}

func (tx *clientTransaction) start(ctx context.Context) error {
	if err := tx.session.registerTransaction(tx); err != nil {
		return err
	}
	if err := tx.send(ctx, tx.request); err != nil {
		tx.abort(nil)
		return &transactionSendError{err: err, reliable: tx.reliable}
	}
	go tx.run()
	return nil
}

func transactionLayerErrorResponse(req sip.Message, err error) (sip.Message, bool) {
	var sendErr *transactionSendError
	if !errors.As(err, &sendErr) {
		return sip.Message{}, false
	}
	if !sendErr.reliable {
		return sip.Message{}, false
	}
	cause := sendErr.Unwrap()
	if errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return sip.Message{}, false
	}
	resp := sip.NewResponse(sipStatusServiceUnavailable, "Service Unavailable")
	resp.Headers = sip.ResponseHeaders(req, sipStatusServiceUnavailable)
	warning := sip.WarningValue{Code: 399, Agent: "vowifi-go", Text: cause.Error()}
	if text, marshalErr := warning.MarshalText(); marshalErr == nil {
		resp.Headers.Add("Warning", string(text))
	}
	return resp, true
}

func (tx *clientTransaction) await(ctx context.Context) (sip.Message, error) {
	select {
	case <-ctx.Done():
		tx.abort(nil)
		return sip.Message{}, ctx.Err()
	case result := <-tx.resultCh:
		if result.err != nil {
			return sip.Message{}, result.err
		}
		return result.msg, nil
	}
}

func (tx *clientTransaction) handleResponse(inbound inboundMessage) {
	select {
	case tx.responseCh <- inbound:
	default:
		msg := inbound.msg
		tx.session.logger.Warn("dropping buffered transaction response", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "status", msg.StatusCode())
	}
}

func (tx *clientTransaction) acceptsResponse(msg sip.Message) bool {
	return responseMatchesRequestTransaction(tx.request, msg)
}

func (tx *clientTransaction) abort(err error) {
	tx.cancelOnce.Do(func() {
		close(tx.cancelCh)
		tx.session.unregisterTransaction(tx)
		if err != nil {
			tx.deliverError(err)
		}
	})
}

func (tx *clientTransaction) terminate() {
	tx.abort(nil)
}

func (tx *clientTransaction) deliverResponse(msg sip.Message) {
	select {
	case tx.resultCh <- transactionResult{msg: msg}:
	default:
	}
}

func (tx *clientTransaction) deliverError(err error) {
	select {
	case tx.resultCh <- transactionResult{err: err}:
	default:
	}
}

func (tx *clientTransaction) run() {
	if tx.method == "INVITE" {
		tx.runInvite()
		return
	}
	tx.runNonInvite()
}

func (tx *clientTransaction) runNonInvite() {
	timerF := time.NewTimer(tx.timers.TF)
	defer timerF.Stop()

	retransmitDelay := tx.timers.T1
	state := clientTransactionTrying
	var timerEC <-chan time.Time
	timerE := (*time.Timer)(nil)
	if !tx.reliable {
		timerE = time.NewTimer(retransmitDelay)
		timerEC = timerE.C
		defer timerE.Stop()
	}

	for {
		select {
		case <-tx.cancelCh:
			return
		case <-timerF.C:
			tx.abort(&TransactionTimeoutError{Method: tx.method, Timer: "F"})
			return
		case <-timerEC:
			if !tx.resend() {
				return
			}
			if state == clientTransactionProceeding {
				retransmitDelay = tx.timers.T2
			} else if retransmitDelay < tx.timers.T2 {
				retransmitDelay *= 2
				if retransmitDelay > tx.timers.T2 {
					retransmitDelay = tx.timers.T2
				}
			}
			timerE.Reset(retransmitDelay)
		case inbound := <-tx.responseCh:
			if tx.opts.AcceptResponseTransport != nil && !tx.opts.AcceptResponseTransport(inbound.transport) {
				continue
			}
			resp := inbound.msg
			if isProvisionalResponse(resp) {
				if err := tx.notifyProvisional(resp); err != nil {
					tx.abort(err)
					return
				}
				state = clientTransactionProceeding
				continue
			}
			state = clientTransactionCompleted
			tx.deliverResponse(resp)
			if tx.reliable {
				tx.terminate()
				return
			}
			tx.awaitDrain(tx.timers.T4)
			return
		}
	}
}

func (tx *clientTransaction) runInvite() {
	timerB := time.NewTimer(tx.timers.TB)
	defer timerB.Stop()

	retransmitDelay := tx.timers.T1
	state := clientTransactionCalling
	timerBC := timerB.C
	var timerAC <-chan time.Time
	timerA := (*time.Timer)(nil)
	if !tx.reliable {
		timerA = time.NewTimer(retransmitDelay)
		timerAC = timerA.C
		defer timerA.Stop()
	}

	for {
		select {
		case <-tx.cancelCh:
			return
		case <-timerBC:
			if state != clientTransactionCalling {
				continue
			}
			tx.abort(&TransactionTimeoutError{Method: tx.method, Timer: "B"})
			return
		case <-timerAC:
			if !tx.resend() {
				return
			}
			retransmitDelay *= 2
			timerA.Reset(retransmitDelay)
		case inbound := <-tx.responseCh:
			if tx.opts.AcceptResponseTransport != nil && !tx.opts.AcceptResponseTransport(inbound.transport) {
				continue
			}
			resp := inbound.msg
			switch {
			case isProvisionalResponse(resp):
				if err := tx.notifyProvisional(resp); err != nil {
					tx.abort(err)
					return
				}
				state = clientTransactionProceeding
				timerAC = nil
				stopTimer(timerA)
				timerBC = nil
				stopTimer(timerB)
			case resp.StatusCode() >= 200 && resp.StatusCode() < 300:
				state = clientTransactionTerminated
				tx.deliverResponse(resp)
				tx.terminate()
				return
			default:
				state = clientTransactionCompleted
				ack := buildInviteErrorACK(tx.request, resp)
				tx.deliverResponse(resp)
				tx.sendACK(ack)
				if tx.reliable {
					state = clientTransactionTerminated
					tx.terminate()
					return
				}
				tx.awaitInviteCompleted(ack, tx.timerD())
				return
			}
		}
	}
}

func (tx *clientTransaction) notifyProvisional(resp sip.Message) error {
	ctx, cancel := tx.session.timeoutContext(max(tx.timers.T1, 250*time.Millisecond))
	defer cancel()
	if err := tx.session.handleInboundResponse(ctx, resp); err != nil {
		return fmt.Errorf("handling provisional %s response: %w", tx.method, err)
	}
	if tx.opts.OnProvisional != nil {
		tx.opts.OnProvisional(resp)
	}
	return nil
}

func (tx *clientTransaction) resend() bool {
	ctx, cancel := tx.session.timeoutContext(max(tx.timers.T1, 250*time.Millisecond))
	defer cancel()
	if err := tx.send(ctx, tx.request); err != nil {
		tx.abort(fmt.Errorf("sending %s retransmission: %w", tx.method, err))
		return false
	}
	return true
}

func (tx *clientTransaction) send(ctx context.Context, req sip.Message) error {
	return tx.session.writeRequest(ctx, tx.transport, req)
}

func (tx *clientTransaction) awaitDrain(timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-tx.cancelCh:
			return
		case <-timer.C:
			tx.terminate()
			return
		case <-tx.responseCh:
		}
	}
}

func (tx *clientTransaction) awaitInviteCompleted(ack sip.Message, timeout time.Duration) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case <-tx.cancelCh:
			return
		case <-timer.C:
			tx.terminate()
			return
		case inbound := <-tx.responseCh:
			resp := inbound.msg
			if resp.StatusCode() >= 300 && resp.StatusCode() < 700 {
				tx.sendACK(ack)
			}
		}
	}
}

func (tx *clientTransaction) sendACK(ack sip.Message) {
	ctx, cancel := tx.session.timeoutContext(max(tx.timers.T1, 250*time.Millisecond))
	defer cancel()
	if err := tx.send(ctx, ack); err != nil {
		tx.session.logger.Warn("sending invite error ack", "call_id", ack.Header("Call-ID"), "cseq", ack.Header("CSeq"), "err", err)
	}
}

func (tx *clientTransaction) timerD() time.Duration {
	if tx.reliable {
		return 0
	}
	if tx.timers.TD > 0 {
		return tx.timers.TD
	}
	return 32 * time.Second
}

func (s *Session) registerTransaction(tx *clientTransaction) error {
	if tx.key == "" {
		return errors.New("registering transaction: key is empty")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("registering transaction: session is closed")
	}
	if _, exists := s.transactions[tx.key]; exists {
		s.mu.Unlock()
		return fmt.Errorf("registering transaction: duplicate key %q", tx.key)
	}
	s.transactions[tx.key] = tx
	s.notifyTransactionsChanged()
	s.mu.Unlock()
	return nil
}

func (s *Session) unregisterTransaction(tx *clientTransaction) {
	s.mu.Lock()
	if current, ok := s.transactions[tx.key]; ok && current == tx {
		delete(s.transactions, tx.key)
		s.notifyTransactionsChanged()
	}
	s.mu.Unlock()
}

func (s *Session) abortTransactions(err error) {
	s.mu.Lock()
	transactions := make([]*clientTransaction, 0, len(s.transactions))
	for _, tx := range s.transactions {
		transactions = append(transactions, tx)
	}
	s.mu.Unlock()
	for _, tx := range transactions {
		tx.abort(err)
	}
}

func (s *Session) abortTransportTransactions(transport Transport, err error) {
	s.mu.Lock()
	clientTxs := make([]*clientTransaction, 0)
	for _, tx := range s.transactions {
		if tx.transport == transport {
			clientTxs = append(clientTxs, tx)
		}
	}
	serverTxs := make([]*serverTransaction, 0)
	for _, tx := range s.serverTxs {
		if tx.transport == transport {
			serverTxs = append(serverTxs, tx)
		}
	}
	s.mu.Unlock()
	for _, tx := range clientTxs {
		tx.abort(err)
	}
	for _, tx := range serverTxs {
		tx.terminate()
	}
}

func transportIsReliable(transport Transport) bool {
	switch transport.LocalAddr().(type) {
	case *net.TCPAddr:
		return true
	default:
		return false
	}
}

func buildInviteErrorACK(req, resp sip.Message) sip.Message {
	ack := sip.NewRequest("ACK", sip.RequestURI(req))
	ack.Headers.Add("Via", req.Header("Via"))
	for _, route := range req.HeadersByName("Route") {
		ack.Headers.Add("Route", route)
	}
	ack.Headers.Add("Max-Forwards", strconv.Itoa(sip.DefaultMaxForwards))
	ack.Headers.Add("From", req.Header("From"))
	ack.Headers.Add("To", resp.Header("To"))
	ack.Headers.Add("Call-ID", req.Header("Call-ID"))
	ack.Headers.Add("CSeq", fmt.Sprintf("%d ACK", sip.CSeqNumber(req.Header("CSeq"))))
	return ack
}

func stopTimer(timer *time.Timer) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
}
