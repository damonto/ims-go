package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/damonto/ims-client/ims/sip"
)

type transactionTimers struct {
	T1 time.Duration
	T2 time.Duration
	T4 time.Duration
	TD time.Duration
}

type clientTransaction struct {
	session   *Session
	transport Transport
	request   sip.Message
	key       string
	method    string
	reliable  bool
	timers    transactionTimers

	responseCh chan sip.Message
	resultCh   chan transactionResult
	cancelCh   chan struct{}

	cancelOnce sync.Once
}

type transactionResult struct {
	msg sip.Message
	err error
}

var defaultTransactionTimers = transactionTimers{
	T1: 500 * time.Millisecond,
	T2: 4 * time.Second,
	T4: 5 * time.Second,
	TD: 32 * time.Second,
}

func newClientTransaction(s *Session, transport Transport, req sip.Message) *clientTransaction {
	return &clientTransaction{
		session:    s,
		transport:  transport,
		request:    req,
		key:        sip.PendingKey(req),
		method:     strings.ToUpper(req.Method()),
		reliable:   transportIsReliable(transport),
		timers:     defaultTransactionTimers,
		responseCh: make(chan sip.Message, 8),
		resultCh:   make(chan transactionResult, 1),
		cancelCh:   make(chan struct{}),
	}
}

func (tx *clientTransaction) start(ctx context.Context) error {
	if err := tx.session.registerTransaction(tx); err != nil {
		return err
	}
	if err := tx.send(ctx, tx.request); err != nil {
		tx.abort(nil)
		return err
	}
	go tx.run()
	return nil
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

func (tx *clientTransaction) handleResponse(msg sip.Message) {
	select {
	case tx.responseCh <- msg:
	default:
		tx.session.logger.Warn("dropping buffered transaction response", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "status", msg.StatusCode())
	}
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
	timerF := time.NewTimer(64 * tx.timers.T1)
	defer timerF.Stop()

	retransmitDelay := tx.timers.T1
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
			tx.abort(fmt.Errorf("waiting for %s response: transaction timeout", tx.method))
			return
		case <-timerEC:
			if !tx.resend() {
				return
			}
			if retransmitDelay < tx.timers.T2 {
				retransmitDelay *= 2
				if retransmitDelay > tx.timers.T2 {
					retransmitDelay = tx.timers.T2
				}
			}
			timerE.Reset(retransmitDelay)
		case resp := <-tx.responseCh:
			if isProvisionalResponse(resp) {
				continue
			}
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
	timerB := time.NewTimer(64 * tx.timers.T1)
	defer timerB.Stop()

	retransmitDelay := tx.timers.T1
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
		case <-timerB.C:
			tx.abort(fmt.Errorf("waiting for %s response: transaction timeout", tx.method))
			return
		case <-timerAC:
			if !tx.resend() {
				return
			}
			retransmitDelay *= 2
			timerA.Reset(retransmitDelay)
		case resp := <-tx.responseCh:
			switch {
			case isProvisionalResponse(resp):
				timerAC = nil
				stopTimer(timerA)
			case resp.StatusCode() >= 200 && resp.StatusCode() < 300:
				tx.deliverResponse(resp)
				tx.terminate()
				return
			default:
				ack := buildInviteErrorACK(tx.request, resp)
				tx.deliverResponse(resp)
				tx.sendACK(ack)
				if tx.reliable {
					tx.terminate()
					return
				}
				tx.awaitInviteCompleted(ack, tx.timerD())
				return
			}
		}
	}
}

func (tx *clientTransaction) resend() bool {
	ctx, cancel := context.WithTimeout(context.Background(), max(tx.timers.T1, 250*time.Millisecond))
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
		case resp := <-tx.responseCh:
			if resp.StatusCode() >= 300 && resp.StatusCode() < 700 {
				tx.sendACK(ack)
			}
		}
	}
}

func (tx *clientTransaction) sendACK(ack sip.Message) {
	ctx, cancel := context.WithTimeout(context.Background(), max(tx.timers.T1, 250*time.Millisecond))
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
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("registering transaction: session is closed")
	}
	if _, exists := s.transactions[tx.key]; exists {
		return fmt.Errorf("registering transaction: duplicate key %q", tx.key)
	}
	s.transactions[tx.key] = tx
	return nil
}

func (s *Session) unregisterTransaction(tx *clientTransaction) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.transactions[tx.key]; ok && current == tx {
		delete(s.transactions, tx.key)
	}
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
	ack.Headers.Add("Max-Forwards", "70")
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
