package session

import (
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

type serverTransaction struct {
	session   *Session
	transport Transport
	peer      net.Addr
	request   sip.Message
	key       string
	reliable  bool

	method     string
	branch     string
	sentBy     string
	requestURI string
	topVia     string
	callID     string
	fromTag    string
	toTag      string
	cseqNumber int64

	mu            sync.Mutex
	lastResponse  sip.Message
	finalStatus   int
	tryingTimer   *time.Timer
	lifetimeTimer *time.Timer
	retryTimer    *time.Timer
	retryDelay    time.Duration
	state         serverTransactionState
}

type serverTransactionState uint8

const (
	serverTransactionProceeding serverTransactionState = iota
	serverTransactionCompleted
	serverTransactionConfirmed
	serverTransactionTerminated
)

const inviteTryingDelay = 200 * time.Millisecond

func newServerTransaction(s *Session, req Request) *serverTransaction {
	msg := cloneSIPMessage(req.Message)
	via := strings.TrimSpace(msg.Header("Via"))
	return &serverTransaction{
		session:    s,
		transport:  req.Transport,
		peer:       req.PeerAddr,
		request:    msg,
		key:        serverTransactionKey(msg),
		reliable:   transportIsReliable(req.Transport),
		method:     strings.ToUpper(msg.Method()),
		branch:     strings.TrimSpace(sip.TopViaBranch(via)),
		sentBy:     strings.TrimSpace(sip.TopViaSentBy(via)),
		requestURI: strings.TrimSpace(sip.RequestURI(msg)),
		topVia:     via,
		callID:     strings.TrimSpace(msg.Header("Call-ID")),
		fromTag:    strings.TrimSpace(sip.HeaderTag(msg.Header("From"))),
		toTag:      strings.TrimSpace(sip.HeaderTag(msg.Header("To"))),
		cseqNumber: sip.CSeqNumber(msg.Header("CSeq")),
	}
}

func (s *Session) processServerTransaction(ctx context.Context, req Request) (bool, error) {
	method := strings.ToUpper(strings.TrimSpace(req.Message.Method()))
	switch method {
	case "":
		return false, nil
	case "ACK":
		tx := s.matchServerACK(req.Message)
		if tx == nil {
			return false, nil
		}
		if tx.finalResponseCode() >= 300 {
			tx.confirmInviteErrorACK()
			return true, nil
		}
		return false, nil
	case "CANCEL":
		tx := s.matchCanceledTransaction(req.Message)
		if tx == nil {
			return true, s.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
		}
		if err := s.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
			return true, err
		}
		if err := tx.handleCancel(ctx); err != nil {
			return true, err
		}
		_, err := s.dispatchRequest(ctx, req)
		return true, err
	default:
		if tx := s.lookupServerTransaction(req.Message); tx != nil {
			return true, tx.retransmit(ctx)
		}
		s.registerServerTransaction(newServerTransaction(s, req))
		return false, nil
	}
}

func (s *Session) registerServerTransaction(tx *serverTransaction) {
	if tx.key == "" {
		return
	}
	registered := false
	s.mu.Lock()
	if !s.closed {
		s.serverTxs[tx.key] = tx
		s.notifyTransactionsChanged()
		registered = true
	}
	s.mu.Unlock()
	if registered {
		tx.startInviteTryingTimer()
	}
}

func (s *Session) unregisterServerTransaction(tx *serverTransaction) {
	if tx.key == "" {
		return
	}
	tx.markTerminated()
	s.mu.Lock()
	if current, ok := s.serverTxs[tx.key]; ok && current == tx {
		delete(s.serverTxs, tx.key)
		s.notifyTransactionsChanged()
	}
	s.mu.Unlock()
}

func (s *Session) clearServerTransactions() {
	s.mu.Lock()
	transactions := make([]*serverTransaction, 0, len(s.serverTxs))
	for _, tx := range s.serverTxs {
		transactions = append(transactions, tx)
	}
	s.serverTxs = make(map[string]*serverTransaction)
	s.notifyTransactionsChanged()
	s.mu.Unlock()
	for _, tx := range transactions {
		tx.markTerminated()
	}
}

func (s *Session) lookupServerTransaction(msg sip.Message) *serverTransaction {
	key := serverTransactionKey(msg)
	if key == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverTxs[key]
}

func (s *Session) matchCanceledTransaction(msg sip.Message) *serverTransaction {
	s.mu.Lock()
	transactions := make([]*serverTransaction, 0, len(s.serverTxs))
	for _, tx := range s.serverTxs {
		transactions = append(transactions, tx)
	}
	s.mu.Unlock()
	for _, tx := range transactions {
		if cancelMatchesServerTransaction(msg, tx) {
			return tx
		}
	}
	return nil
}

func (s *Session) matchServerACK(msg sip.Message) *serverTransaction {
	s.mu.Lock()
	transactions := make([]*serverTransaction, 0, len(s.serverTxs))
	for _, tx := range s.serverTxs {
		transactions = append(transactions, tx)
	}
	s.mu.Unlock()
	for _, tx := range transactions {
		if ackMatchesServerTransaction(msg, tx) {
			return tx
		}
	}
	return nil
}

func (s *Session) recordServerTransactionResponse(req Request, resp sip.Message) {
	tx := s.lookupServerTransaction(req.Message)
	if tx == nil {
		return
	}
	tx.recordResponse(resp)
}

func (tx *serverTransaction) recordResponse(resp sip.Message) {
	tx.mu.Lock()
	if tx.state != serverTransactionProceeding {
		tx.mu.Unlock()
		return
	}
	tryingTimer := tx.tryingTimer
	tx.tryingTimer = nil
	tx.lastResponse = cloneSIPMessage(resp)
	tx.finalStatus = resp.StatusCode()
	final := tx.finalStatus >= 200
	reliable := tx.reliable
	method := tx.method
	status := tx.finalStatus
	timers := tx.session.cfg.TransactionTimers
	if final && method == "INVITE" && status >= 300 {
		tx.state = serverTransactionCompleted
		if !reliable {
			tx.retryDelay = timers.T1
			tx.retryTimer = time.AfterFunc(tx.retryDelay, tx.retransmitInviteFinal)
		}
		tx.startLifetimeTimer(timers.TH)
	}
	tx.mu.Unlock()
	stopTimer(tryingTimer)
	if !final {
		return
	}
	if method == "INVITE" && status >= 300 {
		return
	}
	if method == "INVITE" {
		tx.terminate()
		return
	}
	if reliable {
		tx.terminate()
		return
	}
	tx.scheduleTermination(tx.session.cfg.TransactionTimers.TJ)
}

func (tx *serverTransaction) startInviteTryingTimer() {
	if tx.method != "INVITE" {
		return
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.tryingTimer = time.AfterFunc(inviteTryingDelay, tx.sendAutomaticTrying)
}

func (tx *serverTransaction) sendAutomaticTrying() {
	tx.mu.Lock()
	if tx.state != serverTransactionProceeding || tx.lastResponse.StartLine != "" {
		tx.tryingTimer = nil
		tx.mu.Unlock()
		return
	}
	req := cloneSIPMessage(tx.request)
	transport := tx.transport
	peer := tx.peer
	resp := sip.NewResponse(sipStatusTrying, "Trying")
	resp.Headers = sip.ResponseHeaders(req, sipStatusTrying)
	tx.session.applyResponseDecorator(&resp)
	tx.lastResponse = cloneSIPMessage(resp)
	tx.finalStatus = sipStatusTrying
	tx.tryingTimer = nil
	tx.mu.Unlock()

	ctx, cancel := tx.session.timeoutContext(max(tx.session.cfg.TransactionTimers.T1, 250*time.Millisecond))
	defer cancel()
	if err := tx.session.writeResponse(ctx, transport, peer, req, resp); err != nil {
		tx.session.logger.Warn("sending automatic invite trying response", "call_id", req.Header("Call-ID"), "cseq", req.Header("CSeq"), "err", err)
	}
}

func (tx *serverTransaction) retransmit(ctx context.Context) error {
	tx.mu.Lock()
	resp := cloneSIPMessage(tx.lastResponse)
	req := cloneSIPMessage(tx.request)
	transport := tx.transport
	peer := tx.peer
	tx.mu.Unlock()
	if resp.StartLine == "" {
		return nil
	}
	return tx.session.writeResponse(ctx, transport, peer, req, resp)
}

func (tx *serverTransaction) handleCancel(ctx context.Context) error {
	tx.mu.Lock()
	final := tx.finalStatus >= 200
	method := tx.method
	req := cloneSIPMessage(tx.request)
	transport := tx.transport
	peer := tx.peer
	tx.mu.Unlock()
	if final || method != "INVITE" {
		return nil
	}
	resp := sip.NewResponse(sipStatusRequestTerminated, "Request Terminated")
	resp.Headers = sip.ResponseHeaders(req, sipStatusRequestTerminated)
	tx.session.applyResponseDecorator(&resp)
	if err := tx.session.writeResponse(ctx, transport, peer, req, resp); err != nil {
		return err
	}
	tx.recordResponse(resp)
	return nil
}

func (tx *serverTransaction) finalResponseCode() int {
	tx.mu.Lock()
	defer tx.mu.Unlock()
	return tx.finalStatus
}

func (tx *serverTransaction) terminate() {
	tx.session.unregisterServerTransaction(tx)
}

func (tx *serverTransaction) confirmInviteErrorACK() {
	tx.mu.Lock()
	switch tx.state {
	case serverTransactionCompleted:
		stopTimer(tx.retryTimer)
		tx.retryTimer = nil
		tx.state = serverTransactionConfirmed
		timeout := tx.session.cfg.TransactionTimers.T4
		if tx.reliable {
			timeout = 0
		}
		if timeout > 0 {
			tx.startLifetimeTimer(timeout)
		}
		tx.mu.Unlock()
		if timeout <= 0 {
			tx.terminate()
		}
	case serverTransactionConfirmed:
		tx.mu.Unlock()
	default:
		tx.mu.Unlock()
	}
}

func (tx *serverTransaction) retransmitInviteFinal() {
	tx.mu.Lock()
	if tx.state != serverTransactionCompleted {
		tx.mu.Unlock()
		return
	}
	resp := cloneSIPMessage(tx.lastResponse)
	req := cloneSIPMessage(tx.request)
	transport := tx.transport
	peer := tx.peer
	timers := tx.session.cfg.TransactionTimers
	tx.mu.Unlock()

	ctx, cancel := tx.session.timeoutContext(max(timers.T1, 250*time.Millisecond))
	defer cancel()
	if err := tx.session.writeResponse(ctx, transport, peer, req, resp); err != nil {
		tx.session.logger.Warn("retransmitting invite final response", "call_id", req.Header("Call-ID"), "cseq", req.Header("CSeq"), "status", resp.StatusCode(), "err", err)
	}

	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.state != serverTransactionCompleted || tx.retryTimer == nil {
		return
	}
	nextDelay := tx.retryDelay * 2
	if nextDelay > timers.T2 {
		nextDelay = timers.T2
	}
	tx.retryDelay = nextDelay
	tx.retryTimer.Reset(nextDelay)
}

func (tx *serverTransaction) scheduleTermination(timeout time.Duration) {
	if timeout <= 0 {
		tx.terminate()
		return
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	tx.startLifetimeTimer(timeout)
}

func (tx *serverTransaction) startLifetimeTimer(timeout time.Duration) {
	if tx.lifetimeTimer != nil {
		tx.lifetimeTimer.Reset(timeout)
		return
	}
	tx.lifetimeTimer = time.AfterFunc(timeout, func() {
		tx.session.unregisterServerTransaction(tx)
	})
}

func (tx *serverTransaction) markTerminated() {
	tx.mu.Lock()
	tx.state = serverTransactionTerminated
	tryingTimer := tx.tryingTimer
	tx.tryingTimer = nil
	lifetimeTimer := tx.lifetimeTimer
	tx.lifetimeTimer = nil
	retryTimer := tx.retryTimer
	tx.retryTimer = nil
	tx.mu.Unlock()
	stopTimer(tryingTimer)
	stopTimer(lifetimeTimer)
	stopTimer(retryTimer)
}

func serverTransactionKey(msg sip.Message) string {
	method := strings.ToUpper(strings.TrimSpace(msg.Method()))
	if method == "" || method == "ACK" || method == "CANCEL" {
		return ""
	}
	via := strings.TrimSpace(msg.Header("Via"))
	branch := strings.TrimSpace(sip.TopViaBranch(via))
	if strings.HasPrefix(branch, "z9hG4bK") {
		sentBy := strings.TrimSpace(sip.TopViaSentBy(via))
		if sentBy == "" {
			return ""
		}
		return "3261|" + branch + "|" + sentBy + "|" + method
	}

	requestURI := strings.TrimSpace(sip.RequestURI(msg))
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	fromTag := strings.TrimSpace(sip.HeaderTag(msg.Header("From")))
	toTag := strings.TrimSpace(sip.HeaderTag(msg.Header("To")))
	if requestURI == "" || via == "" || callID == "" || cseq == "" || fromTag == "" {
		return ""
	}
	return "2543|" + requestURI + "|" + toTag + "|" + fromTag + "|" + callID + "|" + cseq + "|" + via
}

func cancelMatchesServerTransaction(msg sip.Message, tx *serverTransaction) bool {
	via := strings.TrimSpace(msg.Header("Via"))
	branch := strings.TrimSpace(sip.TopViaBranch(via))
	if strings.HasPrefix(branch, "z9hG4bK") {
		return branch != "" &&
			branch == tx.branch &&
			strings.TrimSpace(sip.TopViaSentBy(via)) == tx.sentBy &&
			strings.TrimSpace(msg.Header("Call-ID")) == tx.callID &&
			sip.CSeqNumber(msg.Header("CSeq")) == tx.cseqNumber
	}
	return strings.TrimSpace(sip.RequestURI(msg)) == tx.requestURI &&
		strings.TrimSpace(msg.Header("Via")) == tx.topVia &&
		strings.TrimSpace(msg.Header("Call-ID")) == tx.callID &&
		strings.TrimSpace(sip.HeaderTag(msg.Header("From"))) == tx.fromTag &&
		sip.CSeqNumber(msg.Header("CSeq")) == tx.cseqNumber
}

func ackMatchesServerTransaction(msg sip.Message, tx *serverTransaction) bool {
	if tx.method != "INVITE" {
		return false
	}
	via := strings.TrimSpace(msg.Header("Via"))
	branch := strings.TrimSpace(sip.TopViaBranch(via))
	if strings.HasPrefix(branch, "z9hG4bK") {
		return branch == tx.branch &&
			strings.TrimSpace(sip.TopViaSentBy(via)) == tx.sentBy &&
			strings.TrimSpace(msg.Header("Call-ID")) == tx.callID &&
			sip.CSeqNumber(msg.Header("CSeq")) == tx.cseqNumber
	}
	tx.mu.Lock()
	responseToTag := strings.TrimSpace(sip.HeaderTag(tx.lastResponse.Header("To")))
	tx.mu.Unlock()
	return responseToTag != "" &&
		strings.TrimSpace(sip.RequestURI(msg)) == tx.requestURI &&
		via == tx.topVia &&
		strings.TrimSpace(msg.Header("Call-ID")) == tx.callID &&
		strings.TrimSpace(sip.HeaderTag(msg.Header("From"))) == tx.fromTag &&
		strings.TrimSpace(sip.HeaderTag(msg.Header("To"))) == responseToTag &&
		sip.CSeqNumber(msg.Header("CSeq")) == tx.cseqNumber
}

func cloneSIPMessage(msg sip.Message) sip.Message {
	cloned := msg
	cloned.Headers = msg.Headers.Clone()
	cloned.Body = append([]byte(nil), msg.Body...)
	return cloned
}
