package session

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/damonto/ims-client/ims/sip"
)

type serverTransaction struct {
	session   *Session
	transport Transport
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
	lifetimeTimer *time.Timer
}

func newServerTransaction(s *Session, req Request) *serverTransaction {
	msg := cloneSIPMessage(req.Message)
	via := strings.TrimSpace(msg.Header("Via"))
	return &serverTransaction{
		session:    s,
		transport:  req.Transport,
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
			tx.terminate()
			return true, nil
		}
		return false, nil
	case "CANCEL":
		tx := s.matchCanceledTransaction(req.Message)
		if tx == nil {
			return true, s.WriteStatus(ctx, req, 481, "Call/Transaction Does Not Exist")
		}
		if err := s.WriteStatus(ctx, req, 200, "OK"); err != nil {
			return true, err
		}
		return true, tx.handleCancel(ctx)
	default:
		if tx := s.lookupServerTransaction(req.Message); tx != nil {
			return true, tx.retransmit(ctx)
		}
		s.registerServerTransaction(newServerTransaction(s, req))
		return false, nil
	}
}

func (s *Session) registerServerTransaction(tx *serverTransaction) {
	if tx == nil || tx.key == "" {
		return
	}
	s.mu.Lock()
	if !s.closed {
		s.serverTxs[tx.key] = tx
	}
	s.mu.Unlock()
}

func (s *Session) unregisterServerTransaction(tx *serverTransaction) {
	if tx == nil || tx.key == "" {
		return
	}
	tx.stopLifetimeTimer()
	s.mu.Lock()
	if current, ok := s.serverTxs[tx.key]; ok && current == tx {
		delete(s.serverTxs, tx.key)
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
	s.mu.Unlock()
	for _, tx := range transactions {
		tx.stopLifetimeTimer()
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
	tx.lastResponse = cloneSIPMessage(resp)
	tx.finalStatus = resp.StatusCode()
	final := tx.finalStatus >= 200
	reliable := tx.reliable
	tx.mu.Unlock()
	if !final {
		return
	}
	if reliable {
		tx.terminate()
		return
	}
	if tx.method == "INVITE" && tx.finalStatus >= 300 {
		tx.scheduleTermination(tx.session.cfg.TransactionTimers.TH)
		return
	}
	tx.scheduleTermination(tx.session.cfg.TransactionTimers.TJ)
}

func (tx *serverTransaction) retransmit(ctx context.Context) error {
	tx.mu.Lock()
	resp := cloneSIPMessage(tx.lastResponse)
	req := cloneSIPMessage(tx.request)
	transport := tx.transport
	tx.mu.Unlock()
	if resp.StartLine == "" {
		return nil
	}
	return tx.session.writeResponse(ctx, transport, req, resp)
}

func (tx *serverTransaction) handleCancel(ctx context.Context) error {
	tx.mu.Lock()
	final := tx.finalStatus >= 200
	method := tx.method
	req := cloneSIPMessage(tx.request)
	transport := tx.transport
	tx.mu.Unlock()
	if final || method != "INVITE" {
		return nil
	}
	resp := sip.NewResponse(487, "Request Terminated")
	resp.Headers = sip.ResponseHeaders(req, 487)
	if err := tx.session.writeResponse(ctx, transport, req, resp); err != nil {
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

func (tx *serverTransaction) scheduleTermination(timeout time.Duration) {
	if timeout <= 0 {
		tx.terminate()
		return
	}
	tx.mu.Lock()
	defer tx.mu.Unlock()
	if tx.lifetimeTimer != nil {
		tx.lifetimeTimer.Reset(timeout)
		return
	}
	tx.lifetimeTimer = time.AfterFunc(timeout, func() {
		tx.session.unregisterServerTransaction(tx)
	})
}

func (tx *serverTransaction) stopLifetimeTimer() {
	tx.mu.Lock()
	timer := tx.lifetimeTimer
	tx.lifetimeTimer = nil
	tx.mu.Unlock()
	if timer != nil {
		timer.Stop()
	}
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
	if tx == nil {
		return false
	}
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
	if tx == nil || tx.method != "INVITE" {
		return false
	}
	via := strings.TrimSpace(msg.Header("Via"))
	branch := strings.TrimSpace(sip.TopViaBranch(via))
	if !strings.HasPrefix(branch, "z9hG4bK") {
		return false
	}
	return branch == tx.branch &&
		strings.TrimSpace(sip.TopViaSentBy(via)) == tx.sentBy &&
		strings.TrimSpace(msg.Header("Call-ID")) == tx.callID &&
		sip.CSeqNumber(msg.Header("CSeq")) == tx.cseqNumber
}

func cloneSIPMessage(msg sip.Message) sip.Message {
	cloned := msg
	cloned.Headers = msg.Headers.Clone()
	cloned.Body = append([]byte(nil), msg.Body...)
	return cloned
}
