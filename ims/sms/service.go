package sms

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"mime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"github.com/damonto/ims-client/usim"
)

type Config struct {
	ServiceCenter       string
	SubmitReportTimeout time.Duration
	OnIncoming          func(Incoming)
	OnStatusReport      func(StatusReport)
	OnError             func(error)
}

type Card interface {
	SMSC() string
}

type Service struct {
	cfg        Config
	sess       *session.Session
	reg        *registration.Service
	card       Card
	logger     *slog.Logger
	attachment session.Attachment

	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupWG     sync.WaitGroup

	mu        sync.Mutex
	cseq      int64
	rpRef     uint32
	rpRefs    map[byte]struct{}
	pending   map[string]pendingEntry
	submitted map[string]submittedEntry
	recent    map[string]time.Time
	concat    map[string]concatState
	moActive  bool
	moSending bool
	moPending int
	mtActive  bool
	closed    bool
}

type SubmissionSegment struct {
	Index       int
	Count       int
	CallID      string
	RPReference byte
	TPReference byte
	SubmittedAt time.Time
}

type outboundSegment struct {
	index            int
	count            int
	to               string
	smscAddress      string
	target           string
	part             smsUserDataPart
	rpRef            byte
	tpRef            byte
	retryCount       int
	rejectDuplicates bool
	callID           string
	msg              sip.Message
	reportCh         <-chan rpMessage
}

type pendingEntry struct {
	rpRef     byte
	reportCh  chan rpMessage
	segment   outboundSegment
	response  submitResponse
	expiresAt time.Time
	async     bool
}

type submittedEntry struct {
	rpRef     byte
	expiresAt time.Time
	segment   outboundSegment
	response  submitResponse
	completed bool
}

type submitResponse struct {
	statusCode   int
	reasonPhrase string
}

type concatState struct {
	total     int
	parts     map[int]string
	updatedAt time.Time
}

type serviceCentre struct {
	target  string
	address string
}

type serviceCentreProvider interface {
	ServiceCentre() usim.ServiceCentre
}

const (
	concatRetention       = 10 * time.Minute
	submitRetention       = 5 * time.Minute
	deliveryReportTimeout = 30 * time.Second
)

var submitReportTimeoutNanos atomic.Int64

func init() {
	setSubmitReportTimeout(defaultSubmitReportTimeout)
}

const defaultSubmitReportTimeout = 130 * time.Second

func DefaultSubmitReportTimeout() time.Duration {
	return defaultSubmitReportTimeout
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.ServiceCenter = strings.TrimSpace(cfg.ServiceCenter)
	if cfg.SubmitReportTimeout < 0 {
		return Config{}, errors.New("creating sms service: submit report timeout must be >= 0")
	}
	if cfg.SubmitReportTimeout == 0 {
		cfg.SubmitReportTimeout = currentSubmitReportTimeout()
	}
	return cfg, nil
}

func New(cfg Config, sess *session.Session, reg *registration.Service, card Card) (*Service, error) {
	if sess == nil {
		return nil, errors.New("creating sms service: session is nil")
	}
	if reg == nil {
		return nil, errors.New("creating sms service: registration service is nil")
	}
	if card == nil {
		return nil, errors.New("creating sms service: card is nil")
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	s := &Service{
		cfg:           normalized,
		sess:          sess,
		reg:           reg,
		card:          card,
		logger:        slog.Default().With("component", "ims-sms"),
		cleanupCtx:    cleanupCtx,
		cleanupCancel: cleanupCancel,
		rpRefs:        make(map[byte]struct{}),
		pending:       make(map[string]pendingEntry),
		submitted:     make(map[string]submittedEntry),
		recent:        make(map[string]time.Time),
		concat:        make(map[string]concatState),
	}
	attachment, err := sess.Attach(s)
	if err != nil {
		return nil, fmt.Errorf("creating sms service: %w", err)
	}
	s.attachment = attachment
	s.cleanupWG.Go(func() {
		s.runSubmitCleanup()
	})
	return s, nil
}

func (s *Service) Send(ctx context.Context, to, text string) ([]SubmissionSegment, error) {
	ctx = normalizeContext(ctx)
	if err := s.beginMOTransfer(); err != nil {
		return nil, err
	}
	defer s.finishMOSend()

	sc, err := s.resolveServiceCentre()
	if err != nil {
		return nil, err
	}
	parts, err := buildSMSUserDataParts(text)
	if err != nil {
		return nil, err
	}
	submissions := make([]SubmissionSegment, 0, len(parts))
	for i, part := range parts {
		segment, err := s.newOutboundSegment(to, sc, part, i, len(parts))
		if err != nil {
			return nil, err
		}
		if err := s.sendSegment(ctx, segment); err != nil {
			return nil, err
		}
		submissions = append(submissions, SubmissionSegment{
			Index:       segment.index,
			Count:       segment.count,
			CallID:      segment.callID,
			RPReference: segment.rpRef,
			TPReference: segment.tpRef,
			SubmittedAt: time.Now(),
		})
	}
	return submissions, nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
	if s.attachment != nil {
		_ = s.attachment.Close()
	}
	s.cleanupWG.Wait()
	return nil
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	if !strings.EqualFold(req.Message.Method(), "MESSAGE") {
		return false, nil
	}
	if mediaType, _, err := mime.ParseMediaType(req.Message.Header("Content-Type")); err != nil || !strings.EqualFold(mediaType, "application/vnd.3gpp.sms") {
		return false, nil
	}
	return true, s.handleMessageRequest(ctx, req)
}

func (s *Service) HandleError(err error) {
	s.emitAsyncError(err)
}

func currentSubmitReportTimeout() time.Duration {
	return time.Duration(submitReportTimeoutNanos.Load())
}

func setSubmitReportTimeout(timeout time.Duration) {
	submitReportTimeoutNanos.Store(int64(timeout))
}

func newConcatState(total int) concatState {
	return concatState{total: total, parts: make(map[int]string, max(total, 0))}
}

func (state concatState) expired(now time.Time) bool {
	return now.Sub(state.updatedAt) > concatRetention
}

func (state *concatState) reset(total int) {
	*state = newConcatState(total)
}

func (state *concatState) addPart(sequence int, text string, now time.Time) {
	if state.parts == nil {
		state.parts = make(map[int]string, max(state.total, 0))
	}
	state.parts[sequence] = text
	state.updatedAt = now
}

func (state concatState) joinedText() (string, bool) {
	if state.total <= 0 || len(state.parts) < state.total {
		return "", false
	}
	parts := make([]string, state.total)
	for i := 1; i <= state.total; i++ {
		part, ok := state.parts[i]
		if !ok {
			return "", false
		}
		parts[i-1] = part
	}
	return strings.Join(parts, ""), true
}

func (s *Service) reserveReference() (byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for range 256 {
		ref := byte(atomic.AddUint32(&s.rpRef, 1))
		if _, exists := s.rpRefs[ref]; exists {
			continue
		}
		s.rpRefs[ref] = struct{}{}
		return ref, nil
	}
	return 0, errors.New("sending SMS: no free RP reference")
}

func (s *Service) releaseReference(ref byte) {
	s.mu.Lock()
	delete(s.rpRefs, ref)
	s.mu.Unlock()
}

func (s *Service) beginMOTransfer() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("sending SMS: service is closed")
	}
	if s.moActive {
		return errors.New("sending SMS: mobile originated transfer in progress")
	}
	s.moActive = true
	s.moSending = true
	s.moPending = 0
	return nil
}

func (s *Service) finishMOSend() {
	s.mu.Lock()
	s.moSending = false
	if s.moPending == 0 {
		s.moActive = false
	}
	s.mu.Unlock()
}

func (s *Service) completeMOPending() {
	s.mu.Lock()
	if s.moPending > 0 {
		s.moPending--
	}
	if !s.moSending && s.moPending == 0 {
		s.moActive = false
	}
	s.mu.Unlock()
}

func (s *Service) beginMTTransfer() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.mtActive {
		return false
	}
	s.mtActive = true
	return true
}

func (s *Service) endMTTransfer() {
	s.mu.Lock()
	s.mtActive = false
	s.mu.Unlock()
}

func (s *Service) registerPending(callID string, rpRef byte) (<-chan rpMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if callID == "" {
		return nil, errors.New("sending SMS: call id is empty")
	}
	if _, exists := s.pending[callID]; exists {
		return nil, fmt.Errorf("sending SMS: duplicate Call-ID %q", callID)
	}
	ch := make(chan rpMessage, 1)
	s.pending[callID] = pendingEntry{rpRef: rpRef, reportCh: ch}
	return ch, nil
}

func (s *Service) removePending(callID string) {
	s.mu.Lock()
	delete(s.pending, callID)
	s.mu.Unlock()
}

func (s *Service) markSubmitted(segment outboundSegment, response submitResponse, now time.Time) {
	if segment.callID == "" {
		return
	}
	s.mu.Lock()
	s.submitted[segment.callID] = submittedEntry{
		rpRef:     segment.rpRef,
		expiresAt: now.Add(submitRetention),
		segment:   segment,
		response:  response,
	}
	s.mu.Unlock()
}

func (s *Service) completeSubmitted(callID string) {
	if callID == "" {
		return
	}
	s.mu.Lock()
	entry, ok := s.submitted[callID]
	if ok {
		entry.segment = outboundSegment{}
		entry.response = submitResponse{}
		entry.completed = true
		s.submitted[callID] = entry
	}
	s.mu.Unlock()
}

func (s *Service) submitSweepInterval() time.Duration {
	interval := s.cfg.SubmitReportTimeout / 4
	if interval < 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	if interval > time.Second {
		return time.Second
	}
	return interval
}

func (s *Service) runSubmitCleanup() {
	timer := time.NewTimer(s.submitSweepInterval())
	defer timer.Stop()
	for {
		select {
		case <-s.cleanupCtx.Done():
			return
		case <-timer.C:
			s.expireSubmitState(time.Now())
			timer.Reset(s.submitSweepInterval())
		}
	}
}

func (s *Service) expireSubmitState(now time.Time) {
	var expired []pendingEntry
	s.mu.Lock()
	s.evictExpiredConcat(now)
	for callID, entry := range s.submitted {
		if !entry.expiresAt.After(now) {
			delete(s.submitted, callID)
		}
	}
	for callID, entry := range s.pending {
		if !entry.async || entry.expiresAt.IsZero() || entry.expiresAt.After(now) {
			continue
		}
		delete(s.pending, callID)
		expired = append(expired, entry)
	}
	s.mu.Unlock()
	for _, entry := range expired {
		if err := s.handleExpiredSegment(entry); err != nil {
			s.emitAsyncError(err)
		}
	}
}

func submitResponseFromMessage(resp sip.Message) submitResponse {
	statusCode := resp.StatusCode()
	return submitResponse{
		statusCode:   statusCode,
		reasonPhrase: strings.TrimSpace(strings.TrimPrefix(resp.StartLine, fmt.Sprintf("SIP/2.0 %d", statusCode))),
	}
}

func (s *Service) activatePendingAsync(segment outboundSegment, response submitResponse, now time.Time) (rpMessage, bool) {
	s.mu.Lock()
	entry, ok := s.pending[segment.callID]
	if !ok {
		s.mu.Unlock()
		return rpMessage{}, false
	}
	entry.segment = segment
	entry.response = response
	entry.expiresAt = now.Add(s.cfg.SubmitReportTimeout)
	entry.async = true
	s.pending[segment.callID] = entry
	select {
	case report := <-entry.reportCh:
		delete(s.pending, segment.callID)
		s.mu.Unlock()
		return report, true
	default:
		s.moPending++
		s.mu.Unlock()
		return rpMessage{}, false
	}
}

func (s *Service) completePending(ctx context.Context, msg sip.Message, report rpMessage) bool {
	callID := strings.TrimSpace(msg.Header("In-Reply-To"))
	if callID == "" {
		s.logger.Debug("submit report missing In-Reply-To", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
		return false
	}
	now := time.Now()
	s.mu.Lock()
	entry, ok := s.pending[callID]
	if ok {
		if entry.rpRef != report.Reference {
			s.mu.Unlock()
			s.handleUnexpectedSubmitReference(ctx, msg, report, entry.rpRef)
			return true
		}
		if entry.async {
			delete(s.pending, callID)
			s.mu.Unlock()
			s.completeSubmitted(callID)
			s.releaseReference(entry.rpRef)
			s.completeMOPending()
			if err := s.handleAsyncSegmentReport(entry.segment, entry.response, report); err != nil {
				s.logger.Warn("submit report", "to", entry.segment.to, "smsc", entry.segment.smscAddress, "call_id", entry.segment.msg.Header("Call-ID"), "cseq", entry.segment.msg.Header("CSeq"), "rp_ref", entry.segment.rpRef, "err", err)
				s.emitAsyncError(err)
			}
			return true
		}
		select {
		case entry.reportCh <- report:
		default:
		}
		s.mu.Unlock()
		return true
	}
	submitted, ok := s.submitted[callID]
	if ok && !submitted.expiresAt.After(now) {
		delete(s.submitted, callID)
		ok = false
	}
	s.mu.Unlock()
	if ok {
		if submitted.rpRef != report.Reference {
			s.handleUnexpectedSubmitReference(ctx, msg, report, submitted.rpRef)
			return true
		}
		if submitted.completed {
			return true
		}
		s.completeSubmitted(callID)
		s.releaseReference(submitted.rpRef)
		if err := s.handleAsyncSegmentReport(submitted.segment, submitted.response, report); err != nil {
			s.logger.Warn("submit report", "to", submitted.segment.to, "smsc", submitted.segment.smscAddress, "call_id", submitted.segment.msg.Header("Call-ID"), "cseq", submitted.segment.msg.Header("CSeq"), "rp_ref", submitted.segment.rpRef, "err", err)
			s.emitAsyncError(err)
		}
		return true
	}
	s.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference)
	return false
}

func (s *Service) handleUnexpectedSubmitReference(ctx context.Context, msg sip.Message, report rpMessage, expected byte) {
	s.logger.Debug("submit report reference mismatch", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", msg.Header("In-Reply-To"), "rp_ref", report.Reference, "expected_rp_ref", expected)
	if report.Type == rpAckNetworkToMS {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(report.Reference, rpCauseInvalidShortMessageTransferReference))
	}
}

func (s *Service) knowsSubmit(callID string, now time.Time) bool {
	if callID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.pending[callID]; ok {
		return true
	}
	submitted, ok := s.submitted[callID]
	if !ok {
		return false
	}
	if !submitted.expiresAt.After(now) {
		delete(s.submitted, callID)
		return false
	}
	return true
}

func malformedNetworkSubmitReport(body []byte) (rpMessage, bool) {
	if len(body) < 2 {
		return rpMessage{}, false
	}
	switch body[0] {
	case rpAckNetworkToMS:
		return rpMessage{Type: rpAckNetworkToMS, Reference: body[1]}, true
	case rpErrorNetworkToMS:
		return rpMessage{Type: rpErrorNetworkToMS, Reference: body[1], Cause: rpCauseProtocolErrorUnspecified, HasCause: true}, true
	default:
		return rpMessage{}, false
	}
}

func (s *Service) resolveServiceCentre() (serviceCentre, error) {
	cfgValue := strings.TrimSpace(s.cfg.ServiceCenter)
	cardCentre := usim.ServiceCentre{Address: strings.TrimSpace(s.card.SMSC())}
	if provider, ok := s.card.(serviceCentreProvider); ok {
		cardCentre = provider.ServiceCentre()
		cardCentre.Address = strings.TrimSpace(cardCentre.Address)
		cardCentre.PSI = strings.TrimSpace(cardCentre.PSI)
		if cardCentre.Address == "" {
			cardCentre.Address = strings.TrimSpace(s.card.SMSC())
		}
	}

	sc := serviceCentre{
		target:  cardCentre.Target(),
		address: cardCentre.Address,
	}
	if cfgValue != "" {
		sc.target = smsServiceCentreTarget(cfgValue)
		if address := smsServiceCentreAddress(cfgValue); address != "" {
			sc.address = address
		}
	}
	if sc.target == "" && sc.address != "" {
		sc.target = "tel:" + sc.address
	}
	if sc.target == "" {
		return serviceCentre{}, errors.New("sending SMS: service centre target is empty")
	}
	if sc.address == "" {
		return serviceCentre{}, errors.New("sending SMS: SMSC address is empty")
	}
	return sc, nil
}

func smsServiceCentreTarget(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return value
	}
	return "tel:" + value
}

func smsServiceCentreAddress(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "tel:") {
		return strings.TrimSpace(value[len("tel:"):])
	}
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return ""
	}
	return value
}

func (s *Service) newOutboundSegment(to string, sc serviceCentre, part smsUserDataPart, index, count int) (outboundSegment, error) {
	rpRef, err := s.reserveReference()
	if err != nil {
		return outboundSegment{}, err
	}
	return s.buildOutboundSegment(to, sc, part, index, count, rpRef, rpRef, 0, false)
}

func (s *Service) buildOutboundSegment(to string, sc serviceCentre, part smsUserDataPart, index, count int, rpRef, tpRef byte, retryCount int, rejectDuplicates bool) (outboundSegment, error) {
	tpdu, err := newSMSSubmitTPDU(tpRef, to, part, rejectDuplicates).MarshalBinary()
	if err != nil {
		s.releaseReference(rpRef)
		return outboundSegment{}, fmt.Errorf("sending SMS: %w", err)
	}
	rpdu, err := newRPDataMessage(rpRef, sc.address, tpdu).MarshalBinary()
	if err != nil {
		s.releaseReference(rpRef)
		return outboundSegment{}, fmt.Errorf("sending SMS: %w", err)
	}
	msg := s.buildMessage(sc.target, rpdu, "")
	callID := msg.Header("Call-ID")
	reportCh, err := s.registerPending(callID, rpRef)
	if err != nil {
		s.releaseReference(rpRef)
		return outboundSegment{}, err
	}
	return outboundSegment{
		index:            index,
		count:            count,
		to:               to,
		smscAddress:      sc.address,
		target:           sc.target,
		part:             part,
		rpRef:            rpRef,
		tpRef:            tpRef,
		retryCount:       retryCount,
		rejectDuplicates: rejectDuplicates,
		callID:           callID,
		msg:              msg,
		reportCh:         reportCh,
	}, nil
}

func (s *Service) sendSegment(ctx context.Context, segment outboundSegment) error {
	resp, err := s.sess.Exchange(ctx, segment.msg)
	if err != nil {
		s.removePending(segment.callID)
		s.releaseReference(segment.rpRef)
		return err
	}
	if status := resp.StatusCode(); status != 200 && status != 202 {
		s.removePending(segment.callID)
		s.releaseReference(segment.rpRef)
		return fmt.Errorf("sending SMS: unexpected status %d (%s)", status, strings.TrimSpace(resp.StartLine))
	}
	return s.trackSegmentReport(ctx, segment, submitResponseFromMessage(resp))
}

func (s *Service) trackSegmentReport(ctx context.Context, segment outboundSegment, response submitResponse) error {
	s.markSubmitted(segment, response, time.Now())
	select {
	case report := <-segment.reportCh:
		s.removePending(segment.callID)
		s.releaseReference(segment.rpRef)
		s.completeSubmitted(segment.callID)
		return s.finishSegmentReportWithContext(ctx, segment, response, report)
	default:
	}
	if report, ok := s.activatePendingAsync(segment, response, time.Now()); ok {
		s.completeSubmitted(segment.callID)
		s.releaseReference(segment.rpRef)
		return s.finishSegmentReportWithContext(ctx, segment, response, report)
	}
	return nil
}

func (s *Service) handleSegmentReport(segment outboundSegment, response submitResponse, report rpMessage) error {
	if report.Reference != segment.rpRef {
		return fmt.Errorf("sending SMS segment %d/%d: unexpected rp reference %d", segment.index+1, segment.count, report.Reference)
	}
	switch report.Type {
	case rpAckNetworkToMS:
		s.logger.Debug("sms segment accepted", "segment_index", segment.index+1, "segment_count", segment.count, "to", segment.to, "smsc", segment.smscAddress, "target", segment.target, "call_id", segment.msg.Header("Call-ID"), "cseq", segment.msg.Header("CSeq"), "rp_ref", segment.rpRef, "tp_ref", segment.tpRef, "status_code", response.statusCode, "reason_phrase", response.reasonPhrase)
		return nil
	case rpErrorNetworkToMS:
		return fmt.Errorf("sending SMS segment %d/%d: %w", segment.index+1, segment.count, &RPError{Cause: report.Cause})
	default:
		return fmt.Errorf("sending SMS segment %d/%d: unexpected rp type 0x%02X", segment.index+1, segment.count, report.Type)
	}
}

func (s *Service) finishSegmentReportWithContext(_ context.Context, segment outboundSegment, response submitResponse, report rpMessage) error {
	return s.handleSegmentReport(segment, response, report)
}

func (s *Service) handleAsyncSegmentReport(segment outboundSegment, response submitResponse, report rpMessage) error {
	return s.handleSegmentReport(segment, response, report)
}

func (s *Service) handleExpiredSegment(entry pendingEntry) error {
	segment := entry.segment
	s.completeSubmitted(segment.callID)
	s.releaseReference(segment.rpRef)
	s.completeMOPending()
	return fmt.Errorf("sending SMS segment %d/%d: submit report not received", segment.index+1, segment.count)
}

func (s *Service) handleMessageRequest(ctx context.Context, req session.Request) error {
	msg := req.Message
	var rp rpMessage
	if err := rp.UnmarshalBinary(msg.Body); err != nil {
		if report, ok := malformedNetworkSubmitReport(msg.Body); ok {
			callID := strings.TrimSpace(msg.Header("In-Reply-To"))
			if !s.knowsSubmit(callID, time.Now()) {
				s.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "err", err)
				return s.writeMessageStatus(ctx, req, 488, "Not Acceptable Here")
			}
			if err := s.writeMessageStatus(ctx, req, 200, "OK"); err != nil {
				return err
			}
			switch report.Type {
			case rpAckNetworkToMS:
				s.logger.Debug("submit report invalid mandatory information", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "err", err)
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(report.Reference, rpCauseInvalidMandatoryInformation))
			case rpErrorNetworkToMS:
				s.logger.Debug("submit report protocol error", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "cause", rpCauseProtocolErrorUnspecified, "err", err)
				s.completePending(ctx, msg, report)
			}
			return nil
		}
		if err := s.writeMessageStatus(ctx, req, 200, "OK"); err != nil {
			return err
		}
		if len(msg.Body) >= 2 && msg.Body[0] == rpDataNetworkToMS {
			if s.beginMTTransfer() {
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseInvalidMandatoryInformation))
				s.endMTTransfer()
			} else {
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseMessageNotCompatibleWithState))
			}
		}
		s.logger.Debug("ignoring malformed sms message", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
		return nil
	}
	if isSubmitReport(rp) {
		if s.completePending(ctx, msg, rp) {
			return s.writeMessageStatus(ctx, req, 200, "OK")
		}
		return s.writeMessageStatus(ctx, req, 488, "Not Acceptable Here")
	}
	if err := s.writeMessageStatus(ctx, req, 200, "OK"); err != nil {
		return err
	}
	return s.handleInboundRP(ctx, msg, rp)
}

func (s *Service) writeMessageStatus(ctx context.Context, req session.Request, code int, reason string) error {
	return s.sess.WriteStatus(ctx, req, code, reason)
}

func (s *Service) handleInboundRP(ctx context.Context, msg sip.Message, rp rpMessage) error {
	if rp.Type != rpDataNetworkToMS {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseMessageTypeNotImplemented))
		return nil
	}
	if !s.beginMTTransfer() {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseMessageNotCompatibleWithState))
		return nil
	}
	defer s.endMTTransfer()

	mti, err := smsTPDUMessageType(rp.TPDU)
	if err != nil {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
		return nil
	}
	switch mti {
	case tpduMTISMSDeliver, tpduMTIReserved:
		var tpdu smsDeliverTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			s.logger.Debug("rejecting inbound sms deliver", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		s.deliverIncoming(msg, rp, tpdu)
		if ok := s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference)); !ok {
			return nil
		}
	case tpduMTISMSStatusReport:
		var tpdu smsStatusReportTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			s.logger.Debug("rejecting inbound sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		s.deliverIncomingStatusReport(msg, rp, tpdu.Message)
		if ok := s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference)); !ok {
			return nil
		}
	default:
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
	}
	return nil
}

func isSubmitReport(rp rpMessage) bool {
	return rp.Type == rpAckNetworkToMS || rp.Type == rpErrorNetworkToMS
}

func (s *Service) sendInboundDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage) bool {
	ctx = normalizeContext(ctx)
	if !s.markDeliveryReportSent(msg) {
		return true
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.clearDeliveryReportSent(msg)
		return false
	}
	s.cleanupWG.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.cleanupWG.Done()
		reportCtx, cancel := context.WithTimeout(s.cleanupCtx, deliveryReportTimeout)
		defer cancel()
		if err := s.sendDeliveryReport(reportCtx, msg, report); err != nil {
			s.clearDeliveryReportSent(msg)
			if ctx.Err() == nil && s.cleanupCtx.Err() == nil {
				s.logger.Warn("sending inbound sms delivery report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
			}
		}
	}()
	return true
}

func (s *Service) sendDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage) error {
	target := s.reportTarget(msg)
	if target == "" {
		return errors.New("delivery report target is empty")
	}
	payload, err := report.MarshalBinary()
	if err != nil {
		return fmt.Errorf("building sms delivery report: %w", err)
	}
	reportMsg := s.buildMessage(target, payload, msg.Header("Call-ID"))
	resp, err := s.sess.Exchange(normalizeContext(ctx), reportMsg)
	if err != nil {
		return fmt.Errorf("sending sms delivery report: %w", err)
	}
	if status := resp.StatusCode(); status != 200 && status != 202 {
		return fmt.Errorf("sending sms delivery report: unexpected status %d", status)
	}
	return nil
}

func (s *Service) deliverIncoming(msg sip.Message, rp rpMessage, tpdu smsDeliverTPDU) {
	incoming := tpdu.Message
	incoming.CallID = strings.TrimSpace(msg.Header("Call-ID"))
	incoming.To = incomingRecipient(msg)
	incoming.ServiceCenter = rp.Originator
	if tpdu.Concat != nil {
		s.deliverConcat(incoming, *tpdu.Concat)
		return
	}
	s.deliverSingle(msg, incoming)
}

func (s *Service) deliverIncomingStatusReport(msg sip.Message, rp rpMessage, report StatusReport) {
	if s.cfg.OnStatusReport == nil {
		return
	}
	report.ServiceCenter = rp.Originator
	if s.markSeen(msg) {
		s.cfg.OnStatusReport(report)
		return
	}
	s.logger.Debug("suppressing duplicate sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "message_reference", report.MessageReference, "status", report.Status)
}

func incomingRecipient(msg sip.Message) string {
	for _, candidate := range []string{msg.Header("To"), sip.RequestURI(msg)} {
		if target := envelopeAddress(candidate); target != "" {
			return target
		}
	}
	return ""
}

func envelopeAddress(value string) string {
	uri := sip.AddressURI(value)
	if uri == "" {
		return ""
	}
	switch lower := strings.ToLower(uri); {
	case strings.HasPrefix(lower, "tel:"):
		return uri[len("tel:"):]
	case strings.HasPrefix(lower, "sip:"), strings.HasPrefix(lower, "sips:"):
		return uri
	default:
		return uri
	}
}

func (s *Service) deliverConcat(msg Incoming, concat smsConcatInfo) {
	if s.cfg.OnIncoming == nil {
		return
	}
	incoming, complete, concatKey := s.appendConcat(msg, concat)
	if !complete {
		return
	}
	if s.markConcatSeen(concatKey) {
		s.cfg.OnIncoming(incoming)
	}
}

func (s *Service) deliverSingle(msg sip.Message, incoming Incoming) {
	if s.cfg.OnIncoming == nil {
		return
	}
	if s.markSeen(msg) {
		s.cfg.OnIncoming(incoming)
		return
	}
	s.logger.Debug("suppressing duplicate sms", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "from", incoming.From, "text", incoming.Text)
}

func (s *Service) buildMessage(target string, body []byte, inReplyTo string) sip.Message {
	state := s.reg.State()
	if target == "" {
		target = s.mustResolveServiceCentreTarget()
	}
	callID, _, tag, branch := sip.NewTransaction()
	senderIdentity := preferredIdentity(state)
	msg := sip.NewRequest("MESSAGE", target)
	msg.Headers.Add("Call-ID", callID)
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, tag))
	msg.Headers.Add("To", fmt.Sprintf("<%s>", target))
	msg.Headers.Add("Request-Disposition", "no-fork")
	msg.Headers.Add("Accept-Contact", "*;+g.3gpp.smsip")
	msg.Headers.Add("CSeq", fmt.Sprintf("%d MESSAGE", atomic.AddInt64(&s.cseq, 1)))
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, branch))
	msg.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	s.reg.RequestPolicy().Apply(&msg)
	msg.Headers.Add("Content-Type", "application/vnd.3gpp.sms")
	msg.Headers.Add("Content-Transfer-Encoding", "binary")
	if inReplyTo != "" {
		msg.Headers.Add("In-Reply-To", inReplyTo)
	}
	msg.Body = body
	return msg
}

func preferredIdentity(state registration.State) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(state.TelPublicID)), "tel:") {
		return state.TelPublicID
	}
	if identity := strings.TrimSpace(state.DefaultPublicID); identity != "" {
		return identity
	}
	return state.PublicIdentity
}

func (s *Service) mustResolveServiceCentreTarget() string {
	sc, _ := s.resolveServiceCentre()
	return sc.target
}

func (s *Service) reportTarget(msg sip.Message) string {
	for _, candidate := range []string{
		sip.AddressURI(msg.Header("P-Asserted-Identity")),
		sip.AddressURI(msg.Header("From")),
	} {
		if target := sipMessageTarget(candidate); target != "" {
			return target
		}
	}
	return viaMessageTarget(msg)
}

func sipMessageTarget(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	lower := strings.ToLower(uri)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return uri
	}
	return ""
}

func viaMessageTarget(msg sip.Message) string {
	var last string
	for _, value := range msg.HeadersByName("Via") {
		for part := range strings.SplitSeq(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				last = trimmed
			}
		}
	}
	if last == "" {
		return ""
	}
	fields := strings.Fields(last)
	if len(fields) < 2 {
		return ""
	}
	sentBy, _, _ := strings.Cut(fields[1], ";")
	sentBy = strings.TrimSpace(sentBy)
	if sentBy == "" {
		return ""
	}
	return "sip:" + sentBy
}

func (s *Service) markRecentKey(key string, ttl time.Duration) bool {
	if key == "" {
		return true
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for seenKey, seenAt := range s.recent {
		if now.Sub(seenAt) > ttl {
			delete(s.recent, seenKey)
		}
	}
	if seenAt, exists := s.recent[key]; exists && now.Sub(seenAt) <= ttl {
		return false
	}
	s.recent[key] = now
	return true
}

func (s *Service) clearRecentKey(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.recent, key)
	s.mu.Unlock()
}

func (s *Service) markConcatSeen(key string) bool {
	return s.markRecentKey("concat|"+key, concatRetention)
}

func (s *Service) concatKey(msg Incoming, concat smsConcatInfo) string {
	return fmt.Sprintf("%t|%d|%s|%s", concat.SixteenBit, concat.Reference, msg.From, msg.ServiceCenter)
}

func (s *Service) evictExpiredConcat(now time.Time) {
	for cacheKey, state := range s.concat {
		if state.expired(now) {
			delete(s.concat, cacheKey)
		}
	}
}

func (s *Service) appendConcat(msg Incoming, concat smsConcatInfo) (Incoming, bool, string) {
	key := s.concatKey(msg, concat)
	now := time.Now()
	s.mu.Lock()
	s.evictExpiredConcat(now)
	state := s.concat[key]
	if state.parts == nil || state.total != int(concat.Total) {
		state.reset(int(concat.Total))
	}
	state.addPart(int(concat.Sequence), msg.Text, now)
	text, ok := state.joinedText()
	if !ok {
		s.concat[key] = state
		s.mu.Unlock()
		return Incoming{}, false, key
	}
	delete(s.concat, key)
	s.mu.Unlock()
	msg.Text = text
	return msg, true, key
}

func (s *Service) markSeen(msg sip.Message) bool {
	key, ok := smsSeenKey(msg)
	if !ok {
		return true
	}
	return s.markRecentKey("sip|"+key, 2*time.Minute)
}

func (s *Service) markDeliveryReportSent(msg sip.Message) bool {
	key, ok := smsSeenKey(msg)
	if !ok {
		return true
	}
	return s.markRecentKey("report|"+key, 2*time.Minute)
}

func (s *Service) clearDeliveryReportSent(msg sip.Message) {
	key, ok := smsSeenKey(msg)
	if !ok {
		return
	}
	s.clearRecentKey("report|" + key)
}

func smsSeenKey(msg sip.Message) (string, bool) {
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	if callID == "" || cseq == "" {
		return "", false
	}
	return callID + "|" + cseq, true
}

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

func (s *Service) emitAsyncError(err error) {
	if err == nil || s.cfg.OnError == nil {
		return
	}
	s.cfg.OnError(err)
}
