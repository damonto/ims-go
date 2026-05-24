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

	mu           sync.Mutex
	cseq         int64
	rpRef        uint32
	smsRefs      map[byte]struct{}
	smsPending   map[string]smsPendingEntry
	smsSubmitted map[string]smsSubmittedEntry
	recentSMS    map[string]time.Time
	concatSMS    map[string]concatSMSState
	moActive     bool
	moSending    bool
	moPending    int
	mtActive     bool
	closed       bool
}

type SubmissionSegment struct {
	Index       int
	Count       int
	CallID      string
	RPReference byte
	TPReference byte
	SubmittedAt time.Time
}

type outboundSMSSegment struct {
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

type smsPendingEntry struct {
	rpRef     byte
	reportCh  chan rpMessage
	segment   outboundSMSSegment
	response  smsSubmitResponse
	expiresAt time.Time
	async     bool
}

type smsSubmittedEntry struct {
	rpRef     byte
	expiresAt time.Time
	segment   outboundSMSSegment
	response  smsSubmitResponse
	completed bool
}

type smsSubmitResponse struct {
	statusCode   int
	reasonPhrase string
}

type concatSMSState struct {
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
	concatSMSRetention       = 10 * time.Minute
	smsSubmitRetention       = 5 * time.Minute
	smsDeliveryReportTimeout = 30 * time.Second
)

var smsSubmitReportTimeoutNanos atomic.Int64

func init() {
	setSMSSubmitReportTimeout(defaultSubmitReportTimeout)
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
		cfg.SubmitReportTimeout = currentSMSSubmitReportTimeout()
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
		smsRefs:       make(map[byte]struct{}),
		smsPending:    make(map[string]smsPendingEntry),
		smsSubmitted:  make(map[string]smsSubmittedEntry),
		recentSMS:     make(map[string]time.Time),
		concatSMS:     make(map[string]concatSMSState),
	}
	attachment, err := sess.Attach(s)
	if err != nil {
		return nil, fmt.Errorf("creating sms service: %w", err)
	}
	s.attachment = attachment
	s.cleanupWG.Go(func() {
		s.runSMSSubmitCleanup()
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
		segment, err := s.newOutboundSMSSegment(to, sc, part, i, len(parts))
		if err != nil {
			return nil, err
		}
		if err := s.sendSMSSegment(ctx, segment); err != nil {
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

func currentSMSSubmitReportTimeout() time.Duration {
	return time.Duration(smsSubmitReportTimeoutNanos.Load())
}

func setSMSSubmitReportTimeout(timeout time.Duration) {
	smsSubmitReportTimeoutNanos.Store(int64(timeout))
}

func newConcatSMSState(total int) concatSMSState {
	return concatSMSState{total: total, parts: make(map[int]string, max(total, 0))}
}

func (state concatSMSState) expired(now time.Time) bool {
	return now.Sub(state.updatedAt) > concatSMSRetention
}

func (state *concatSMSState) reset(total int) {
	*state = newConcatSMSState(total)
}

func (state *concatSMSState) addPart(sequence int, text string, now time.Time) {
	if state.parts == nil {
		state.parts = make(map[int]string, max(state.total, 0))
	}
	state.parts[sequence] = text
	state.updatedAt = now
}

func (state concatSMSState) joinedText() (string, bool) {
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

func (s *Service) reserveSMSReference() (byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for range 256 {
		ref := byte(atomic.AddUint32(&s.rpRef, 1))
		if _, exists := s.smsRefs[ref]; exists {
			continue
		}
		s.smsRefs[ref] = struct{}{}
		return ref, nil
	}
	return 0, errors.New("sending SMS: no free RP reference")
}

func (s *Service) releaseSMSReference(ref byte) {
	s.mu.Lock()
	delete(s.smsRefs, ref)
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

func (s *Service) registerSMSPending(callID string, rpRef byte) (<-chan rpMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if callID == "" {
		return nil, errors.New("sending SMS: call id is empty")
	}
	if _, exists := s.smsPending[callID]; exists {
		return nil, fmt.Errorf("sending SMS: duplicate Call-ID %q", callID)
	}
	ch := make(chan rpMessage, 1)
	s.smsPending[callID] = smsPendingEntry{rpRef: rpRef, reportCh: ch}
	return ch, nil
}

func (s *Service) removeSMSPending(callID string) {
	s.mu.Lock()
	delete(s.smsPending, callID)
	s.mu.Unlock()
}

func (s *Service) markSMSSubmitted(segment outboundSMSSegment, response smsSubmitResponse, now time.Time) {
	if segment.callID == "" {
		return
	}
	s.mu.Lock()
	s.smsSubmitted[segment.callID] = smsSubmittedEntry{
		rpRef:     segment.rpRef,
		expiresAt: now.Add(smsSubmitRetention),
		segment:   segment,
		response:  response,
	}
	s.mu.Unlock()
}

func (s *Service) completeSMSSubmitted(callID string) {
	if callID == "" {
		return
	}
	s.mu.Lock()
	entry, ok := s.smsSubmitted[callID]
	if ok {
		entry.segment = outboundSMSSegment{}
		entry.response = smsSubmitResponse{}
		entry.completed = true
		s.smsSubmitted[callID] = entry
	}
	s.mu.Unlock()
}

func (s *Service) smsSubmitSweepInterval() time.Duration {
	interval := s.cfg.SubmitReportTimeout / 4
	if interval < 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	if interval > time.Second {
		return time.Second
	}
	return interval
}

func (s *Service) runSMSSubmitCleanup() {
	timer := time.NewTimer(s.smsSubmitSweepInterval())
	defer timer.Stop()
	for {
		select {
		case <-s.cleanupCtx.Done():
			return
		case <-timer.C:
			s.expireSMSSubmitState(time.Now())
			timer.Reset(s.smsSubmitSweepInterval())
		}
	}
}

func (s *Service) expireSMSSubmitState(now time.Time) {
	var expired []smsPendingEntry
	s.mu.Lock()
	s.evictExpiredConcatSMS(now)
	for callID, entry := range s.smsSubmitted {
		if !entry.expiresAt.After(now) {
			delete(s.smsSubmitted, callID)
		}
	}
	for callID, entry := range s.smsPending {
		if !entry.async || entry.expiresAt.IsZero() || entry.expiresAt.After(now) {
			continue
		}
		delete(s.smsPending, callID)
		expired = append(expired, entry)
	}
	s.mu.Unlock()
	for _, entry := range expired {
		if err := s.handleExpiredSMSSegment(entry); err != nil {
			s.emitAsyncError(err)
		}
	}
}

func smsSubmitResponseFromMessage(resp sip.Message) smsSubmitResponse {
	statusCode := resp.StatusCode()
	return smsSubmitResponse{
		statusCode:   statusCode,
		reasonPhrase: strings.TrimSpace(strings.TrimPrefix(resp.StartLine, fmt.Sprintf("SIP/2.0 %d", statusCode))),
	}
}

func (s *Service) activateSMSPendingAsync(segment outboundSMSSegment, response smsSubmitResponse, now time.Time) (rpMessage, bool) {
	s.mu.Lock()
	entry, ok := s.smsPending[segment.callID]
	if !ok {
		s.mu.Unlock()
		return rpMessage{}, false
	}
	entry.segment = segment
	entry.response = response
	entry.expiresAt = now.Add(s.cfg.SubmitReportTimeout)
	entry.async = true
	s.smsPending[segment.callID] = entry
	select {
	case report := <-entry.reportCh:
		delete(s.smsPending, segment.callID)
		s.mu.Unlock()
		return report, true
	default:
		s.moPending++
		s.mu.Unlock()
		return rpMessage{}, false
	}
}

func (s *Service) completeSMSPending(ctx context.Context, msg sip.Message, report rpMessage) bool {
	callID := strings.TrimSpace(msg.Header("In-Reply-To"))
	if callID == "" {
		s.logger.Debug("submit report missing In-Reply-To", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
		return false
	}
	now := time.Now()
	s.mu.Lock()
	entry, ok := s.smsPending[callID]
	if ok {
		if entry.rpRef != report.Reference {
			s.mu.Unlock()
			s.handleUnexpectedSMSSubmitReference(ctx, msg, report, entry.rpRef)
			return true
		}
		if entry.async {
			delete(s.smsPending, callID)
			s.mu.Unlock()
			s.completeSMSSubmitted(callID)
			s.releaseSMSReference(entry.rpRef)
			s.completeMOPending()
			if err := s.handleAsyncSMSSegmentReport(entry.segment, entry.response, report); err != nil {
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
	submitted, ok := s.smsSubmitted[callID]
	if ok && !submitted.expiresAt.After(now) {
		delete(s.smsSubmitted, callID)
		ok = false
	}
	s.mu.Unlock()
	if ok {
		if submitted.rpRef != report.Reference {
			s.handleUnexpectedSMSSubmitReference(ctx, msg, report, submitted.rpRef)
			return true
		}
		if submitted.completed {
			return true
		}
		s.completeSMSSubmitted(callID)
		s.releaseSMSReference(submitted.rpRef)
		if err := s.handleAsyncSMSSegmentReport(submitted.segment, submitted.response, report); err != nil {
			s.logger.Warn("submit report", "to", submitted.segment.to, "smsc", submitted.segment.smscAddress, "call_id", submitted.segment.msg.Header("Call-ID"), "cseq", submitted.segment.msg.Header("CSeq"), "rp_ref", submitted.segment.rpRef, "err", err)
			s.emitAsyncError(err)
		}
		return true
	}
	s.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference)
	return false
}

func (s *Service) handleUnexpectedSMSSubmitReference(ctx context.Context, msg sip.Message, report rpMessage, expected byte) {
	s.logger.Debug("submit report reference mismatch", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", msg.Header("In-Reply-To"), "rp_ref", report.Reference, "expected_rp_ref", expected)
	if report.Type == rpAckNetworkToMS {
		_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(report.Reference, rpCauseInvalidShortMessageTransferReference))
	}
}

func (s *Service) knowsSMSSubmit(callID string, now time.Time) bool {
	if callID == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.smsPending[callID]; ok {
		return true
	}
	submitted, ok := s.smsSubmitted[callID]
	if !ok {
		return false
	}
	if !submitted.expiresAt.After(now) {
		delete(s.smsSubmitted, callID)
		return false
	}
	return true
}

func malformedNetworkSMSSubmitReport(body []byte) (rpMessage, bool) {
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

func (s *Service) newOutboundSMSSegment(to string, sc serviceCentre, part smsUserDataPart, index, count int) (outboundSMSSegment, error) {
	rpRef, err := s.reserveSMSReference()
	if err != nil {
		return outboundSMSSegment{}, err
	}
	return s.buildOutboundSMSSegment(to, sc, part, index, count, rpRef, rpRef, 0, false)
}

func (s *Service) buildOutboundSMSSegment(to string, sc serviceCentre, part smsUserDataPart, index, count int, rpRef, tpRef byte, retryCount int, rejectDuplicates bool) (outboundSMSSegment, error) {
	tpdu, err := newSMSSubmitTPDU(tpRef, to, part, rejectDuplicates).MarshalBinary()
	if err != nil {
		s.releaseSMSReference(rpRef)
		return outboundSMSSegment{}, fmt.Errorf("sending SMS: %w", err)
	}
	rpdu, err := newRPDataMessage(rpRef, sc.address, tpdu).MarshalBinary()
	if err != nil {
		s.releaseSMSReference(rpRef)
		return outboundSMSSegment{}, fmt.Errorf("sending SMS: %w", err)
	}
	msg := s.buildMessage(sc.target, rpdu, "")
	callID := msg.Header("Call-ID")
	reportCh, err := s.registerSMSPending(callID, rpRef)
	if err != nil {
		s.releaseSMSReference(rpRef)
		return outboundSMSSegment{}, err
	}
	return outboundSMSSegment{
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

func (s *Service) sendSMSSegment(ctx context.Context, segment outboundSMSSegment) error {
	resp, err := s.sess.Exchange(ctx, segment.msg)
	if err != nil {
		s.removeSMSPending(segment.callID)
		s.releaseSMSReference(segment.rpRef)
		return err
	}
	if status := resp.StatusCode(); status != 200 && status != 202 {
		s.removeSMSPending(segment.callID)
		s.releaseSMSReference(segment.rpRef)
		return fmt.Errorf("sending SMS: unexpected status %d (%s)", status, strings.TrimSpace(resp.StartLine))
	}
	return s.trackSMSSegmentReport(ctx, segment, smsSubmitResponseFromMessage(resp))
}

func (s *Service) trackSMSSegmentReport(ctx context.Context, segment outboundSMSSegment, response smsSubmitResponse) error {
	s.markSMSSubmitted(segment, response, time.Now())
	select {
	case report := <-segment.reportCh:
		s.removeSMSPending(segment.callID)
		s.releaseSMSReference(segment.rpRef)
		s.completeSMSSubmitted(segment.callID)
		return s.finishSMSSegmentReportWithContext(ctx, segment, response, report)
	default:
	}
	if report, ok := s.activateSMSPendingAsync(segment, response, time.Now()); ok {
		s.completeSMSSubmitted(segment.callID)
		s.releaseSMSReference(segment.rpRef)
		return s.finishSMSSegmentReportWithContext(ctx, segment, response, report)
	}
	return nil
}

func (s *Service) handleSMSSegmentReport(segment outboundSMSSegment, response smsSubmitResponse, report rpMessage) error {
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

func (s *Service) finishSMSSegmentReportWithContext(_ context.Context, segment outboundSMSSegment, response smsSubmitResponse, report rpMessage) error {
	return s.handleSMSSegmentReport(segment, response, report)
}

func (s *Service) handleAsyncSMSSegmentReport(segment outboundSMSSegment, response smsSubmitResponse, report rpMessage) error {
	return s.handleSMSSegmentReport(segment, response, report)
}

func (s *Service) handleExpiredSMSSegment(entry smsPendingEntry) error {
	segment := entry.segment
	s.completeSMSSubmitted(segment.callID)
	s.releaseSMSReference(segment.rpRef)
	s.completeMOPending()
	return fmt.Errorf("sending SMS segment %d/%d: submit report not received", segment.index+1, segment.count)
}

func (s *Service) handleMessageRequest(ctx context.Context, req session.Request) error {
	msg := req.Message
	var rp rpMessage
	if err := rp.UnmarshalBinary(msg.Body); err != nil {
		if report, ok := malformedNetworkSMSSubmitReport(msg.Body); ok {
			callID := strings.TrimSpace(msg.Header("In-Reply-To"))
			if !s.knowsSMSSubmit(callID, time.Now()) {
				s.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "err", err)
				return s.writeMessageStatus(ctx, req, 488, "Not Acceptable Here")
			}
			if err := s.writeMessageStatus(ctx, req, 200, "OK"); err != nil {
				return err
			}
			switch report.Type {
			case rpAckNetworkToMS:
				s.logger.Debug("submit report invalid mandatory information", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "err", err)
				_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(report.Reference, rpCauseInvalidMandatoryInformation))
			case rpErrorNetworkToMS:
				s.logger.Debug("submit report protocol error", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "cause", rpCauseProtocolErrorUnspecified, "err", err)
				s.completeSMSPending(ctx, msg, report)
			}
			return nil
		}
		if err := s.writeMessageStatus(ctx, req, 200, "OK"); err != nil {
			return err
		}
		if len(msg.Body) >= 2 && msg.Body[0] == rpDataNetworkToMS {
			if s.beginMTTransfer() {
				_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseInvalidMandatoryInformation))
				s.endMTTransfer()
			} else {
				_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseMessageNotCompatibleWithState))
			}
		}
		s.logger.Debug("ignoring malformed sms message", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
		return nil
	}
	if isSMSReport(rp) {
		if s.completeSMSPending(ctx, msg, rp) {
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
		_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseMessageTypeNotImplemented))
		return nil
	}
	if !s.beginMTTransfer() {
		_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseMessageNotCompatibleWithState))
		return nil
	}
	defer s.endMTTransfer()

	mti, err := smsTPDUMessageType(rp.TPDU)
	if err != nil {
		_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
		return nil
	}
	switch mti {
	case tpduMTISMSDeliver, tpduMTIReserved:
		var tpdu smsDeliverTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			s.logger.Debug("rejecting inbound sms deliver", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		s.deliverIncomingSMS(msg, rp, tpdu)
		if ok := s.sendInboundSMSDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference)); !ok {
			return nil
		}
	case tpduMTISMSStatusReport:
		var tpdu smsStatusReportTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			s.logger.Debug("rejecting inbound sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		s.deliverIncomingSMSStatusReport(msg, rp, tpdu.Message)
		if ok := s.sendInboundSMSDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference)); !ok {
			return nil
		}
	default:
		_ = s.sendInboundSMSDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
	}
	return nil
}

func isSMSReport(rp rpMessage) bool {
	return rp.Type == rpAckNetworkToMS || rp.Type == rpErrorNetworkToMS
}

func (s *Service) sendInboundSMSDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage) bool {
	ctx = normalizeContext(ctx)
	if !s.markSMSDeliveryReportSent(msg) {
		return true
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.clearSMSDeliveryReportSent(msg)
		return false
	}
	s.cleanupWG.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.cleanupWG.Done()
		reportCtx, cancel := context.WithTimeout(s.cleanupCtx, smsDeliveryReportTimeout)
		defer cancel()
		if err := s.sendSMSDeliveryReport(reportCtx, msg, report); err != nil {
			s.clearSMSDeliveryReportSent(msg)
			if ctx.Err() == nil && s.cleanupCtx.Err() == nil {
				s.logger.Warn("sending inbound sms delivery report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
			}
		}
	}()
	return true
}

func (s *Service) sendSMSDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage) error {
	target := s.smsReportTarget(msg)
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

func (s *Service) deliverIncomingSMS(msg sip.Message, rp rpMessage, tpdu smsDeliverTPDU) {
	incoming := tpdu.Message
	incoming.CallID = strings.TrimSpace(msg.Header("Call-ID"))
	incoming.To = incomingSMSRecipient(msg)
	incoming.ServiceCenter = rp.Originator
	if tpdu.Concat != nil {
		s.deliverConcatSMS(incoming, *tpdu.Concat)
		return
	}
	s.deliverSingleSMS(msg, incoming)
}

func (s *Service) deliverIncomingSMSStatusReport(msg sip.Message, rp rpMessage, report StatusReport) {
	if s.cfg.OnStatusReport == nil {
		return
	}
	report.ServiceCenter = rp.Originator
	if s.markSMSSeen(msg) {
		s.cfg.OnStatusReport(report)
		return
	}
	s.logger.Debug("suppressing duplicate sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "message_reference", report.MessageReference, "status", report.Status)
}

func incomingSMSRecipient(msg sip.Message) string {
	for _, candidate := range []string{msg.Header("To"), sip.RequestURI(msg)} {
		if target := smsEnvelopeAddress(candidate); target != "" {
			return target
		}
	}
	return ""
}

func smsEnvelopeAddress(value string) string {
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

func (s *Service) deliverConcatSMS(msg Incoming, concat smsConcatInfo) {
	if s.cfg.OnIncoming == nil {
		return
	}
	incoming, complete, concatKey := s.appendConcatSMS(msg, concat)
	if !complete {
		return
	}
	if s.markConcatSMSSeen(concatKey) {
		s.cfg.OnIncoming(incoming)
	}
}

func (s *Service) deliverSingleSMS(msg sip.Message, incoming Incoming) {
	if s.cfg.OnIncoming == nil {
		return
	}
	if s.markSMSSeen(msg) {
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
	senderIdentity := smsPreferredIdentity(state)
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

func smsPreferredIdentity(state registration.State) string {
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

func (s *Service) smsReportTarget(msg sip.Message) string {
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

func (s *Service) markRecentSMSKey(key string, ttl time.Duration) bool {
	if key == "" {
		return true
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for seenKey, seenAt := range s.recentSMS {
		if now.Sub(seenAt) > ttl {
			delete(s.recentSMS, seenKey)
		}
	}
	if seenAt, exists := s.recentSMS[key]; exists && now.Sub(seenAt) <= ttl {
		return false
	}
	s.recentSMS[key] = now
	return true
}

func (s *Service) clearRecentSMSKey(key string) {
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.recentSMS, key)
	s.mu.Unlock()
}

func (s *Service) markConcatSMSSeen(key string) bool {
	return s.markRecentSMSKey("concat|"+key, concatSMSRetention)
}

func (s *Service) concatSMSKey(msg Incoming, concat smsConcatInfo) string {
	return fmt.Sprintf("%t|%d|%s|%s", concat.SixteenBit, concat.Reference, msg.From, msg.ServiceCenter)
}

func (s *Service) evictExpiredConcatSMS(now time.Time) {
	for cacheKey, state := range s.concatSMS {
		if state.expired(now) {
			delete(s.concatSMS, cacheKey)
		}
	}
}

func (s *Service) appendConcatSMS(msg Incoming, concat smsConcatInfo) (Incoming, bool, string) {
	key := s.concatSMSKey(msg, concat)
	now := time.Now()
	s.mu.Lock()
	s.evictExpiredConcatSMS(now)
	state := s.concatSMS[key]
	if state.parts == nil || state.total != int(concat.Total) {
		state.reset(int(concat.Total))
	}
	state.addPart(int(concat.Sequence), msg.Text, now)
	text, ok := state.joinedText()
	if !ok {
		s.concatSMS[key] = state
		s.mu.Unlock()
		return Incoming{}, false, key
	}
	delete(s.concatSMS, key)
	s.mu.Unlock()
	msg.Text = text
	return msg, true, key
}

func (s *Service) markSMSSeen(msg sip.Message) bool {
	key, ok := smsSeenKey(msg)
	if !ok {
		return true
	}
	return s.markRecentSMSKey("sip|"+key, 2*time.Minute)
}

func (s *Service) markSMSDeliveryReportSent(msg sip.Message) bool {
	key, ok := smsSeenKey(msg)
	if !ok {
		return true
	}
	return s.markRecentSMSKey("report|"+key, 2*time.Minute)
}

func (s *Service) clearSMSDeliveryReportSent(msg sip.Message) {
	key, ok := smsSeenKey(msg)
	if !ok {
		return
	}
	s.clearRecentSMSKey("report|" + key)
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
