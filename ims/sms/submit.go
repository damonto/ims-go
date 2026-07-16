package sms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/sip"
)

func submitResponseFromMessage(resp sip.Message) submitResponse {
	statusCode := resp.StatusCode()
	return submitResponse{
		statusCode:   statusCode,
		reasonPhrase: strings.TrimSpace(strings.TrimPrefix(resp.StartLine, fmt.Sprintf("SIP/2.0 %d", statusCode))),
	}
}

func newSubmissionTracker(segmentCount int) *submissionTracker {
	tracker := &submissionTracker{
		updates: make(chan SubmissionUpdate, max(1, segmentCount*3)),
	}
	tracker.remaining.Store(int32(segmentCount))
	return tracker
}

func (t *submissionTracker) close() {
	if t == nil {
		return
	}
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		close(t.updates)
		t.mu.Unlock()
	})
}

func (t *submissionTracker) completeSegment() {
	if t == nil {
		return
	}
	for {
		remaining := t.remaining.Load()
		if remaining <= 0 {
			return
		}
		if !t.remaining.CompareAndSwap(remaining, remaining-1) {
			continue
		}
		if remaining == 1 {
			t.close()
		}
		return
	}
}

func (t *submissionTracker) completeSegments(count int) {
	for range count {
		t.completeSegment()
	}
}

func (t *submissionTracker) publish(update SubmissionUpdate) bool {
	if t == nil {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	select {
	case t.updates <- update:
		return true
	default:
		return false
	}
}

func (s *Endpoint) trackSegmentReport(_ context.Context, segment outboundSegment, response submitResponse) error {
	s.markSubmitted(segment, response, time.Now())
	s.publishSubmissionUpdate(segment, response, rpMessage{}, SubmissionSubmittedToIMS)
	if report, ok := s.activatePendingAsync(segment, response, time.Now()); ok {
		s.completeSubmitted(segment.callID)
		s.releaseReference(segment.rpRef)
		err := s.handleSegmentReport(segment, response, report)
		if segment.tracker != nil && report.Reference == segment.rpRef && report.Type == rpErrorNetworkToMS {
			return nil
		}
		return err
	}
	return nil
}

func (s *Endpoint) handleSegmentReport(segment outboundSegment, response submitResponse, report rpMessage) error {
	if report.Reference != segment.rpRef {
		segment.tracker.completeSegment()
		return fmt.Errorf("sending SMS segment %d/%d: unexpected rp reference %d", segment.index+1, segment.count, report.Reference)
	}
	if len(report.UserData) != 0 {
		submitReport, err := decodeSubmitReport(report.UserData, report.Type == rpErrorNetworkToMS)
		if err != nil {
			segment.tracker.completeSegment()
			return fmt.Errorf("sending SMS segment %d/%d: decoding SMS-SUBMIT-REPORT: %w", segment.index+1, segment.count, err)
		}
		report.SubmitReport = &submitReport
	}
	switch report.Type {
	case rpAckNetworkToMS:
		s.publishSubmissionUpdate(segment, response, report, SubmissionAcceptedBySMSC)
		segment.tracker.completeSegment()
		s.logger.Debug("sms segment accepted", "segment_index", segment.index+1, "segment_count", segment.count, "to", segment.to, "smsc", segment.smscAddress, "target", segment.target, "call_id", segment.msg.Header("Call-ID"), "cseq", segment.msg.Header("CSeq"), "rp_ref", segment.rpRef, "tp_ref", segment.tpRef, "status_code", response.statusCode, "reason_phrase", response.reasonPhrase)
		return nil
	case rpErrorNetworkToMS:
		s.publishSubmissionUpdate(segment, response, report, SubmissionRejectedBySMSC)
		segment.tracker.completeSegment()
		return fmt.Errorf("sending SMS segment %d/%d: %w", segment.index+1, segment.count, &RPError{Cause: report.Cause})
	default:
		segment.tracker.completeSegment()
		return fmt.Errorf("sending SMS segment %d/%d: unexpected rp type 0x%02X", segment.index+1, segment.count, report.Type)
	}
}

func (s *Endpoint) publishSubmissionUpdate(segment outboundSegment, _ submitResponse, report rpMessage, state SubmissionState) {
	if segment.tracker == nil {
		return
	}
	update := SubmissionUpdate{
		Index:         segment.index,
		Count:         segment.count,
		Recipient:     segment.recipient,
		ServiceCenter: segment.smscAddress,
		CallID:        segment.callID,
		RPReference:   segment.rpRef,
		TPReference:   segment.tpRef,
		State:         state,
		RPCause:       report.Cause,
		HasRPCause:    report.HasCause,
		SubmitReport:  report.SubmitReport,
		At:            time.Now(),
	}
	if !segment.tracker.publish(update) {
		s.logger.Debug("dropping sms submission update", "segment_index", segment.index+1, "segment_count", segment.count, "to", segment.to, "smsc", segment.smscAddress, "call_id", segment.callID, "state", state)
	}
}

func (s *Endpoint) registerPending(callID string, rpRef byte) (<-chan rpMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("sending SMS: endpoint is closed")
	}
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

func (s *Endpoint) registerPendingSegment(segment outboundSegment) (<-chan rpMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("sending SMS: endpoint is closed")
	}
	if segment.callID == "" {
		return nil, errors.New("sending SMS: call id is empty")
	}
	if _, exists := s.pending[segment.callID]; exists {
		return nil, fmt.Errorf("sending SMS: duplicate Call-ID %q", segment.callID)
	}
	ch := make(chan rpMessage, 1)
	s.pending[segment.callID] = pendingEntry{
		rpRef:    segment.rpRef,
		reportCh: ch,
		segment:  segment,
	}
	return ch, nil
}

func (s *Endpoint) removePending(callID string) {
	s.mu.Lock()
	delete(s.pending, callID)
	s.mu.Unlock()
}

func (s *Endpoint) markSubmitted(segment outboundSegment, response submitResponse, now time.Time) {
	if segment.callID == "" {
		return
	}
	s.mu.Lock()
	s.submitted[segment.callID] = submittedEntry{
		rpRef:             segment.rpRef,
		expiresAt:         now.Add(submitRetention),
		segment:           segment,
		response:          response,
		requiresInReplyTo: submitReportRequiresInReplyTo(segment),
	}
	s.mu.Unlock()
}

func (s *Endpoint) completeSubmitted(callID string) {
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

func (s *Endpoint) activatePendingAsync(segment outboundSegment, response submitResponse, now time.Time) (rpMessage, bool) {
	s.mu.Lock()
	entry, ok := s.pending[segment.callID]
	if !ok {
		s.mu.Unlock()
		return rpMessage{}, false
	}
	entry.segment = segment
	entry.response = response
	entry.expiresAt = now.Add(s.submitReportTimeout())
	entry.async = true
	s.pending[segment.callID] = entry
	select {
	case report := <-entry.reportCh:
		delete(s.pending, segment.callID)
		s.mu.Unlock()
		return report, true
	default:
		s.mu.Unlock()
		return rpMessage{}, false
	}
}

func submitReportRequiresInReplyTo(segment outboundSegment) bool {
	return isSIPURI(segment.to)
}

func (s *Endpoint) pendingByReference(ref byte) (string, pendingEntry, bool) {
	for callID, entry := range s.pending {
		if entry.rpRef == ref {
			return callID, entry, true
		}
	}
	return "", pendingEntry{}, false
}

func (s *Endpoint) submittedByReference(ref byte, now time.Time) (string, submittedEntry, bool) {
	var completedCallID string
	var completed submittedEntry
	for callID, entry := range s.submitted {
		if !entry.expiresAt.After(now) {
			delete(s.submitted, callID)
			continue
		}
		if entry.rpRef != ref {
			continue
		}
		if !entry.completed {
			return callID, entry, true
		}
		if completedCallID == "" {
			completedCallID = callID
			completed = entry
		}
	}
	if completedCallID != "" {
		return completedCallID, completed, true
	}
	return "", submittedEntry{}, false
}

func (s *Endpoint) knowsSubmit(ref byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.pendingByReference(ref); ok {
		return true
	}
	_, _, ok := s.submittedByReference(ref, now)
	return ok
}

func (s *Endpoint) completePending(msg sip.Message, report rpMessage) bool {
	now := time.Now()
	inReplyTo := strings.TrimSpace(msg.Header("In-Reply-To"))
	if inReplyTo != "" {
		return s.completePendingByCallID(msg, report, inReplyTo, now)
	}
	return s.completePendingByReference(msg, report, now)
}

func (s *Endpoint) completePendingByReference(msg sip.Message, report rpMessage, now time.Time) bool {
	s.mu.Lock()
	callID, entry, ok := s.pendingByReference(report.Reference)
	if ok {
		if submitReportRequiresInReplyTo(entry.segment) {
			s.mu.Unlock()
			s.logger.Debug("submit report missing In-Reply-To", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
			return false
		}
		if entry.async {
			delete(s.pending, callID)
			s.mu.Unlock()
			s.finishAsyncPendingReport(callID, entry, report)
			return true
		}
		deliverPendingReport(entry, report)
		s.mu.Unlock()
		return true
	}
	callID, submitted, ok := s.submittedByReference(report.Reference, now)
	s.mu.Unlock()
	if ok {
		if submitted.requiresInReplyTo {
			s.logger.Debug("submit report missing In-Reply-To", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
			return false
		}
		if submitted.completed {
			return true
		}
		return s.finishSubmittedReport(callID, submitted, report)
	}
	s.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
	return false
}

func (s *Endpoint) completePendingByCallID(msg sip.Message, report rpMessage, inReplyTo string, now time.Time) bool {
	s.mu.Lock()
	entry, ok := s.pending[inReplyTo]
	if ok {
		if entry.rpRef != report.Reference {
			s.mu.Unlock()
			s.logger.Debug("submit report reference mismatch", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", inReplyTo, "rp_ref", report.Reference)
			return false
		}
		if entry.async {
			delete(s.pending, inReplyTo)
			s.mu.Unlock()
			s.finishAsyncPendingReport(inReplyTo, entry, report)
			return true
		}
		deliverPendingReport(entry, report)
		s.mu.Unlock()
		return true
	}
	submitted, ok := s.submitted[inReplyTo]
	if ok && !submitted.expiresAt.After(now) {
		delete(s.submitted, inReplyTo)
		ok = false
	}
	s.mu.Unlock()
	if ok {
		if submitted.rpRef != report.Reference {
			s.logger.Debug("submit report reference mismatch", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", inReplyTo, "rp_ref", report.Reference)
			return false
		}
		if submitted.completed {
			return true
		}
		return s.finishSubmittedReport(inReplyTo, submitted, report)
	}
	s.logger.Debug("submit report In-Reply-To not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", inReplyTo, "rp_ref", report.Reference)
	return false
}

func deliverPendingReport(entry pendingEntry, report rpMessage) {
	select {
	case entry.reportCh <- report:
	default:
	}
}

func (s *Endpoint) finishAsyncPendingReport(callID string, entry pendingEntry, report rpMessage) {
	s.completeSubmitted(callID)
	s.releaseReference(entry.rpRef)
	if err := s.handleSegmentReport(entry.segment, entry.response, report); err != nil {
		s.warnSubmitReport(entry.segment, err)
	}
}

func (s *Endpoint) finishSubmittedReport(callID string, entry submittedEntry, report rpMessage) bool {
	s.completeSubmitted(callID)
	s.releaseReference(entry.rpRef)
	if err := s.handleSegmentReport(entry.segment, entry.response, report); err != nil {
		s.warnSubmitReport(entry.segment, err)
	}
	return true
}

func (s *Endpoint) warnSubmitReport(segment outboundSegment, err error) {
	s.logger.Warn("submit report", "to", segment.to, "smsc", segment.smscAddress, "call_id", segment.msg.Header("Call-ID"), "cseq", segment.msg.Header("CSeq"), "rp_ref", segment.rpRef, "err", err)
	s.emitAsyncError(err)
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

func (s *Endpoint) expirePendingSegment(entry pendingEntry) {
	segment := entry.segment
	s.completeSubmitted(segment.callID)
	s.releaseReference(segment.rpRef)
	s.publishSubmissionUpdate(segment, entry.response, rpMessage{}, SubmissionSubmitUnknown)
	segment.tracker.completeSegment()
	s.logger.Debug("submit report not received", "segment_index", segment.index+1, "segment_count", segment.count, "to", segment.to, "smsc", segment.smscAddress, "target", segment.target, "call_id", segment.msg.Header("Call-ID"), "cseq", segment.msg.Header("CSeq"), "rp_ref", segment.rpRef, "tp_ref", segment.tpRef, "status_code", entry.response.statusCode, "reason_phrase", entry.response.reasonPhrase)
}

func (s *Endpoint) submitSweepInterval() time.Duration {
	interval := s.submitReportTimeout() / 4
	if interval < 10*time.Millisecond {
		return 10 * time.Millisecond
	}
	if interval > time.Second {
		return time.Second
	}
	return interval
}

func (s *Endpoint) submitReportTimeout() time.Duration {
	return time.Duration(s.submitTimeout.Load())
}

func (s *Endpoint) runSubmitCleanup() {
	timer := time.NewTimer(s.submitSweepInterval())
	defer timer.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-timer.C:
			s.expireSubmitState(time.Now())
			timer.Reset(s.submitSweepInterval())
		}
	}
}

func (s *Endpoint) expireSubmitState(now time.Time) {
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
		s.expirePendingSegment(entry)
	}
}

func (s *Endpoint) closePendingSubmissions() {
	var pending []pendingEntry
	s.mu.Lock()
	for callID, entry := range s.pending {
		delete(s.pending, callID)
		if entry.segment.tracker != nil {
			pending = append(pending, entry)
		}
	}
	clear(s.submitted)
	s.mu.Unlock()
	for _, entry := range pending {
		s.releaseReference(entry.rpRef)
		if entry.async {
			s.publishSubmissionUpdate(entry.segment, entry.response, rpMessage{}, SubmissionSubmitUnknown)
		}
		entry.segment.tracker.completeSegment()
	}
}
