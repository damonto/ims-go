package sms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

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

func (s *Service) completePending(msg sip.Message, report rpMessage) bool {
	now := time.Now()
	inReplyTo := strings.TrimSpace(msg.Header("In-Reply-To"))
	if inReplyTo != "" {
		return s.completePendingByCallID(msg, report, inReplyTo, now)
	}
	s.mu.Lock()
	callID, entry, ok := s.pendingByReferenceLocked(report.Reference)
	if ok {
		if submitReportRequiresInReplyTo(entry.segment) {
			s.mu.Unlock()
			s.logger.Debug("submit report missing In-Reply-To", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
			return false
		}
		if entry.async {
			delete(s.pending, callID)
			s.mu.Unlock()
			s.completeSubmitted(callID)
			s.releaseReference(entry.rpRef)
			if err := s.handleAsyncSegmentReport(entry.segment, entry.response, report); err != nil {
				s.logger.Warn("submit report", "to", entry.segment.to, "smsc", entry.segment.smscAddress, "call_id", entry.segment.msg.Header("Call-ID"), "cseq", entry.segment.msg.Header("CSeq"), "rp_ref", entry.segment.rpRef, "err", err)
				s.emitAsyncError(err)
			}
			s.completeMOPending()
			return true
		}
		select {
		case entry.reportCh <- report:
		default:
		}
		s.mu.Unlock()
		return true
	}
	callID, submitted, ok := s.submittedByReferenceLocked(report.Reference, now)
	s.mu.Unlock()
	if ok {
		if submitReportRequiresInReplyTo(submitted.segment) {
			s.logger.Debug("submit report missing In-Reply-To", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
			return false
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
	s.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference)
	return false
}

func (s *Service) completePendingByCallID(msg sip.Message, report rpMessage, inReplyTo string, now time.Time) bool {
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
			s.completeSubmitted(inReplyTo)
			s.releaseReference(entry.rpRef)
			if err := s.handleAsyncSegmentReport(entry.segment, entry.response, report); err != nil {
				s.logger.Warn("submit report", "to", entry.segment.to, "smsc", entry.segment.smscAddress, "call_id", entry.segment.msg.Header("Call-ID"), "cseq", entry.segment.msg.Header("CSeq"), "rp_ref", entry.segment.rpRef, "err", err)
				s.emitAsyncError(err)
			}
			s.completeMOPending()
			return true
		}
		select {
		case entry.reportCh <- report:
		default:
		}
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
		s.completeSubmitted(inReplyTo)
		s.releaseReference(submitted.rpRef)
		if err := s.handleAsyncSegmentReport(submitted.segment, submitted.response, report); err != nil {
			s.logger.Warn("submit report", "to", submitted.segment.to, "smsc", submitted.segment.smscAddress, "call_id", submitted.segment.msg.Header("Call-ID"), "cseq", submitted.segment.msg.Header("CSeq"), "rp_ref", submitted.segment.rpRef, "err", err)
			s.emitAsyncError(err)
		}
		return true
	}
	s.logger.Debug("submit report In-Reply-To not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", inReplyTo, "rp_ref", report.Reference)
	return false
}

func submitReportRequiresInReplyTo(segment outboundSegment) bool {
	return isSIPURI(segment.to)
}

func (s *Service) pendingByReferenceLocked(ref byte) (string, pendingEntry, bool) {
	for callID, entry := range s.pending {
		if entry.rpRef == ref {
			return callID, entry, true
		}
	}
	return "", pendingEntry{}, false
}

func (s *Service) submittedByReferenceLocked(ref byte, now time.Time) (string, submittedEntry, bool) {
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

func (s *Service) knowsSubmit(ref byte, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, _, ok := s.pendingByReferenceLocked(ref); ok {
		return true
	}
	_, _, ok := s.submittedByReferenceLocked(ref, now)
	return ok
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
