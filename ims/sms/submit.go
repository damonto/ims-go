package sms

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/ims-client/ims/sip"
	"strings"
	"time"
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
