package sms

import (
	"context"
	"fmt"
	"time"
)

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

func (s *Service) trackSegmentReport(_ context.Context, segment outboundSegment, response submitResponse) error {
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

func (s *Service) handleSegmentReport(segment outboundSegment, response submitResponse, report rpMessage) error {
	if report.Reference != segment.rpRef {
		segment.tracker.completeSegment()
		return fmt.Errorf("sending SMS segment %d/%d: unexpected rp reference %d", segment.index+1, segment.count, report.Reference)
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

func (s *Service) publishSubmissionUpdate(segment outboundSegment, _ submitResponse, report rpMessage, state SubmissionState) {
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
		At:            time.Now(),
	}
	if !segment.tracker.publish(update) {
		s.logger.Debug("dropping sms submission update", "segment_index", segment.index+1, "segment_count", segment.count, "to", segment.to, "smsc", segment.smscAddress, "call_id", segment.callID, "state", state)
	}
}
