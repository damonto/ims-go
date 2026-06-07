package sms

import (
	"strings"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) completePending(msg sip.Message, report rpMessage) bool {
	now := time.Now()
	inReplyTo := strings.TrimSpace(msg.Header("In-Reply-To"))
	if inReplyTo != "" {
		return s.completePendingByCallID(msg, report, inReplyTo, now)
	}
	return s.completePendingByReference(msg, report, now)
}

func (s *Service) completePendingByReference(msg sip.Message, report rpMessage, now time.Time) bool {
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

func (s *Service) finishAsyncPendingReport(callID string, entry pendingEntry, report rpMessage) {
	s.completeSubmitted(callID)
	s.releaseReference(entry.rpRef)
	if err := s.handleSegmentReport(entry.segment, entry.response, report); err != nil {
		s.warnSubmitReport(entry.segment, err)
	}
}

func (s *Service) finishSubmittedReport(callID string, entry submittedEntry, report rpMessage) bool {
	s.completeSubmitted(callID)
	s.releaseReference(entry.rpRef)
	if err := s.handleSegmentReport(entry.segment, entry.response, report); err != nil {
		s.warnSubmitReport(entry.segment, err)
	}
	return true
}

func (s *Service) warnSubmitReport(segment outboundSegment, err error) {
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

func (s *Service) expirePendingSegment(entry pendingEntry) {
	segment := entry.segment
	s.completeSubmitted(segment.callID)
	s.releaseReference(segment.rpRef)
	s.publishSubmissionUpdate(segment, entry.response, rpMessage{}, SubmissionSubmitUnknown)
	segment.tracker.completeSegment()
	s.logger.Debug("submit report not received", "segment_index", segment.index+1, "segment_count", segment.count, "to", segment.to, "smsc", segment.smscAddress, "target", segment.target, "call_id", segment.msg.Header("Call-ID"), "cseq", segment.msg.Header("CSeq"), "rp_ref", segment.rpRef, "tp_ref", segment.tpRef, "status_code", entry.response.statusCode, "reason_phrase", entry.response.reasonPhrase)
}
