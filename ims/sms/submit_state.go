package sms

import (
	"errors"
	"fmt"
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

func (s *Service) registerPendingSegment(segment outboundSegment) (<-chan rpMessage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
		rpRef:             segment.rpRef,
		expiresAt:         now.Add(submitRetention),
		segment:           segment,
		response:          response,
		requiresInReplyTo: submitReportRequiresInReplyTo(segment),
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
		s.mu.Unlock()
		return rpMessage{}, false
	}
}

func submitReportRequiresInReplyTo(segment outboundSegment) bool {
	return isSIPURI(segment.to)
}

func (s *Service) pendingByReference(ref byte) (string, pendingEntry, bool) {
	for callID, entry := range s.pending {
		if entry.rpRef == ref {
			return callID, entry, true
		}
	}
	return "", pendingEntry{}, false
}

func (s *Service) submittedByReference(ref byte, now time.Time) (string, submittedEntry, bool) {
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
	if _, _, ok := s.pendingByReference(ref); ok {
		return true
	}
	_, _, ok := s.submittedByReference(ref, now)
	return ok
}
