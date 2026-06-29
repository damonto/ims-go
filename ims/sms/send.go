package sms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Endpoint) Send(ctx context.Context, to, text string) (Submission, error) {
	if err := s.beginMOTransfer(); err != nil {
		return Submission{}, err
	}
	defer s.finishMOSend()

	sc, err := s.resolveServiceCenter()
	if err != nil {
		return Submission{}, err
	}
	parts, err := buildUserDataParts(text)
	if err != nil {
		return Submission{}, err
	}
	tracker := newSubmissionTracker(len(parts))
	submission, err := s.sendParts(ctx, to, sc, parts, tracker)
	if err != nil {
		if len(submission.Segments) > 0 {
			return submission, &PartialSubmissionError{Submission: submission, Err: err}
		}
		tracker.close()
		return Submission{}, err
	}
	return submission, nil
}

func (s *Endpoint) sendParts(ctx context.Context, to string, sc serviceCenter, parts []userDataPart, tracker *submissionTracker) (Submission, error) {
	submissions := make([]SubmissionSegment, 0, len(parts))
	for i, part := range parts {
		segment, err := s.newOutboundSegment(to, sc, part, i, len(parts), tracker)
		if err != nil {
			tracker.completeSegments(len(parts) - i)
			return newSubmission(submissions, tracker), err
		}
		response, err := s.exchangeSegment(ctx, segment)
		if err != nil {
			tracker.completeSegments(len(parts) - i)
			return newSubmission(submissions, tracker), err
		}
		submissions = append(submissions, SubmissionSegment{
			Index:         segment.index,
			Count:         segment.count,
			Recipient:     segment.recipient,
			ServiceCenter: segment.smscAddress,
			CallID:        segment.callID,
			RPReference:   segment.rpRef,
			TPReference:   segment.tpRef,
			SubmittedAt:   time.Now(),
		})
		if err := s.trackSegmentReport(ctx, segment, response); err != nil {
			tracker.completeSegments(len(parts) - i - 1)
			return newSubmission(submissions, tracker), err
		}
	}
	return newSubmission(submissions, tracker), nil
}

func newSubmission(segments []SubmissionSegment, tracker *submissionTracker) Submission {
	var updates <-chan SubmissionUpdate
	if tracker != nil {
		updates = tracker.updates
	}
	return Submission{Segments: segments, Updates: updates}
}

func (s *Endpoint) NotifyMemoryAvailable(ctx context.Context, target string) error {
	if err := s.beginMOTransfer(); err != nil {
		return err
	}
	defer s.finishMOSend()

	rpRef, err := s.reserveReference()
	if err != nil {
		return err
	}
	rpdu, err := newRPSMMAMessage(rpRef).MarshalBinary()
	if err != nil {
		s.releaseReference(rpRef)
		return fmt.Errorf("notifying SMS memory available: %w", err)
	}
	msg, err := s.buildMessage(target, rpdu, "")
	if err != nil {
		s.releaseReference(rpRef)
		return err
	}
	callID := msg.Header("Call-ID")
	reportCh, err := s.registerPending(callID, rpRef)
	if err != nil {
		s.releaseReference(rpRef)
		return err
	}
	defer s.removePending(callID)
	defer s.releaseReference(rpRef)

	resp, err := s.sess.Exchange(ctx, msg)
	if err != nil {
		return fmt.Errorf("notifying SMS memory available: %w", err)
	}
	if status := resp.StatusCode(); status != sipStatusOK && status != sipStatusAccepted {
		return fmt.Errorf("notifying SMS memory available: unexpected response: %w", sip.NewResponseError(resp))
	}
	return s.waitMemoryAvailableReport(ctx, rpRef, reportCh)
}

func (s *Endpoint) waitMemoryAvailableReport(ctx context.Context, rpRef byte, reportCh <-chan rpMessage) error {
	timer := time.NewTimer(s.cfg.SubmitReportTimeout)
	defer timer.Stop()
	select {
	case report := <-reportCh:
		if report.Reference != rpRef {
			return fmt.Errorf("notifying SMS memory available: unexpected rp reference %d", report.Reference)
		}
		switch report.Type {
		case rpAckNetworkToMS:
			return nil
		case rpErrorNetworkToMS:
			return fmt.Errorf("notifying SMS memory available: %w", &RPError{Cause: report.Cause})
		default:
			return fmt.Errorf("notifying SMS memory available: unexpected rp type 0x%02X", report.Type)
		}
	case <-ctx.Done():
		return fmt.Errorf("notifying SMS memory available: %w", ctx.Err())
	case <-timer.C:
		return errors.New("notifying SMS memory available: submit report not received")
	}
}

func (s *Endpoint) reserveReference() (byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for range 256 {
		ref := byte(atomic.AddUint32(&s.rpRef, 1))
		if _, exists := s.rpRefs[ref]; exists {
			continue
		}
		if _, _, exists := s.submittedByReference(ref, now); exists {
			continue
		}
		s.rpRefs[ref] = struct{}{}
		return ref, nil
	}
	return 0, errors.New("sending SMS: no free RP reference")
}

func (s *Endpoint) releaseReference(ref byte) {
	s.mu.Lock()
	delete(s.rpRefs, ref)
	s.mu.Unlock()
}

func (s *Endpoint) reserveTPReference() byte {
	return byte(atomic.AddUint32(&s.tpRef, 1))
}

func (s *Endpoint) beginMOTransfer() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("sending SMS: endpoint is closed")
	}
	if s.moState != moTransferIdle {
		return errors.New("sending SMS: mobile originated transfer in progress")
	}
	s.moState = moTransferSending
	return nil
}

func (s *Endpoint) finishMOSend() {
	s.mu.Lock()
	s.moState = moTransferIdle
	s.mu.Unlock()
}

func (s *Endpoint) beginMTTransfer() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.mtState != mtTransferIdle {
		return false
	}
	s.mtState = mtTransferActive
	return true
}

func (s *Endpoint) endMTTransfer() {
	s.mu.Lock()
	s.mtState = mtTransferIdle
	s.mu.Unlock()
}

func (s *Endpoint) newOutboundSegment(to string, sc serviceCenter, part userDataPart, index, count int, tracker *submissionTracker) (outboundSegment, error) {
	rpRef, err := s.reserveReference()
	if err != nil {
		return outboundSegment{}, err
	}
	return s.buildOutboundSegment(to, sc, part, index, count, rpRef, s.reserveTPReference(), tracker)
}

func (s *Endpoint) buildOutboundSegment(to string, sc serviceCenter, part userDataPart, index, count int, rpRef, tpRef byte, tracker *submissionTracker) (outboundSegment, error) {
	tpDestination := to
	if isSIPURI(to) {
		tpDestination = dummyMSISDN
	}
	tpdu, err := newSubmitTPDU(submitTPDUConfig{
		Reference:           tpRef,
		Destination:         tpDestination,
		Part:                part,
		RequestStatusReport: s.cfg.RequestStatusReport,
	}).MarshalBinary()
	if err != nil {
		s.releaseReference(rpRef)
		return outboundSegment{}, fmt.Errorf("sending SMS: %w", err)
	}
	rpdu, err := newRPDataMessage(rpRef, sc.address, tpdu).MarshalBinary()
	if err != nil {
		s.releaseReference(rpRef)
		return outboundSegment{}, fmt.Errorf("sending SMS: %w", err)
	}
	msg, err := s.buildMessage(sc.target, rpdu, "")
	if err != nil {
		s.releaseReference(rpRef)
		return outboundSegment{}, err
	}
	if isSIPURI(to) {
		body, contentType, err := buildMultipartPayload(xmlInfo{To: to}, rpdu)
		if err != nil {
			s.releaseReference(rpRef)
			return outboundSegment{}, fmt.Errorf("sending SMS: %w", err)
		}
		msg.Body = body
		msg.Headers.Set("Content-Type", contentType)
		msg.Headers.Del("Content-Transfer-Encoding")
	}
	callID := msg.Header("Call-ID")
	segment := outboundSegment{
		index:       index,
		count:       count,
		to:          to,
		recipient:   tpDestination,
		smscAddress: sc.address,
		target:      sc.target,
		part:        part,
		rpRef:       rpRef,
		tpRef:       tpRef,
		callID:      callID,
		msg:         msg,
		tracker:     tracker,
	}
	reportCh, err := s.registerPendingSegment(segment)
	if err != nil {
		s.releaseReference(rpRef)
		return outboundSegment{}, err
	}
	segment.reportCh = reportCh
	return segment, nil
}

func isSIPURI(uri string) bool {
	scheme, _, ok := strings.Cut(strings.TrimSpace(uri), ":")
	if !ok {
		return false
	}
	return strings.EqualFold(scheme, "sip") || strings.EqualFold(scheme, "sips")
}

func (s *Endpoint) exchangeSegment(ctx context.Context, segment outboundSegment) (submitResponse, error) {
	resp, err := s.sess.Exchange(ctx, segment.msg)
	if err != nil {
		s.removePending(segment.callID)
		s.releaseReference(segment.rpRef)
		return submitResponse{}, err
	}
	if status := resp.StatusCode(); status != sipStatusOK && status != sipStatusAccepted {
		s.removePending(segment.callID)
		s.releaseReference(segment.rpRef)
		return submitResponse{}, fmt.Errorf("sending SMS: unexpected response: %w", sip.NewResponseError(resp))
	}
	return submitResponseFromMessage(resp), nil
}
