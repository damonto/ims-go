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

func (s *Service) Send(ctx context.Context, to, text string) ([]SubmissionSegment, error) {
	if err := s.beginMOTransfer(); err != nil {
		return nil, err
	}
	defer s.finishMOSend()

	sc, err := s.resolveServiceCenter()
	if err != nil {
		return nil, err
	}
	parts, err := buildUserDataParts(text)
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
			Index:         segment.index,
			Count:         segment.count,
			Recipient:     segment.recipient,
			ServiceCenter: segment.smscAddress,
			CallID:        segment.callID,
			RPReference:   segment.rpRef,
			TPReference:   segment.tpRef,
			SubmittedAt:   time.Now(),
		})
	}
	return submissions, nil
}

func (s *Service) NotifyMemoryAvailable(ctx context.Context, target string) error {
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
	msg := s.buildMessage(strings.TrimSpace(target), rpdu, "")
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

func (s *Service) waitMemoryAvailableReport(ctx context.Context, rpRef byte, reportCh <-chan rpMessage) error {
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
	if s.moState != moTransferIdle {
		return errors.New("sending SMS: mobile originated transfer in progress")
	}
	s.moState = moTransferSending
	s.moPending = 0
	return nil
}

func (s *Service) finishMOSend() {
	s.mu.Lock()
	if s.moPending == 0 {
		s.moState = moTransferIdle
	} else {
		s.moState = moTransferWaitingReports
	}
	s.mu.Unlock()
}

func (s *Service) completeMOPending() {
	s.mu.Lock()
	if s.moPending > 0 {
		s.moPending--
	}
	if s.moState == moTransferWaitingReports && s.moPending == 0 {
		s.moState = moTransferIdle
	}
	s.mu.Unlock()
}

func (s *Service) beginMTTransfer() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.mtState != mtTransferIdle {
		return false
	}
	s.mtState = mtTransferActive
	return true
}

func (s *Service) endMTTransfer() {
	s.mu.Lock()
	s.mtState = mtTransferIdle
	s.mu.Unlock()
}

func (s *Service) newOutboundSegment(to string, sc serviceCenter, part userDataPart, index, count int) (outboundSegment, error) {
	rpRef, err := s.reserveReference()
	if err != nil {
		return outboundSegment{}, err
	}
	return s.buildOutboundSegment(to, sc, part, index, count, rpRef, rpRef)
}

func (s *Service) buildOutboundSegment(to string, sc serviceCenter, part userDataPart, index, count int, rpRef, tpRef byte) (outboundSegment, error) {
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
	msg := s.buildMessage(sc.target, rpdu, "")
	if isSIPURI(to) {
		body, contentType, err := buildMultipartSMSPayload(smsXMLInfo{To: to}, rpdu)
		if err != nil {
			s.releaseReference(rpRef)
			return outboundSegment{}, fmt.Errorf("sending SMS: %w", err)
		}
		msg.Body = body
		msg.Headers.Set("Content-Type", contentType)
		msg.Headers.Del("Content-Transfer-Encoding")
	}
	callID := msg.Header("Call-ID")
	reportCh, err := s.registerPending(callID, rpRef)
	if err != nil {
		s.releaseReference(rpRef)
		return outboundSegment{}, err
	}
	return outboundSegment{
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
		reportCh:    reportCh,
	}, nil
}

func isSIPURI(uri string) bool {
	scheme, _, ok := strings.Cut(strings.TrimSpace(uri), ":")
	if !ok {
		return false
	}
	return strings.EqualFold(scheme, "sip") || strings.EqualFold(scheme, "sips")
}

func (s *Service) sendSegment(ctx context.Context, segment outboundSegment) error {
	resp, err := s.sess.Exchange(ctx, segment.msg)
	if err != nil {
		s.removePending(segment.callID)
		s.releaseReference(segment.rpRef)
		return err
	}
	if status := resp.StatusCode(); status != sipStatusOK && status != sipStatusAccepted {
		s.removePending(segment.callID)
		s.releaseReference(segment.rpRef)
		return fmt.Errorf("sending SMS: unexpected response: %w", sip.NewResponseError(resp))
	}
	return s.trackSegmentReport(ctx, segment, submitResponseFromMessage(resp))
}
