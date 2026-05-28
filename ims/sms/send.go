package sms

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/sip"
	"sync/atomic"
	"time"
)

func (s *Service) Send(ctx context.Context, to, text string) ([]SubmissionSegment, error) {
	if err := s.beginMOTransfer(); err != nil {
		return nil, err
	}
	defer s.finishMOSend()

	sc, err := s.resolveServiceCentre()
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

func (s *Service) newOutboundSegment(to string, sc serviceCentre, part userDataPart, index, count int) (outboundSegment, error) {
	rpRef, err := s.reserveReference()
	if err != nil {
		return outboundSegment{}, err
	}
	return s.buildOutboundSegment(to, sc, part, index, count, rpRef, rpRef, 0, false)
}

func (s *Service) buildOutboundSegment(to string, sc serviceCentre, part userDataPart, index, count int, rpRef, tpRef byte, retryCount int, rejectDuplicates bool) (outboundSegment, error) {
	tpdu, err := newSubmitTPDU(tpRef, to, part, rejectDuplicates).MarshalBinary()
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
		return fmt.Errorf("sending SMS: unexpected response: %w", sip.NewResponseError(resp))
	}
	return s.trackSegmentReport(ctx, segment, submitResponseFromMessage(resp))
}
