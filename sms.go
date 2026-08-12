package ims

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	imssms "github.com/damonto/ims-go/ims/sms"
)

type SMS struct {
	CallID        string
	From          string
	FromURI       string
	To            string
	ToURI         string
	ServiceCenter string
	Text          string
	ReceivedAt    time.Time
}

// SMSSubmissionState describes one stage of an outbound SMS submission.
type SMSSubmissionState uint8

const (
	SMSSubmissionStateUnknown SMSSubmissionState = iota
	SMSSubmittedToIMS
	SMSAcceptedBySMSC
	SMSRejectedBySMSC
	SMSSubmitUnknown
	SMSDelivered
	SMSDeliveryCompleted
	SMSDeliveryRetrying
	SMSDeliveryFailed
	SMSDeliveryUnknown
)

func (s SMSSubmissionState) String() string {
	switch s {
	case SMSSubmittedToIMS:
		return "submitted_to_ims"
	case SMSAcceptedBySMSC:
		return "accepted_by_smsc"
	case SMSRejectedBySMSC:
		return "rejected_by_smsc"
	case SMSSubmitUnknown:
		return "submit_unknown"
	case SMSDelivered:
		return "delivered"
	case SMSDeliveryCompleted:
		return "delivery_completed"
	case SMSDeliveryRetrying:
		return "delivery_retrying"
	case SMSDeliveryFailed:
		return "delivery_failed"
	case SMSDeliveryUnknown:
		return "delivery_unknown"
	default:
		return "unknown"
	}
}

type SMSReport struct {
	SubmissionID          string
	SegmentIndex          int
	SegmentCount          int
	ServiceCenter         string
	Recipient             string
	MessageReference      byte
	Status                imssms.ReportStatus
	MoreMessagesWaiting   bool
	LoopPrevention        bool
	FromCommand           bool
	HasUserDataHeader     bool
	ServiceCenterTime     time.Time
	DischargeTime         time.Time
	ProtocolIdentifier    byte
	HasProtocolIdentifier bool
	DataCodingScheme      byte
	HasDataCodingScheme   bool
	UserDataLength        int
	UserData              []byte
	ReceivedAt            time.Time
}

// SMSSubmission describes an outbound SMS accepted by the IMS stack.
//
// Updates is ordered per submission and carries both submit-report and
// delivery-report state. When delivery reports are requested, Updates can stay
// open until every segment receives a final delivery report; call Close to stop
// tracking when the caller no longer needs updates.
type SMSSubmission struct {
	ID           string
	To           string
	Text         string
	SubmittedAt  time.Time
	SegmentCount int
	Segments     []SMSSubmissionSegment
	Updates      <-chan SMSSubmissionUpdate

	closeFn func()
}

// SMSSubmissionSegment describes one TPDU segment in an outbound SMS.
type SMSSubmissionSegment struct {
	Index         int
	SubmittedAt   time.Time
	Recipient     string
	ServiceCenter string
	CallID        string
	RPReference   byte
	TPReference   byte
}

// SMSSubmissionUpdate reports one state transition for one SMS segment.
type SMSSubmissionUpdate struct {
	SubmissionID  string
	SegmentIndex  int
	SegmentCount  int
	ServiceCenter string
	Recipient     string
	CallID        string
	RPReference   byte
	TPReference   byte
	State         SMSSubmissionState
	RPCause       byte
	HasRPCause    bool
	Status        imssms.ReportStatus
	HasStatus     bool
	ReceivedAt    time.Time
}

// Close stops per-submission tracking and closes Updates.
func (s SMSSubmission) Close() {
	if s.closeFn != nil {
		s.closeFn()
	}
}

type SMSClient struct {
	client *Client
}

type smsReportLink struct {
	submissionID  string
	segmentIndex  int
	segmentCount  int
	recipient     string
	serviceCenter string
	callID        string
	rpReference   byte
	tpReference   byte
	sink          *smsSubmissionSink
}

type smsSubmissionSink struct {
	mu              sync.Mutex
	updates         chan SMSSubmissionUpdate
	queue           []SMSSubmissionUpdate
	notify          chan struct{}
	done            chan struct{}
	accepting       bool
	finishing       bool
	canceled        bool
	submitDone      bool
	cancelOnce      sync.Once
	cleanupOnce     sync.Once
	onClose         func()
	deliveryPending map[int]SMSSubmissionUpdate
	deliveryTimeout time.Duration
	deliveryCancel  context.CancelFunc
}

func (s *SMSClient) Send(ctx context.Context, to, text string) (SMSSubmission, error) {
	low, err := s.client.currentSMSClient()
	if err != nil {
		return SMSSubmission{}, fmt.Errorf("sending SMS: %w", err)
	}

	s.client.logger.Info("sending SMS", "to", to)
	submittedAt := time.Now()
	lowSubmission, err := low.Send(ctx, to, text)
	if err != nil {
		partial, ok := errors.AsType[*imssms.PartialSubmissionError](err)
		if !ok || len(partial.Submission.Segments) == 0 {
			return SMSSubmission{}, err
		}
		lowSubmission = partial.Submission
	}
	submission := s.newSMSSubmission(to, text, submittedAt, lowSubmission)
	if err != nil {
		return submission, err
	}
	s.client.logger.Info("SMS submitted", "id", submission.ID, "to", submission.To, "segments", submission.SegmentCount)
	return submission, nil
}

func (s *SMSClient) newSMSSubmission(to, text string, submittedAt time.Time, lowSubmission imssms.Submission) SMSSubmission {
	segments := lowSubmission.Segments
	id := fmt.Sprintf("sms-%d", s.client.smsSeq.Add(1))
	sink := newSMSSubmissionSink(len(segments), s.client.cfg.smsRequestStatusReport)
	sink.setDeliveryTimeout(s.client.cfg.IMS.SMSDeliveryReportTimeout)
	sink.onClose = func() {
		s.client.untrackSMSSubmission(id, sink)
	}

	submission := SMSSubmission{
		ID:           id,
		To:           to,
		Text:         text,
		SubmittedAt:  submittedAt,
		SegmentCount: len(segments),
		Segments:     make([]SMSSubmissionSegment, 0, len(segments)),
		Updates:      sink.updates,
	}
	for _, segment := range segments {
		submission.Segments = append(submission.Segments, SMSSubmissionSegment{
			Index:         segment.Index,
			SubmittedAt:   segment.SubmittedAt,
			Recipient:     segment.Recipient,
			ServiceCenter: segment.ServiceCenter,
			CallID:        segment.CallID,
			RPReference:   segment.RPReference,
			TPReference:   segment.TPReference,
		})
	}
	submission.closeFn = func() {
		sink.cancel()
	}
	s.client.trackSMSSubmission(submission, sink)
	go s.client.forwardSMSSubmitUpdates(submission.ID, lowSubmission.Updates, sink)
	return submission
}

func (c *Client) currentSMSClient() (*imssms.Endpoint, error) {
	return currentIMSEndpoint(c, func(ims imsStack) *imssms.Endpoint { return ims.sms })
}

func (c *Client) handleSMS(msg imssms.Incoming) {
	c.emitSMS(SMS{
		CallID:        msg.CallID,
		From:          msg.From,
		FromURI:       msg.FromURI,
		To:            msg.To,
		ToURI:         msg.ToURI,
		ServiceCenter: msg.ServiceCenter,
		Text:          msg.Text,
		ReceivedAt:    time.Now(),
	})
}

func (c *Client) handleSMSStatusReport(report imssms.StatusReport) {
	link, matched := c.smsReportLink(report)
	if matched && report.Status.Final() {
		c.forgetSMSReportLink(report.MessageReference, link)
	}

	event := SMSReport{
		SubmissionID:          link.submissionID,
		SegmentIndex:          link.segmentIndex,
		SegmentCount:          link.segmentCount,
		ServiceCenter:         report.ServiceCenter,
		Recipient:             report.Recipient,
		MessageReference:      report.MessageReference,
		Status:                report.Status,
		MoreMessagesWaiting:   report.MoreMessagesWaiting,
		LoopPrevention:        report.LoopPrevention,
		FromCommand:           report.FromCommand,
		HasUserDataHeader:     report.HasUserDataHeader,
		ServiceCenterTime:     report.ServiceCenterTime,
		DischargeTime:         report.DischargeTime,
		ProtocolIdentifier:    report.ProtocolIdentifier,
		HasProtocolIdentifier: report.HasProtocolIdentifier,
		DataCodingScheme:      report.DataCodingScheme,
		HasDataCodingScheme:   report.HasDataCodingScheme,
		UserDataLength:        report.UserDataLength,
		UserData:              append([]byte(nil), report.UserData...),
		ReceivedAt:            time.Now(),
	}
	c.emitSMSReport(event)
	if matched && link.sink != nil {
		link.sink.publish(smsStatusReportUpdate(event, link))
		if report.Status.Final() {
			link.sink.completeDeliverySegment(link.segmentIndex)
		}
	}
}

func (c *Client) trackSMSSubmission(submission SMSSubmission, sink *smsSubmissionSink) {
	c.smsReportsMu.Lock()
	defer c.smsReportsMu.Unlock()

	for _, segment := range submission.Segments {
		link := smsReportLink{
			submissionID:  submission.ID,
			segmentIndex:  segment.Index,
			segmentCount:  submission.SegmentCount,
			recipient:     segment.Recipient,
			serviceCenter: segment.ServiceCenter,
			callID:        segment.CallID,
			rpReference:   segment.RPReference,
			tpReference:   segment.TPReference,
			sink:          sink,
		}
		if sink != nil {
			sink.trackDeliverySegment(link)
		}
		c.smsReports[segment.TPReference] = append(c.smsReports[segment.TPReference], link)
	}
}

func (c *Client) smsReportLink(report imssms.StatusReport) (smsReportLink, bool) {
	c.smsReportsMu.Lock()
	defer c.smsReportsMu.Unlock()

	links := c.smsReports[report.MessageReference]
	return smsReportLinkFromCandidates(links, report)
}

func smsReportLinkFromCandidates(links []smsReportLink, report imssms.StatusReport) (smsReportLink, bool) {
	var match smsReportLink
	matched := false
	for _, link := range links {
		if smsReportLinkMatches(link, report) {
			if matched {
				return smsReportLink{}, false
			}
			match = link
			matched = true
		}
	}
	return match, matched
}

func (c *Client) forgetSMSReportLink(messageReference byte, link smsReportLink) {
	c.smsReportsMu.Lock()
	defer c.smsReportsMu.Unlock()

	links := c.smsReports[messageReference]
	for i, existing := range links {
		if existing == link {
			links = append(links[:i], links[i+1:]...)
			break
		}
	}
	if len(links) == 0 {
		delete(c.smsReports, messageReference)
	} else {
		c.smsReports[messageReference] = links
	}
}

func smsReportLinkMatches(link smsReportLink, report imssms.StatusReport) bool {
	if link.recipient != "" && report.Recipient != "" && link.recipient != report.Recipient {
		return false
	}
	return true
}

func newSMSSubmissionSink(segmentCount int, waitDelivery bool) *smsSubmissionSink {
	sink := &smsSubmissionSink{
		updates:   make(chan SMSSubmissionUpdate, max(1, segmentCount*4)),
		notify:    make(chan struct{}, 1),
		done:      make(chan struct{}),
		accepting: true,
	}
	if waitDelivery {
		sink.deliveryPending = make(map[int]SMSSubmissionUpdate, segmentCount)
	}
	go sink.run()
	return sink
}

func (s *smsSubmissionSink) setDeliveryTimeout(timeout time.Duration) {
	s.mu.Lock()
	s.deliveryTimeout = timeout
	s.mu.Unlock()
}

func (s *smsSubmissionSink) trackDeliverySegment(link smsReportLink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deliveryPending == nil {
		return
	}
	s.deliveryPending[link.segmentIndex] = SMSSubmissionUpdate{
		SubmissionID:  link.submissionID,
		SegmentIndex:  link.segmentIndex,
		SegmentCount:  link.segmentCount,
		ServiceCenter: link.serviceCenter,
		Recipient:     link.recipient,
		CallID:        link.callID,
		RPReference:   link.rpReference,
		TPReference:   link.tpReference,
	}
}

func (s *smsSubmissionSink) publish(update SMSSubmissionUpdate) {
	s.mu.Lock()
	if !s.accepting {
		s.mu.Unlock()
		return
	}
	s.queue = append(s.queue, update)
	s.mu.Unlock()
	s.signal()
}

func (s *smsSubmissionSink) signal() {
	select {
	case s.notify <- struct{}{}:
	default:
	}
}

func (s *smsSubmissionSink) run() {
	defer close(s.updates)
	for {
		s.mu.Lock()
		if s.canceled {
			s.mu.Unlock()
			return
		}
		if len(s.queue) > 0 {
			update := s.queue[0]
			var zero SMSSubmissionUpdate
			s.queue[0] = zero
			s.queue = s.queue[1:]
			s.mu.Unlock()
			select {
			case s.updates <- update:
			case <-s.done:
				return
			}
			continue
		}
		if s.finishing {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()

		select {
		case <-s.notify:
		case <-s.done:
			return
		}
	}
}

func (s *smsSubmissionSink) finish() {
	s.mu.Lock()
	if s.canceled || s.finishing {
		s.mu.Unlock()
		return
	}
	s.beginFinishLocked()
	s.mu.Unlock()

	s.cleanup()
	s.signal()
}

func (s *smsSubmissionSink) cancel() {
	s.cancelOnce.Do(func() {
		s.mu.Lock()
		s.accepting = false
		s.canceled = true
		clear(s.queue)
		s.queue = nil
		s.mu.Unlock()

		s.cleanup()
		close(s.done)
		s.signal()
	})
}

func (s *smsSubmissionSink) cleanup() {
	s.cleanupOnce.Do(func() {
		s.stopDeliveryTimer()
		if s.onClose != nil {
			s.onClose()
		}
	})
}

func (s *smsSubmissionSink) stopDeliveryTimer() {
	s.mu.Lock()
	cancel := s.deliveryCancel
	s.deliveryCancel = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *smsSubmissionSink) completeSubmit() {
	s.mu.Lock()
	if s.canceled || s.finishing {
		s.mu.Unlock()
		return
	}
	s.submitDone = true
	if len(s.deliveryPending) > 0 {
		s.startDeliveryTimerLocked()
		s.mu.Unlock()
		return
	}
	s.beginFinishLocked()
	s.mu.Unlock()

	s.cleanup()
	s.signal()
}

func (s *smsSubmissionSink) completeDeliverySegment(segmentIndex int) {
	s.mu.Lock()
	if s.canceled || s.finishing || len(s.deliveryPending) == 0 {
		s.mu.Unlock()
		return
	}
	if _, ok := s.deliveryPending[segmentIndex]; !ok {
		s.mu.Unlock()
		return
	}
	delete(s.deliveryPending, segmentIndex)
	if len(s.deliveryPending) > 0 || !s.submitDone {
		s.mu.Unlock()
		return
	}
	s.beginFinishLocked()
	s.mu.Unlock()

	s.cleanup()
	s.signal()
}

func (s *smsSubmissionSink) startDeliveryTimerLocked() {
	if s.deliveryTimeout <= 0 || s.deliveryCancel != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.deliveryTimeout)
	s.deliveryCancel = cancel
	go func() {
		<-ctx.Done()
		if ctx.Err() == context.DeadlineExceeded {
			s.expireDelivery(time.Now())
		}
	}()
}

func (s *smsSubmissionSink) expireDelivery(now time.Time) {
	s.mu.Lock()
	if s.canceled || s.finishing || len(s.deliveryPending) == 0 {
		s.mu.Unlock()
		return
	}
	unknown := make([]SMSSubmissionUpdate, 0, len(s.deliveryPending))
	for segmentIndex, update := range s.deliveryPending {
		update.State = SMSDeliveryUnknown
		update.ReceivedAt = now
		unknown = append(unknown, update)
		delete(s.deliveryPending, segmentIndex)
	}
	slices.SortFunc(unknown, func(a, b SMSSubmissionUpdate) int {
		return a.SegmentIndex - b.SegmentIndex
	})
	s.queue = append(s.queue, unknown...)
	s.beginFinishLocked()
	s.mu.Unlock()

	s.cleanup()
	s.signal()
}

func (s *smsSubmissionSink) beginFinishLocked() {
	s.accepting = false
	s.finishing = true
}

func (c *Client) forwardSMSSubmitUpdates(submissionID string, updates <-chan imssms.SubmissionUpdate, sink *smsSubmissionSink) {
	for update := range updates {
		sink.publish(smsSubmitUpdate(submissionID, update))
		if update.State == imssms.SubmissionRejectedBySMSC {
			sink.completeDeliverySegment(update.Index)
		}
	}
	sink.completeSubmit()
}

func smsSubmitUpdate(submissionID string, update imssms.SubmissionUpdate) SMSSubmissionUpdate {
	return SMSSubmissionUpdate{
		SubmissionID:  submissionID,
		SegmentIndex:  update.Index,
		SegmentCount:  update.Count,
		ServiceCenter: update.ServiceCenter,
		Recipient:     update.Recipient,
		CallID:        update.CallID,
		RPReference:   update.RPReference,
		TPReference:   update.TPReference,
		State:         smsSubmissionState(update.State),
		RPCause:       update.RPCause,
		HasRPCause:    update.HasRPCause,
		ReceivedAt:    update.At,
	}
}

func smsSubmissionState(state imssms.SubmissionState) SMSSubmissionState {
	switch state {
	case imssms.SubmissionSubmittedToIMS:
		return SMSSubmittedToIMS
	case imssms.SubmissionAcceptedBySMSC:
		return SMSAcceptedBySMSC
	case imssms.SubmissionRejectedBySMSC:
		return SMSRejectedBySMSC
	case imssms.SubmissionSubmitUnknown:
		return SMSSubmitUnknown
	default:
		return SMSSubmissionStateUnknown
	}
}

func smsStatusReportUpdate(report SMSReport, link smsReportLink) SMSSubmissionUpdate {
	return SMSSubmissionUpdate{
		SubmissionID:  report.SubmissionID,
		SegmentIndex:  report.SegmentIndex,
		SegmentCount:  report.SegmentCount,
		ServiceCenter: report.ServiceCenter,
		Recipient:     report.Recipient,
		CallID:        link.callID,
		RPReference:   link.rpReference,
		TPReference:   link.tpReference,
		State:         smsDeliveryState(report.Status),
		Status:        report.Status,
		HasStatus:     true,
		ReceivedAt:    report.ReceivedAt,
	}
}

func smsDeliveryState(status imssms.ReportStatus) SMSSubmissionState {
	switch {
	case status.Delivered():
		return SMSDelivered
	case status.Failed():
		return SMSDeliveryFailed
	case status.Retrying():
		return SMSDeliveryRetrying
	default:
		return SMSDeliveryCompleted
	}
}

func (c *Client) untrackSMSSubmission(submissionID string, sink *smsSubmissionSink) {
	c.smsReportsMu.Lock()
	defer c.smsReportsMu.Unlock()

	for reference, links := range c.smsReports {
		filtered := links[:0]
		for _, link := range links {
			if link.submissionID == submissionID && link.sink == sink {
				continue
			}
			filtered = append(filtered, link)
		}
		if len(filtered) == 0 {
			delete(c.smsReports, reference)
			continue
		}
		c.smsReports[reference] = filtered
	}
}
