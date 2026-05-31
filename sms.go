package vowifi

import (
	"context"
	"fmt"
	"time"

	imssms "github.com/damonto/vowifi-go/ims/sms"
)

func (s *SMSService) Send(ctx context.Context, to, text string) (SMSSubmission, error) {
	low, err := s.client.currentSMSService()
	if err != nil {
		return SMSSubmission{}, fmt.Errorf("sending SMS: %w", err)
	}

	s.client.logger.Info("sending SMS", "to", to)
	submittedAt := time.Now()
	segments, err := low.Send(ctx, to, text)
	if err != nil {
		s.client.logger.Error("sending SMS", "to", to, "err", err)
		return SMSSubmission{}, err
	}

	submission := SMSSubmission{
		ID:           fmt.Sprintf("sms-%d", s.client.smsSeq.Add(1)),
		To:           to,
		Text:         text,
		SubmittedAt:  submittedAt,
		SegmentCount: len(segments),
		Segments:     make([]SMSSubmissionSegment, 0, len(segments)),
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
	s.client.trackSMSSubmission(submission)
	s.client.logger.Info("SMS submitted", "id", submission.ID, "to", submission.To, "segments", submission.SegmentCount)
	return submission, nil
}

func (c *Client) currentSMSService() (*imssms.Service, error) {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil || active.sms == nil {
		return nil, ErrClientNotConnected
	}
	return active.sms, nil
}

func (c *Client) handleSMS(msg imssms.Incoming) {
	c.emitSMS(SMS{
		CallID:        msg.CallID,
		From:          msg.From,
		To:            msg.To,
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

	c.emitSMSReport(SMSReport{
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
		UserData:              append([]byte(nil), report.UserData...),
		ReceivedAt:            time.Now(),
	})
}

func (c *Client) trackSMSSubmission(submission SMSSubmission) {
	c.smsReportsMu.Lock()
	defer c.smsReportsMu.Unlock()

	for _, segment := range submission.Segments {
		link := smsReportLink{
			submissionID:  submission.ID,
			segmentIndex:  segment.Index,
			segmentCount:  submission.SegmentCount,
			recipient:     segment.Recipient,
			serviceCenter: segment.ServiceCenter,
		}
		links := c.smsReports[segment.TPReference]
		replaced := false
		for i, existing := range links {
			if sameSMSReportRoute(existing, link) {
				links[i] = link
				replaced = true
				break
			}
		}
		if !replaced {
			links = append(links, link)
		}
		c.smsReports[segment.TPReference] = links
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

func sameSMSReportRoute(a, b smsReportLink) bool {
	return a.recipient == b.recipient && a.serviceCenter == b.serviceCenter
}

func smsReportLinkMatches(link smsReportLink, report imssms.StatusReport) bool {
	if link.recipient != "" && report.Recipient != "" && link.recipient != report.Recipient {
		return false
	}
	if link.serviceCenter != "" && report.ServiceCenter != "" && link.serviceCenter != report.ServiceCenter {
		return false
	}
	return true
}
