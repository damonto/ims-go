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

	submittedAt := time.Now()
	segments, err := low.Send(ctx, to, text)
	if err != nil {
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
			Index:       segment.Index,
			SubmittedAt: segment.SubmittedAt,
			CallID:      segment.CallID,
			RPReference: segment.RPReference,
			TPReference: segment.TPReference,
		})
	}
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
	c.emitSMSReport(SMSReport{
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
