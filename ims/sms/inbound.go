package sms

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"github.com/damonto/vowifi-go/usim"
	"strings"
	"sync/atomic"
	"time"
)

func (s *Service) handleMessageRequest(ctx context.Context, req session.Request) error {
	msg := req.Message
	var rp rpMessage
	if err := rp.UnmarshalBinary(msg.Body); err != nil {
		if report, ok := malformedNetworkSubmitReport(msg.Body); ok {
			callID := strings.TrimSpace(msg.Header("In-Reply-To"))
			if !s.knowsSubmit(callID, time.Now()) {
				s.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "err", err)
				return s.writeMessageStatus(ctx, req, 488, "Not Acceptable Here")
			}
			if err := s.writeMessageStatus(ctx, req, 200, "OK"); err != nil {
				return err
			}
			switch report.Type {
			case rpAckNetworkToMS:
				s.logger.Debug("submit report invalid mandatory information", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "err", err)
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(report.Reference, rpCauseInvalidMandatoryInformation))
			case rpErrorNetworkToMS:
				s.logger.Debug("submit report protocol error", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "in_reply_to", callID, "rp_ref", report.Reference, "cause", rpCauseProtocolErrorUnspecified, "err", err)
				s.completePending(ctx, msg, report)
			}
			return nil
		}
		if err := s.writeMessageStatus(ctx, req, 200, "OK"); err != nil {
			return err
		}
		if len(msg.Body) >= 2 && msg.Body[0] == rpDataNetworkToMS {
			if s.beginMTTransfer() {
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseInvalidMandatoryInformation))
				s.endMTTransfer()
			} else {
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseMessageNotCompatibleWithState))
			}
		}
		s.logger.Debug("ignoring malformed sms message", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
		return nil
	}
	if isSubmitReport(rp) {
		if s.completePending(ctx, msg, rp) {
			return s.writeMessageStatus(ctx, req, 200, "OK")
		}
		return s.writeMessageStatus(ctx, req, 488, "Not Acceptable Here")
	}
	if err := s.writeMessageStatus(ctx, req, 200, "OK"); err != nil {
		return err
	}
	return s.handleInboundRP(ctx, msg, rp)
}

func (s *Service) writeMessageStatus(ctx context.Context, req session.Request, code int, reason string) error {
	return s.sess.WriteStatus(ctx, req, code, reason)
}

func (s *Service) handleInboundRP(ctx context.Context, msg sip.Message, rp rpMessage) error {
	if rp.Type != rpDataNetworkToMS {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseMessageTypeNotImplemented))
		return nil
	}
	if !s.beginMTTransfer() {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseMessageNotCompatibleWithState))
		return nil
	}
	defer s.endMTTransfer()

	mti, err := tpduMessageType(rp.TPDU)
	if err != nil {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
		return nil
	}
	switch mti {
	case tpduMTIDeliver, tpduMTIReserved:
		fields, err := decodeDeliverFields(rp.TPDU)
		if err != nil {
			s.logger.Debug("rejecting inbound sms deliver", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		if isPPDataDownload(fields.part) {
			s.handlePPDataDownload(ctx, msg, rp)
			return nil
		}

		var tpdu deliverTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			s.logger.Debug("rejecting inbound sms deliver", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		s.deliverIncoming(msg, rp, tpdu)
		if ok := s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference, nil)); !ok {
			return nil
		}
	case tpduMTIStatusReport:
		var tpdu statusReportTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			s.logger.Debug("rejecting inbound sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
			return nil
		}
		s.deliverIncomingStatusReport(msg, rp, tpdu.Message)
		if ok := s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference, nil)); !ok {
			return nil
		}
	default:
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation))
	}
	return nil
}

func (s *Service) handlePPDataDownload(ctx context.Context, msg sip.Message, rp rpMessage) {
	downloader, ok := s.card.(ppDownloader)
	if !ok {
		s.logger.Debug("rejecting sms-pp data download", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", "card does not support SMS-PP download")
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseProtocolErrorUnspecified))
		return
	}

	resp, err := downloader.SMSPPDownload(ctx, usim.SMSPPDownloadRequest{
		ServiceCenterAddress: rp.Originator,
		TPDU:                 rp.TPDU,
	})
	if err != nil {
		s.logger.Debug("rejecting sms-pp data download", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseProtocolErrorUnspecified))
		return
	}
	s.logger.Debug("sms-pp data download delivered", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "sw1", resp.SW1, "sw2", resp.SW2, "response_len", len(resp.Data))
	_ = s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference, resp.Data))
}

func isSubmitReport(rp rpMessage) bool {
	return rp.Type == rpAckNetworkToMS || rp.Type == rpErrorNetworkToMS
}

func (s *Service) sendInboundDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage) bool {
	if !s.markDeliveryReportSent(msg) {
		return true
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.clearDeliveryReportSent(msg)
		return false
	}
	s.cleanupWG.Add(1)
	s.mu.Unlock()

	go func() {
		defer s.cleanupWG.Done()
		reportCtx, cancel := context.WithTimeout(s.cleanupCtx, deliveryReportTimeout)
		defer cancel()
		if err := s.sendDeliveryReport(reportCtx, msg, report); err != nil {
			s.clearDeliveryReportSent(msg)
			if ctx.Err() == nil && s.cleanupCtx.Err() == nil {
				s.logger.Warn("sending inbound sms delivery report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
			}
		}
	}()
	return true
}

func (s *Service) sendDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage) error {
	target := s.reportTarget(msg)
	if target == "" {
		return errors.New("delivery report target is empty")
	}
	payload, err := report.MarshalBinary()
	if err != nil {
		return fmt.Errorf("building sms delivery report: %w", err)
	}
	reportMsg := s.buildMessage(target, payload, msg.Header("Call-ID"))
	resp, err := s.sess.Exchange(ctx, reportMsg)
	if err != nil {
		return fmt.Errorf("sending sms delivery report: %w", err)
	}
	if status := resp.StatusCode(); status != 200 && status != 202 {
		return fmt.Errorf("sending sms delivery report: unexpected response: %w", sip.NewResponseError(resp))
	}
	return nil
}

func (s *Service) deliverIncoming(msg sip.Message, rp rpMessage, tpdu deliverTPDU) {
	incoming := tpdu.Message
	incoming.CallID = strings.TrimSpace(msg.Header("Call-ID"))
	incoming.To = incomingRecipient(msg)
	incoming.ServiceCenter = rp.Originator
	if tpdu.Concat != nil {
		s.deliverConcat(incoming, *tpdu.Concat)
		return
	}
	s.deliverSingle(msg, incoming)
}

func (s *Service) deliverIncomingStatusReport(msg sip.Message, rp rpMessage, report StatusReport) {
	if s.cfg.OnStatusReport == nil {
		return
	}
	report.ServiceCenter = rp.Originator
	if s.markSeen(msg) {
		s.cfg.OnStatusReport(report)
		return
	}
	s.logger.Debug("suppressing duplicate sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "message_reference", report.MessageReference, "status", report.Status)
}

func incomingRecipient(msg sip.Message) string {
	for _, candidate := range []string{msg.Header("To"), sip.RequestURI(msg)} {
		if target := envelopeAddress(candidate); target != "" {
			return target
		}
	}
	return ""
}

func envelopeAddress(value string) string {
	uri := sip.AddressURI(value)
	if uri == "" {
		return ""
	}
	switch lower := strings.ToLower(uri); {
	case strings.HasPrefix(lower, "tel:"):
		return uri[len("tel:"):]
	case strings.HasPrefix(lower, "sip:"), strings.HasPrefix(lower, "sips:"):
		return uri
	default:
		return uri
	}
}

func (s *Service) deliverSingle(msg sip.Message, incoming Incoming) {
	if s.cfg.OnIncoming == nil {
		return
	}
	if s.markSeen(msg) {
		s.cfg.OnIncoming(incoming)
		return
	}
	s.logger.Debug("suppressing duplicate sms", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "from", incoming.From, "text", incoming.Text)
}

func (s *Service) buildMessage(target string, body []byte, inReplyTo string) sip.Message {
	state := s.reg.State()
	if target == "" {
		target = s.mustResolveServiceCentreTarget()
	}
	callID, _, tag, branch := sip.NewTransaction()
	senderIdentity := preferredIdentity(state)
	msg := sip.NewRequest("MESSAGE", target)
	msg.Headers.Add("Call-ID", callID)
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, tag))
	msg.Headers.Add("To", fmt.Sprintf("<%s>", target))
	msg.Headers.Add("Request-Disposition", "no-fork")
	msg.Headers.Add("Accept-Contact", "*;+g.3gpp.smsip")
	msg.Headers.Add("CSeq", fmt.Sprintf("%d MESSAGE", atomic.AddInt64(&s.cseq, 1)))
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, branch))
	msg.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	s.reg.RequestPolicy().Apply(&msg)
	msg.Headers.Add("Content-Type", "application/vnd.3gpp.sms")
	msg.Headers.Add("Content-Transfer-Encoding", "binary")
	if inReplyTo != "" {
		msg.Headers.Add("In-Reply-To", inReplyTo)
	}
	msg.Body = body
	return msg
}

func preferredIdentity(state registration.State) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(state.TelPublicID)), "tel:") {
		return state.TelPublicID
	}
	if identity := strings.TrimSpace(state.DefaultPublicID); identity != "" {
		return identity
	}
	return state.PublicIdentity
}

func (s *Service) mustResolveServiceCentreTarget() string {
	sc, _ := s.resolveServiceCentre()
	return sc.target
}

func (s *Service) reportTarget(msg sip.Message) string {
	for _, candidate := range []string{
		sip.AddressURI(msg.Header("P-Asserted-Identity")),
		sip.AddressURI(msg.Header("From")),
	} {
		if target := sipMessageTarget(candidate); target != "" {
			return target
		}
	}
	return viaMessageTarget(msg)
}

func sipMessageTarget(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	lower := strings.ToLower(uri)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return uri
	}
	return ""
}

func viaMessageTarget(msg sip.Message) string {
	var last string
	for _, value := range msg.HeadersByName("Via") {
		for part := range strings.SplitSeq(value, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				last = trimmed
			}
		}
	}
	if last == "" {
		return ""
	}
	fields := strings.Fields(last)
	if len(fields) < 2 {
		return ""
	}
	sentBy, _, _ := strings.Cut(fields[1], ";")
	sentBy = strings.TrimSpace(sentBy)
	if sentBy == "" {
		return ""
	}
	return "sip:" + sentBy
}
