package sms

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/ims/identity"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) handleMessageRequest(ctx context.Context, req session.Request) error {
	msg := req.Message
	payload, err := decodeMessagePayload(msg)
	if err != nil {
		s.logger.Debug("rejecting sms message payload", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
		return s.writeMessageStatus(ctx, req, sipStatusUnsupportedMediaType, "Unsupported Media Type")
	}
	msg.Body = payload.RPDU
	var rp rpMessage
	if err := rp.UnmarshalBinary(msg.Body); err != nil {
		var unsupportedType unsupportedRPMessageTypeError
		if errors.As(err, &unsupportedType) && len(msg.Body) >= 2 {
			if err := s.writeMessageStatus(ctx, req, sipStatusOK, "OK"); err != nil {
				return err
			}
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseMessageTypeNotImplemented), payload.Info)
			s.logger.Debug("rejecting unsupported sms rp message type", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", msg.Body[1], "rp_type", unsupportedType.Type)
			return nil
		}
		if report, ok := malformedNetworkSubmitReport(msg.Body); ok {
			if !s.knowsSubmit(report.Reference, time.Now()) {
				s.logger.Debug("submit report not matched", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference, "err", err)
				return s.writeMessageStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
			}
			if err := s.writeMessageStatus(ctx, req, sipStatusOK, "OK"); err != nil {
				return err
			}
			switch report.Type {
			case rpAckNetworkToMS:
				s.logger.Debug("submit report invalid mandatory information", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference, "err", err)
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(report.Reference, rpCauseInvalidMandatoryInformation), payload.Info)
			case rpErrorNetworkToMS:
				s.logger.Debug("submit report protocol error", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", report.Reference, "cause", rpCauseProtocolErrorUnspecified, "err", err)
				s.completePending(msg, report)
			}
			return nil
		}
		if err := s.writeMessageStatus(ctx, req, sipStatusOK, "OK"); err != nil {
			return err
		}
		if len(msg.Body) >= 2 && msg.Body[0] == rpDataNetworkToMS {
			if s.beginMTTransfer() {
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseInvalidMandatoryInformation), payload.Info)
				s.endMTTransfer()
			} else {
				_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(msg.Body[1], rpCauseMessageNotCompatibleWithState), payload.Info)
			}
		}
		s.logger.Debug("ignoring malformed sms message", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
		return nil
	}
	if isSubmitReport(rp) {
		if s.completePending(msg, rp) {
			return s.writeMessageStatus(ctx, req, sipStatusOK, "OK")
		}
		return s.writeMessageStatus(ctx, req, sipStatusNotAcceptableHere, "Not Acceptable Here")
	}
	if err := s.writeMessageStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		return err
	}
	return s.handleInboundRP(ctx, msg, rp, payload.Info)
}

func (s *Service) writeMessageStatus(ctx context.Context, req session.Request, code int, reason string) error {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req.Message, code)
	if code == sipStatusUnsupportedMediaType {
		resp.Headers.Add("Accept", acceptHeader)
	}
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) handleInboundRP(ctx context.Context, msg sip.Message, rp rpMessage, info xmlInfo) error {
	if rp.Type != rpDataNetworkToMS {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseMessageTypeNotImplemented), info)
		return nil
	}
	if !s.beginMTTransfer() {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseMessageNotCompatibleWithState), info)
		return nil
	}
	defer s.endMTTransfer()

	mti, err := tpduMessageType(rp.TPDU)
	if err != nil {
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation), info)
		return nil
	}
	switch mti {
	case tpduMTIDeliver, tpduMTIReserved:
		fields, err := decodeDeliverFields(rp.TPDU)
		if err != nil {
			s.logger.Debug("rejecting inbound sms deliver", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation), info)
			return nil
		}
		if isPPDataDownload(fields.part) {
			s.handlePPDataDownload(ctx, msg, rp, info)
			return nil
		}
		ackInfo := xmlInfo{}
		if strings.TrimSpace(fields.from) == dummyMSISDN {
			if !hasMSISDNLessFeatureCaps(msg) {
				s.logger.Debug("discarding msisdn-less sms without feature-caps", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference)
				return nil
			}
			if strings.TrimSpace(info.From) == "" {
				s.logger.Debug("discarding msisdn-less sms without xml From", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference)
				return nil
			}
			ackInfo = info
		}

		var tpdu deliverTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			s.logger.Debug("rejecting inbound sms deliver", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation), ackInfo)
			return nil
		}
		if fromURI := strings.TrimSpace(ackInfo.From); fromURI != "" {
			tpdu.Message.FromURI = fromURI
			tpdu.Message.From = identity.MSISDN(fromURI)
		}
		s.deliverIncoming(msg, rp, tpdu)
		if ok := s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference, nil), ackInfo); !ok {
			return nil
		}
	case tpduMTIStatusReport:
		var tpdu statusReportTPDU
		if err := tpdu.UnmarshalBinary(rp.TPDU); err != nil {
			s.logger.Debug("rejecting inbound sms status report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
			_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation), info)
			return nil
		}
		s.deliverIncomingStatusReport(msg, rp, tpdu.Message)
		if ok := s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference, nil), xmlInfo{}); !ok {
			return nil
		}
	default:
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation), info)
	}
	return nil
}

func (s *Service) handlePPDataDownload(ctx context.Context, msg sip.Message, rp rpMessage, info xmlInfo) {
	downloader, ok := s.card.(ppDownloader)
	if !ok {
		s.logger.Debug("rejecting sms-pp data download", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", "card does not support SMS-PP download")
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseProtocolErrorUnspecified), info)
		return
	}

	resp, err := downloader.SMSPPDownload(ctx, usim.SMSPPDownloadRequest{
		ServiceCenterAddress: rp.Originator,
		TPDU:                 rp.TPDU,
	})
	if err != nil {
		s.logger.Debug("rejecting sms-pp data download", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "err", err)
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseProtocolErrorUnspecified), info)
		return
	}
	s.logger.Debug("sms-pp data download delivered", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "rp_ref", rp.Reference, "sw1", resp.SW1, "sw2", resp.SW2, "response_len", len(resp.Data))
	_ = s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference, resp.Data), info)
}

func isSubmitReport(rp rpMessage) bool {
	return rp.Type == rpAckNetworkToMS || rp.Type == rpErrorNetworkToMS
}

func (s *Service) sendInboundDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage, info xmlInfo) bool {
	if !s.markDeliveryReportSent(msg) {
		return true
	}

	started := s.startBackgroundTask(func(done <-chan struct{}) {
		reportCtx, cancel := contextWithDoneTimeout(done, s.cfg.DeliveryReportTimeout)
		defer cancel()
		if err := s.sendDeliveryReport(reportCtx, msg, report, info); err != nil {
			s.clearDeliveryReportSent(msg)
			if ctx.Err() == nil && !s.cleanupStopped() {
				s.logger.Warn("sending inbound sms delivery report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
			}
		}
	})
	if !started {
		s.clearDeliveryReportSent(msg)
		return false
	}
	return true
}

func (s *Service) sendDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage, info xmlInfo) error {
	target := s.reportTarget(msg)
	if target == "" {
		return errors.New("delivery report target is empty")
	}
	payload, err := report.MarshalBinary()
	if err != nil {
		return fmt.Errorf("building sms delivery report: %w", err)
	}
	reportMsg, err := s.buildDeliveryReportMessage(target, payload, msg.Header("Call-ID"), info)
	if err != nil {
		return err
	}
	resp, err := s.sess.Exchange(ctx, reportMsg)
	if err != nil {
		return fmt.Errorf("sending sms delivery report: %w", err)
	}
	if status := resp.StatusCode(); status != sipStatusOK && status != sipStatusAccepted {
		return fmt.Errorf("sending sms delivery report: unexpected response: %w", sip.NewResponseError(resp))
	}
	return nil
}

func (s *Service) deliverIncoming(msg sip.Message, rp rpMessage, tpdu deliverTPDU) {
	incoming := tpdu.Message
	recipient := incomingRecipient(msg)
	incoming.CallID = strings.TrimSpace(msg.Header("Call-ID"))
	incoming.To = recipient.Number
	incoming.ToURI = recipient.URI
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

type endpoint struct {
	Number string
	URI    string
}

func incomingRecipient(msg sip.Message) endpoint {
	for _, candidate := range []string{msg.Header("To"), sip.RequestURI(msg)} {
		if target := envelopeEndpoint(candidate); target.URI != "" || target.Number != "" {
			return target
		}
	}
	return endpoint{}
}

func envelopeEndpoint(value string) endpoint {
	uri := sip.AddressURI(value)
	if uri == "" {
		return endpoint{}
	}
	switch lower := strings.ToLower(uri); {
	case strings.HasPrefix(lower, "tel:"):
		return endpoint{Number: identity.MSISDN(uri), URI: uri}
	case strings.HasPrefix(lower, "sip:"), strings.HasPrefix(lower, "sips:"):
		return endpoint{Number: identity.MSISDN(uri), URI: uri}
	default:
		return endpoint{Number: uri}
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
	s.logger.Debug("suppressing duplicate sms", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "from", incoming.From, "from_uri", incoming.FromURI, "text", incoming.Text)
}

func hasMSISDNLessFeatureCaps(msg sip.Message) bool {
	for _, value := range msg.HeadersByName("Feature-Caps") {
		for _, featureCap := range sip.SplitHeaderList(value) {
			for _, param := range strings.Split(featureCap, ";") {
				name, _, _ := strings.Cut(strings.TrimSpace(param), "=")
				if strings.EqualFold(name, ipMSISDNLessFeatureTag) {
					return true
				}
			}
		}
	}
	return false
}
