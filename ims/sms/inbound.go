package sms

import (
	"bytes"
	"context"
	"encoding"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"
	"sync/atomic"
	"time"

	"github.com/damonto/vowifi-go/ims/identity"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"github.com/damonto/vowifi-go/usim"
)

var (
	_ encoding.TextMarshaler   = smsXMLInfo{}
	_ encoding.TextUnmarshaler = (*smsXMLInfo)(nil)
)

const (
	smsContentType                 = "application/vnd.3gpp.sms"
	smsXMLContentType              = "application/vnd.3gpp.sms+xml"
	mixedMultipartType             = "multipart/mixed"
	smsAcceptHeader                = smsContentType + ", " + smsXMLContentType + ", " + mixedMultipartType
	smsXMLDisposition              = "render;handling=optional"
	smsXMLDispositionType          = "render"
	smsXMLDispositionHandlingParam = "handling"
	smsXMLDispositionHandlingValue = "optional"
	binaryTransferValue            = "binary"
	smsIPFeatureTag                = "+g.3gpp.smsip"
	smsIPMSISDNLessFeatureTag      = "+g.3gpp.smsip-msisdn-less"
	dummyMSISDN                    = "+000000000000000"
)

const (
	smsDeliveryOutcomeSuccessfulTransfer        = "SuccessfulTransfer"
	smsDeliveryOutcomeAbsentSubscriber          = "AbsentSubscriber"
	smsDeliveryOutcomeUserBusyForMTSMS          = "UserBusyForMTSMS"
	smsDeliveryOutcomeIllegalUser               = "IllegalUser"
	smsDeliveryOutcomeIllegalEquipment          = "IllegalEquipment"
	smsDeliveryOutcomeSMDeliveryFailure         = "SMDeliveryFailure"
	smsDeliveryOutcomeServiceBarred             = "ServiceBarred"
	smsDeliveryOutcomeTeleserviceNotProvisioned = "TeleserviceNotProvisioned"
)

type messagePayload struct {
	RPDU []byte
	Info smsXMLInfo
}

type smsXMLInfo struct {
	To               string
	From             string
	CorrelationID    smsXMLCorrelationID
	HasCorrelationID bool
	DeliveryOutcome  string
}

type smsXMLCorrelationID struct {
	Sender   string
	Receiver string
	HLRID    string
}

func decodeMessagePayload(msg sip.Message) (messagePayload, error) {
	mediaType, params, err := mime.ParseMediaType(msg.Header("Content-Type"))
	if err != nil {
		return messagePayload{}, fmt.Errorf("parsing sms content type: %w", err)
	}
	switch {
	case strings.EqualFold(mediaType, smsContentType):
		if err := validateBinaryTransferEncoding(msg.Header("Content-Transfer-Encoding")); err != nil {
			return messagePayload{}, err
		}
		return messagePayload{RPDU: bytes.Clone(msg.Body)}, nil
	case strings.EqualFold(mediaType, mixedMultipartType):
		return decodeMultipartMessagePayload(msg, params)
	default:
		return messagePayload{}, fmt.Errorf("unsupported sms content type: %s", mediaType)
	}
}

func decodeMultipartMessagePayload(msg sip.Message, params map[string]string) (messagePayload, error) {
	boundary := strings.TrimSpace(params["boundary"])
	if boundary == "" {
		return messagePayload{}, errors.New("multipart sms boundary is empty")
	}
	var payload messagePayload
	var xmlSeen bool
	reader := multipart.NewReader(bytes.NewReader(msg.Body), boundary)
	for {
		part, err := reader.NextRawPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return messagePayload{}, fmt.Errorf("reading multipart sms body: %w", err)
		}
		mediaType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
		if err != nil {
			if isOptionalBodyPart(part.Header.Get("Content-Disposition")) {
				_ = part.Close()
				continue
			}
			_ = part.Close()
			return messagePayload{}, fmt.Errorf("parsing multipart sms part content type: %w", err)
		}
		switch {
		case strings.EqualFold(mediaType, smsContentType):
			if err := validateBinaryTransferEncoding(part.Header.Get("Content-Transfer-Encoding")); err != nil {
				_ = part.Close()
				return messagePayload{}, err
			}
		case strings.EqualFold(mediaType, smsXMLContentType):
			if err := validateSMSXMLDisposition(part.Header.Get("Content-Disposition")); err != nil {
				_ = part.Close()
				return messagePayload{}, err
			}
		default:
			if isOptionalBodyPart(part.Header.Get("Content-Disposition")) {
				_ = part.Close()
				continue
			}
			_ = part.Close()
			return messagePayload{}, fmt.Errorf("unsupported multipart sms part content type: %s", mediaType)
		}
		data, err := io.ReadAll(part)
		if err != nil {
			_ = part.Close()
			return messagePayload{}, fmt.Errorf("reading multipart sms part: %w", err)
		}
		if err := part.Close(); err != nil {
			return messagePayload{}, fmt.Errorf("closing multipart sms part: %w", err)
		}
		switch {
		case strings.EqualFold(mediaType, smsContentType):
			if payload.RPDU != nil {
				return messagePayload{}, errors.New("multipart sms body contains duplicate RP-DATA part")
			}
			payload.RPDU = bytes.Clone(data)
		case strings.EqualFold(mediaType, smsXMLContentType):
			if xmlSeen {
				return messagePayload{}, errors.New("multipart sms body contains duplicate XML info part")
			}
			xmlSeen = true
			info, err := decodeSMSXMLInfo(data)
			if err != nil {
				return messagePayload{}, err
			}
			payload.Info = info
		}
	}
	if payload.RPDU == nil {
		return messagePayload{}, errors.New("multipart sms body missing RP-DATA part")
	}
	return payload, nil
}

func isOptionalBodyPart(value string) bool {
	_, params, err := mime.ParseMediaType(value)
	if err != nil {
		return false
	}
	return strings.EqualFold(params["handling"], smsXMLDispositionHandlingValue)
}

func validateBinaryTransferEncoding(value string) error {
	value = strings.TrimSpace(value)
	if value == "" || strings.EqualFold(value, binaryTransferValue) {
		return nil
	}
	return fmt.Errorf("unsupported sms content transfer encoding: %s", value)
}

func validateSMSXMLDisposition(value string) error {
	disposition, params, err := mime.ParseMediaType(value)
	if err != nil {
		return fmt.Errorf("parsing sms xml content disposition: %w", err)
	}
	if !strings.EqualFold(disposition, smsXMLDispositionType) {
		return fmt.Errorf("unsupported sms xml content disposition: %s", disposition)
	}
	if !strings.EqualFold(params[smsXMLDispositionHandlingParam], smsXMLDispositionHandlingValue) {
		return fmt.Errorf("unsupported sms xml handling: %s", params[smsXMLDispositionHandlingParam])
	}
	return nil
}

func decodeSMSXMLInfo(data []byte) (smsXMLInfo, error) {
	var info smsXMLInfo
	if err := info.UnmarshalText(data); err != nil {
		return smsXMLInfo{}, err
	}
	return info, nil
}

func (info smsXMLInfo) MarshalText() ([]byte, error) {
	if err := info.validate(); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	encoder := xml.NewEncoder(&buf)
	if err := info.marshalXML(encoder); err != nil {
		return nil, err
	}
	if err := encoder.Flush(); err != nil {
		return nil, fmt.Errorf("marshaling sms xml info: %w", err)
	}
	return buf.Bytes(), nil
}

func (info smsXMLInfo) marshalXML(encoder *xml.Encoder) error {
	start := xml.StartElement{Name: xml.Name{Local: "short-message-info"}}
	if err := encoder.EncodeToken(start); err != nil {
		return fmt.Errorf("marshaling sms xml info: %w", err)
	}
	if to := strings.TrimSpace(info.To); to != "" {
		if err := encoder.EncodeElement(to, xml.StartElement{Name: xml.Name{Local: "To"}}); err != nil {
			return fmt.Errorf("marshaling sms xml To: %w", err)
		}
	}
	if from := strings.TrimSpace(info.From); from != "" {
		if err := encoder.EncodeElement(from, xml.StartElement{Name: xml.Name{Local: "From"}}); err != nil {
			return fmt.Errorf("marshaling sms xml From: %w", err)
		}
	}
	if info.HasCorrelationID || info.CorrelationID != (smsXMLCorrelationID{}) {
		if err := info.CorrelationID.marshalXML(encoder); err != nil {
			return err
		}
	}
	if outcome := strings.TrimSpace(info.DeliveryOutcome); outcome != "" {
		if err := encoder.EncodeElement(outcome, xml.StartElement{Name: xml.Name{Local: "Delivery-Outcome"}}); err != nil {
			return fmt.Errorf("marshaling sms xml Delivery-Outcome: %w", err)
		}
	}
	if err := encoder.EncodeToken(start.End()); err != nil {
		return fmt.Errorf("marshaling sms xml info: %w", err)
	}
	return nil
}

func (id smsXMLCorrelationID) marshalXML(encoder *xml.Encoder) error {
	sender := strings.TrimSpace(id.Sender)
	receiver := strings.TrimSpace(id.Receiver)
	hlrID := strings.TrimSpace(id.HLRID)
	if sender == "" || receiver == "" || hlrID == "" {
		return errors.New("marshaling sms xml Correlation-ID: sender, receiver, and HLR-ID are required")
	}
	if err := validateSMSXMLSIPURI("Correlation-ID Sender", sender); err != nil {
		return err
	}
	if err := validateSMSXMLSIPURI("Correlation-ID Receiver", receiver); err != nil {
		return err
	}
	start := xml.StartElement{Name: xml.Name{Local: "Correlation-ID"}}
	if err := encoder.EncodeToken(start); err != nil {
		return fmt.Errorf("marshaling sms xml Correlation-ID: %w", err)
	}
	if err := encoder.EncodeElement(sender, xml.StartElement{Name: xml.Name{Local: "Sender"}}); err != nil {
		return fmt.Errorf("marshaling sms xml Sender: %w", err)
	}
	if err := encoder.EncodeElement(receiver, xml.StartElement{Name: xml.Name{Local: "Receiver"}}); err != nil {
		return fmt.Errorf("marshaling sms xml Receiver: %w", err)
	}
	if err := encoder.EncodeElement(hlrID, xml.StartElement{Name: xml.Name{Local: "HLR-ID"}}); err != nil {
		return fmt.Errorf("marshaling sms xml HLR-ID: %w", err)
	}
	if err := encoder.EncodeToken(start.End()); err != nil {
		return fmt.Errorf("marshaling sms xml Correlation-ID: %w", err)
	}
	return nil
}

func (info *smsXMLInfo) UnmarshalText(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var out smsXMLInfo
	var rootSeen bool
	var toSeen bool
	var fromSeen bool
	var correlationIDSeen bool
	var deliveryOutcomeSeen bool
	var depth int
	var rootNamespace string
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("parsing sms xml info: %w", err)
		}
		switch tok := token.(type) {
		case xml.StartElement:
			depth++
			if !rootSeen {
				if tok.Name.Local != "short-message-info" {
					return errors.New("sms xml root is not short-message-info")
				}
				rootSeen = true
				rootNamespace = tok.Name.Space
				continue
			}
			if depth != 2 || !smsXMLElementInDocumentNamespace(tok.Name, rootNamespace) {
				continue
			}
			switch tok.Name.Local {
			case "To":
				if toSeen {
					return errors.New("sms xml info contains duplicate To")
				}
				toSeen = true
				var value string
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return fmt.Errorf("parsing sms xml To: %w", err)
				}
				out.To = strings.TrimSpace(value)
				if err := validateSMSXMLSIPURI("To", out.To); err != nil {
					return fmt.Errorf("parsing sms xml To: %w", err)
				}
				depth--
			case "From":
				if fromSeen {
					return errors.New("sms xml info contains duplicate From")
				}
				fromSeen = true
				var value string
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return fmt.Errorf("parsing sms xml From: %w", err)
				}
				out.From = strings.TrimSpace(value)
				if err := validateSMSXMLSIPURI("From", out.From); err != nil {
					return fmt.Errorf("parsing sms xml From: %w", err)
				}
				depth--
			case "Correlation-ID":
				if correlationIDSeen {
					return errors.New("sms xml info contains duplicate Correlation-ID")
				}
				correlationIDSeen = true
				correlationID, err := decodeSMSXMLCorrelationID(decoder, tok.Name.Space)
				if err != nil {
					return fmt.Errorf("parsing sms xml Correlation-ID: %w", err)
				}
				out.CorrelationID = correlationID
				out.HasCorrelationID = true
				depth--
			case "Delivery-Outcome":
				if deliveryOutcomeSeen {
					return errors.New("sms xml info contains duplicate Delivery-Outcome")
				}
				deliveryOutcomeSeen = true
				var value string
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return fmt.Errorf("parsing sms xml Delivery-Outcome: %w", err)
				}
				out.DeliveryOutcome = normalizeSMSDeliveryOutcome(strings.TrimSpace(value))
				depth--
			}
		case xml.EndElement:
			depth--
		}
	}
	if !rootSeen {
		return errors.New("sms xml info is empty")
	}
	*info = out
	return nil
}

func decodeSMSXMLCorrelationID(decoder *xml.Decoder, documentNamespace string) (smsXMLCorrelationID, error) {
	var out smsXMLCorrelationID
	var senderSeen, receiverSeen, hlrIDSeen bool
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return smsXMLCorrelationID{}, errors.New("unexpected EOF")
		}
		if err != nil {
			return smsXMLCorrelationID{}, err
		}
		switch tok := token.(type) {
		case xml.StartElement:
			depth++
			if depth != 1 || !smsXMLElementInDocumentNamespace(tok.Name, documentNamespace) {
				if err := decoder.Skip(); err != nil {
					return smsXMLCorrelationID{}, err
				}
				depth--
				continue
			}
			var value string
			switch tok.Name.Local {
			case "Sender":
				if senderSeen {
					return smsXMLCorrelationID{}, errors.New("duplicate Sender")
				}
				senderSeen = true
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return smsXMLCorrelationID{}, fmt.Errorf("Sender: %w", err)
				}
				out.Sender = strings.TrimSpace(value)
				if err := validateSMSXMLSIPURI("Correlation-ID Sender", out.Sender); err != nil {
					return smsXMLCorrelationID{}, err
				}
				depth--
			case "Receiver":
				if receiverSeen {
					return smsXMLCorrelationID{}, errors.New("duplicate Receiver")
				}
				receiverSeen = true
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return smsXMLCorrelationID{}, fmt.Errorf("Receiver: %w", err)
				}
				out.Receiver = strings.TrimSpace(value)
				if err := validateSMSXMLSIPURI("Correlation-ID Receiver", out.Receiver); err != nil {
					return smsXMLCorrelationID{}, err
				}
				depth--
			case "HLR-ID":
				if hlrIDSeen {
					return smsXMLCorrelationID{}, errors.New("duplicate HLR-ID")
				}
				hlrIDSeen = true
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return smsXMLCorrelationID{}, fmt.Errorf("HLR-ID: %w", err)
				}
				out.HLRID = strings.TrimSpace(value)
				depth--
			default:
				if err := decoder.Skip(); err != nil {
					return smsXMLCorrelationID{}, err
				}
				depth--
			}
		case xml.EndElement:
			if depth == 0 && smsXMLElementInDocumentNamespace(tok.Name, documentNamespace) && tok.Name.Local == "Correlation-ID" {
				if out.Sender == "" || out.Receiver == "" || out.HLRID == "" {
					return smsXMLCorrelationID{}, errors.New("missing Sender, Receiver, or HLR-ID")
				}
				return out, nil
			}
			depth--
		}
	}
}

func smsXMLElementInDocumentNamespace(name xml.Name, documentNamespace string) bool {
	return name.Space == "" || name.Space == documentNamespace
}

func (info smsXMLInfo) validate() error {
	if err := validateSMSXMLSIPURI("To", info.To); err != nil {
		return fmt.Errorf("marshaling sms xml To: %w", err)
	}
	if err := validateSMSXMLSIPURI("From", info.From); err != nil {
		return fmt.Errorf("marshaling sms xml From: %w", err)
	}
	if outcome := strings.TrimSpace(info.DeliveryOutcome); outcome != "" && !validSMSDeliveryOutcome(outcome) {
		return fmt.Errorf("marshaling sms xml Delivery-Outcome: unsupported value %q", outcome)
	}
	return nil
}

func normalizeSMSDeliveryOutcome(outcome string) string {
	if outcome == "" || validSMSDeliveryOutcome(outcome) {
		return outcome
	}
	return smsDeliveryOutcomeSMDeliveryFailure
}

func validSMSDeliveryOutcome(outcome string) bool {
	switch outcome {
	case smsDeliveryOutcomeSuccessfulTransfer,
		smsDeliveryOutcomeAbsentSubscriber,
		smsDeliveryOutcomeUserBusyForMTSMS,
		smsDeliveryOutcomeIllegalUser,
		smsDeliveryOutcomeIllegalEquipment,
		smsDeliveryOutcomeSMDeliveryFailure,
		smsDeliveryOutcomeServiceBarred,
		smsDeliveryOutcomeTeleserviceNotProvisioned:
		return true
	default:
		return false
	}
}

func validateSMSXMLSIPURI(field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if !isSIPURI(value) {
		return fmt.Errorf("%s %q is not a SIP URI", field, value)
	}
	return nil
}

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
		resp.Headers.Add("Accept", smsAcceptHeader)
	}
	return s.sess.WriteResponse(ctx, req, resp)
}

func (s *Service) handleInboundRP(ctx context.Context, msg sip.Message, rp rpMessage, info smsXMLInfo) error {
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
		ackInfo := smsXMLInfo{}
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
		if ok := s.sendInboundDeliveryReport(ctx, msg, newRPAckDeliverReportMessage(rp.Reference, nil), smsXMLInfo{}); !ok {
			return nil
		}
	default:
		_ = s.sendInboundDeliveryReport(ctx, msg, newRPErrorMessage(rp.Reference, rpCauseInvalidMandatoryInformation), info)
	}
	return nil
}

func (s *Service) handlePPDataDownload(ctx context.Context, msg sip.Message, rp rpMessage, info smsXMLInfo) {
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

func (s *Service) sendInboundDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage, info smsXMLInfo) bool {
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
		reportCtx, cancel := context.WithTimeout(s.cleanupCtx, s.cfg.DeliveryReportTimeout)
		defer cancel()
		if err := s.sendDeliveryReport(reportCtx, msg, report, info); err != nil {
			s.clearDeliveryReportSent(msg)
			if ctx.Err() == nil && s.cleanupCtx.Err() == nil {
				s.logger.Warn("sending inbound sms delivery report", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "err", err)
			}
		}
	}()
	return true
}

func (s *Service) sendDeliveryReport(ctx context.Context, msg sip.Message, report rpMessage, info smsXMLInfo) error {
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

func (s *Service) deliverSingle(msg sip.Message, incoming IncomingSMS) {
	if s.cfg.OnIncoming == nil {
		return
	}
	if s.markSeen(msg) {
		s.cfg.OnIncoming(incoming)
		return
	}
	s.logger.Debug("suppressing duplicate sms", "call_id", msg.Header("Call-ID"), "cseq", msg.Header("CSeq"), "from", incoming.From, "from_uri", incoming.FromURI, "text", incoming.Text)
}

func (s *Service) buildMessage(target string, body []byte, inReplyTo string) sip.Message {
	state := s.reg.State()
	if target == "" {
		target = s.mustResolveServiceCenterTarget()
	}
	callID, _, tag, branch := sip.NewTransaction()
	senderIdentity := preferredIdentity(state)
	msg := sip.NewRequest("MESSAGE", target)
	msg.Headers.Add("Call-ID", callID)
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, tag))
	msg.Headers.Add("To", fmt.Sprintf("<%s>", target))
	msg.Headers.Add("Request-Disposition", "no-fork")
	msg.Headers.Add("Accept-Contact", smsAcceptContact)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d MESSAGE", atomic.AddInt64(&s.cseq, 1)))
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.sess.LocalAddr()), state.ContactHost, state.MessagePort, branch))
	msg.Headers.Add("P-Preferred-Identity", fmt.Sprintf("<%s>", senderIdentity))
	s.reg.RequestPolicy().Apply(&msg)
	msg.Headers.Add("Content-Type", smsContentType)
	msg.Headers.Add("Content-Transfer-Encoding", binaryTransferValue)
	if inReplyTo != "" {
		msg.Headers.Add("In-Reply-To", inReplyTo)
	}
	msg.Body = body
	return msg
}

func (s *Service) buildDeliveryReportMessage(target string, body []byte, inReplyTo string, info smsXMLInfo) (sip.Message, error) {
	if strings.TrimSpace(info.From) == "" {
		return s.buildMessage(target, body, inReplyTo), nil
	}
	payload, contentType, err := buildMultipartSMSPayload(smsXMLInfo{To: strings.TrimSpace(info.From)}, body)
	if err != nil {
		return sip.Message{}, fmt.Errorf("building sms delivery report multipart body: %w", err)
	}

	msg := s.buildMessage(target, payload, inReplyTo)
	msg.Headers.Set("Content-Type", contentType)
	msg.Headers.Del("Content-Transfer-Encoding")
	return msg, nil
}

func buildMultipartSMSPayload(info smsXMLInfo, rpdu []byte) ([]byte, string, error) {
	var payload bytes.Buffer
	writer := multipart.NewWriter(&payload)
	xmlPart, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":        {smsXMLContentType},
		"Content-Disposition": {smsXMLDisposition},
	})
	if err != nil {
		return nil, "", fmt.Errorf("creating sms xml part: %w", err)
	}
	xmlBody, err := info.MarshalText()
	if err != nil {
		return nil, "", fmt.Errorf("marshaling sms xml body: %w", err)
	}
	if _, err := xmlPart.Write(xmlBody); err != nil {
		return nil, "", fmt.Errorf("writing sms xml part: %w", err)
	}
	smsPart, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {smsContentType},
		"Content-Transfer-Encoding": {binaryTransferValue},
	})
	if err != nil {
		return nil, "", fmt.Errorf("creating sms RP-DATA part: %w", err)
	}
	if _, err := smsPart.Write(rpdu); err != nil {
		return nil, "", fmt.Errorf("writing sms RP-DATA part: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("closing sms multipart body: %w", err)
	}
	return payload.Bytes(), fmt.Sprintf("%s; boundary=%q", mixedMultipartType, writer.Boundary()), nil
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

func (s *Service) mustResolveServiceCenterTarget() string {
	sc, _ := s.resolveServiceCenter()
	return sc.target
}

func (s *Service) reportTarget(msg sip.Message) string {
	return sipMessageTarget(sip.AddressURI(msg.Header("P-Asserted-Identity")))
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

func hasMSISDNLessFeatureCaps(msg sip.Message) bool {
	for _, value := range msg.HeadersByName("Feature-Caps") {
		for _, featureCap := range sip.SplitHeaderList(value) {
			for _, param := range strings.Split(featureCap, ";") {
				name, _, _ := strings.Cut(strings.TrimSpace(param), "=")
				if strings.EqualFold(name, smsIPMSISDNLessFeatureTag) {
					return true
				}
			}
		}
	}
	return false
}
