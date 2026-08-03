package sms

import (
	"bytes"
	"encoding"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

var (
	_ encoding.TextAppender    = xmlInfo{}
	_ encoding.TextMarshaler   = xmlInfo{}
	_ encoding.TextUnmarshaler = (*xmlInfo)(nil)
	_ io.ReaderFrom            = (*xmlInfo)(nil)
	_ io.WriterTo              = xmlInfo{}
)

const (
	deliveryOutcomeSuccessfulTransfer        = "SuccessfulTransfer"
	deliveryOutcomeAbsentSubscriber          = "AbsentSubscriber"
	deliveryOutcomeUserBusyForMTSMS          = "UserBusyForMTSMS"
	deliveryOutcomeIllegalUser               = "IllegalUser"
	deliveryOutcomeIllegalEquipment          = "IllegalEquipment"
	deliveryOutcomeSMDeliveryFailure         = "SMDeliveryFailure"
	deliveryOutcomeServiceBarred             = "ServiceBarred"
	deliveryOutcomeTeleserviceNotProvisioned = "TeleserviceNotProvisioned"
)

type xmlInfo struct {
	To               string
	From             string
	CorrelationID    xmlCorrelationID
	HasCorrelationID bool
	DeliveryOutcome  string
}

type xmlCorrelationID struct {
	Sender   string
	Receiver string
	HLRID    string
}

func decodeXMLInfo(data []byte) (xmlInfo, error) {
	var info xmlInfo
	if _, err := info.ReadFrom(bytes.NewReader(data)); err != nil {
		return xmlInfo{}, err
	}
	return info, nil
}

func (info xmlInfo) MarshalText() ([]byte, error) {
	return info.AppendText(nil)
}

func (info xmlInfo) AppendText(dst []byte) ([]byte, error) {
	if err := info.validate(); err != nil {
		return nil, err
	}
	buf := bytes.NewBuffer(dst)
	encoder := xml.NewEncoder(buf)
	if err := info.marshalXML(encoder); err != nil {
		return nil, err
	}
	if err := encoder.Flush(); err != nil {
		return nil, fmt.Errorf("marshaling sms xml info: %w", err)
	}
	return buf.Bytes(), nil
}

func (info xmlInfo) marshalXML(encoder *xml.Encoder) error {
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
	if info.HasCorrelationID || info.CorrelationID != (xmlCorrelationID{}) {
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

func (id xmlCorrelationID) marshalXML(encoder *xml.Encoder) error {
	sender := strings.TrimSpace(id.Sender)
	receiver := strings.TrimSpace(id.Receiver)
	hlrID := strings.TrimSpace(id.HLRID)
	if sender == "" || receiver == "" || hlrID == "" {
		return errors.New("marshaling sms xml Correlation-ID: sender, receiver, and HLR-ID are required")
	}
	if err := validateXMLSIPURI("Correlation-ID Sender", sender); err != nil {
		return err
	}
	if err := validateXMLSIPURI("Correlation-ID Receiver", receiver); err != nil {
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

func (info *xmlInfo) UnmarshalText(data []byte) error {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	var out xmlInfo
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
			if depth != 2 || !xmlElementInDocumentNamespace(tok.Name, rootNamespace) {
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
				if err := validateXMLSIPURI("To", out.To); err != nil {
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
				if err := validateXMLSIPURI("From", out.From); err != nil {
					return fmt.Errorf("parsing sms xml From: %w", err)
				}
				depth--
			case "Correlation-ID":
				if correlationIDSeen {
					return errors.New("sms xml info contains duplicate Correlation-ID")
				}
				correlationIDSeen = true
				correlationID, err := decodeXMLCorrelationID(decoder, tok.Name.Space)
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
				out.DeliveryOutcome = normalizeDeliveryOutcome(strings.TrimSpace(value))
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

func (info *xmlInfo) ReadFrom(r io.Reader) (int64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("reading sms xml info: %w", err)
	}
	if err := info.UnmarshalText(data); err != nil {
		return int64(len(data)), err
	}
	return int64(len(data)), nil
}

func (info xmlInfo) WriteTo(w io.Writer) (int64, error) {
	data, err := info.MarshalText()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	if err != nil {
		return int64(n), fmt.Errorf("writing sms xml info: %w", err)
	}
	if n != len(data) {
		return int64(n), io.ErrShortWrite
	}
	return int64(n), nil
}

func decodeXMLCorrelationID(decoder *xml.Decoder, documentNamespace string) (xmlCorrelationID, error) {
	var out xmlCorrelationID
	var senderSeen, receiverSeen, hlrIDSeen bool
	depth := 0
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return xmlCorrelationID{}, errors.New("unexpected EOF")
		}
		if err != nil {
			return xmlCorrelationID{}, err
		}
		switch tok := token.(type) {
		case xml.StartElement:
			depth++
			if depth != 1 || !xmlElementInDocumentNamespace(tok.Name, documentNamespace) {
				if err := decoder.Skip(); err != nil {
					return xmlCorrelationID{}, err
				}
				depth--
				continue
			}
			var value string
			switch tok.Name.Local {
			case "Sender":
				if senderSeen {
					return xmlCorrelationID{}, errors.New("duplicate Sender")
				}
				senderSeen = true
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return xmlCorrelationID{}, fmt.Errorf("Sender: %w", err)
				}
				out.Sender = strings.TrimSpace(value)
				if err := validateXMLSIPURI("Correlation-ID Sender", out.Sender); err != nil {
					return xmlCorrelationID{}, err
				}
				depth--
			case "Receiver":
				if receiverSeen {
					return xmlCorrelationID{}, errors.New("duplicate Receiver")
				}
				receiverSeen = true
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return xmlCorrelationID{}, fmt.Errorf("Receiver: %w", err)
				}
				out.Receiver = strings.TrimSpace(value)
				if err := validateXMLSIPURI("Correlation-ID Receiver", out.Receiver); err != nil {
					return xmlCorrelationID{}, err
				}
				depth--
			case "HLR-ID":
				if hlrIDSeen {
					return xmlCorrelationID{}, errors.New("duplicate HLR-ID")
				}
				hlrIDSeen = true
				if err := decoder.DecodeElement(&value, &tok); err != nil {
					return xmlCorrelationID{}, fmt.Errorf("HLR-ID: %w", err)
				}
				out.HLRID = strings.TrimSpace(value)
				depth--
			default:
				if err := decoder.Skip(); err != nil {
					return xmlCorrelationID{}, err
				}
				depth--
			}
		case xml.EndElement:
			if depth == 0 && xmlElementInDocumentNamespace(tok.Name, documentNamespace) && tok.Name.Local == "Correlation-ID" {
				if out.Sender == "" || out.Receiver == "" || out.HLRID == "" {
					return xmlCorrelationID{}, errors.New("missing Sender, Receiver, or HLR-ID")
				}
				return out, nil
			}
			depth--
		}
	}
}

func xmlElementInDocumentNamespace(name xml.Name, documentNamespace string) bool {
	return name.Space == "" || name.Space == documentNamespace
}

func (info xmlInfo) validate() error {
	if err := validateXMLSIPURI("To", info.To); err != nil {
		return fmt.Errorf("marshaling sms xml To: %w", err)
	}
	if err := validateXMLSIPURI("From", info.From); err != nil {
		return fmt.Errorf("marshaling sms xml From: %w", err)
	}
	if outcome := strings.TrimSpace(info.DeliveryOutcome); outcome != "" && !validDeliveryOutcome(outcome) {
		return fmt.Errorf("marshaling sms xml Delivery-Outcome: unsupported value %q", outcome)
	}
	return nil
}

func normalizeDeliveryOutcome(outcome string) string {
	if outcome == "" || validDeliveryOutcome(outcome) {
		return outcome
	}
	return deliveryOutcomeSMDeliveryFailure
}

func validDeliveryOutcome(outcome string) bool {
	switch outcome {
	case deliveryOutcomeSuccessfulTransfer,
		deliveryOutcomeAbsentSubscriber,
		deliveryOutcomeUserBusyForMTSMS,
		deliveryOutcomeIllegalUser,
		deliveryOutcomeIllegalEquipment,
		deliveryOutcomeSMDeliveryFailure,
		deliveryOutcomeServiceBarred,
		deliveryOutcomeTeleserviceNotProvisioned:
		return true
	default:
		return false
	}
}

func validateXMLSIPURI(field, value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	if !isSIPURI(value) {
		return fmt.Errorf("%s %q is not a SIP URI", field, value)
	}
	return nil
}
