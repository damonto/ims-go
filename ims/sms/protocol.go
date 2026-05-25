package sms

import (
	"encoding"
	"errors"
	"fmt"
)

var (
	_ encoding.BinaryMarshaler   = submitTPDU{}
	_ encoding.BinaryMarshaler   = deliverTPDU{}
	_ encoding.BinaryUnmarshaler = (*deliverTPDU)(nil)
	_ encoding.BinaryMarshaler   = statusReportTPDU{}
	_ encoding.BinaryUnmarshaler = (*statusReportTPDU)(nil)
	_ encoding.BinaryMarshaler   = rpMessage{}
	_ encoding.BinaryUnmarshaler = (*rpMessage)(nil)
)

type submitTPDU struct {
	Reference        byte
	Destination      string
	Part             userDataPart
	RejectDuplicates bool
}

func newSubmitTPDU(reference byte, destination string, part userDataPart, rejectDuplicates bool) submitTPDU {
	return submitTPDU{
		Reference:        reference,
		Destination:      destination,
		Part:             part,
		RejectDuplicates: rejectDuplicates,
	}
}

func (tp submitTPDU) MarshalBinary() ([]byte, error) {
	firstOctet := byte(0x01)
	if tp.RejectDuplicates {
		firstOctet |= 0x04
	}
	if tp.Part.udhi {
		firstOctet |= 0x40
	}
	payload := make([]byte, 0, 32+len(tp.Part.userData))
	payload = append(payload, firstOctet)
	payload = append(payload, tp.Reference)
	payload = append(payload, encodeTPAddress(tp.Destination)...)
	payload = append(payload, tp.Part.pid)
	payload = append(payload, tp.Part.dcs)
	payload = append(payload, byte(tp.Part.udl))
	payload = append(payload, tp.Part.userData...)
	return payload, nil
}

type deliverTPDU struct {
	From    string
	Part    userDataPart
	Message Incoming
	Concat  *concatInfo
}

type statusReportTPDU struct {
	Message StatusReport
}

func newDeliverTPDU(from string, part userDataPart) deliverTPDU {
	return deliverTPDU{From: from, Part: part}
}

func (tp deliverTPDU) MarshalBinary() ([]byte, error) {
	firstOctet := byte(0x00)
	if tp.Part.udhi {
		firstOctet |= 0x40
	}
	payload := make([]byte, 0, 32+len(tp.Part.userData))
	payload = append(payload, firstOctet)
	payload = append(payload, encodeTPAddress(tp.From)...)
	payload = append(payload, tp.Part.pid, tp.Part.dcs)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	payload = append(payload, byte(tp.Part.udl))
	payload = append(payload, tp.Part.userData...)
	return payload, nil
}

type deliverFields struct {
	from string
	part userDataPart
}

type userDataEncoding byte

const (
	userDataEncodingGSM7 userDataEncoding = iota
	userDataEncoding8Bit
	userDataEncodingUCS2
)

func userDataEncodingFromAlphabetBits(bits, dcs byte) (userDataEncoding, error) {
	switch bits {
	case 0x00:
		return userDataEncodingGSM7, nil
	case 0x01:
		return userDataEncoding8Bit, nil
	case 0x02:
		return userDataEncodingUCS2, nil
	default:
		return 0, fmt.Errorf("decoding SMS DCS: reserved alphabet bits in dcs 0x%02X", dcs)
	}
}

func userDataEncodingFromDCS(dcs byte) (userDataEncoding, error) {
	switch {
	case dcs&0xC0 == 0x00:
		if dcs&0x20 != 0 {
			return 0, fmt.Errorf("decoding SMS DCS: compressed dcs 0x%02X is unsupported", dcs)
		}
		return userDataEncodingFromAlphabetBits((dcs>>2)&0x03, dcs)
	case dcs&0xF0 == 0xF0:
		return userDataEncodingFromAlphabetBits((dcs>>2)&0x03, dcs)
	default:
		return 0, fmt.Errorf("decoding SMS DCS: unsupported dcs 0x%02X", dcs)
	}
}

func decodeDeliverFields(data []byte) (deliverFields, error) {
	mti, err := tpduMessageType(data)
	if err != nil {
		return deliverFields{}, errors.New("decoding SMS-DELIVER: packet too short")
	}
	if mti != tpduMTIDeliver && mti != tpduMTIReserved {
		return deliverFields{}, fmt.Errorf("decoding SMS-DELIVER: unexpected tp-mti 0x%02X", mti)
	}
	part := userDataPart{udhi: (data[0]>>6)&0x01 == 1}
	idx := 1
	from, n, err := decodeTPAddress(data[idx:])
	if err != nil {
		return deliverFields{}, err
	}
	idx += n
	if len(data[idx:]) < 10 {
		return deliverFields{}, errors.New("decoding SMS-DELIVER: truncated mandatory fields")
	}
	part.pid = data[idx]
	idx++
	part.dcs = data[idx]
	idx++
	idx += 7
	part.udl = int(data[idx])
	idx++
	part.userData = append([]byte(nil), data[idx:]...)
	return deliverFields{from: from, part: part}, nil
}

func decodeDeliverGSM7(part userDataPart) (string, *concatInfo, error) {
	octets := gsm7OctetCount(part.udl)
	if len(part.userData) < octets {
		return "", nil, errors.New("decoding SMS-DELIVER: truncated GSM7 payload")
	}
	payload := part.userData[:octets]
	if !part.udhi {
		text, err := decodeGSM7(unpackSeptets(payload, part.udl))
		if err != nil {
			return "", nil, err
		}
		return text, nil, nil
	}
	headerLen, concat, err := decodeUserDataHeader(payload)
	if err != nil {
		return "", nil, err
	}
	headerSeptets := septetCountForOctets(headerLen)
	if part.udl < headerSeptets {
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: invalid GSM7 UDL %d", part.udl)
	}
	text, err := decodeGSM7(unpackSeptetsAt(payload, headerSeptets*7, part.udl-headerSeptets))
	if err != nil {
		return "", nil, err
	}
	return text, concat, nil
}

func decodeDeliverUCS2(part userDataPart) (string, *concatInfo, error) {
	if len(part.userData) < part.udl {
		return "", nil, errors.New("decoding SMS-DELIVER: truncated UCS2 payload")
	}
	payload := part.userData[:part.udl]
	if !part.udhi {
		return decodeUCS2(payload), nil, nil
	}
	headerLen, concat, err := decodeUserDataHeader(payload)
	if err != nil {
		return "", nil, err
	}
	if part.udl < headerLen {
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: invalid UCS2 UDL %d", part.udl)
	}
	return decodeUCS2(payload[headerLen:]), concat, nil
}

func decodeDeliverUserData(part userDataPart) (string, *concatInfo, error) {
	encoding, err := userDataEncodingFromDCS(part.dcs)
	if err != nil {
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: %w", err)
	}
	switch encoding {
	case userDataEncodingGSM7:
		return decodeDeliverGSM7(part)
	case userDataEncodingUCS2:
		return decodeDeliverUCS2(part)
	default:
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: 8-bit dcs 0x%02X is unsupported", part.dcs)
	}
}

func isPPDataDownload(part userDataPart) bool {
	return part.pid == 0x7F && dcsMessageClass(part.dcs) == 2
}

func dcsMessageClass(dcs byte) int {
	switch {
	case dcs&0xC0 == 0x00:
		if dcs&0x10 == 0 {
			return -1
		}
		return int(dcs & 0x03)
	case dcs&0xF0 == 0xF0:
		return int(dcs & 0x03)
	default:
		return -1
	}
}

func (tp *deliverTPDU) UnmarshalBinary(data []byte) error {
	fields, err := decodeDeliverFields(data)
	if err != nil {
		return err
	}
	text, concat, err := decodeDeliverUserData(fields.part)
	if err != nil {
		return err
	}
	*tp = deliverTPDU{
		From:    fields.from,
		Part:    fields.part,
		Message: Incoming{From: fields.from, Text: text},
		Concat:  concat,
	}
	return nil
}

func (tp statusReportTPDU) MarshalBinary() ([]byte, error) {
	msg := tp.Message
	if len(msg.UserData) > 0 && !msg.HasDataCodingScheme {
		return nil, errors.New("marshalling SMS-STATUS-REPORT: TP-UD requires TP-DCS")
	}
	if len(msg.UserData) > 0 && msg.DataCodingScheme == 0x00 {
		return nil, errors.New("marshalling SMS-STATUS-REPORT: TP-UD with GSM7 DCS is unsupported")
	}
	payload := make([]byte, 0, 32)
	firstOctet := byte(tpduMTIStatusReport)
	if !msg.MoreMessagesWaiting {
		firstOctet |= 0x04
	}
	if msg.LoopPrevention {
		firstOctet |= 0x08
	}
	if msg.FromCommand {
		firstOctet |= 0x20
	}
	if msg.HasUserDataHeader {
		firstOctet |= 0x40
	}
	payload = append(payload, firstOctet)
	payload = append(payload, msg.MessageReference)
	payload = append(payload, encodeTPAddress(msg.Recipient)...)
	payload = append(payload, encodeTimestamp(msg.ServiceCenterTime)...)
	payload = append(payload, encodeTimestamp(msg.DischargeTime)...)
	payload = append(payload, msg.Status)
	var pi byte
	if msg.HasProtocolIdentifier {
		pi |= 0x01
	}
	if msg.HasDataCodingScheme {
		pi |= 0x02
	}
	if len(msg.UserData) > 0 {
		pi |= 0x04
	}
	if pi == 0 {
		return payload, nil
	}
	payload = append(payload, pi)
	if msg.HasProtocolIdentifier {
		payload = append(payload, msg.ProtocolIdentifier)
	}
	if msg.HasDataCodingScheme {
		payload = append(payload, msg.DataCodingScheme)
	}
	if len(msg.UserData) == 0 {
		return payload, nil
	}
	payload = append(payload, byte(len(msg.UserData)))
	payload = append(payload, msg.UserData...)
	return payload, nil
}

func (tp *statusReportTPDU) UnmarshalBinary(data []byte) error {
	mti, err := tpduMessageType(data)
	if err != nil {
		return errors.New("decoding SMS-STATUS-REPORT: packet too short")
	}
	if mti != tpduMTIStatusReport {
		return fmt.Errorf("decoding SMS-STATUS-REPORT: unexpected tp-mti 0x%02X", mti)
	}
	if len(data) < 2 {
		return errors.New("decoding SMS-STATUS-REPORT: packet too short")
	}
	idx := 1
	firstOctet := data[0]
	report := StatusReport{
		MessageReference:    data[idx],
		MoreMessagesWaiting: firstOctet&0x04 == 0,
		LoopPrevention:      firstOctet&0x08 != 0,
		FromCommand:         firstOctet&0x20 != 0,
		HasUserDataHeader:   firstOctet&0x40 != 0,
	}
	idx++
	var n int
	report.Recipient, n, err = decodeTPAddress(data[idx:])
	if err != nil {
		return err
	}
	idx += n
	if len(data[idx:]) < 15 {
		return errors.New("decoding SMS-STATUS-REPORT: truncated mandatory fields")
	}
	report.ServiceCenterTime, err = decodeTimestamp(data[idx : idx+7])
	if err != nil {
		return err
	}
	idx += 7
	report.DischargeTime, err = decodeTimestamp(data[idx : idx+7])
	if err != nil {
		return err
	}
	idx += 7
	report.Status = data[idx]
	idx++

	if len(data[idx:]) > 0 {
		piOctets := make([]byte, 0, 1)
		for {
			if len(data[idx:]) < 1 {
				return errors.New("decoding SMS-STATUS-REPORT: missing parameter indicator")
			}
			pi := data[idx]
			idx++
			piOctets = append(piOctets, pi)
			if pi&0x80 == 0 {
				break
			}
		}
		pi := piOctets[0]
		if pi&0x01 != 0 {
			if len(data[idx:]) < 1 {
				return errors.New("decoding SMS-STATUS-REPORT: missing protocol identifier")
			}
			report.ProtocolIdentifier = data[idx]
			report.HasProtocolIdentifier = true
			idx++
		}
		dcs := byte(0x00)
		if pi&0x02 != 0 {
			if len(data[idx:]) < 1 {
				return errors.New("decoding SMS-STATUS-REPORT: missing data coding scheme")
			}
			dcs = data[idx]
			report.DataCodingScheme = dcs
			report.HasDataCodingScheme = true
			idx++
		}
		if pi&0x04 != 0 {
			if len(data[idx:]) < 1 {
				return errors.New("decoding SMS-STATUS-REPORT: missing user data length")
			}
			userDataLength := int(data[idx])
			idx++
			octets := userDataLength
			if encoding, err := userDataEncodingFromDCS(dcs); err == nil && encoding == userDataEncodingGSM7 {
				octets = gsm7OctetCount(userDataLength)
			}
			if len(data[idx:]) < octets {
				return errors.New("decoding SMS-STATUS-REPORT: truncated user data")
			}
			report.UserData = append([]byte(nil), data[idx:idx+octets]...)
			idx += octets
		}
	}

	tp.Message = report
	return nil
}

func newRPDataMessage(reference byte, destination string, tpdu []byte) rpMessage {
	return rpMessage{Type: rpDataMSToNetwork, Reference: reference, Destination: destination, TPDU: append([]byte(nil), tpdu...)}
}

func newRPAckMessage(reference byte) rpMessage {
	return rpMessage{Type: rpAckMSToNetwork, Reference: reference}
}

func newRPAckDeliverReportMessage(reference byte, userData []byte) rpMessage {
	if len(userData) == 0 {
		userData = []byte{0x00, 0x00}
	}
	return rpMessage{Type: rpAckMSToNetwork, Reference: reference, UserData: append([]byte(nil), userData...)}
}

func newRPErrorMessage(reference, cause byte) rpMessage {
	return rpMessage{Type: rpErrorMSToNetwork, Reference: reference, Cause: cause, HasCause: true}
}

func (m rpMessage) MarshalBinary() ([]byte, error) {
	switch m.Type {
	case rpDataMSToNetwork, rpDataNetworkToMS:
		if len(m.TPDU) > 233 {
			return nil, fmt.Errorf("marshalling RP-DATA: tpdu too long %d", len(m.TPDU))
		}
		payload := []byte{m.Type, m.Reference}
		payload = append(payload, encodeRPAddress(m.Originator)...)
		payload = append(payload, encodeRPAddress(m.Destination)...)
		payload = append(payload, byte(len(m.TPDU)))
		payload = append(payload, m.TPDU...)
		return payload, nil
	case rpAckMSToNetwork, rpAckNetworkToMS:
		payload := []byte{m.Type, m.Reference}
		if len(m.UserData) == 0 {
			return payload, nil
		}
		payload = append(payload, marshalRPUserData(m.UserData)...)
		return payload, nil
	case rpErrorMSToNetwork, rpErrorNetworkToMS:
		payload := []byte{m.Type, m.Reference, 0x01, m.Cause}
		if len(m.UserData) == 0 {
			return payload, nil
		}
		payload = append(payload, marshalRPUserData(m.UserData)...)
		return payload, nil
	default:
		return nil, fmt.Errorf("marshalling RP: unsupported type 0x%02X", m.Type)
	}
}

func (m *rpMessage) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("decoding RP: packet too short")
	}
	msg := rpMessage{Type: data[0], Reference: data[1]}
	switch msg.Type {
	case rpAckMSToNetwork, rpAckNetworkToMS:
		userData, err := decodeRPUserData(data[2:])
		if err != nil {
			return err
		}
		msg.UserData = userData
		*m = msg
		return nil
	case rpErrorMSToNetwork, rpErrorNetworkToMS:
		if len(data) < 4 {
			return errors.New("decoding RP-ERROR: missing cause")
		}
		causeLength := int(data[2])
		if causeLength < 1 || len(data) < 3+causeLength {
			return fmt.Errorf("decoding RP-ERROR: invalid cause length %d", causeLength)
		}
		msg.Cause = data[3]
		msg.HasCause = true
		userData, err := decodeRPUserData(data[3+causeLength:])
		if err != nil {
			return err
		}
		msg.UserData = userData
		*m = msg
		return nil
	case rpDataMSToNetwork, rpDataNetworkToMS:
		idx := 2
		originator, n, err := decodeRPAddress(data[idx:])
		if err != nil {
			return err
		}
		idx += n
		destination, n, err := decodeRPAddress(data[idx:])
		if err != nil {
			return err
		}
		idx += n
		if len(data[idx:]) < 1 {
			return errors.New("decoding RP: missing user data length")
		}
		length := int(data[idx])
		idx++
		if len(data[idx:]) < length {
			return errors.New("decoding RP: truncated user data")
		}
		msg.Originator = originator
		msg.Destination = destination
		msg.TPDU = append([]byte(nil), data[idx:idx+length]...)
		*m = msg
		return nil
	default:
		return fmt.Errorf("decoding RP: unsupported type 0x%02X", msg.Type)
	}
}

func marshalRPUserData(data []byte) []byte {
	payload := make([]byte, 0, len(data)+2)
	payload = append(payload, 0x41, byte(len(data)))
	payload = append(payload, data...)
	return payload
}
