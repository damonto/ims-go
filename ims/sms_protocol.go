package ims

import (
	"encoding"
	"errors"
	"fmt"
)

var (
	_ encoding.BinaryMarshaler   = smsSubmitTPDU{}
	_ encoding.BinaryMarshaler   = smsDeliverTPDU{}
	_ encoding.BinaryUnmarshaler = (*smsDeliverTPDU)(nil)
	_ encoding.BinaryMarshaler   = rpMessage{}
	_ encoding.BinaryUnmarshaler = (*rpMessage)(nil)
)

type smsSubmitTPDU struct {
	Reference   byte
	Destination string
	Part        smsUserDataPart
}

func newSMSSubmitTPDU(reference byte, destination string, part smsUserDataPart) smsSubmitTPDU {
	return smsSubmitTPDU{Reference: reference, Destination: destination, Part: part}
}

func (tp smsSubmitTPDU) MarshalBinary() ([]byte, error) {
	firstOctet := byte(0x01)
	if tp.Part.udhi {
		firstOctet |= 0x40
	}
	payload := make([]byte, 0, 32+len(tp.Part.userData))
	payload = append(payload, firstOctet)
	payload = append(payload, tp.Reference)
	payload = append(payload, encodeTPAddress(tp.Destination)...)
	payload = append(payload, 0x00)
	payload = append(payload, tp.Part.dcs)
	payload = append(payload, byte(tp.Part.udl))
	payload = append(payload, tp.Part.userData...)
	return payload, nil
}

type smsDeliverTPDU struct {
	From    string
	Part    smsUserDataPart
	Message IncomingSMS
	Concat  *smsConcatInfo
}

func newSMSDeliverTPDU(from string, part smsUserDataPart) smsDeliverTPDU {
	return smsDeliverTPDU{From: from, Part: part}
}

func (tp smsDeliverTPDU) MarshalBinary() ([]byte, error) {
	firstOctet := byte(0x00)
	if tp.Part.udhi {
		firstOctet |= 0x40
	}
	payload := make([]byte, 0, 32+len(tp.Part.userData))
	payload = append(payload, firstOctet)
	payload = append(payload, encodeTPAddress(tp.From)...)
	payload = append(payload, 0x00, tp.Part.dcs)
	payload = append(payload, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	payload = append(payload, byte(tp.Part.udl))
	payload = append(payload, tp.Part.userData...)
	return payload, nil
}

type smsDeliverFields struct {
	from string
	part smsUserDataPart
}

func decodeSMSDeliverFields(data []byte) (smsDeliverFields, error) {
	if len(data) < 1 {
		return smsDeliverFields{}, errors.New("decoding SMS-DELIVER: packet too short")
	}
	part := smsUserDataPart{udhi: (data[0]>>6)&0x01 == 1}
	idx := 1
	from, n, err := decodeTPAddress(data[idx:])
	if err != nil {
		return smsDeliverFields{}, err
	}
	idx += n
	if len(data[idx:]) < 9 {
		return smsDeliverFields{}, errors.New("decoding SMS-DELIVER: truncated mandatory fields")
	}
	idx++
	part.dcs = data[idx]
	idx++
	idx += 7
	part.udl = int(data[idx])
	idx++
	part.userData = append([]byte(nil), data[idx:]...)
	return smsDeliverFields{from: from, part: part}, nil
}

func decodeSMSDeliverGSM7(part smsUserDataPart) (string, *smsConcatInfo, error) {
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
	headerLen, concat, err := decodeSMSUserDataHeader(payload)
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

func decodeSMSDeliverUCS2(part smsUserDataPart) (string, *smsConcatInfo, error) {
	if len(part.userData) < part.udl {
		return "", nil, errors.New("decoding SMS-DELIVER: truncated UCS2 payload")
	}
	payload := part.userData[:part.udl]
	if !part.udhi {
		return decodeUCS2(payload), nil, nil
	}
	headerLen, concat, err := decodeSMSUserDataHeader(payload)
	if err != nil {
		return "", nil, err
	}
	if part.udl < headerLen {
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: invalid UCS2 UDL %d", part.udl)
	}
	return decodeUCS2(payload[headerLen:]), concat, nil
}

func decodeSMSDeliverUserData(part smsUserDataPart) (string, *smsConcatInfo, error) {
	switch part.dcs {
	case 0x00:
		return decodeSMSDeliverGSM7(part)
	case 0x08:
		return decodeSMSDeliverUCS2(part)
	default:
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: unsupported dcs 0x%02X", part.dcs)
	}
}

func (tp *smsDeliverTPDU) UnmarshalBinary(data []byte) error {
	fields, err := decodeSMSDeliverFields(data)
	if err != nil {
		return err
	}
	text, concat, err := decodeSMSDeliverUserData(fields.part)
	if err != nil {
		return err
	}
	*tp = smsDeliverTPDU{
		From:    fields.from,
		Part:    fields.part,
		Message: IncomingSMS{From: fields.from, Text: text},
		Concat:  concat,
	}
	return nil
}

func newRPDataMessage(reference byte, destination string, tpdu []byte) rpMessage {
	return rpMessage{Type: rpDataMSToNetwork, Reference: reference, Destination: destination, TPDU: append([]byte(nil), tpdu...)}
}

func newRPAckMessage(reference byte) rpMessage {
	return rpMessage{Type: rpAckMSToNetwork, Reference: reference}
}

func newRPAckDeliverReportMessage(reference byte) rpMessage {
	return rpMessage{Type: rpAckMSToNetwork, Reference: reference, UserData: []byte{0x00, 0x00}}
}

func newRPErrorMessage(reference, cause byte) rpMessage {
	return rpMessage{Type: rpErrorMSToNetwork, Reference: reference, Cause: cause, HasCause: true}
}

func (m rpMessage) MarshalBinary() ([]byte, error) {
	switch m.Type {
	case rpDataMSToNetwork, rpDataNetworkToMS:
		if len(m.TPDU) > 255 {
			return nil, fmt.Errorf("marshalling RP-DATA: tpdu too long %d", len(m.TPDU))
		}
		payload := []byte{m.Type, m.Reference}
		payload = append(payload, encodeRPAddress("")...)
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
		_, n, err := decodeRPAddress(data[idx:])
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
