package sms

import (
	"encoding"
	"errors"
	"fmt"
)

var (
	_ encoding.BinaryMarshaler   = deliverTPDU{}
	_ encoding.BinaryUnmarshaler = (*deliverTPDU)(nil)
)

type deliverTPDU struct {
	From    string
	Part    userDataPart
	Message Incoming
	Concat  *concatInfo
}

type deliverFields struct {
	from string
	part userDataPart
}

func newDeliverTPDU(from string, part userDataPart) deliverTPDU {
	return deliverTPDU{From: from, Part: part}
}

func (tp deliverTPDU) MarshalBinary() ([]byte, error) {
	from, err := encodeTPAddress(tp.From)
	if err != nil {
		return nil, fmt.Errorf("marshalling SMS-DELIVER originator address: %w", err)
	}
	firstOctet := byte(tpduMTIDeliver)
	if tp.Part.udhi {
		firstOctet |= tpduUserDataHeaderFlag
	}
	payload := make([]byte, 0, 32+len(tp.Part.userData))
	payload = append(payload, firstOctet)
	payload = append(payload, from...)
	payload = append(payload, tp.Part.pid, tp.Part.dcs)
	payload = append(payload, tpduZeroTimestamp[:]...)
	payload = append(payload, byte(tp.Part.udl))
	payload = append(payload, tp.Part.userData...)
	return payload, nil
}

func decodeDeliverFields(data []byte) (deliverFields, error) {
	mti, err := tpduMessageType(data)
	if err != nil {
		return deliverFields{}, errors.New("decoding SMS-DELIVER: packet too short")
	}
	if mti != tpduMTIDeliver && mti != tpduMTIReserved {
		return deliverFields{}, fmt.Errorf("decoding SMS-DELIVER: unexpected tp-mti 0x%02X", mti)
	}
	part := userDataPart{udhi: data[0]&tpduUserDataHeaderFlag != 0}
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
	octets, err := userDataOctets(part.udl, part.dcs)
	if err != nil {
		return deliverFields{}, fmt.Errorf("decoding SMS-DELIVER: %w", err)
	}
	if len(data[idx:]) < octets {
		return deliverFields{}, errors.New("decoding SMS-DELIVER: truncated user data")
	}
	if len(data[idx:]) > octets {
		return deliverFields{}, errors.New("decoding SMS-DELIVER: trailing data")
	}
	part.userData = append([]byte(nil), data[idx:idx+octets]...)
	return deliverFields{from: from, part: part}, nil
}

func userDataOctets(udl int, dcs byte) (int, error) {
	encoding, err := userDataEncodingFromDCS(dcs)
	if err != nil {
		return 0, err
	}
	if encoding == userDataEncodingGSM7 {
		return gsm7OctetCount(udl), nil
	}
	return udl, nil
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
		text, err := decodeUCS2(payload)
		if err != nil {
			return "", nil, fmt.Errorf("decoding SMS-DELIVER: %w", err)
		}
		return text, nil, nil
	}
	headerLen, concat, err := decodeUserDataHeader(payload)
	if err != nil {
		return "", nil, err
	}
	if part.udl < headerLen {
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: invalid UCS2 UDL %d", part.udl)
	}
	text, err := decodeUCS2(payload[headerLen:])
	if err != nil {
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: %w", err)
	}
	return text, concat, nil
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
	case userDataEncoding8Bit:
		if !part.udhi {
			return "", nil, nil
		}
		_, concat, err := decodeUserDataHeader(part.userData)
		return "", concat, err
	default:
		return "", nil, fmt.Errorf("decoding SMS-DELIVER: unsupported dcs 0x%02X", part.dcs)
	}
}

func isPPDataDownload(part userDataPart) bool {
	return part.pid == tpPIDUSIMDataDownload && dcsMessageClass(part.dcs) == dcsMessageClassSIM
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
	message := Incoming{
		From: fields.from, Text: text,
		ProtocolIdentifier: fields.part.pid,
		DataCodingScheme:   fields.part.dcs,
		UserData:           append([]byte(nil), fields.part.userData...),
		RawTPDU:            append([]byte(nil), data...),
		ReservedMTI:        data[0]&tpduMTIMask == tpduMTIReserved,
	}
	if fields.part.udhi && len(fields.part.userData) > 0 {
		headerLen := int(fields.part.userData[0]) + 1
		if headerLen <= len(fields.part.userData) {
			message.UserDataHeader = append([]byte(nil), fields.part.userData[:headerLen]...)
		}
	}
	*tp = deliverTPDU{
		From:    fields.from,
		Part:    fields.part,
		Message: message,
		Concat:  concat,
	}
	return nil
}
