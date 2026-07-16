package sms

import (
	"encoding"
	"errors"
	"fmt"
)

var (
	_ encoding.BinaryMarshaler   = statusReportTPDU{}
	_ encoding.BinaryUnmarshaler = (*statusReportTPDU)(nil)
)

type statusReportTPDU struct {
	Message StatusReport
}

func (tp statusReportTPDU) MarshalBinary() ([]byte, error) {
	msg := tp.Message
	if len(msg.UserData) == 0 && msg.UserDataLength != 0 {
		return nil, errors.New("marshalling SMS-STATUS-REPORT: TP-UDL requires TP-UD")
	}
	if len(msg.UserData) > 0 && !msg.HasDataCodingScheme {
		return nil, errors.New("marshalling SMS-STATUS-REPORT: TP-UD requires TP-DCS")
	}
	userDataLength := msg.UserDataLength
	if len(msg.UserData) > 0 {
		encoding, err := userDataEncodingFromDCS(msg.DataCodingScheme)
		if err != nil {
			return nil, fmt.Errorf("marshalling SMS-STATUS-REPORT: %w", err)
		}
		switch encoding {
		case userDataEncodingGSM7:
			if userDataLength <= 0 {
				return nil, errors.New("marshalling SMS-STATUS-REPORT: GSM7 TP-UD requires septet TP-UDL")
			}
			if octets := gsm7OctetCount(userDataLength); octets != len(msg.UserData) {
				return nil, fmt.Errorf("marshalling SMS-STATUS-REPORT: GSM7 TP-UDL %d requires %d octets, got %d", userDataLength, octets, len(msg.UserData))
			}
		default:
			if userDataLength == 0 {
				userDataLength = len(msg.UserData)
			}
			if userDataLength != len(msg.UserData) {
				return nil, fmt.Errorf("marshalling SMS-STATUS-REPORT: TP-UDL %d does not match %d user data octets", userDataLength, len(msg.UserData))
			}
		}
		if userDataLength > 255 {
			return nil, fmt.Errorf("marshalling SMS-STATUS-REPORT: TP-UDL %d exceeds one octet", userDataLength)
		}
	}
	recipient, err := encodeTPAddress(msg.Recipient)
	if err != nil {
		return nil, fmt.Errorf("marshalling SMS-STATUS-REPORT recipient address: %w", err)
	}
	payload := make([]byte, 0, 32)
	firstOctet := byte(tpduMTIStatusReport)
	if !msg.MoreMessagesWaiting {
		firstOctet |= tpduNoMoreMessagesFlag
	}
	if msg.LoopPrevention {
		firstOctet |= tpduLoopPreventionFlag
	}
	if msg.FromCommand {
		firstOctet |= tpduStatusReportFromCommand
	}
	if msg.HasUserDataHeader {
		firstOctet |= tpduUserDataHeaderFlag
	}
	payload = append(payload, firstOctet)
	payload = append(payload, msg.MessageReference)
	payload = append(payload, recipient...)
	payload = append(payload, encodeTimestamp(msg.ServiceCenterTime)...)
	payload = append(payload, encodeTimestamp(msg.DischargeTime)...)
	payload = append(payload, msg.Status.Code())
	var pi byte
	if msg.HasProtocolIdentifier {
		pi |= tpduParameterIndicatorPID
	}
	if msg.HasDataCodingScheme {
		pi |= tpduParameterIndicatorDCS
	}
	if len(msg.UserData) > 0 {
		pi |= tpduParameterIndicatorUDL
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
	payload = append(payload, byte(userDataLength))
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
		MoreMessagesWaiting: firstOctet&tpduNoMoreMessagesFlag == 0,
		LoopPrevention:      firstOctet&tpduLoopPreventionFlag != 0,
		FromCommand:         firstOctet&tpduStatusReportFromCommand != 0,
		HasUserDataHeader:   firstOctet&tpduUserDataHeaderFlag != 0,
	}
	idx++
	var n int
	report.Recipient, n, err = decodeTPAddress(data[idx:])
	if err != nil {
		return err
	}
	idx += n
	if len(data[idx:]) < tpduStatusReportTimeStatusLen {
		return errors.New("decoding SMS-STATUS-REPORT: truncated mandatory fields")
	}
	report.ServiceCenterTime, err = decodeTimestamp(data[idx : idx+tpduTimestampOctets])
	if err != nil {
		return err
	}
	idx += tpduTimestampOctets
	report.DischargeTime, err = decodeTimestamp(data[idx : idx+tpduTimestampOctets])
	if err != nil {
		return err
	}
	idx += tpduTimestampOctets
	report.Status = ReportStatus(data[idx])
	idx++

	ignoreTrailing := false
	if len(data[idx:]) > 0 {
		piOctets := make([]byte, 0, 1)
		for {
			if len(data[idx:]) < 1 {
				return errors.New("decoding SMS-STATUS-REPORT: missing parameter indicator")
			}
			pi := data[idx]
			idx++
			piOctets = append(piOctets, pi)
			if pi&tpduParameterIndicatorExtFlag == 0 {
				break
			}
		}
		pi := piOctets[0]
		ignoreTrailing = pi&tpduParameterIndicatorReservedMask != 0
		if pi&tpduParameterIndicatorPID != 0 {
			if len(data[idx:]) < 1 {
				return errors.New("decoding SMS-STATUS-REPORT: missing protocol identifier")
			}
			report.ProtocolIdentifier = data[idx]
			report.HasProtocolIdentifier = true
			idx++
		}
		dcs := byte(tpDCSGSM7)
		if pi&tpduParameterIndicatorDCS != 0 {
			if len(data[idx:]) < 1 {
				return errors.New("decoding SMS-STATUS-REPORT: missing data coding scheme")
			}
			dcs = data[idx]
			report.DataCodingScheme = dcs
			report.HasDataCodingScheme = true
			idx++
		}
		if pi&tpduParameterIndicatorUDL != 0 {
			if len(data[idx:]) < 1 {
				return errors.New("decoding SMS-STATUS-REPORT: missing user data length")
			}
			userDataLength := int(data[idx])
			report.UserDataLength = userDataLength
			idx++
			octets, err := userDataOctets(userDataLength, dcs)
			if err != nil {
				return fmt.Errorf("decoding SMS-STATUS-REPORT: %w", err)
			}
			if len(data[idx:]) < octets {
				return errors.New("decoding SMS-STATUS-REPORT: truncated user data")
			}
			report.UserData = append([]byte(nil), data[idx:idx+octets]...)
			idx += octets
		}
	}
	if idx != len(data) && !ignoreTrailing {
		return errors.New("decoding SMS-STATUS-REPORT: trailing data")
	}

	report.RawTPDU = append([]byte(nil), data...)
	tp.Message = report
	return nil
}
