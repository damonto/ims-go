package sms

import (
	"encoding"
	"errors"
	"fmt"
)

var (
	_ encoding.BinaryMarshaler   = rpMessage{}
	_ encoding.BinaryUnmarshaler = (*rpMessage)(nil)
)

const (
	rpDataMSToNetwork  = 0x00
	rpDataNetworkToMS  = 0x01
	rpAckMSToNetwork   = 0x02
	rpAckNetworkToMS   = 0x03
	rpErrorMSToNetwork = 0x04
	rpErrorNetworkToMS = 0x05
	rpSMMAMSToNetwork  = 0x06
)

const (
	rpCauseUnassignedNumber                     = 1
	rpCauseOperatorDeterminedBarring            = 8
	rpCauseCallBarred                           = 10
	rpCauseShortMessageTransferRejected         = 21
	rpCauseMemoryCapacityExceeded               = 22
	rpCauseDestinationOutOfOrder                = 27
	rpCauseUnidentifiedSubscriber               = 28
	rpCauseFacilityRejected                     = 29
	rpCauseUnknownSubscriber                    = 30
	rpCauseNetworkOutOfOrder                    = 38
	rpCauseTemporaryFailure                     = 41
	rpCauseCongestion                           = 42
	rpCauseResourcesUnavailable                 = 47
	rpCauseRequestedFacilityNotSubscribed       = 50
	rpCauseRequestedFacilityNotImplemented      = 69
	rpCauseInvalidShortMessageTransferReference = 81
	rpCauseSemanticallyIncorrectMessage         = 95
	rpCauseInvalidMandatoryInformation          = 96
	rpCauseMessageTypeNotImplemented            = 97
	rpCauseMessageNotCompatibleWithState        = 98
	rpCauseInformationElementNotImplemented     = 99
	rpCauseProtocolErrorUnspecified             = 111
	rpCauseInterworkingUnspecified              = 127
)

type rpMessage struct {
	Type         byte
	Reference    byte
	TPDU         []byte
	Originator   string
	Destination  string
	Cause        byte
	HasCause     bool
	UserData     []byte
	SubmitReport *SubmitReport
}

type RPError struct {
	Cause byte
}

// RPCauseMemoryCapacityExceeded rejects an MT short message when the receiver
// cannot persist it, as defined by TS 24.011 table 8.4 part 2.
const RPCauseMemoryCapacityExceeded byte = rpCauseMemoryCapacityExceeded

type unsupportedRPMessageTypeError struct {
	Type byte
}

func (e unsupportedRPMessageTypeError) Error() string {
	return fmt.Sprintf("decoding RP: unsupported type 0x%02X", e.Type)
}

func (e *RPError) Error() string {
	if text := rpCauseText(e.Cause); text != "" {
		return fmt.Sprintf("rp-error cause %d (%s)", e.Cause, text)
	}
	return fmt.Sprintf("rp-error cause %d", e.Cause)
}

func rpCauseText(cause byte) string {
	switch cause {
	case rpCauseUnassignedNumber:
		return "unassigned number"
	case rpCauseOperatorDeterminedBarring:
		return "operator determined barring"
	case rpCauseCallBarred:
		return "call barred"
	case rpCauseShortMessageTransferRejected:
		return "short message transfer rejected"
	case rpCauseMemoryCapacityExceeded:
		return "memory capacity exceeded"
	case rpCauseDestinationOutOfOrder:
		return "destination out of order"
	case rpCauseUnidentifiedSubscriber:
		return "unidentified subscriber"
	case rpCauseFacilityRejected:
		return "facility rejected"
	case rpCauseUnknownSubscriber:
		return "unknown subscriber"
	case rpCauseNetworkOutOfOrder:
		return "network out of order"
	case rpCauseTemporaryFailure:
		return "temporary failure"
	case rpCauseCongestion:
		return "congestion"
	case rpCauseResourcesUnavailable:
		return "resources unavailable"
	case rpCauseRequestedFacilityNotSubscribed:
		return "requested facility not subscribed"
	case rpCauseRequestedFacilityNotImplemented:
		return "requested facility not implemented"
	case rpCauseInvalidShortMessageTransferReference:
		return "invalid short message transfer reference"
	case rpCauseSemanticallyIncorrectMessage:
		return "semantically incorrect message"
	case rpCauseInvalidMandatoryInformation:
		return "invalid mandatory information"
	case rpCauseMessageTypeNotImplemented:
		return "message type not implemented"
	case rpCauseMessageNotCompatibleWithState:
		return "message not compatible with short message protocol state"
	case rpCauseInformationElementNotImplemented:
		return "information element not implemented"
	case rpCauseProtocolErrorUnspecified:
		return "protocol error"
	case rpCauseInterworkingUnspecified:
		return "interworking"
	default:
		return ""
	}
}

const (
	rpUserDataIEI               = 0x41
	maxRPDataUserDataOctets     = 233
	maxRPAckErrorUserDataOctets = 234
	rpCauseValueOctets          = 1
	maxRPCauseLength            = 2
)

func newRPDataMessage(reference byte, destination string, tpdu []byte) rpMessage {
	return rpMessage{Type: rpDataMSToNetwork, Reference: reference, Destination: destination, TPDU: append([]byte(nil), tpdu...)}
}

func newRPAckMessage(reference byte) rpMessage {
	return rpMessage{Type: rpAckMSToNetwork, Reference: reference}
}

func newRPAckDeliverReportMessage(reference byte, userData []byte) rpMessage {
	if len(userData) == 0 {
		userData = []byte{tpduMTIDeliverReport, tpduParameterIndicatorNone}
	}
	return rpMessage{Type: rpAckMSToNetwork, Reference: reference, UserData: append([]byte(nil), userData...)}
}

func newRPErrorMessage(reference, cause byte) rpMessage {
	return rpMessage{Type: rpErrorMSToNetwork, Reference: reference, Cause: cause, HasCause: true}
}

func newRPErrorDeliverReportMessage(reference, cause, failureCause byte) rpMessage {
	return rpMessage{
		Type:      rpErrorMSToNetwork,
		Reference: reference,
		Cause:     cause,
		HasCause:  true,
		UserData:  []byte{tpduMTIDeliverReport, failureCause, tpduParameterIndicatorNone},
	}
}

func newRPSMMAMessage(reference byte) rpMessage {
	return rpMessage{Type: rpSMMAMSToNetwork, Reference: reference}
}

func (m rpMessage) MarshalBinary() ([]byte, error) {
	switch m.Type {
	case rpDataMSToNetwork, rpDataNetworkToMS:
		if len(m.TPDU) == 0 {
			return nil, errors.New("marshalling RP-DATA: user data is empty")
		}
		if len(m.TPDU) > maxRPDataUserDataOctets {
			return nil, fmt.Errorf("marshalling RP-DATA: tpdu too long %d", len(m.TPDU))
		}
		originator, err := marshalRPAddress(m.Originator)
		if err != nil {
			return nil, fmt.Errorf("marshalling RP-DATA originator address: %w", err)
		}
		destination, err := marshalRPAddress(m.Destination)
		if err != nil {
			return nil, fmt.Errorf("marshalling RP-DATA destination address: %w", err)
		}
		payload := []byte{m.Type, m.Reference}
		payload = append(payload, originator...)
		payload = append(payload, destination...)
		payload = append(payload, byte(len(m.TPDU)))
		payload = append(payload, m.TPDU...)
		return payload, nil
	case rpAckMSToNetwork, rpAckNetworkToMS:
		if len(m.UserData) > maxRPAckErrorUserDataOctets {
			return nil, fmt.Errorf("marshalling RP-ACK: user data too long %d", len(m.UserData))
		}
		payload := []byte{m.Type, m.Reference}
		if len(m.UserData) == 0 {
			return payload, nil
		}
		payload = append(payload, marshalRPUserData(m.UserData)...)
		return payload, nil
	case rpErrorMSToNetwork, rpErrorNetworkToMS:
		if len(m.UserData) > maxRPAckErrorUserDataOctets {
			return nil, fmt.Errorf("marshalling RP-ERROR: user data too long %d", len(m.UserData))
		}
		payload := []byte{m.Type, m.Reference, rpCauseValueOctets, m.Cause}
		if len(m.UserData) == 0 {
			return payload, nil
		}
		payload = append(payload, marshalRPUserData(m.UserData)...)
		return payload, nil
	case rpSMMAMSToNetwork:
		return []byte{m.Type, m.Reference}, nil
	default:
		return nil, fmt.Errorf("marshalling RP: unsupported type 0x%02X", m.Type)
	}
}

func (m *rpMessage) UnmarshalBinary(data []byte) error {
	if len(data) < 2 {
		return errors.New("decoding RP: packet too short")
	}
	// TS 24.011 8.2.2 defines the MTI as the low three bits. Spare bits are
	// ignored by the receiver.
	msg := rpMessage{Type: data[0] & 0x07, Reference: data[1]}
	switch msg.Type {
	case rpAckMSToNetwork, rpAckNetworkToMS:
		userData, err := decodeRPUserData(data[2:], maxRPAckErrorUserDataOctets)
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
		if causeLength < 1 || causeLength > maxRPCauseLength || len(data) < 3+causeLength {
			return fmt.Errorf("decoding RP-ERROR: invalid cause length %d", causeLength)
		}
		msg.Cause = data[3]
		msg.HasCause = true
		userData, err := decodeRPUserData(data[3+causeLength:], maxRPAckErrorUserDataOctets)
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
		if length == 0 {
			return errors.New("decoding RP-DATA: user data is empty")
		}
		if length > maxRPDataUserDataOctets {
			return fmt.Errorf("decoding RP-DATA: user data too long %d", length)
		}
		if len(data[idx:]) < length {
			return errors.New("decoding RP: truncated user data")
		}
		if len(data[idx:]) > length {
			return errors.New("decoding RP-DATA: trailing data")
		}
		msg.Originator = originator
		msg.Destination = destination
		msg.TPDU = append([]byte(nil), data[idx:idx+length]...)
		*m = msg
		return nil
	case rpSMMAMSToNetwork:
		if len(data) != 2 {
			return errors.New("decoding RP-SMMA: trailing data")
		}
		*m = msg
		return nil
	default:
		return unsupportedRPMessageTypeError{Type: msg.Type}
	}
}

func decodeRPUserData(data []byte, maxLen int) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < 2 {
		return nil, errors.New("decoding RP user data: truncated field")
	}
	if data[0] != rpUserDataIEI {
		return nil, fmt.Errorf("decoding RP user data: unexpected IEI 0x%02X", data[0])
	}
	length := int(data[1])
	if length > maxLen {
		return nil, fmt.Errorf("decoding RP user data: too long %d", length)
	}
	if len(data) < 2+length {
		return nil, errors.New("decoding RP user data: truncated payload")
	}
	if len(data) > 2+length {
		return nil, errors.New("decoding RP user data: trailing data")
	}
	return append([]byte(nil), data[2:2+length]...), nil
}

func marshalRPUserData(data []byte) []byte {
	payload := make([]byte, 0, len(data)+2)
	payload = append(payload, rpUserDataIEI, byte(len(data)))
	payload = append(payload, data...)
	return payload
}
