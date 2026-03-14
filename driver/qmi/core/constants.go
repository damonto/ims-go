package core

import (
	"errors"
	"fmt"
)

type Service uint8

const (
	ServiceControl Service = 0x00
	ServiceUIM     Service = 0x0B
)

type MessageType uint8

const (
	MessageTypeRequest  MessageType = 0x00
	MessageTypeResponse MessageType = 0x02
)

type MessageID uint16

const (
	MessageProxyOpen        MessageID = 0xFF00
	MessageAllocateClientID MessageID = 0x0022
	MessageReleaseClientID  MessageID = 0x0023

	MessageReadTransparent MessageID = 0x0020
	MessageReadRecord      MessageID = 0x0021
	MessageGetFileAttrs    MessageID = 0x0024
	MessageGetCardStatus   MessageID = 0x002F
	MessageAuthenticate    MessageID = 0x0034
	MessageSwitchSlot      MessageID = 0x0046
	MessageGetSlotStatus   MessageID = 0x0047
)

type Session uint8

const (
	SessionPrimaryGWProvisioning Session = 0

	SessionNonProvisioningSlot1 Session = 4
	SessionNonProvisioningSlot2 Session = 5
	SessionCardSlot1            Session = 6
	SessionCardSlot2            Session = 7

	SessionNonProvisioningSlot3 Session = 16
	SessionNonProvisioningSlot4 Session = 17
	SessionNonProvisioningSlot5 Session = 18
	SessionCardSlot3            Session = 19
	SessionCardSlot4            Session = 20
	SessionCardSlot5            Session = 21
)

const (
	QMUXIfType             = 0x01
	QMUXControlFlagRequest = 0x00

	TLVResult     = 0x02
	TLVCardResult = 0x10

	Authenticate3GContext = 3
)

type Error uint16

const (
	ErrorNoMemory           Error = 2
	ErrorDeviceInUse        Error = 23
	ErrorDeviceUnsupported  Error = 25
	ErrorSessionInactive    Error = 65
	ErrorSessionInvalid     Error = 66
	ErrorSIMFileNotFound    Error = 80
	ErrorNotSupported       Error = 94
	ErrorInvalidSessionType Error = 100
	ErrorNoSIM              Error = 102
)

func (e Error) Error() string {
	switch e {
	case ErrorNoMemory:
		return "QMI no memory"
	case ErrorDeviceInUse:
		return "QMI device in use"
	case ErrorDeviceUnsupported:
		return "QMI device unsupported"
	case ErrorSessionInactive:
		return "QMI session inactive"
	case ErrorSessionInvalid:
		return "QMI session invalid"
	case ErrorSIMFileNotFound:
		return "QMI SIM file not found"
	case ErrorNotSupported:
		return "QMI operation not supported"
	case ErrorInvalidSessionType:
		return "QMI invalid session type"
	case ErrorNoSIM:
		return "QMI no SIM"
	default:
		return fmt.Sprintf("QMI error %d", uint16(e))
	}
}

func RetryableSessionError(err error) bool {
	return errors.Is(err, ErrorSessionInactive) ||
		errors.Is(err, ErrorSessionInvalid) ||
		errors.Is(err, ErrorInvalidSessionType)
}
