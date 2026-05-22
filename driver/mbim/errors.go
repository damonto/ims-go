package mbim

import "fmt"

type ProtocolError uint32

const (
	ProtocolErrorInvalid ProtocolError = iota
	ProtocolErrorTimeoutFragment
	ProtocolErrorFragmentOutOfSequence
	ProtocolErrorLengthMismatch
	ProtocolErrorDuplicatedTID
	ProtocolErrorNotOpened
	ProtocolErrorUnknown
	ProtocolErrorCancel
	ProtocolErrorMaxTransfer
)

func (e ProtocolError) Error() string {
	switch e {
	case ProtocolErrorInvalid:
		return "MBIM protocol invalid"
	case ProtocolErrorTimeoutFragment:
		return "MBIM protocol timeout fragment"
	case ProtocolErrorFragmentOutOfSequence:
		return "MBIM protocol fragment out of sequence"
	case ProtocolErrorLengthMismatch:
		return "MBIM protocol length mismatch"
	case ProtocolErrorDuplicatedTID:
		return "MBIM protocol duplicated transaction ID"
	case ProtocolErrorNotOpened:
		return "MBIM protocol not opened"
	case ProtocolErrorUnknown:
		return "MBIM protocol unknown"
	case ProtocolErrorCancel:
		return "MBIM protocol canceled"
	case ProtocolErrorMaxTransfer:
		return "MBIM protocol max transfer"
	default:
		return fmt.Sprintf("MBIM protocol error %d", uint32(e))
	}
}

type Status uint32

const (
	StatusNone Status = iota
	StatusBusy
	StatusFailure
	StatusSIMNotInserted
	StatusBadSIM
	StatusPINRequired
	StatusPINDisabled
	StatusNotRegistered
	StatusProvidersNotFound
	StatusNoDeviceSupport
	StatusProviderNotVisible
	StatusDataClassNotAvailable
	StatusPacketServiceDetached
	StatusMaxActivatedContexts
	StatusNotInitialized
	StatusVoiceCallInProgress
	StatusContextNotActivated
	StatusServiceNotActivated
	StatusInvalidAccessString
	StatusInvalidUserNamePassword
	StatusRadioPowerOff
	StatusInvalidParameters
	StatusReadFailure
	StatusWriteFailure
	StatusReserved
	StatusNoPhonebook
	StatusParameterTooLong
	StatusSTKBusy
	StatusOperationNotAllowed
	StatusMemoryFailure
	StatusInvalidMemoryIndex
	StatusMemoryFull
	StatusFilterNotSupported
	StatusDSSInstanceLimit
	StatusInvalidDeviceServiceOperation
	StatusAuthIncorrectAUTN
	StatusAuthSyncFailure
	StatusAuthAMFNotSet
	StatusContextNotSupported
)

const (
	StatusMSNoLogicalChannels     Status = 0x87430001
	StatusMSSelectFailed          Status = 0x87430002
	StatusMSInvalidLogicalChannel Status = 0x87430003
)

func (e Status) Error() string {
	switch e {
	case StatusNone:
		return "MBIM success"
	case StatusBusy:
		return "MBIM busy"
	case StatusFailure:
		return "MBIM failure"
	case StatusSIMNotInserted:
		return "MBIM SIM not inserted"
	case StatusBadSIM:
		return "MBIM bad SIM"
	case StatusPINRequired:
		return "MBIM PIN required"
	case StatusPINDisabled:
		return "MBIM PIN disabled"
	case StatusNotRegistered:
		return "MBIM not registered"
	case StatusProvidersNotFound:
		return "MBIM providers not found"
	case StatusNoDeviceSupport:
		return "MBIM no device support"
	case StatusProviderNotVisible:
		return "MBIM provider not visible"
	case StatusDataClassNotAvailable:
		return "MBIM data class not available"
	case StatusPacketServiceDetached:
		return "MBIM packet service detached"
	case StatusMaxActivatedContexts:
		return "MBIM max activated contexts"
	case StatusNotInitialized:
		return "MBIM not initialized"
	case StatusVoiceCallInProgress:
		return "MBIM voice call in progress"
	case StatusContextNotActivated:
		return "MBIM context not activated"
	case StatusServiceNotActivated:
		return "MBIM service not activated"
	case StatusInvalidAccessString:
		return "MBIM invalid access string"
	case StatusInvalidUserNamePassword:
		return "MBIM invalid user name or password"
	case StatusRadioPowerOff:
		return "MBIM radio power off"
	case StatusInvalidParameters:
		return "MBIM invalid parameters"
	case StatusReadFailure:
		return "MBIM read failure"
	case StatusWriteFailure:
		return "MBIM write failure"
	case StatusReserved:
		return "MBIM reserved status"
	case StatusNoPhonebook:
		return "MBIM no phonebook"
	case StatusParameterTooLong:
		return "MBIM parameter too long"
	case StatusSTKBusy:
		return "MBIM STK busy"
	case StatusOperationNotAllowed:
		return "MBIM operation not allowed"
	case StatusMemoryFailure:
		return "MBIM memory failure"
	case StatusInvalidMemoryIndex:
		return "MBIM invalid memory index"
	case StatusMemoryFull:
		return "MBIM memory full"
	case StatusFilterNotSupported:
		return "MBIM filter not supported"
	case StatusDSSInstanceLimit:
		return "MBIM DSS instance limit"
	case StatusInvalidDeviceServiceOperation:
		return "MBIM invalid device service operation"
	case StatusAuthIncorrectAUTN:
		return "MBIM auth incorrect AUTN"
	case StatusAuthSyncFailure:
		return "MBIM auth sync failure"
	case StatusAuthAMFNotSet:
		return "MBIM auth AMF not set"
	case StatusContextNotSupported:
		return "MBIM context not supported"
	case StatusMSNoLogicalChannels:
		return "MBIM no logical channels"
	case StatusMSSelectFailed:
		return "MBIM select failed"
	case StatusMSInvalidLogicalChannel:
		return "MBIM invalid logical channel"
	default:
		return fmt.Sprintf("MBIM status %d", uint32(e))
	}
}
