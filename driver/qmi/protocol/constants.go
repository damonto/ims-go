package protocol

// ServiceType represents QMI service types
type ServiceType uint8

const (
	QMIServiceControl ServiceType = 0x00 // Control service
	QMIServiceCAT2    ServiceType = 0x0A // Card Application Toolkit service v2
	QMIServiceUIM     ServiceType = 0x0B // UIM service
	QMIServiceCAT     ServiceType = 0xE0 // Card Application Toolkit service v1

	ServiceControl = QMIServiceControl
	ServiceCAT2    = QMIServiceCAT2
	ServiceUIM     = QMIServiceUIM
	ServiceCAT     = QMIServiceCAT
)

// MessageType represents QMI message types
type MessageType uint8

const (
	QMIMessageTypeRequest    MessageType = 0x00
	QMIMessageTypeResponse   MessageType = 0x02
	QMIMessageTypeIndication MessageType = 0x04

	MessageTypeRequest  = QMIMessageTypeRequest
	MessageTypeResponse = QMIMessageTypeResponse
)

// MessageID represents QMI command message IDs
type MessageID uint16

const (
	// CTL service commands
	QMICtlCmdGetVersionInfo   MessageID = 0x0021
	QMICtlCmdAllocateClientID MessageID = 0x0022
	QMICtlCmdReleaseClientID  MessageID = 0x0023
	QMICtlInternalProxyOpen   MessageID = 0xFF00

	// UIM service commands
	QMIUIMReadTransparent     MessageID = 0x0020
	QMIUIMReadRecord          MessageID = 0x0021
	QMIUIMGetFileAttributes   MessageID = 0x0024
	QMIUIMSendAPDU            MessageID = 0x003B
	QMIUIMOpenLogicalChannel  MessageID = 0x0042
	QMIUIMCloseLogicalChannel MessageID = 0x003F
	QMIUIMSwitchSlot          MessageID = 0x0046
	QMIUIMGetSlotStatus       MessageID = 0x0047
	QMIUIMGetCardStatus       MessageID = 0x002F
	QMIUIMAuthenticate        MessageID = 0x0034

	// CAT/CAT2 service commands
	QMICATSendEnvelope MessageID = 0x0022

	MessageReadTransparent = QMIUIMReadTransparent
	MessageReadRecord      = QMIUIMReadRecord
	MessageGetFileAttrs    = QMIUIMGetFileAttributes
	MessageGetCardStatus   = QMIUIMGetCardStatus
	MessageAuthenticate    = QMIUIMAuthenticate
	MessageSwitchSlot      = QMIUIMSwitchSlot
	MessageGetSlotStatus   = QMIUIMGetSlotStatus
)

// QMUX header constants
const (
	QMUXHeaderIfType             = 0x01
	QMUXHeaderControlFlagRequest = 0x00

	QMUXIfType             = QMUXHeaderIfType
	QMUXControlFlagRequest = QMUXHeaderControlFlagRequest
)

const (
	MaxEncodedMessageLength = 0xffff

	QMUXHeaderLength         = 1 + 5
	QMIControlHeaderLength   = 6
	QMIServiceHeaderLength   = 7
	QRTRInternalHeaderLength = 1 + 5

	MaxQMUXControlTLVLength = MaxEncodedMessageLength - QMUXHeaderLength - QMIControlHeaderLength
	MaxQMUXServiceTLVLength = MaxEncodedMessageLength - QMUXHeaderLength - QMIServiceHeaderLength
	MaxQRTRServiceTLVLength = MaxEncodedMessageLength - QRTRInternalHeaderLength - QMIServiceHeaderLength
	MaxQRTRQMIMessageLength = QMIServiceHeaderLength + MaxQRTRServiceTLVLength
)

// QMIResult represents the result code in QMI responses
type QMIResult uint16

const (
	QMIResultSuccess QMIResult = 0x0000 // Success
	QMIResultFailure QMIResult = 0x0001 // Failure
)
