package sms

import (
	"time"
)

type Incoming struct {
	CallID        string
	From          string
	FromURI       string
	To            string
	ToURI         string
	ServiceCenter string
	Text          string
	RawTPDU       []byte
	RawTPDUs      [][]byte
	ReservedMTI   bool
}

type StatusReport struct {
	ServiceCenter         string
	Recipient             string
	MessageReference      byte
	Status                ReportStatus
	MoreMessagesWaiting   bool
	LoopPrevention        bool
	FromCommand           bool
	HasUserDataHeader     bool
	ServiceCenterTime     time.Time
	DischargeTime         time.Time
	ProtocolIdentifier    byte
	HasProtocolIdentifier bool
	DataCodingScheme      byte
	HasDataCodingScheme   bool
	UserData              []byte
}
