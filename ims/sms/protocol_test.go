package sms

import (
	"bytes"
	"testing"
)

func TestDecodeSMSDeliverFieldsRejectsTruncatedMandatoryTail(t *testing.T) {
	raw := []byte{0x00}
	raw = append(raw, encodeTPAddress("+12345")...)
	raw = append(raw, 0x00, 0x00)
	raw = append(raw, bytes.Repeat([]byte{0x00}, 7)...)

	if _, err := decodeSMSDeliverFields(raw); err == nil {
		t.Fatal("decodeSMSDeliverFields() error = nil, want non-nil")
	}
}

func TestRPDataMarshalBinaryRejectsTPDUOver233Octets(t *testing.T) {
	msg := rpMessage{
		Type:      rpDataNetworkToMS,
		Reference: 1,
		TPDU:      bytes.Repeat([]byte{0x00}, 234),
	}

	if _, err := msg.MarshalBinary(); err == nil {
		t.Fatal("MarshalBinary() error = nil, want non-nil")
	}
}
