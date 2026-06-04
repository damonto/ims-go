package qrtr

import (
	"bytes"
	"testing"

	"github.com/damonto/vowifi-go/driver/qmi/protocol"
)

func TestMarshalRequest(t *testing.T) {
	req := protocol.Request{
		TransactionID: 3,
		MessageID:     protocol.MessageReadTransparent,
		TLVs: protocol.TLVs{
			tlv(0x01, []byte{0x06, 0x00}),
			tlv(0x02, []byte{0x07, 0x6F, 0x00}),
			tlv(0x03, []byte{0x00, 0x00, 0x09, 0x00}),
		},
	}
	want := []byte{
		0x00, 0x03, 0x00, 0x20, 0x00, 0x12, 0x00,
		0x01, 0x02, 0x00, 0x06, 0x00,
		0x02, 0x03, 0x00, 0x07, 0x6F, 0x00,
		0x03, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00,
	}
	got, err := MarshalRequest(req)
	if err != nil {
		t.Fatalf("MarshalRequest() error = %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalRequest() = % X, want % X", got, want)
	}
}

func TestMarshalRequestReturnsTLVError(t *testing.T) {
	req := protocol.Request{
		TransactionID: 3,
		MessageID:     protocol.MessageReadTransparent,
		TLVs:          protocol.TLVs{{Type: 0x01, Len: 2, Value: []byte{0x01}}},
	}

	if _, err := MarshalRequest(req); err == nil {
		t.Fatal("MarshalRequest() error = nil, want TLV error")
	}
}

func TestParseResponse(t *testing.T) {
	frame := []byte{
		0x02, 0x03, 0x00, 0x20, 0x00, 0x0C, 0x00,
		0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x02, 0x00, 0x90, 0x00,
	}

	resp, err := ParseResponse(frame)
	if err != nil {
		t.Fatalf("ParseResponse() error = %v", err)
	}
	if resp.TransactionID != 3 || resp.MessageID != protocol.MessageReadTransparent {
		t.Fatalf("ParseResponse() = %+v", resp)
	}
	if err := resp.TLVs.Error(); err != nil {
		t.Fatalf("Result error = %v", err)
	}
}

func tlv(typ byte, value []byte) protocol.TLV {
	return protocol.TLV{Type: typ, Len: uint16(len(value)), Value: value}
}
