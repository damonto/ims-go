package qmi

import (
	"bytes"
	"testing"

	"github.com/damonto/ims-client/driver/qmi/protocol"
)

func TestMarshalRequest(t *testing.T) {
	tests := []struct {
		name string
		req  protocol.Request
		want []byte
	}{
		{
			name: "read transparent request",
			req: protocol.Request{
				Service:       protocol.ServiceUIM,
				ClientID:      7,
				TransactionID: 3,
				MessageID:     protocol.MessageReadTransparent,
				TLVs: protocol.TLVs{
					tlv(0x01, []byte{0x06, 0x00}),
					tlv(0x02, []byte{0x07, 0x6F, 0x00}),
					tlv(0x03, []byte{0x00, 0x00, 0x09, 0x00}),
				},
			},
			want: []byte{
				0x01, 0x1E, 0x00, 0x00, 0x0B, 0x07,
				0x00, 0x03, 0x00, 0x20, 0x00, 0x12, 0x00,
				0x01, 0x02, 0x00, 0x06, 0x00,
				0x02, 0x03, 0x00, 0x07, 0x6F, 0x00,
				0x03, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00,
			},
		},
		{
			name: "authenticate request",
			req: protocol.Request{
				Service:       protocol.ServiceUIM,
				ClientID:      7,
				TransactionID: 4,
				MessageID:     protocol.MessageAuthenticate,
				TLVs: protocol.TLVs{
					tlv(0x01, []byte{0x00, 0x00}),
					tlv(0x02, []byte{0x03, 0x04, 0x00, 0x10, 0x01, 0x10, 0x02}),
				},
			},
			want: []byte{
				0x01, 0x1B, 0x00, 0x00, 0x0B, 0x07,
				0x00, 0x04, 0x00, 0x34, 0x00, 0x0F, 0x00,
				0x01, 0x02, 0x00, 0x00, 0x00,
				0x02, 0x07, 0x00, 0x03, 0x04, 0x00, 0x10, 0x01, 0x10, 0x02,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MarshalRequest(tt.req); !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalRequest() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestParseResponse(t *testing.T) {
	tests := []struct {
		name    string
		frame   []byte
		service protocol.ServiceType
		client  uint8
		txn     uint16
		message protocol.MessageID
	}{
		{
			name: "service response",
			frame: []byte{
				0x01, 0x18, 0x00, 0x80, 0x0B, 0x07,
				0x02, 0x03, 0x00, 0x20, 0x00, 0x0C, 0x00,
				0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x10, 0x02, 0x00, 0x90, 0x00,
			},
			service: protocol.ServiceUIM,
			client:  7,
			txn:     3,
			message: protocol.MessageReadTransparent,
		},
		{
			name: "control response",
			frame: []byte{
				0x01, 0x12, 0x00, 0x80, 0x00, 0x00,
				0x01, 0x01, 0x00, 0xFF, 0x07, 0x00,
				0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			service: protocol.ServiceControl,
			client:  0,
			txn:     1,
			message: protocol.QMICtlInternalProxyOpen,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := ParseResponse(tt.frame)
			if err != nil {
				t.Fatalf("ParseResponse() error = %v", err)
			}
			if resp.Service != tt.service || resp.ClientID != tt.client || resp.TransactionID != tt.txn || resp.MessageID != tt.message {
				t.Fatalf("ParseResponse() = %+v", resp)
			}
			if err := resp.TLVs.Error(); err != nil {
				t.Fatalf("Result error = %v", err)
			}
		})
	}
}

func tlv(typ byte, value []byte) protocol.TLV {
	return protocol.TLV{Type: typ, Len: uint16(len(value)), Value: value}
}
