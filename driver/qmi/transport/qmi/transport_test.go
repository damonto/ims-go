package qmi

import (
	"bytes"
	"testing"

	"github.com/damonto/ims-client/driver/qmi/core"
)

func TestMarshalRequest(t *testing.T) {
	tests := []struct {
		name string
		req  core.Request
		want []byte
	}{
		{
			name: "read transparent request",
			req: core.Request{
				Service:       core.ServiceUIM,
				ClientID:      7,
				TransactionID: 3,
				MessageID:     core.MessageReadTransparent,
				TLVs: core.TLVs{
					core.TLVBytes(0x01, []byte{byte(core.SessionCardSlot1), 0x00}),
					core.TLVBytes(0x02, []byte{0x07, 0x6F, 0x00}),
					core.TLVBytes(0x03, []byte{0x00, 0x00, 0x09, 0x00}),
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
			req: core.Request{
				Service:       core.ServiceUIM,
				ClientID:      7,
				TransactionID: 4,
				MessageID:     core.MessageAuthenticate,
				TLVs: core.TLVs{
					core.TLVBytes(0x01, []byte{byte(core.SessionPrimaryGWProvisioning), 0x00}),
					core.TLVBytes(0x02, []byte{0x03, 0x04, 0x00, 0x10, 0x01, 0x10, 0x02}),
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
	frame := []byte{
		0x01, 0x18, 0x00, 0x80, 0x0B, 0x07,
		0x02, 0x03, 0x00, 0x20, 0x00, 0x0C, 0x00,
		0x02, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x02, 0x00, 0x90, 0x00,
	}

	resp, err := ParseResponse(frame)
	if err != nil {
		t.Fatalf("ParseResponse() error = %v", err)
	}
	if resp.Service != core.ServiceUIM || resp.ClientID != 7 || resp.TransactionID != 3 || resp.MessageID != core.MessageReadTransparent {
		t.Fatalf("ParseResponse() = %+v", resp)
	}
	if err := core.MustResultOK(resp); err != nil {
		t.Fatalf("MustResultOK() error = %v", err)
	}
	if err := resp.TLVs.CardError(); err != nil {
		t.Fatalf("CardError() error = %v", err)
	}
}
