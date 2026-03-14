package qrtr

import (
	"bytes"
	"testing"

	"github.com/damonto/ims-client/driver/qmi/core"
)

func TestMarshalRequest(t *testing.T) {
	req := core.Request{
		TransactionID: 3,
		MessageID:     core.MessageReadTransparent,
		TLVs: core.TLVs{
			core.TLVBytes(0x01, []byte{byte(core.SessionCardSlot1), 0x00}),
			core.TLVBytes(0x02, []byte{0x07, 0x6F, 0x00}),
			core.TLVBytes(0x03, []byte{0x00, 0x00, 0x09, 0x00}),
		},
	}
	want := []byte{
		0x00, 0x03, 0x00, 0x20, 0x00, 0x12, 0x00,
		0x01, 0x02, 0x00, 0x06, 0x00,
		0x02, 0x03, 0x00, 0x07, 0x6F, 0x00,
		0x03, 0x04, 0x00, 0x00, 0x00, 0x09, 0x00,
	}
	if got := MarshalRequest(req); !bytes.Equal(got, want) {
		t.Fatalf("MarshalRequest() = % X, want % X", got, want)
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
	if resp.TransactionID != 3 || resp.MessageID != core.MessageReadTransparent {
		t.Fatalf("ParseResponse() = %+v", resp)
	}
	if err := core.WithCardResult(resp); err != nil {
		t.Fatalf("WithCardResult() error = %v", err)
	}
}
