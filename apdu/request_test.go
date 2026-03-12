package apdu

import (
	"bytes"
	"testing"
)

func TestRequestAPDU(t *testing.T) {
	tests := []struct {
		name string
		req  *Request
		want []byte
	}{
		{"select-id", SelectID([]byte{0x3F, 0x00}, true), []byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00}},
		{"read-binary", ReadBinary(0x10, 0x0020), []byte{0x00, 0xB0, 0x00, 0x20, 0x10}},
		{"authenticate-3g", Authenticate3G(bytes.Repeat([]byte{0x01}, 16), bytes.Repeat([]byte{0x02}, 16)), append([]byte{0x00, 0x88, 0x00, 0x81, 0x22, 0x10}, append(bytes.Repeat([]byte{0x01}, 16), append([]byte{0x10}, bytes.Repeat([]byte{0x02}, 16)...)...)...)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.req.APDU(); !bytes.Equal(got, tt.want) {
				t.Fatalf("APDU() = %X, want %X", got, tt.want)
			}
		})
	}
}

func TestResponseAccessors(t *testing.T) {
	tests := []struct {
		name     string
		res      Response
		wantSW   uint16
		wantOK   bool
		wantMore bool
	}{
		{"ok", Response{0xDE, 0xAD, 0x90, 0x00}, 0x9000, true, false},
		{"more", Response{0x61, 0x10}, 0x6110, false, true},
		{"short", Response{0x90}, 0x0000, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.res.SW(); got != tt.wantSW {
				t.Fatalf("SW() = 0x%04X, want 0x%04X", got, tt.wantSW)
			}
			if got := tt.res.OK(); got != tt.wantOK {
				t.Fatalf("OK() = %v, want %v", got, tt.wantOK)
			}
			if got := tt.res.HasMore(); got != tt.wantMore {
				t.Fatalf("HasMore() = %v, want %v", got, tt.wantMore)
			}
		})
	}
}
