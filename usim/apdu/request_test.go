package apdu

import (
	"bytes"
	"testing"
)

func TestRequestAPDU(t *testing.T) {
	le := byte(0x10)
	tests := []struct {
		name string
		req  Request
		want []byte
	}{
		{
			name: "select id",
			req: Request{
				CLA:  0x00,
				INS:  0xA4,
				P1:   0x00,
				P2:   0x04,
				Data: []byte{0x3F, 0x00},
			},
			want: []byte{0x00, 0xA4, 0x00, 0x04, 0x02, 0x3F, 0x00},
		},
		{
			name: "read binary",
			req: Request{
				CLA: 0x00,
				INS: 0xB0,
				P1:  0x00,
				P2:  0x20,
				Le:  &le,
			},
			want: []byte{0x00, 0xB0, 0x00, 0x20, 0x10},
		},
		{
			name: "authenticate",
			req: Request{
				CLA:  0x00,
				INS:  0x88,
				P1:   0x00,
				P2:   0x81,
				Data: append([]byte{0x10}, append(bytes.Repeat([]byte{0x01}, 16), append([]byte{0x10}, bytes.Repeat([]byte{0x02}, 16)...)...)...),
			},
			want: append([]byte{0x00, 0x88, 0x00, 0x81, 0x22, 0x10}, append(bytes.Repeat([]byte{0x01}, 16), append([]byte{0x10}, bytes.Repeat([]byte{0x02}, 16)...)...)...),
		},
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
