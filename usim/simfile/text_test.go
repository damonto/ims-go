package simfile

import (
	"errors"
	"testing"

	"github.com/damonto/vowifi-go/usim/apdu"
)

func TestDecodeText(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr error
	}{
		{
			name: "TLV payload",
			data: []byte{0x80, 0x04, 'I', 'S', 'I', 'M'},
			want: "ISIM",
		},
		{
			name: "plain ASCII fallback",
			data: []byte("ims.mnc001.mcc001.3gppnetwork.org\xFF\xFF"),
			want: "ims.mnc001.mcc001.3gppnetwork.org",
		},
		{
			name:    "non ASCII fallback rejected",
			data:    []byte{0x01, 0x02, 0xFF},
			wantErr: apdu.ErrMalformedResponse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeText(tt.data)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("DecodeText() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodeText() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("DecodeText() = %q, want %q", got, tt.want)
			}
		})
	}
}
