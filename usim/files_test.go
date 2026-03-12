package usim

import (
	"errors"
	"testing"

	"github.com/damonto/ims-client/apdu"
)

func TestFileControlInfoUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    fileControlInfo
		wantErr string
	}{
		{
			name: "transparent file",
			data: []byte{0x62, 0x08, 0x82, 0x02, 0x41, 0x21, 0x80, 0x02, 0x00, 0x09},
			want: fileControlInfo{FileStruct: fileStructTransparent, FileType: 0x21, FileSize: 9},
		},
		{
			name: "linear fixed file",
			data: []byte{0x62, 0x0B, 0x82, 0x05, 0x42, 0x21, 0x00, 0x20, 0x03, 0x80, 0x02, 0x00, 0x60},
			want: fileControlInfo{FileStruct: fileStructLinearFixed, FileType: 0x21, RecordSize: 32, RecordCount: 3, FileSize: 96},
		},
		{
			name:    "missing descriptor",
			data:    []byte{0x62, 0x04, 0x80, 0x02, 0x00, 0x09},
			wantErr: "missing file descriptor",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got fileControlInfo
			err := got.UnmarshalBinary(tt.data)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("UnmarshalBinary() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEFDirRecordUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantAID []byte
		wantLbl string
		wantErr bool
	}{
		{
			name:    "record with padding",
			data:    []byte{0x61, 0x0F, 0x4F, 0x07, 0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02, 0x50, 0x04, 0x55, 0x53, 0x49, 0x4D, 0xFF, 0xFF, 0xFF},
			wantAID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02},
			wantLbl: "USIM",
		},
		{
			name: "all padding means empty record",
			data: []byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
		{
			name:    "bad tag",
			data:    []byte{0x62, 0x01, 0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got efDirRecord
			err := got.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if string(got.AID) != string(tt.wantAID) {
				t.Fatalf("UnmarshalBinary().AID = % X, want % X", got.AID, tt.wantAID)
			}
			if got.Label != tt.wantLbl {
				t.Fatalf("UnmarshalBinary().Label = %q, want %q", got.Label, tt.wantLbl)
			}
		})
	}
}

func TestDecodeTLVText(t *testing.T) {
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
			got, err := decodeTLVText(tt.data)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("decodeTLVText() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeTLVText() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("decodeTLVText() = %q, want %q", got, tt.want)
			}
		})
	}
}
