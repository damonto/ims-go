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

	if _, err := decodeDeliverFields(raw); err == nil {
		t.Fatal("decodeDeliverFields() error = nil, want non-nil")
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

func TestIsSMSPPDataDownload(t *testing.T) {
	tests := []struct {
		name string
		part userDataPart
		want bool
	}{
		{
			name: "rel5 8-bit class 2",
			part: userDataPart{pid: 0x7F, dcs: 0xF6},
			want: true,
		},
		{
			name: "general 8-bit class 2",
			part: userDataPart{pid: 0x7F, dcs: 0x16},
			want: true,
		},
		{
			name: "normal pid",
			part: userDataPart{pid: 0x00, dcs: 0xF6},
			want: false,
		},
		{
			name: "not class 2",
			part: userDataPart{pid: 0x7F, dcs: 0xF5},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isPPDataDownload(tt.part); got != tt.want {
				t.Fatalf("isPPDataDownload() = %v, want %v", got, tt.want)
			}
		})
	}
}
