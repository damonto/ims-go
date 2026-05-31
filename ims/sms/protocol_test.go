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

func TestRPDataMarshalBinaryRejectsInvalidUserData(t *testing.T) {
	tests := []struct {
		name string
		tpdu []byte
	}{
		{
			name: "empty",
		},
		{
			name: "over 233 octets",
			tpdu: bytes.Repeat([]byte{0x00}, 234),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := rpMessage{
				Type:      rpDataNetworkToMS,
				Reference: 1,
				TPDU:      tt.tpdu,
			}

			if _, err := msg.MarshalBinary(); err == nil {
				t.Fatal("MarshalBinary() error = nil, want non-nil")
			}
		})
	}
}

func TestRPDataMarshalBinaryRejectsInvalidAddressLength(t *testing.T) {
	tests := []struct {
		name        string
		originator  string
		destination string
	}{
		{
			name:        "originator exceeds RP address length octet",
			originator:  "+123456789012345678901",
			destination: "+15550000000",
		},
		{
			name:        "destination exceeds RP address length octet",
			destination: "+123456789012345678901",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := rpMessage{
				Type:        rpDataMSToNetwork,
				Reference:   1,
				Originator:  tt.originator,
				Destination: tt.destination,
				TPDU:        []byte{0x00},
			}

			if _, err := msg.MarshalBinary(); err == nil {
				t.Fatal("MarshalBinary() error = nil, want non-nil")
			}
		})
	}
}

func TestRPMessageUnmarshalRejectsMalformedLengths(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "rp-data trailing octet",
			raw: func() []byte {
				raw := append([]byte{rpDataNetworkToMS, 1}, encodeRPAddress("+15550000000")...)
				raw = append(raw, encodeRPAddress("")...)
				raw = append(raw, 0x01, 0x00, 0xFF)
				return raw
			}(),
		},
		{
			name: "rp-data user data over 233",
			raw: func() []byte {
				raw := append([]byte{rpDataNetworkToMS, 1}, encodeRPAddress("+15550000000")...)
				raw = append(raw, encodeRPAddress("")...)
				raw = append(raw, byte(maxRPDataUserDataOctets+1))
				raw = append(raw, bytes.Repeat([]byte{0x00}, maxRPDataUserDataOctets+1)...)
				return raw
			}(),
		},
		{
			name: "rp-data empty user data",
			raw: func() []byte {
				raw := append([]byte{rpDataNetworkToMS, 1}, encodeRPAddress("+15550000000")...)
				raw = append(raw, encodeRPAddress("")...)
				raw = append(raw, 0x00)
				return raw
			}(),
		},
		{
			name: "rp-data address length one",
			raw:  []byte{rpDataNetworkToMS, 1, 0x01, tpTOAInternationalISDN, 0x00, 0x01, 0x00},
		},
		{
			name: "rp-data address length over eleven",
			raw:  append([]byte{rpDataNetworkToMS, 1, maxRPAddressValueOctets + 1}, bytes.Repeat([]byte{0x00}, maxRPAddressValueOctets+1)...),
		},
		{
			name: "rp-ack user data trailing octet",
			raw:  []byte{rpAckNetworkToMS, 1, rpUserDataIEI, 0x01, 0x00, 0xFF},
		},
		{
			name: "rp-ack user data over 234",
			raw:  append([]byte{rpAckNetworkToMS, 1, rpUserDataIEI, byte(maxRPAckErrorUserDataOctets + 1)}, bytes.Repeat([]byte{0x00}, maxRPAckErrorUserDataOctets+1)...),
		},
		{
			name: "rp-error cause length over two",
			raw:  []byte{rpErrorNetworkToMS, 1, maxRPCauseLength + 1, rpCauseProtocolErrorUnspecified, 0x00, 0x00},
		},
		{
			name: "rp-smma trailing data",
			raw:  []byte{rpSMMAMSToNetwork, 1, 0x00},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var msg rpMessage
			if err := msg.UnmarshalBinary(tt.raw); err == nil {
				t.Fatal("UnmarshalBinary() error = nil, want non-nil")
			}
		})
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
