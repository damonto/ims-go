package tunnel

import (
	"strings"
	"testing"
)

func TestN1ModeCapabilityNotifyDataBinary(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		value   byte
		wantErr string
	}{
		{name: "reference vector", wire: []byte{0x01, 0x01}, value: 0x01},
		{name: "wrong data length", wire: []byte{0x01, 0x01, 0x02}, wantErr: "data length"},
		{name: "wrong value length", wire: []byte{0x02, 0x01}, wantErr: "value length"},
		{name: "unset pdu session id", wire: []byte{0x01, 0x00}, wantErr: "unset"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got n1ModeCapabilityNotifyData
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.PDUSessionID != tt.value {
				t.Fatalf("PDUSessionID = %#x, want %#x", got.PDUSessionID, tt.value)
			}
			wire, err := got.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if string(wire) != string(tt.wire) {
				t.Fatalf("MarshalBinary() = % X, want % X", wire, tt.wire)
			}
		})
	}
}

func TestN1ModeInformationNotifyDataBinary(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		snssai  []byte
		wantErr string
	}{
		{name: "reference vector", wire: []byte{0x04, 0x11, 0x22, 0x33, 0x44}, snssai: []byte{0x11, 0x22, 0x33, 0x44}},
		{name: "zero length", wire: []byte{0x00}},
		{name: "wrong snssai length", wire: []byte{0x05, 0x11, 0x22, 0x33, 0x44}, wantErr: "does not match"},
		{name: "missing length field", wire: []byte{}, wantErr: "length field"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got n1ModeInformationNotifyData
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if string(got.SNSSAI) != string(tt.snssai) {
				t.Fatalf("SNSSAI = % X, want % X", got.SNSSAI, tt.snssai)
			}
			wire, err := got.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if string(wire) != string(tt.wire) {
				t.Fatalf("MarshalBinary() = % X, want % X", wire, tt.wire)
			}
		})
	}
}

func TestN1ModeSNSSAIPlmnIDNotifyDataBinary(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		plmnID  []byte
		wantErr string
	}{
		{name: "three octet plmn id", wire: []byte{0x03, 0x13, 0x10, 0x01}, plmnID: []byte{0x13, 0x10, 0x01}},
		{name: "wrong data length", wire: []byte{0x03, 0x13, 0x10}, wantErr: "data length"},
		{name: "wrong value length", wire: []byte{0x02, 0x13, 0x10, 0x01}, wantErr: "value length"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got n1ModeSNSSAIPlmnIDNotifyData
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if string(got.PLMNID) != string(tt.plmnID) {
				t.Fatalf("PLMNID = % X, want % X", got.PLMNID, tt.plmnID)
			}
			wire, err := got.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if string(wire) != string(tt.wire) {
				t.Fatalf("MarshalBinary() = % X, want % X", wire, tt.wire)
			}
		})
	}
}
