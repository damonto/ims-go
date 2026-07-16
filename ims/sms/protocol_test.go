package sms

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestIncomingRPCause(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want byte
	}{
		{name: "memory capacity", err: &RPError{Cause: RPCauseMemoryCapacityExceeded}, want: rpCauseMemoryCapacityExceeded},
		{name: "protocol cause", err: &RPError{Cause: rpCauseInvalidMandatoryInformation}, want: rpCauseInvalidMandatoryInformation},
		{name: "invalid MT cause", err: &RPError{Cause: rpCauseTemporaryFailure}, want: rpCauseProtocolErrorUnspecified},
		{name: "application error", err: errors.New("storage unavailable"), want: rpCauseProtocolErrorUnspecified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := incomingRPCause(tt.err); got != tt.want {
				t.Fatalf("incomingRPCause() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestDecodeSubmitReport(t *testing.T) {
	ts := time.Date(2026, time.July, 16, 12, 34, 56, 0, time.FixedZone("", 8*60*60))
	tests := []struct {
		name    string
		failed  bool
		data    []byte
		wantFCS byte
	}{
		{name: "RP-ACK report", data: append([]byte{tpduMTISubmit, 0}, encodeTimestamp(ts)...)},
		{name: "RP-ERROR report", failed: true, data: append([]byte{tpduMTISubmit, 0xD3, 0}, encodeTimestamp(ts)...), wantFCS: 0xD3},
		{name: "reserved PI permits extension data", data: append(append([]byte{tpduMTISubmit, 0x08}, encodeTimestamp(ts)...), 0xAA)},
		{name: "RP-ERROR unused bits force unspecified FCS", failed: true, data: []byte{tpduMTISubmit | 0x04, 0xD3}, wantFCS: tpFailureCauseUnspecified},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeSubmitReport(tt.data, tt.failed)
			if err != nil {
				t.Fatalf("decodeSubmitReport() error = %v", err)
			}
			if got.HasFailureCause != tt.failed || got.FailureCause != tt.wantFCS {
				t.Fatalf("failure cause = (%t, 0x%02X), want (%t, 0x%02X)", got.HasFailureCause, got.FailureCause, tt.failed, tt.wantFCS)
			}
			if len(tt.data) > 2 && !got.ServiceCenterTime.Equal(ts) {
				t.Fatalf("ServiceCenterTime = %v, want %v", got.ServiceCenterTime, ts)
			}
			if !bytes.Equal(got.RawTPDU, tt.data) {
				t.Fatalf("RawTPDU = %x, want %x", got.RawTPDU, tt.data)
			}
		})
	}
}

func TestDecodeSMSDeliverFieldsRejectsTruncatedMandatoryTail(t *testing.T) {
	raw := []byte{0x00}
	raw = append(raw, mustEncodeTPAddress(t, "+12345")...)
	raw = append(raw, 0x00, 0x00)
	raw = append(raw, bytes.Repeat([]byte{0x00}, 7)...)

	if _, err := decodeDeliverFields(raw); err == nil {
		t.Fatal("decodeDeliverFields() error = nil, want non-nil")
	}
}

func TestStatusReportRejectsUnsupportedUserDataDCS(t *testing.T) {
	base := StatusReport{
		Recipient:         "+15551234567",
		ServiceCenterTime: time.Date(2026, time.July, 16, 1, 2, 3, 0, time.UTC),
		DischargeTime:     time.Date(2026, time.July, 16, 1, 3, 3, 0, time.UTC),
		Status:            ReportStatusReceivedBySME,
	}
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "marshal",
			run: func(t *testing.T) {
				report := base
				report.DataCodingScheme = 0x80
				report.HasDataCodingScheme = true
				report.UserData = []byte{0x01}
				if _, err := (statusReportTPDU{Message: report}).MarshalBinary(); err == nil {
					t.Fatal("MarshalBinary() error = nil, want unsupported DCS error")
				}
			},
		},
		{
			name: "unmarshal",
			run: func(t *testing.T) {
				data, err := (statusReportTPDU{Message: base}).MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				data = append(data, tpduParameterIndicatorDCS|tpduParameterIndicatorUDL, 0x80, 1, 0x01)
				var got statusReportTPDU
				if err := got.UnmarshalBinary(data); err == nil {
					t.Fatal("UnmarshalBinary() error = nil, want unsupported DCS error")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestStatusReportGSM7UserData(t *testing.T) {
	gsm7, err := NewGSM7("hello")
	if err != nil {
		t.Fatalf("NewGSM7() error = %v", err)
	}
	base := StatusReport{
		Recipient:           "+15551234567",
		ServiceCenterTime:   time.Date(2026, time.July, 16, 1, 2, 3, 0, time.UTC),
		DischargeTime:       time.Date(2026, time.July, 16, 1, 3, 3, 0, time.UTC),
		Status:              ReportStatusReceivedBySME,
		HasDataCodingScheme: true,
		DataCodingScheme:    tpDCSGSM7,
		UserDataLength:      gsm7.SeptetCount(),
		UserData:            gsm7.Packed(),
	}
	tests := []struct {
		name    string
		mutate  func(*StatusReport)
		wantErr bool
	}{
		{name: "round trip"},
		{
			name: "missing septet count",
			mutate: func(report *StatusReport) {
				report.UserDataLength = 0
			},
			wantErr: true,
		},
		{
			name: "septet count does not match packed octets",
			mutate: func(report *StatusReport) {
				report.UserDataLength = 16
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report := base
			if tt.mutate != nil {
				tt.mutate(&report)
			}
			data, err := (statusReportTPDU{Message: report}).MarshalBinary()
			if tt.wantErr {
				if err == nil {
					t.Fatal("MarshalBinary() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got statusReportTPDU
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Message.UserDataLength != report.UserDataLength {
				t.Fatalf("UserDataLength = %d, want %d", got.Message.UserDataLength, report.UserDataLength)
			}
			if got.Message.DataCodingScheme != tpDCSGSM7 || !got.Message.HasDataCodingScheme {
				t.Fatalf("DataCodingScheme = 0x%02X, has = %t, want 0x%02X/true", got.Message.DataCodingScheme, got.Message.HasDataCodingScheme, tpDCSGSM7)
			}
			if !bytes.Equal(got.Message.UserData, report.UserData) {
				t.Fatalf("UserData = % X, want % X", got.Message.UserData, report.UserData)
			}
		})
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

func TestRPDataMarshalBinaryRejectsInvalidAddressDigit(t *testing.T) {
	tests := []struct {
		name        string
		destination string
	}{
		{name: "letter", destination: "+123Z"},
		{name: "embedded space", destination: "+12 3"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := newRPDataMessage(1, tt.destination, []byte{tpduMTISubmit})
			if _, err := msg.MarshalBinary(); err == nil {
				t.Fatal("MarshalBinary() error = nil, want invalid RP address error")
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
