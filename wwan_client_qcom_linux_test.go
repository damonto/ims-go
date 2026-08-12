//go:build linux

package ims

import (
	"net"
	"testing"

	"github.com/damonto/wwan-go/qcom"
	"github.com/damonto/wwan-go/qcom/tlv"
)

func TestQCOMIMSPDNNetworkInfo(t *testing.T) {
	tests := []struct {
		name string
		info qcom.IMSPDNInfo
	}{
		{
			name: "preserves point-to-point gateways",
			info: qcom.IMSPDNInfo{PDNInfo: qcom.PDNInfo{
				LocalIPv4:   net.ParseIP("10.0.0.2"),
				LocalIPv6:   net.ParseIP("2001:db8::2"),
				IPv4Gateway: net.ParseIP("10.0.0.1"),
				IPv6Gateway: net.ParseIP("2001:db8::1"),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := qcomPDNNetworkInfo(tt.info)
			if !got.LocalIPv4.Equal(tt.info.LocalIPv4) || !got.LocalIPv6.Equal(tt.info.LocalIPv6) ||
				!got.IPv4Gateway.Equal(tt.info.IPv4Gateway) || !got.IPv6Gateway.Equal(tt.info.IPv6Gateway) {
				t.Fatalf("qcomPDNNetworkInfo() = %+v, want local addresses and gateways from %+v", got, tt.info)
			}
		})
	}
}

func TestQCOMClientIPPreference(t *testing.T) {
	tests := []struct {
		name    string
		pdnType string
		want    qcom.WDSIPPreference
		wantErr bool
	}{
		{name: "IPv4", pdnType: "ipv4", want: qcom.WDSIPPreferenceIPv4},
		{name: "IPv6", pdnType: "ipv6", want: qcom.WDSIPPreferenceIPv6},
		{name: "dual stack", pdnType: "ipv4v6", want: qcom.WDSIPPreferenceDefault},
		{name: "unsupported", pdnType: "ipv5", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := qcomIPPreference(tt.pdnType)
			if tt.wantErr {
				if err == nil {
					t.Fatal("qcomIPPreference() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("qcomIPPreference() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("qcomIPPreference() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestQCOMIMSDualStackOmitsIPFamilyTLV(t *testing.T) {
	configs, err := qcomIMSPDNConfigs(imsPDNConfig{
		APN:          "ims",
		PDNType:      "ipv4v6",
		ProfileIndex: 3,
	}, QCOMClientConfig{})
	if err != nil {
		t.Fatalf("qcomIMSPDNConfigs() error = %v", err)
	}
	request := qcom.WDSStartNetworkInterfaceRequest{
		APN:          configs[0].APN,
		IPPreference: configs[0].IPPreference,
	}.Request()
	if _, ok := tlv.Value(request.TLVs, 0x19); ok {
		t.Fatal("dual-stack WDS request included an IP Family TLV")
	}
}

func TestQCOMConfigCopiesMuxDataPort(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "mux and endpoint"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port := qcom.WDSMuxDataPort{
				Endpoint: &qcom.DataEndpoint{Type: qcom.DataEndpointHSUSB, InterfaceID: 4},
				MuxID:    2,
			}
			got := cloneQCOMMuxDataPort(&port)
			port.MuxID = 9
			port.Endpoint.InterfaceID = 10

			if got == nil || got.MuxID != 2 || got.Endpoint == nil || got.Endpoint.InterfaceID != 4 {
				t.Fatalf("cloneQCOMMuxDataPort() = %+v, want copied mux 2 endpoint 4", got)
			}
		})
	}
}

func TestQCOMIMSPDNConfigs(t *testing.T) {
	tests := []struct {
		name           string
		mux            *qcom.WDSMuxDataPort
		legacy         qcom.WDSSIOPort
		wantPreference qcom.WDSIPPreference
		wantModern     uint8
		wantLegacy     qcom.WDSSIOPort
		wantCount      int
	}{
		{name: "without mux", wantPreference: qcom.WDSIPPreferenceDefault, wantCount: 1},
		{name: "modern mux", mux: &qcom.WDSMuxDataPort{MuxID: 2}, wantPreference: qcom.WDSIPPreferenceDefault, wantModern: 2, wantCount: 1},
		{name: "legacy mux", legacy: qcom.WDSSIOPortA2MuxRMNET1, wantPreference: qcom.WDSIPPreferenceDefault, wantLegacy: qcom.WDSSIOPortA2MuxRMNET1, wantCount: 1},
		{
			name:           "modern with legacy fallback",
			mux:            &qcom.WDSMuxDataPort{MuxID: 2},
			legacy:         qcom.WDSSIOPortA2MuxRMNET1,
			wantPreference: qcom.WDSIPPreferenceDefault,
			wantModern:     2,
			wantLegacy:     qcom.WDSSIOPortA2MuxRMNET1,
			wantCount:      2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := qcomIMSPDNConfigs(imsPDNConfig{APN: "ims", PDNType: "ipv4v6", ProfileIndex: 3}, QCOMClientConfig{
				MuxDataPort:       tt.mux,
				LegacyMuxDataPort: tt.legacy,
			})
			if err != nil {
				t.Fatalf("qcomIMSPDNConfigs() error = %v", err)
			}
			if len(got) != tt.wantCount {
				t.Fatalf("qcomIMSPDNConfigs() count = %d, want %d", len(got), tt.wantCount)
			}
			if got[0].APN != "ims" || got[0].ProfileIndex != 3 || got[0].IPPreference != tt.wantPreference {
				t.Fatalf("primary config = %+v", got[0])
			}
			if tt.wantModern != 0 && (got[0].MuxDataPort == nil || got[0].MuxDataPort.MuxID != tt.wantModern) {
				t.Fatalf("primary MuxDataPort = %+v, want mux %d", got[0].MuxDataPort, tt.wantModern)
			}
			if tt.wantLegacy != 0 && got[len(got)-1].LegacyMuxDataPort != tt.wantLegacy {
				t.Fatalf("fallback LegacyMuxDataPort = %d, want %d", got[len(got)-1].LegacyMuxDataPort, tt.wantLegacy)
			}
		})
	}
}
