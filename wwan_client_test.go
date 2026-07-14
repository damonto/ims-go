package ims

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/damonto/wwan-go/mbim"
	"github.com/damonto/wwan-go/qcom"
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
			got := qcomIMSPDNNetworkInfo(tt.info)
			if !got.LocalIPv4.Equal(tt.info.LocalIPv4) || !got.LocalIPv6.Equal(tt.info.LocalIPv6) ||
				!got.IPv4Gateway.Equal(tt.info.IPv4Gateway) || !got.IPv6Gateway.Equal(tt.info.IPv6Gateway) {
				t.Fatalf("qcomIMSPDNNetworkInfo() = %+v, want local addresses and gateways from %+v", got, tt.info)
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
		{name: "dual stack", pdnType: "ipv4v6", want: qcom.WDSIPPreferenceUnspecified},
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
		name       string
		mux        *qcom.WDSMuxDataPort
		legacy     qcom.WDSSIOPort
		wantModern uint8
		wantLegacy qcom.WDSSIOPort
		wantCount  int
	}{
		{name: "without mux", wantCount: 1},
		{name: "modern mux", mux: &qcom.WDSMuxDataPort{MuxID: 2}, wantModern: 2, wantCount: 1},
		{name: "legacy mux", legacy: qcom.WDSSIOPortA2MuxRMNET1, wantLegacy: qcom.WDSSIOPortA2MuxRMNET1, wantCount: 1},
		{
			name:       "modern with legacy fallback",
			mux:        &qcom.WDSMuxDataPort{MuxID: 2},
			legacy:     qcom.WDSSIOPortA2MuxRMNET1,
			wantModern: 2,
			wantLegacy: qcom.WDSSIOPortA2MuxRMNET1,
			wantCount:  2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := qcomIMSPDNConfigs(imsPDNConfig{APN: "ims", PDNType: "ipv4v6", ProfileIndex: 3}, tt.mux, tt.legacy)
			if err != nil {
				t.Fatalf("qcomIMSPDNConfigs() error = %v", err)
			}
			if len(got) != tt.wantCount {
				t.Fatalf("qcomIMSPDNConfigs() count = %d, want %d", len(got), tt.wantCount)
			}
			if got[0].APN != "ims" || got[0].ProfileIndex != 3 || got[0].IPPreference != qcom.WDSIPPreferenceUnspecified {
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

type fakeIMSPDNSession struct {
	closeCalls int
}

func (*fakeIMSPDNSession) Info() imsPDNInfo { return imsPDNInfo{} }
func (s *fakeIMSPDNSession) Close() error {
	s.closeCalls++
	return nil
}

type fakeIMSPDNNetwork struct {
	replaceErr error
	closeCalls int
}

func (n *fakeIMSPDNNetwork) Replace(context.Context, IMSPDNNetworkInfo) error {
	return n.replaceErr
}
func (n *fakeIMSPDNNetwork) Close() error {
	n.closeCalls++
	return nil
}

func TestConfigureIMSPDNNetworkLifecycle(t *testing.T) {
	errReplace := errors.New("replace network")
	tests := []struct {
		name             string
		withNetwork      bool
		replaceErr       error
		wantErr          error
		wantNetworkClose int
		wantSessionClose int
	}{
		{name: "no network", wantSessionClose: 1},
		{name: "configured and closed", withNetwork: true, wantNetworkClose: 1, wantSessionClose: 1},
		{name: "configuration failure cleans up", withNetwork: true, replaceErr: errReplace, wantErr: errReplace, wantNetworkClose: 1, wantSessionClose: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &fakeIMSPDNSession{}
			var fakeNetwork *fakeIMSPDNNetwork
			var network IMSPDNNetwork
			if tt.withNetwork {
				fakeNetwork = &fakeIMSPDNNetwork{replaceErr: tt.replaceErr}
				network = fakeNetwork
			}
			configured, err := configureIMSPDNNetwork(context.Background(), session, network, IMSPDNNetworkInfo{})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("configureIMSPDNNetwork() error = %v, want %v", err, tt.wantErr)
			}
			if err == nil {
				if err := configured.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			}
			gotNetworkClose := 0
			if fakeNetwork != nil {
				gotNetworkClose = fakeNetwork.closeCalls
			}
			if gotNetworkClose != tt.wantNetworkClose || session.closeCalls != tt.wantSessionClose {
				t.Fatalf("close calls = network %d session %d, want %d/%d", gotNetworkClose, session.closeCalls, tt.wantNetworkClose, tt.wantSessionClose)
			}
		})
	}
}

func TestMBIMClientIPType(t *testing.T) {
	tests := []struct {
		name    string
		pdnType string
		want    mbim.ContextIPType
		wantErr bool
	}{
		{name: "IPv4", pdnType: "ipv4", want: mbim.ContextIPTypeIPv4},
		{name: "IPv6", pdnType: "ipv6", want: mbim.ContextIPTypeIPv6},
		{name: "dual stack", pdnType: "ipv4v6", want: mbim.ContextIPTypeIPv4v6},
		{name: "unsupported", pdnType: "ipv5", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mbimIPType(tt.pdnType)
			if tt.wantErr {
				if err == nil {
					t.Fatal("mbimIPType() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("mbimIPType() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("mbimIPType() = %d, want %d", got, tt.want)
			}
		})
	}
}
