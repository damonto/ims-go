package ims

import (
	"context"
	"errors"
	"testing"
)

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

func (n *fakeIMSPDNNetwork) Replace(context.Context, PDNNetworkInfo) (string, error) {
	return "test0", n.replaceErr
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
		wantInterface    string
		wantNetworkClose int
		wantSessionClose int
	}{
		{name: "no network", wantSessionClose: 1},
		{name: "configured and closed", withNetwork: true, wantInterface: "test0", wantNetworkClose: 1, wantSessionClose: 1},
		{name: "configuration failure cleans up", withNetwork: true, replaceErr: errReplace, wantErr: errReplace, wantNetworkClose: 1, wantSessionClose: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &fakeIMSPDNSession{}
			var fakeNetwork *fakeIMSPDNNetwork
			var network PDNNetwork
			if tt.withNetwork {
				fakeNetwork = &fakeIMSPDNNetwork{replaceErr: tt.replaceErr}
				network = fakeNetwork
			}
			configured, err := configurePDNNetwork(t.Context(), session, network, PDNNetworkInfo{})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("configurePDNNetwork() error = %v, want %v", err, tt.wantErr)
			}
			if err == nil {
				if got := configured.Info().InterfaceName; got != tt.wantInterface {
					t.Fatalf("Info().InterfaceName = %q, want %q", got, tt.wantInterface)
				}
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
