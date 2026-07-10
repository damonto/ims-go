package lte

import (
	"net"
	"testing"
)

func TestInfoLocalIPForRemote(t *testing.T) {
	info := Info{
		LocalIPv4: net.IPv4(10, 0, 0, 2),
		LocalIPv6: net.ParseIP("2001:db8::2"),
	}
	tests := []struct {
		name   string
		info   Info
		remote net.IP
		want   net.IP
	}{
		{name: "ipv4 remote selects ipv4", info: info, remote: net.IPv4(192, 0, 2, 1), want: net.IPv4(10, 0, 0, 2)},
		{name: "ipv6 remote selects ipv6", info: info, remote: net.ParseIP("2001:db8::1"), want: net.ParseIP("2001:db8::2")},
		{name: "unknown remote prefers ipv6", info: info, want: net.ParseIP("2001:db8::2")},
		{
			name: "unknown remote follows default pcscf family",
			info: Info{
				LocalIPv4: net.IPv4(10, 0, 0, 2),
				LocalIPv6: net.ParseIP("2001:db8::2"),
				PCSCFIPs:  []net.IP{net.IPv4(198, 51, 100, 10)},
			},
			want: net.IPv4(10, 0, 0, 2),
		},
		{name: "ipv4 remote without local ipv4 returns nil", info: Info{LocalIPv6: net.ParseIP("2001:db8::2")}, remote: net.IPv4(198, 51, 100, 1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.LocalIPForRemote(tt.remote)
			if tt.want == nil {
				if len(got) != 0 {
					t.Fatalf("LocalIPForRemote() = %v, want nil", got)
				}
				return
			}
			if !got.Equal(tt.want) {
				t.Fatalf("LocalIPForRemote() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInfoRouteToPCSCF(t *testing.T) {
	tests := []struct {
		name       string
		info       Info
		wantLocal  net.IP
		wantRemote net.IP
		wantOK     bool
	}{
		{
			name: "skips unusable pcscf family",
			info: Info{
				LocalIPv6: net.ParseIP("2001:db8::2"),
				PCSCFIPs: []net.IP{
					net.IPv4(192, 0, 2, 1),
					net.ParseIP("2001:db8::1"),
				},
			},
			wantLocal:  net.ParseIP("2001:db8::2"),
			wantRemote: net.ParseIP("2001:db8::1"),
			wantOK:     true,
		},
		{
			name: "returns false without matching local address",
			info: Info{
				LocalIPv6: net.ParseIP("2001:db8::2"),
				PCSCFIPs:  []net.IP{net.IPv4(192, 0, 2, 1)},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.info.RouteToPCSCF()
			if ok != tt.wantOK {
				t.Fatalf("RouteToPCSCF() ok = %t, want %t", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if !got.LocalIP.Equal(tt.wantLocal) {
				t.Fatalf("RouteToPCSCF() local = %v, want %v", got.LocalIP, tt.wantLocal)
			}
			if !got.RemoteIP.Equal(tt.wantRemote) {
				t.Fatalf("RouteToPCSCF() remote = %v, want %v", got.RemoteIP, tt.wantRemote)
			}
		})
	}
}
