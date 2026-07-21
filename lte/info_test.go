package lte

import (
	"net"
	"strings"
	"testing"
)

func TestConfigNormalized(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{name: "defaults", cfg: Config{}},
		{name: "invalid local ip", cfg: Config{LocalIPv4: net.IP{1, 2, 3}}, wantErr: "invalid IP address"},
		{name: "empty pcscf entry", cfg: Config{PCSCFIPs: []net.IP{nil}}, wantErr: "address 0 is empty"},
		{name: "ipv4 pdn rejects ipv6 override", cfg: Config{PDNType: "ipv4", LocalIPv6: net.ParseIP("2001:db8::1")}, wantErr: "local ipv6 requires"},
		{name: "ipv6 pdn rejects ipv4 override", cfg: Config{PDNType: "ipv6", LocalIPv4: net.IPv4(192, 0, 2, 1)}, wantErr: "local ipv4 requires"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("Normalized() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got.APN != DefaultAPN || got.PDNType != DefaultPDNType {
				t.Fatalf("Normalized() APN/PDN type = %q/%q, want %q/%q", got.APN, got.PDNType, DefaultAPN, DefaultPDNType)
			}
		})
	}
}

func TestNormalizeAccessNetworkInfo(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr string
	}{
		{
			name:  "canonicalizes FDD and cell identity",
			value: " 3gpp-e-utran-fdd; utran-cell-id-3gpp=1112233c476b4321 ",
			want:  "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=1112233C476B4321",
		},
		{
			name:  "accepts TDD with three digit MNC",
			value: "3GPP-E-UTRAN-TDD;utran-cell-id-3gpp=11122233C476B4321",
			want:  "3GPP-E-UTRAN-TDD;utran-cell-id-3gpp=11122233C476B4321",
		},
		{
			name:  "accepts quoted cell identity",
			value: `3GPP-E-UTRAN-FDD;utran-cell-id-3gpp="1112233c476b4321"`,
			want:  "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=1112233C476B4321",
		},
		{
			name:  "accepts quoted pair",
			value: `3GPP-E-UTRAN-FDD;utran-cell-id-3gpp="1112233C476B432\1"`,
			want:  "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=1112233C476B4321",
		},
		{name: "rejects WLAN", value: "IEEE-802.11;i-wlan-node-id=aabbccddeeff", wantErr: "unsupported VoLTE access type"},
		{name: "requires cell identity", value: "3GPP-E-UTRAN-FDD", wantErr: "utran-cell-id-3gpp is required"},
		{name: "rejects unterminated quoted cell identity", value: `3GPP-E-UTRAN-FDD;utran-cell-id-3gpp="1112233C476B4321`, wantErr: "unterminated"},
		{name: "rejects network marker", value: "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=1112233C476B4321;network-provided", wantErr: "reserved for the network"},
		{name: "rejects non-decimal PLMN", value: "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=11A2233C476B4321", wantErr: "PLMN must be decimal"},
		{name: "rejects non-hex cell", value: "3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=1112233C476B432Z", wantErr: "must be hexadecimal"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NormalizeAccessNetworkInfo(tt.value)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NormalizeAccessNetworkInfo() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeAccessNetworkInfo() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeAccessNetworkInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}

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
		{name: "invalid remote returns nil", info: info, remote: net.IP{1, 2, 3}},
		{name: "invalid local address returns nil", info: Info{LocalIPv6: net.IP{1, 2, 3}}, remote: net.ParseIP("2001:db8::1")},
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

func TestInfoRouteTo(t *testing.T) {
	info := Info{
		LocalIPv4: net.IPv4(10, 0, 0, 2),
		LocalIPv6: net.ParseIP("2001:db8::2"),
		PCSCFIPs:  []net.IP{net.ParseIP("2001:db8::1")},
	}
	tests := []struct {
		name       string
		remote     net.IP
		wantLocal  net.IP
		wantRemote net.IP
		wantOK     bool
	}{
		{
			name:      "unknown remote follows default pcscf family",
			wantLocal: net.ParseIP("2001:db8::2"),
			wantOK:    true,
		},
		{
			name:       "ipv4 remote selects ipv4",
			remote:     net.IPv4(192, 0, 2, 1),
			wantLocal:  net.IPv4(10, 0, 0, 2),
			wantRemote: net.IPv4(192, 0, 2, 1),
			wantOK:     true,
		},
		{name: "invalid remote is rejected", remote: net.IP{1, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := info.RouteTo(tt.remote)
			if ok != tt.wantOK {
				t.Fatalf("RouteTo() ok = %t, want %t", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if !got.LocalIP.Equal(tt.wantLocal) {
				t.Fatalf("RouteTo() local = %v, want %v", got.LocalIP, tt.wantLocal)
			}
			if !got.RemoteIP.Equal(tt.wantRemote) {
				t.Fatalf("RouteTo() remote = %v, want %v", got.RemoteIP, tt.wantRemote)
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
		{
			name: "dual stack prefers ipv6",
			info: Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
				LocalIPv6: net.ParseIP("2001:db8::10"),
				PCSCFIPs: []net.IP{
					net.IPv4(192, 0, 2, 20),
					net.ParseIP("2001:db8::20"),
				},
			},
			wantLocal:  net.ParseIP("2001:db8::10"),
			wantRemote: net.ParseIP("2001:db8::20"),
			wantOK:     true,
		},
		{
			name: "skips malformed modem address",
			info: Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
				PCSCFIPs: []net.IP{
					{1, 2, 3},
					net.IPv4(192, 0, 2, 20),
				},
			},
			wantLocal:  net.IPv4(192, 0, 2, 10),
			wantRemote: net.IPv4(192, 0, 2, 20),
			wantOK:     true,
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

func TestInfoWithNextPCSCF(t *testing.T) {
	tests := []struct {
		name       string
		info       Info
		wantOK     bool
		wantRemote net.IP
	}{
		{
			name: "rotates to next usable address",
			info: Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
				LocalIPv6: net.ParseIP("2001:db8::10"),
				PCSCFIPs: []net.IP{
					net.ParseIP("2001:db8::20"),
					net.IPv4(192, 0, 2, 20),
				},
			},
			wantOK:     true,
			wantRemote: net.IPv4(192, 0, 2, 20),
		},
		{
			name: "skips address without matching local family",
			info: Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
				PCSCFIPs: []net.IP{
					net.IPv4(192, 0, 2, 20),
					net.ParseIP("2001:db8::20"),
					net.IPv4(192, 0, 2, 30),
				},
			},
			wantOK:     true,
			wantRemote: net.IPv4(192, 0, 2, 30),
		},
		{
			name: "single usable address",
			info: Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
				PCSCFIPs:  []net.IP{net.IPv4(192, 0, 2, 20)},
			},
			wantRemote: net.IPv4(192, 0, 2, 20),
		},
		{
			name: "dual stack exhausts ipv6 before ipv4",
			info: Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
				LocalIPv6: net.ParseIP("2001:db8::10"),
				PCSCFIPs: []net.IP{
					net.IPv4(192, 0, 2, 20),
					net.ParseIP("2001:db8::20"),
					net.ParseIP("2001:db8::30"),
				},
			},
			wantOK:     true,
			wantRemote: net.ParseIP("2001:db8::30"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.info.WithNextPCSCF()
			if ok != tt.wantOK {
				t.Fatalf("WithNextPCSCF() ok = %v, want %v", ok, tt.wantOK)
			}
			route, routeOK := got.RouteToPCSCF()
			if !routeOK || !route.RemoteIP.Equal(tt.wantRemote) {
				t.Fatalf("RouteToPCSCF() = %v, %v; want remote %v", route, routeOK, tt.wantRemote)
			}
			if tt.wantOK && got.PCSCFCandidateCount() >= tt.info.PCSCFCandidateCount() {
				t.Fatalf("candidate count = %d, want less than %d after marking current unavailable", got.PCSCFCandidateCount(), tt.info.PCSCFCandidateCount())
			}
		})
	}
}

func TestInfoDefaultPCSCFIPSkipsUnusableAddress(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want net.IP
	}{
		{
			name: "skips unusable ipv4",
			info: Info{
				LocalIPv6: net.ParseIP("2001:db8::10"),
				PCSCFIPs: []net.IP{
					net.IPv4(192, 0, 2, 20),
					net.ParseIP("2001:db8::20"),
				},
			},
			want: net.ParseIP("2001:db8::20"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.DefaultPCSCFIP(); !got.Equal(tt.want) {
				t.Fatalf("DefaultPCSCFIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInfoPCSCFFailoverSequence(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want []net.IP
	}{
		{
			name: "dual stack tries ipv6 then ipv4 without wrapping",
			info: Info{
				LocalIPv4: net.IPv4(192, 0, 2, 10),
				LocalIPv6: net.ParseIP("2001:db8::10"),
				PCSCFIPs: []net.IP{
					net.IPv4(192, 0, 2, 20),
					net.ParseIP("2001:db8::20"),
					net.ParseIP("2001:db8::30"),
				},
			},
			want: []net.IP{
				net.ParseIP("2001:db8::20"),
				net.ParseIP("2001:db8::30"),
				net.IPv4(192, 0, 2, 20),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := tt.info
			for i, want := range tt.want {
				route, ok := info.RouteToPCSCF()
				if !ok || !route.RemoteIP.Equal(want) {
					t.Fatalf("candidate %d = %v, %v; want %v", i, route.RemoteIP, ok, want)
				}
				if i+1 == len(tt.want) {
					break
				}
				info, ok = info.WithNextPCSCF()
				if !ok {
					t.Fatalf("WithNextPCSCF() at candidate %d = false", i)
				}
			}
			if _, ok := info.WithNextPCSCF(); ok {
				t.Fatal("WithNextPCSCF() after last candidate = true, want false")
			}
		})
	}
}
