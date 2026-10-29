package registration

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func TestESPSaltDerivation(t *testing.T) {
	ck := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F}
	ik := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
	tests := []struct {
		name   string
		verify security.Param
		bits   byte
		want   [4]byte
	}{
		{
			name:   "aes gmac salt",
			verify: security.Param{Alg: "aes-gmac", EAlg: "null"},
			want:   [4]byte{0x2F, 0x5A, 0x80, 0x8D},
		},
		{
			name:   "aes gmac unique server to UE server salt",
			verify: security.Param{Alg: "aes-gmac-us", EAlg: "null"},
			bits:   1,
			want:   [4]byte{0x2F, 0x5A, 0x80, 0x8C},
		},
		{
			name:   "aes gcm salt",
			verify: security.Param{Alg: "null", EAlg: "aes-gcm"},
			want:   [4]byte{0x1F, 0xBF, 0x69, 0xCD},
		},
		{
			name:   "hmac sha1 has no salt",
			verify: security.Param{Alg: "hmac-sha-1-96", EAlg: "aes-cbc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := espSalt(&tt.verify, ck, ik, tt.bits); got != tt.want {
				t.Fatalf("espSalt() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestSecureTransportConfigCarriesModeAndSalt(t *testing.T) {
	ck := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F}
	ik := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
	verify := security.Param{Alg: "null", EAlg: "aes-gcm-us", Mod: "UDP-enc-tun"}

	cfg := secureTransportConfigWithKeys(secureConfigParams{
		verify: &verify, contactHost: "198.51.100.10",
		localPort: 40000, remotePort: 5060,
		outboundSPI: 1111, inboundSPI: 2222,
		ck: ck, ik: ik, outboundSaltBits: saltUEClientToPCSCFServer, inboundSaltBits: saltPCSCFServerToUEClient,
	})
	if cfg.Mode != "UDP-enc-tun" {
		t.Fatalf("Mode = %q, want UDP-enc-tun", cfg.Mode)
	}
	if cfg.OutboundSalt != ([4]byte{0x1F, 0xBF, 0x69, 0xCD}) || cfg.InboundSalt != ([4]byte{0x1F, 0xBF, 0x69, 0xCE}) {
		t.Fatalf("salts = % X/% X, want 1F BF 69 CD/1F BF 69 CE", cfg.OutboundSalt, cfg.InboundSalt)
	}
	if cfg.Encryption != "aes-gcm-us" || cfg.Integrity != "null" {
		t.Fatalf("algorithms = %s/%s, want aes-gcm-us/null", cfg.Encryption, cfg.Integrity)
	}
	if got := cfg.InnerLocalIP.String(); got != "198.51.100.10" {
		t.Fatalf("InnerLocalIP = %s, want 198.51.100.10", got)
	}
}

func TestDialSecureTransportPreservesSIPTransport(t *testing.T) {
	tests := []struct {
		name    string
		primary session.Transport
		wantTCP bool
		wantUDP bool
	}{
		{name: "TCP over UDP encapsulated tunnel", primary: newTCPTransport(5062, 5060), wantTCP: true},
		{name: "UDP over UDP encapsulated tunnel", primary: newUDPTransport(5062, 5060), wantUDP: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var tcpCalled, udpCalled bool
			svc := newTestService(t, Config{
				DialSecureTCP: func(context.Context, session.SecureTCPConfig) (session.Transport, error) {
					tcpCalled = true
					return newTCPTransport(40000, 4060), nil
				},
				DialSecureUDP: func(context.Context, session.SecureUDPConfig) (session.Transport, error) {
					udpCalled = true
					return newUDPTransport(40000, 4060), nil
				},
			}, tt.primary, stubCard{})
			verify := security.Param{Alg: "hmac-sha-1-96", EAlg: "null", Mod: "UDP-enc-tun", PortS: 4060, SPIS: 0x1001}
			flow := Flow{ContactHost: "198.51.100.10", SecurityClient: security.Param{PortC: 40000, SPIC: 0x2001}}

			transport, err := svc.dialSecureTransport(t.Context(), &verify, flow, nil, make([]byte, 16))
			if err != nil {
				t.Fatalf("dialSecureTransport() error = %v", err)
			}
			if err := transport.Close(); err != nil {
				t.Fatalf("transport.Close() error = %v", err)
			}
			if tcpCalled != tt.wantTCP || udpCalled != tt.wantUDP {
				t.Fatalf("dialers called TCP/UDP = %v/%v, want %v/%v", tcpCalled, udpCalled, tt.wantTCP, tt.wantUDP)
			}
		})
	}
}

func TestSecurityClientCapabilities(t *testing.T) {
	tests := []struct {
		name       string
		algorithms ipsecAlgorithms
		mode       string
		want       []security.Param
	}{
		{
			name:       "default algorithms announce both modes",
			algorithms: ipsecAlgorithms{integrity: []string{"hmac-sha-1-96"}, encryption: []string{"null", "aes-cbc"}, modes: []string{"trans", "UDP-enc-tun"}},
			mode:       "trans",
			want: []security.Param{
				{Alg: "hmac-sha-1-96", EAlg: "null", Mod: "trans"},
				{Alg: "hmac-sha-1-96", EAlg: "null", Mod: "UDP-enc-tun"},
				{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Mod: "trans"},
				{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Mod: "UDP-enc-tun"},
			},
		},
		{
			name:       "MD5 mode is independent from algorithm",
			algorithms: ipsecAlgorithms{integrity: []string{"hmac-md5-96"}, encryption: []string{"null", "aes-cbc"}, modes: []string{"trans", "UDP-enc-tun"}},
			mode:       "trans",
			want: []security.Param{
				{Alg: "hmac-md5-96", EAlg: "null", Mod: "trans"},
				{Alg: "hmac-md5-96", EAlg: "null", Mod: "UDP-enc-tun"},
				{Alg: "hmac-md5-96", EAlg: "aes-cbc", Mod: "trans"},
				{Alg: "hmac-md5-96", EAlg: "aes-cbc", Mod: "UDP-enc-tun"},
			},
		},
		{
			name:       "configured transport mode applies to every algorithm",
			algorithms: ipsecAlgorithms{integrity: []string{"hmac-md5-96", "hmac-sha-1-96"}, encryption: []string{"null"}, modes: []string{"trans"}},
			mode:       "trans",
			want: []security.Param{
				{Alg: "hmac-md5-96", EAlg: "null", Mod: "trans"},
				{Alg: "hmac-sha-1-96", EAlg: "null", Mod: "trans"},
			},
		},
		{
			name:       "modern algorithms advertise only valid pairs",
			algorithms: ipsecAlgorithms{integrity: []string{"aes-gmac-us", "hmac-sha2-256-128", "null"}, encryption: []string{"aes-gcm-us", "null", "aes-cbc"}, modes: []string{"trans", "UDP-enc-tun"}},
			mode:       "trans",
			want: []security.Param{
				{Alg: "aes-gmac-us", EAlg: "null", Mod: "trans"},
				{Alg: "aes-gmac-us", EAlg: "null", Mod: "UDP-enc-tun"},
				{Alg: "hmac-sha2-256-128", EAlg: "null", Mod: "trans"},
				{Alg: "hmac-sha2-256-128", EAlg: "null", Mod: "UDP-enc-tun"},
				{Alg: "hmac-sha2-256-128", EAlg: "aes-cbc", Mod: "trans"},
				{Alg: "hmac-sha2-256-128", EAlg: "aes-cbc", Mod: "UDP-enc-tun"},
				{Alg: "null", EAlg: "aes-gcm-us", Mod: "trans"},
				{Alg: "null", EAlg: "aes-gcm-us", Mod: "UDP-enc-tun"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := security.Param{
				Mechanism: "ipsec-3gpp", Alg: "hmac-sha-1-96", EAlg: "null", Mod: tt.mode,
				PortC: 5062, PortS: 5063, Prot: "esp", SPIC: 1111, SPIS: 2222,
			}
			got := securityClientCapabilities(base, tt.algorithms)
			if len(got) != len(tt.want) {
				t.Fatalf("len(securityClientCapabilities()) = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				want := tt.want[i]
				if got[i].Alg != want.Alg || got[i].EAlg != want.EAlg || got[i].Mod != want.Mod {
					t.Fatalf("capability[%d] = %s/%s/%s, want %s/%s/%s", i, got[i].Alg, got[i].EAlg, got[i].Mod, want.Alg, want.EAlg, want.Mod)
				}
				if got[i].PortC != base.PortC || got[i].PortS != base.PortS || got[i].SPIC != base.SPIC || got[i].SPIS != base.SPIS {
					t.Fatalf("capability[%d] ports/SPIs = %+v, want base ports/SPIs", i, got[i])
				}
			}
		})
	}
}

func TestSecurityClientCapabilitiesIgnoreContactAddress(t *testing.T) {
	tests := []struct {
		name string
		host string
	}{
		{name: "public IPv6", host: "2a03:dd00:1189:636c::1"},
		{name: "public IPv4", host: "8.8.8.8"},
		{name: "private IPv4", host: "10.0.0.8"},
		{name: "unique local IPv6", host: "fd00::8"},
		{name: "shared CGNAT IPv4", host: "100.64.12.8"},
		{name: "loopback", host: "127.0.0.1"},
		{name: "hostname", host: "ue.example"},
	}
	algorithms := ipsecAlgorithms{integrity: []string{"hmac-sha-1-96"}, encryption: []string{"null"}, modes: []string{"trans", "UDP-enc-tun"}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := newFlow(tt.host, 5060, algorithms)
			if len(flow.SecurityClients) != 2 {
				t.Fatalf("Security-Client count = %d, want 2", len(flow.SecurityClients))
			}
			if flow.SecurityClients[0].Mod != "trans" || flow.SecurityClients[1].Mod != "UDP-enc-tun" {
				t.Fatalf("Security-Client modes = %q/%q, want trans/UDP-enc-tun", flow.SecurityClients[0].Mod, flow.SecurityClients[1].Mod)
			}
		})
	}
}

func TestSecurityQValue(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    int
		wantErr bool
	}{
		{name: "default", want: 1000},
		{name: "zero", value: "0"},
		{name: "zero with dot", value: "0."},
		{name: "one decimal", value: "0.1", want: 100},
		{name: "three decimals", value: "0.123", want: 123},
		{name: "one", value: "1", want: 1000},
		{name: "one with zeros", value: "1.000", want: 1000},
		{name: "rejects missing integer", value: ".5", wantErr: true},
		{name: "rejects excess precision", value: "0.1234", wantErr: true},
		{name: "rejects one with nonzero fraction", value: "1.001", wantErr: true},
		{name: "rejects exponent", value: "1e0", wantErr: true},
		{name: "rejects nan", value: "NaN", wantErr: true},
		{name: "rejects negative", value: "-0.1", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := securityQValue(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("securityQValue() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("securityQValue() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("securityQValue() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestSelectSecurityServerRejectsDuplicateQValues(t *testing.T) {
	offered := security.Params{
		{
			Mechanism: "ipsec-3gpp",
			Alg:       "hmac-sha-1-96",
			EAlg:      "null",
			Mod:       "trans",
			PortC:     10000,
			PortS:     10001,
			Prot:      "esp",
			SPIC:      1000,
			SPIS:      1001,
		},
	}
	tests := []struct {
		name   string
		values []string
	}{
		{
			name: "explicit duplicate",
			values: []string{
				"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=20000;port-s=20001;prot=esp;spi-c=0000002000;spi-s=0000002001;q=0.5",
				"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=20002;port-s=20003;prot=esp;spi-c=0000002002;spi-s=0000002003;q=0.5",
			},
		},
		{
			name: "implicit default duplicate",
			values: []string{
				"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=20000;port-s=20001;prot=esp;spi-c=0000002000;spi-s=0000002001",
				"ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=20002;port-s=20003;prot=esp;spi-c=0000002002;spi-s=0000002003",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := selectSecurityServer(tt.values, offered, "trans"); err == nil {
				t.Fatal("selectSecurityServer() error = nil, want duplicate q-value error")
			}
		})
	}
}

func TestSelectSecurityServerCompletesSharedSA(t *testing.T) {
	offered := security.Params{
		{
			Mechanism: "ipsec-3gpp",
			Alg:       "hmac-sha2-256-128",
			EAlg:      "null",
			Mod:       "trans",
			PortC:     16890,
			PortS:     58662,
			Prot:      "esp",
			SPIC:      2013280143,
			SPIS:      172568574,
		},
		{
			Mechanism: "ipsec-3gpp",
			Alg:       "hmac-sha-1-96",
			EAlg:      "aes-cbc",
			Mod:       "UDP-enc-tun",
			PortC:     16890,
			PortS:     58662,
			Prot:      "esp",
			SPIC:      2013280143,
			SPIS:      172568574,
		},
		{
			Mechanism: "ipsec-3gpp",
			Alg:       "hmac-sha-1-96",
			EAlg:      "null",
			Mod:       "trans",
			PortC:     16890,
			PortS:     58662,
			Prot:      "esp",
			SPIC:      2013280143,
			SPIS:      172568574,
		},
	}
	tests := []struct {
		name         string
		value        string
		requiredMode string
		want         security.Param
		wantErr      bool
	}{
		{
			name:  "inherits list association for leading transport candidate",
			value: "ipsec-3gpp;q=0.88;alg=hmac-sha2-256-128;mod=trans,ipsec-3gpp;q=0.80;alg=hmac-sha-1-96;mod=trans;spi-c=209072149;spi-s=210404739;port-c=6050;port-s=6060",
			want: security.Param{
				Mechanism: "ipsec-3gpp", Alg: "hmac-sha2-256-128", EAlg: "null", Mod: "trans",
				PortC: 6050, PortS: 6060, Prot: "esp", SPIC: 209072149, SPIS: 210404739, Q: "0.88",
			},
		},
		{
			name:    "does not borrow tunnel association for transport candidate",
			value:   "ipsec-3gpp;q=0.94;alg=hmac-sha-1-96;mod=UDP-enc-tun;spi-c=209072149;spi-s=210404739;port-c=6050;port-s=6060,ipsec-3gpp;q=0.88;alg=hmac-sha2-256-128;mod=trans",
			wantErr: true,
		},
		{
			name:    "rejects partially missing transport SA",
			value:   "ipsec-3gpp;q=0.88;alg=hmac-sha2-256-128;mod=trans;port-c=6050,ipsec-3gpp;q=0.94;alg=hmac-sha-1-96;mod=UDP-enc-tun;spi-c=209072149;spi-s=210404739;port-c=6050;port-s=6060",
			wantErr: true,
		},
		{
			name:         "accepts complete SHA1 AES UDP tunnel SA",
			value:        "ipsec-3gpp;q=0.90;alg=hmac-sha-1-96;ealg=aes-cbc;mod=UDP-enc-tun;spi-c=209072149;spi-s=210404739;port-c=6050;port-s=6060",
			requiredMode: "UDP-enc-tun",
			want: security.Param{
				Mechanism: "ipsec-3gpp", Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Mod: "UDP-enc-tun",
				PortC: 6050, PortS: 6060, Prot: "esp", SPIC: 209072149, SPIS: 210404739, Q: "0.90",
			},
		},
		{
			name: "rejects ambiguous shared associations",
			value: "ipsec-3gpp;q=0.88;alg=hmac-sha2-256-128;mod=trans," +
				"ipsec-3gpp;q=0.80;alg=hmac-sha-1-96;mod=UDP-enc-tun;spi-c=209072149;spi-s=210404739;port-c=6050;port-s=6060," +
				"ipsec-3gpp;q=0.70;alg=hmac-sha-1-96;mod=UDP-enc-tun;spi-c=209072150;spi-s=210404740;port-c=6051;port-s=6061",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requiredMode := tt.requiredMode
			if requiredMode == "" {
				requiredMode = "trans"
			}
			got, _, err := selectSecurityServer([]string{tt.value}, offered, requiredMode)
			if tt.wantErr {
				if err == nil {
					t.Fatal("selectSecurityServer() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("selectSecurityServer() error = %v", err)
			}
			if *got != tt.want {
				t.Fatalf("selectSecurityServer() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestSelectSecurityServerRejectsUnofferedHigherQValue(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   security.Param
	}{
		{
			name: "rejects unadvertised higher priority candidate",
			values: []string{
				"ipsec-3gpp;q=0.88;alg=hmac-sha2-256-128;ealg=null;mod=trans;spi-c=209072149;spi-s=210404739;port-c=6050;port-s=6060," +
					"ipsec-3gpp;q=0.94;alg=hmac-sha-1-96;ealg=null;mod=UDP-enc-tun;spi-c=209072150;spi-s=210404740;port-c=6051;port-s=6061",
			},
			want: security.Param{
				Mechanism: "ipsec-3gpp", Alg: "hmac-sha2-256-128", EAlg: "null", Mod: "trans",
				PortC: 6050, PortS: 6060, Prot: "esp", SPIC: 209072149, SPIS: 210404739, Q: "0.88",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := security.Param{Mechanism: "ipsec-3gpp", PortC: 16890, PortS: 58662, Prot: "esp", SPIC: 2013280143, SPIS: 172568574}
			offered := securityClientCapabilities(base, ipsecAlgorithms{integrity: []string{"hmac-sha2-256-128"}, encryption: []string{"null"}, modes: []string{"trans", "UDP-enc-tun"}})
			got, _, err := selectSecurityServer(tt.values, offered, "trans")
			if err != nil {
				t.Fatalf("selectSecurityServer() error = %v", err)
			}
			if *got != tt.want {
				t.Fatalf("selectSecurityServer() = %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestSelectSecurityServerRejectsUnadvertisedMD5TunnelMode(t *testing.T) {
	base := security.Param{
		Mechanism: "ipsec-3gpp",
		PortC:     16890,
		PortS:     58662,
		Prot:      "esp",
		SPIC:      2013280143,
		SPIS:      172568574,
	}
	offered := securityClientCapabilities(base, ipsecAlgorithms{
		integrity:  []string{"hmac-md5-96"},
		encryption: []string{"null"},
		modes:      []string{"trans", "UDP-enc-tun"},
	})
	values := []string{
		"ipsec-3gpp;q=0.88;alg=hmac-md5-96;ealg=null;mod=UDP-enc-tun;spi-c=209072149;spi-s=210404739;port-c=6050;port-s=6060," +
			"ipsec-3gpp;q=0.94;alg=hmac-sha-1-96;ealg=null;mod=trans",
	}

	if _, _, err := selectSecurityServer(values, offered, "trans"); err == nil {
		t.Fatal("selectSecurityServer() error = nil, want no compatible mechanism")
	}
}

func TestSecurityClientParametersAreUnique(t *testing.T) {
	tests := []struct {
		name string
		next func() security.Param
	}{
		{
			name: "initial",
			next: func() security.Param {
				return newSecurityClient(5060, ipsecAlgorithms{integrity: []string{"hmac-sha-1-96"}, encryption: []string{"null"}, modes: []string{"trans", "UDP-enc-tun"}})
			},
		},
		{
			name: "reauth",
			next: func() security.Param {
				current := security.Param{SPIC: 310, SPIS: 320, PortC: 5062, PortS: 5063}
				peer := security.Param{SPIC: 330, SPIS: 340}
				return reauthSecurityClient(current, peer, 5060)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.next()
			if got.SPIC == got.SPIS {
				t.Fatalf("SPIC = SPIS = %d, want unique SPIs", got.SPIC)
			}
			if got.SPIC == 310 || got.SPIC == 320 || got.SPIC == 330 || got.SPIC == 340 || got.SPIS == 310 || got.SPIS == 320 || got.SPIS == 330 || got.SPIS == 340 {
				t.Fatalf("SPIs = %d/%d, want different from every active inbound and outbound SPI", got.SPIC, got.SPIS)
			}
			if got.PortC == got.PortS || got.PortC == 5060 || got.PortS == 5060 || got.PortC == 5061 || got.PortS == 5061 {
				t.Fatalf("ports = %d/%d, want unique non-standard protected ports", got.PortC, got.PortS)
			}
		})
	}
}

func TestReauthenticationSecurityClientCapabilities(t *testing.T) {
	algorithms := ipsecAlgorithms{
		integrity:  []string{"hmac-sha-1-96"},
		encryption: []string{"null"},
		modes:      []string{"trans", "UDP-enc-tun"},
	}
	tests := []struct {
		name    string
		mode    string
		want    string
		wantErr string
	}{
		{name: "transport", mode: "trans", want: "trans"},
		{name: "UDP encapsulated tunnel", mode: "udp-ENC-tun", want: "UDP-enc-tun"},
		{name: "missing", wantErr: "unsupported IPsec mode"},
		{name: "unsupported", mode: "tun", wantErr: "unsupported IPsec mode"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := security.Param{
				Mechanism: "ipsec-3gpp",
				Alg:       "hmac-sha-1-96",
				EAlg:      "null",
				Mod:       tt.mode,
				PortC:     5062,
				PortS:     5063,
				Prot:      "esp",
				SPIC:      1001,
				SPIS:      1002,
			}

			got, err := reauthenticationSecurityClientCapabilities(base, algorithms)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("reauthenticationSecurityClientCapabilities() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("reauthenticationSecurityClientCapabilities() error = %v", err)
			}
			if len(got) != 1 || got[0].Mod != tt.want {
				t.Fatalf("reauthentication Security-Client = %+v, want mode %q", got, tt.want)
			}
		})
	}
}

func TestNATProtectedPortRotation(t *testing.T) {
	tests := []struct {
		name         string
		rotateServer bool
	}{
		{name: "initial registration rotates client and server", rotateServer: true},
		{name: "re-registration rotates only client", rotateServer: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			algorithms := ipsecAlgorithms{integrity: []string{"hmac-sha-1-96"}, encryption: []string{"null", "aes-cbc"}, modes: []string{"trans", "UDP-enc-tun"}}
			flow := newFlow("198.51.100.10", 5060, algorithms)
			oldClientPort := flow.SecurityClient.PortC
			oldServerPort := flow.SecurityClient.PortS
			rotateNATProtectedPorts(&flow, tt.rotateServer)
			if flow.SecurityClient.PortC == oldClientPort {
				t.Fatalf("protected client port = %d, want changed from %d", flow.SecurityClient.PortC, oldClientPort)
			}
			if tt.rotateServer && flow.SecurityClient.PortS == oldServerPort {
				t.Fatalf("protected server port = %d, want changed from %d", flow.SecurityClient.PortS, oldServerPort)
			}
			if !tt.rotateServer && flow.SecurityClient.PortS != oldServerPort {
				t.Fatalf("protected server port = %d, want unchanged %d", flow.SecurityClient.PortS, oldServerPort)
			}
			for i, capability := range flow.SecurityClients {
				if capability.PortC != flow.SecurityClient.PortC || capability.PortS != flow.SecurityClient.PortS {
					t.Fatalf("capability[%d] ports = %d/%d, want %d/%d", i, capability.PortC, capability.PortS, flow.SecurityClient.PortC, flow.SecurityClient.PortS)
				}
			}
		})
	}
}

func TestIPsecSecurityAssociationsFollowTS33203Flows(t *testing.T) {
	verify := security.Param{
		Alg:   "hmac-sha-1-96",
		EAlg:  "aes-cbc",
		Mod:   "UDP-enc-tun",
		PortC: 4061,
		PortS: 4060,
		SPIC:  0x11111111,
		SPIS:  0x22222222,
	}
	flow := Flow{ContactHost: "198.51.100.10", SecurityClient: security.Param{
		PortC: 5062,
		PortS: 5063,
		SPIC:  0x33333333,
		SPIS:  0x44444444,
	}}
	var clientCfg session.SecureUDPConfig
	var serverCfg session.SecureUDPConfig
	primary := newUDPTransport(5060, 5060)
	svc := newTestService(t, Config{
		DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			clientCfg = cfg
			return newUDPTransport(cfg.LocalPort, cfg.RemotePort), nil
		},
		ListenSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			serverCfg = cfg
			return newUDPTransport(cfg.LocalPort, cfg.RemotePort), nil
		},
	}, primary, stubCard{})

	if _, err := svc.dialSecureTransport(t.Context(), &verify, flow, []byte("ck"), []byte("ik")); err != nil {
		t.Fatalf("dialSecureTransport() error = %v", err)
	}
	_, attachments, err := svc.startSecureServerTransportsWithKeys(t.Context(), &verify, flow, []byte("ck"), []byte("ik"))
	if err != nil {
		t.Fatalf("startSecureServerTransportsWithKeys() error = %v", err)
	}
	t.Cleanup(func() {
		if err := closeAttachments(attachments); err != nil {
			t.Errorf("closeAttachments() error = %v", err)
		}
	})

	tests := []struct {
		name string
		got  uint32
		want uint32
	}{
		{name: "client flow outbound uses Security-Server spi-s", got: clientCfg.OutboundSPI, want: verify.SPIS},
		{name: "client flow inbound uses Security-Client spi-c", got: clientCfg.InboundSPI, want: flow.SecurityClient.SPIC},
		{name: "server flow outbound uses Security-Server spi-c", got: serverCfg.OutboundSPI, want: verify.SPIC},
		{name: "server flow inbound uses Security-Client spi-s", got: serverCfg.InboundSPI, want: flow.SecurityClient.SPIS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("SPI = %#x, want %#x", tt.got, tt.want)
			}
		})
	}
	if clientCfg.LocalPort != flow.SecurityClient.PortC || clientCfg.RemotePort != verify.PortS {
		t.Fatalf("client flow ports = %d/%d, want %d/%d", clientCfg.LocalPort, clientCfg.RemotePort, flow.SecurityClient.PortC, verify.PortS)
	}
	if serverCfg.LocalPort != flow.SecurityClient.PortS || serverCfg.RemotePort != verify.PortC {
		t.Fatalf("server flow ports = %d/%d, want %d/%d", serverCfg.LocalPort, serverCfg.RemotePort, flow.SecurityClient.PortS, verify.PortC)
	}
	if !clientCfg.InnerLocalIP.Equal(net.ParseIP(flow.ContactHost)) || !serverCfg.InnerLocalIP.Equal(net.ParseIP(flow.ContactHost)) {
		t.Fatalf("inner local IPs = %s/%s, want %s", clientCfg.InnerLocalIP, serverCfg.InnerLocalIP, flow.ContactHost)
	}
}

func TestSecurityServerMustMatchSecurityClientOffer(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
	req := svc.buildRegister(nil, nil)
	tests := []struct {
		name     string
		server   string
		received string
		wantErr  bool
	}{
		{
			name:     "offered UDP encapsulation",
			server:   "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;mod=UDP-enc-tun;port-c=4061;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222",
			received: "198.51.100.10",
		},
		{
			name:    "unoffered AES GCM",
			server:  "ipsec-3gpp;alg=null;ealg=aes-gcm;mod=trans;port-c=4061;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := newResponse(req, 401, "Unauthorized",
				sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.example",nonce="` + testNonce + `",algorithm=AKAv1-MD5`},
				sip.Header{Name: "Security-Server", Value: tt.server},
			)
			if tt.received != "" {
				resp.Headers.Set("Via", req.Header("Via")+";received="+tt.received)
			}
			_, err := svc.applyRegisterChallenge(resp)
			if tt.wantErr && !errors.Is(err, errSecurityAgreementInvalid) {
				t.Fatalf("applyRegisterChallenge() error = %v, want invalid security agreement", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("applyRegisterChallenge() error = %v, want nil", err)
			}
		})
	}
}

func TestRegisterUsesIPSecClientAndServerPorts(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
	flow := svc.CurrentFlow()
	tcpSvc := newTestService(t, Config{}, newTCPTransport(5062, 5060), stubCard{})
	tcpFlow := tcpSvc.CurrentFlow()
	auth := &security.Authorization{Algorithm: security.AlgorithmAKAv1MD5}

	tests := []struct {
		name        string
		build       func() sip.Message
		wantViaPort int
		wantContact string
	}{
		{
			name:        "unprotected register uses registration port",
			build:       func() sip.Message { return svc.buildRegister(nil, nil) },
			wantViaPort: flow.RegisterPort,
			wantContact: net.JoinHostPort(flow.ContactHost, strconv.Itoa(flow.RegisterPort)),
		},
		{
			name:        "protected UDP register advertises server port",
			build:       func() sip.Message { return svc.buildRegister(auth, nil) },
			wantViaPort: flow.SecurityClient.PortS,
			wantContact: net.JoinHostPort(flow.ContactHost, strconv.Itoa(flow.SecurityClient.PortS)),
		},
		{
			name:        "protected UDP deregister advertises server port",
			build:       func() sip.Message { return svc.buildDeregister(auth, nil) },
			wantViaPort: flow.SecurityClient.PortS,
			wantContact: "*",
		},
		{
			name:        "protected TCP register advertises client port",
			build:       func() sip.Message { return tcpSvc.buildRegister(auth, nil) },
			wantViaPort: tcpFlow.SecurityClient.PortC,
			wantContact: net.JoinHostPort(tcpFlow.ContactHost, strconv.Itoa(tcpFlow.SecurityClient.PortS)),
		},
		{
			name:        "protected TCP deregister advertises client port",
			build:       func() sip.Message { return tcpSvc.buildDeregister(auth, nil) },
			wantViaPort: tcpFlow.SecurityClient.PortC,
			wantContact: "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := tt.build()
			_, portText, err := net.SplitHostPort(sip.TopViaSentBy(msg.Header("Via")))
			if err != nil {
				t.Fatalf("parsing Via sent-by: %v", err)
			}
			port, err := strconv.Atoi(portText)
			if err != nil {
				t.Fatalf("parsing Via port: %v", err)
			}
			if port != tt.wantViaPort {
				t.Fatalf("Via port = %d, want %d", port, tt.wantViaPort)
			}
			contact := msg.Header("Contact")
			if tt.wantContact == "*" {
				if contact != "*" {
					t.Fatalf("Contact = %q, want *", contact)
				}
				return
			}
			var uri comparableSIPURI
			if err := uri.UnmarshalText([]byte(sip.AddressURI(contact))); err != nil {
				t.Fatalf("parsing Contact URI %q: %v", contact, err)
			}
			if uri.hostPort != tt.wantContact {
				t.Fatalf("Contact endpoint = %q, want %q", uri.hostPort, tt.wantContact)
			}
		})
	}
}

func TestSecurityServerSPIsMustDifferFromClientOffer(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
	req := svc.buildRegister(nil, nil)
	var offered security.Params
	if err := offered.UnmarshalText([]byte(req.Header("Security-Client"))); err != nil {
		t.Fatalf("parsing Security-Client: %v", err)
	}
	server := fmt.Sprintf("ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4061;port-s=4060;prot=esp;spi-c=%010d;spi-s=0000002222", offered[0].SPIC)
	resp := newResponse(req, 401, "Unauthorized",
		sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.example",nonce="` + testNonce + `",algorithm=AKAv1-MD5`},
		sip.Header{Name: "Security-Server", Value: server},
	)

	if _, err := svc.applyRegisterChallenge(resp); !errors.Is(err, errSecurityAgreementInvalid) {
		t.Fatalf("applyRegisterChallenge() error = %v, want SPI collision rejection", err)
	}
}

func TestValidateReauthenticationSecurityServer(t *testing.T) {
	current := Flow{SecurityVerify: &security.Param{Mod: "UDP-enc-tun", PortC: 4062, PortS: 4060, SPIC: 1111, SPIS: 2222}}
	tests := []struct {
		name     string
		selected security.Param
		wantErr  bool
	}{
		{name: "valid", selected: security.Param{Mod: "UDP-enc-tun", PortC: 4600, PortS: 4060, SPIC: 3333, SPIS: 4444}},
		{name: "server port changed", selected: security.Param{Mod: "UDP-enc-tun", PortC: 4600, PortS: 4700, SPIC: 3333, SPIS: 4444}, wantErr: true},
		{name: "client port unchanged", selected: security.Param{Mod: "UDP-enc-tun", PortC: 4062, PortS: 4060, SPIC: 3333, SPIS: 4444}, wantErr: true},
		{name: "mode downgraded", selected: security.Param{Mod: "trans", PortC: 4600, PortS: 4060, SPIC: 3333, SPIS: 4444}, wantErr: true},
		{name: "client SPI reused", selected: security.Param{Mod: "UDP-enc-tun", PortC: 4600, PortS: 4060, SPIC: 1111, SPIS: 4444}, wantErr: true},
		{name: "server SPI reused", selected: security.Param{Mod: "UDP-enc-tun", PortC: 4600, PortS: 4060, SPIC: 3333, SPIS: 2222}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateReauthenticationSecurityServer(current, &tt.selected)
			if tt.wantErr && err == nil {
				t.Fatal("validateReauthenticationSecurityServer() error = nil, want non-nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("validateReauthenticationSecurityServer() error = %v", err)
			}
		})
	}
}

func TestRegisterChallengeNATPolicy(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		omitMode     bool
		received     string
		malformedVia bool
		wantHost     string
		wantErr      bool
	}{
		{
			name:     "matching received keeps transport mode",
			mode:     "trans",
			received: "127.0.0.1",
			wantHost: "127.0.0.1",
		},
		{
			name:     "matching received rejects UDP tunnel mode",
			mode:     "UDP-enc-tun",
			received: "127.0.0.1",
			wantErr:  true,
		},
		{
			name:     "missing received uses transport mode",
			mode:     "trans",
			wantHost: "127.0.0.1",
		},
		{
			name:    "missing received rejects UDP tunnel mode",
			mode:    "UDP-enc-tun",
			wantErr: true,
		},
		{
			name:     "different received uses UDP tunnel mode",
			mode:     "UDP-enc-tun",
			received: "203.0.113.10",
			wantHost: "203.0.113.10",
		},
		{
			name:     "different received rejects transport mode",
			mode:     "trans",
			received: "203.0.113.10",
			wantErr:  true,
		},
		{
			name:     "missing mode with matching received defaults to transport",
			omitMode: true,
			received: "127.0.0.1",
			wantHost: "127.0.0.1",
		},
		{
			name:     "missing mode with received aborts",
			omitMode: true,
			received: "203.0.113.10",
			wantErr:  true,
		},
		{
			name:     "rejects malformed received address",
			mode:     "trans",
			received: "not-an-ip",
			wantErr:  true,
		},
		{
			name:         "rejects malformed Via sent-by address",
			mode:         "trans",
			received:     "127.0.0.1",
			malformedVia: true,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
			req := svc.buildRegister(nil, nil)
			initialSecurityClient := req.Header("Security-Client")
			mode := ";mod=" + tt.mode
			if tt.omitMode {
				mode = ""
			}
			securityServer := "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc" + mode + ";port-c=4061;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222"
			resp := newResponse(req, 401, "Unauthorized",
				sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.example",nonce="` + testNonce + `",algorithm=AKAv1-MD5`},
				sip.Header{Name: "Security-Server", Value: securityServer},
			)
			if tt.received != "" {
				via := req.Header("Via")
				if tt.malformedVia {
					via = "SIP/2.0/UDP not-an-address;branch=z9hG4bK-test"
				}
				resp.Headers.Set("Via", via+";received="+tt.received)
			}

			_, err := svc.applyRegisterChallenge(resp)
			if tt.wantErr {
				if err == nil {
					t.Fatal("applyRegisterChallenge() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("applyRegisterChallenge() error = %v", err)
			}
			if got := svc.CurrentFlow().ContactHost; got != tt.wantHost {
				t.Fatalf("ContactHost = %q, want %q", got, tt.wantHost)
			}

			protected := svc.buildRegister(&security.Authorization{Algorithm: security.AlgorithmAKAv1MD5}, svc.currentSecurityVerify())
			if got := protected.Header("Security-Client"); got != initialSecurityClient {
				t.Fatalf("protected Security-Client = %q, want initial value %q", got, initialSecurityClient)
			}
			if got := protected.Header("Security-Verify"); got != securityServer {
				t.Fatalf("Security-Verify = %q, want mirrored Security-Server %q", got, securityServer)
			}
			if tt.wantHost != "" && !strings.Contains(protected.Header("Contact"), tt.wantHost) {
				t.Fatalf("Contact = %q, want host %q", protected.Header("Contact"), tt.wantHost)
			}
		})
	}
}

func TestRegisterChallengePreservesEstablishedMode(t *testing.T) {
	tests := []struct {
		name        string
		currentMode string
		serverMode  string
		received    string
		wantErr     bool
	}{
		{
			name:        "UDP tunnel reauthentication does not require received",
			currentMode: "UDP-enc-tun",
			serverMode:  "UDP-enc-tun",
		},
		{
			name:        "transport reauthentication ignores non-authoritative received",
			currentMode: "trans",
			serverMode:  "trans",
			received:    "203.0.113.10",
		},
		{
			name:        "UDP tunnel reauthentication rejects transport downgrade",
			currentMode: "UDP-enc-tun",
			serverMode:  "trans",
			wantErr:     true,
		},
		{
			name:        "transport reauthentication rejects UDP tunnel switch",
			currentMode: "trans",
			serverMode:  "UDP-enc-tun",
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
			svc.applySelectedSecurityServer(&security.Param{Mod: tt.currentMode}, nil, "")
			req := svc.buildRegister(nil, nil)
			securityServer := "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;mod=" + tt.serverMode + ";port-c=4061;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222"
			resp := newResponse(req, 401, "Unauthorized",
				sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.example",nonce="` + testNonce + `",algorithm=AKAv1-MD5`},
				sip.Header{Name: "Security-Server", Value: securityServer},
			)
			if tt.received != "" {
				resp.Headers.Set("Via", req.Header("Via")+";received="+tt.received)
			}

			_, err := svc.applyRegisterChallenge(resp)
			if tt.wantErr && !errors.Is(err, errSecurityAgreementInvalid) {
				t.Fatalf("applyRegisterChallenge() error = %v, want invalid security agreement", err)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("applyRegisterChallenge() error = %v", err)
			}
		})
	}
}
