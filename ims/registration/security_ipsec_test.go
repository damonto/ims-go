package registration

import (
	"context"
	"errors"
	"fmt"
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
		want   [4]byte
	}{
		{
			name:   "aes gmac salt",
			verify: security.Param{Alg: "aes-gmac", EAlg: "null"},
			want:   [4]byte{0x2F, 0x5A, 0x80, 0x8D},
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
			if got := espSalt(&tt.verify, ck, ik); got != tt.want {
				t.Fatalf("espSalt() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestSecureTransportConfigCarriesModeAndSalt(t *testing.T) {
	ck := []byte{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F}
	ik := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
	verify := security.Param{Alg: "null", EAlg: "aes-gcm", Mod: "UDP-enc-tun"}

	cfg := secureTransportConfigWithKeys(&verify, 40000, 5060, 1111, 2222, ck, ik)
	if cfg.Mode != "UDP-enc-tun" {
		t.Fatalf("Mode = %q, want UDP-enc-tun", cfg.Mode)
	}
	if cfg.Salt != ([4]byte{0x1F, 0xBF, 0x69, 0xCD}) {
		t.Fatalf("Salt = % X, want 1F BF 69 CD", cfg.Salt)
	}
	if cfg.Encryption != "aes-gcm" || cfg.Integrity != "null" {
		t.Fatalf("algorithms = %s/%s, want aes-gcm/null", cfg.Encryption, cfg.Integrity)
	}
}

func TestSecurityClientCapabilities(t *testing.T) {
	base := security.Param{
		Mechanism: "ipsec-3gpp",
		Alg:       "hmac-sha-1-96",
		EAlg:      "null",
		Mod:       "trans",
		PortC:     5062,
		PortS:     5063,
		Prot:      "esp",
		SPIC:      1111,
		SPIS:      2222,
	}
	want := []security.Param{
		{Alg: "hmac-sha-1-96", EAlg: "null", Mod: "trans"},
		{Alg: "hmac-sha-1-96", EAlg: "null", Mod: "UDP-enc-tun"},
		{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Mod: "trans"},
		{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", Mod: "UDP-enc-tun"},
	}

	got := securityClientCapabilities(base)
	if len(got) != len(want) {
		t.Fatalf("len(securityClientCapabilities()) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Alg != want[i].Alg || got[i].EAlg != want[i].EAlg || got[i].Mod != want[i].Mod {
			t.Fatalf("capability[%d] = %s/%s/%s, want %s/%s/%s", i, got[i].Alg, got[i].EAlg, got[i].Mod, want[i].Alg, want[i].EAlg, want[i].Mod)
		}
		if got[i].PortC != base.PortC || got[i].PortS != base.PortS || got[i].SPIC != base.SPIC || got[i].SPIS != base.SPIS {
			t.Fatalf("capability[%d] ports/SPIs = %+v, want base ports/SPIs", i, got[i])
		}
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
			if _, _, err := selectSecurityServer(tt.values, offered); err == nil {
				t.Fatal("selectSecurityServer() error = nil, want duplicate q-value error")
			}
		})
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
				return newSecurityClient(5060)
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

func TestIPsecSecurityAssociationsFollowTS33203Flows(t *testing.T) {
	verify := security.Param{
		Alg:   "hmac-sha-1-96",
		EAlg:  "aes-cbc",
		Mod:   "trans",
		PortC: 4061,
		PortS: 4060,
		SPIC:  0x11111111,
		SPIS:  0x22222222,
	}
	flow := Flow{SecurityClient: security.Param{
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

	if _, err := svc.dialSecureTransport(context.Background(), &verify, flow, []byte("ck"), []byte("ik")); err != nil {
		t.Fatalf("dialSecureTransport() error = %v", err)
	}
	_, attachments, err := svc.startSecureServerTransportsWithKeys(context.Background(), &verify, flow, []byte("ck"), []byte("ik"))
	if err != nil {
		t.Fatalf("startSecureServerTransportsWithKeys() error = %v", err)
	}
	defer closeAttachments(attachments)

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
}

func TestSecurityServerMustMatchSecurityClientOffer(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
	req := svc.buildRegister(nil, nil)
	tests := []struct {
		name    string
		server  string
		wantErr bool
	}{
		{
			name:   "offered UDP encapsulation",
			server: "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;mod=UDP-enc-tun;port-c=4061;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222",
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
	current := Flow{SecurityVerify: &security.Param{PortC: 4062, PortS: 4060, SPIC: 1111, SPIS: 2222}}
	tests := []struct {
		name     string
		selected security.Param
		wantErr  bool
	}{
		{name: "valid", selected: security.Param{PortC: 4600, PortS: 4060, SPIC: 3333, SPIS: 4444}},
		{name: "server port changed", selected: security.Param{PortC: 4600, PortS: 4700, SPIC: 3333, SPIS: 4444}, wantErr: true},
		{name: "client port unchanged", selected: security.Param{PortC: 4062, PortS: 4060, SPIC: 3333, SPIS: 4444}, wantErr: true},
		{name: "client SPI reused", selected: security.Param{PortC: 4600, PortS: 4060, SPIC: 1111, SPIS: 4444}, wantErr: true},
		{name: "server SPI reused", selected: security.Param{PortC: 4600, PortS: 4060, SPIC: 3333, SPIS: 2222}, wantErr: true},
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

func TestRegisterChallengeNATMode(t *testing.T) {
	tests := []struct {
		name     string
		mode     string
		received string
		wantHost string
		wantErr  bool
	}{
		{
			name:     "public address keeps contact host",
			mode:     "trans",
			received: "127.0.0.1",
			wantHost: "127.0.0.1",
		},
		{
			name:     "missing received keeps transport mode",
			mode:     "trans",
			wantHost: "127.0.0.1",
		},
		{
			name:     "NAT requires and stores UDP encapsulation",
			mode:     "UDP-enc-tun",
			received: "203.0.113.10",
			wantHost: "203.0.113.10",
		},
		{
			name:     "NAT rejects transport mode",
			mode:     "trans",
			received: "203.0.113.10",
			wantErr:  true,
		},
		{
			name:     "rejects malformed received address",
			mode:     "UDP-enc-tun",
			received: "not-an-ip",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
			req := svc.buildRegister(nil, nil)
			initialSecurityClient := req.Header("Security-Client")
			securityServer := "ipsec-3gpp;alg=hmac-sha-1-96;ealg=aes-cbc;mod=" + tt.mode + ";port-c=4061;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222"
			resp := newResponse(req, 401, "Unauthorized",
				sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.example",nonce="` + testNonce + `",algorithm=AKAv1-MD5`},
				sip.Header{Name: "Security-Server", Value: securityServer},
			)
			if tt.received != "" {
				resp.Headers.Set("Via", req.Header("Via")+";received="+tt.received)
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
