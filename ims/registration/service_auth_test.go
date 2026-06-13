package registration

import (
	"bytes"
	"context"
	"encoding/base64"
	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/sip"
	"strings"
	"testing"
)

func TestApplyRegisterChallengeSelectsHighestQSecurityServer(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})

	req := svc.buildRegister(nil, nil)
	resp := newResponse(req, 401, "Unauthorized",
		sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`},
		sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222;q=0.1`},
		sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=333;spi-s=444;q=0.9`},
	)

	if _, err := svc.applyRegisterChallenge(resp); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	state := svc.State()
	if state.SecurityVerify == nil {
		t.Fatal("SecurityVerify = nil, want non-nil")
	}
	if got := state.SecurityVerify.PortC; got != 5062 {
		t.Fatalf("SecurityVerify.PortC = %d, want 5062", got)
	}
	if got := state.SecurityVerify.PortS; got != 5060 {
		t.Fatalf("SecurityVerify.PortS = %d, want 5060", got)
	}
	if got := state.MessagePort; got != state.SecurityClient.PortS {
		t.Fatalf("MessagePort = %d, want %d", got, state.SecurityClient.PortS)
	}
	wantVerify := `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222;q=0.1,ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=333;spi-s=444;q=0.9`
	if got := svc.SecurityVerifyValue(); got != wantVerify {
		t.Fatalf("SecurityVerifyValue() = %q, want %q", got, wantVerify)
	}
	if got := len(state.Flow.SecurityServerRaw); got != 2 {
		t.Fatalf("len(Flow.SecurityServerRaw) = %d, want 2", got)
	}
}

func TestApplyRegisterChallengeSelectsSupportedWWWAuthenticate(t *testing.T) {
	tests := []struct {
		name    string
		headers []sip.Header
		wantAlg string
	}{
		{
			name: "skips unsupported digest algorithm",
			headers: []sip.Header{
				{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="legacy",algorithm=MD5,qop="auth"`},
				{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`},
				{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=333;spi-s=444`},
			},
			wantAlg: security.AlgorithmAKAv1MD5,
		},
		{
			name: "skips unsupported scheme",
			headers: []sip.Header{
				{Name: "WWW-Authenticate", Value: `Basic realm="ims.mnc001.mcc001.3gppnetwork.org"`},
				{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`},
				{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=333;spi-s=444`},
			},
			wantAlg: security.AlgorithmAKAv1MD5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{AuthAlgorithm: tt.wantAlg}, newTCPTransport(5062, 5060), stubCard{})
			resp := newResponse(svc.buildRegister(nil, nil), 401, "Unauthorized", tt.headers...)

			challenge, err := svc.applyRegisterChallenge(resp)
			if err != nil {
				t.Fatalf("applyRegisterChallenge() error = %v", err)
			}
			if challenge.Algorithm != tt.wantAlg {
				t.Fatalf("challenge algorithm = %q, want %q", challenge.Algorithm, tt.wantAlg)
			}
		})
	}
}

func TestRegisterHandlesProxyAuthenticationChallenge(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			if got := req.Header("Authorization"); got == "" {
				t.Fatal("initial Authorization = empty")
			}
			transport.queue(newResponse(req, sipStatusProxyAuthenticationRequired, "Proxy Authentication Required",
				sip.Header{Name: "Proxy-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`},
				sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=333;spi-s=444`},
			))
		case 2:
			if got := req.Header("Authorization"); got != "" {
				t.Fatalf("Authorization = %q, want empty after 407", got)
			}
			if got := req.Header("Proxy-Authorization"); !strings.Contains(got, `nonce="`+testNonce+`"`) {
				t.Fatalf("Proxy-Authorization = %q, want nonce %q", got, testNonce)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
		default:
			t.Fatalf("unexpected REGISTER write %d", countWrites(transport))
		}
	}

	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
}

func TestBuildRegisterUsesSpecDefaultExpires(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})

	msg := svc.buildRegister(nil, nil)
	if got := msg.Header("Expires"); got != "600000" {
		t.Fatalf("Expires = %q, want 600000", got)
	}
}

func TestBuildRegisterAuthorizationIntegrityProtected(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})

	initial := svc.buildRegister(nil, nil)
	if got := initial.Header("Authorization"); !strings.Contains(got, "integrity-protected=no") {
		t.Fatalf("initial Authorization = %q, want integrity-protected=no", got)
	}

	auth, err := svc.buildRegisterAuthorization(context.Background(), "ims.mnc001.mcc001.3gppnetwork.org", testNonce, security.AlgorithmAKAv1MD5, "auth")
	if err != nil {
		t.Fatalf("buildRegisterAuthorization() error = %v", err)
	}
	protected := svc.buildRegister(auth, nil)
	if got := protected.Header("Authorization"); !strings.Contains(got, "integrity-protected=yes") {
		t.Fatalf("protected Authorization = %q, want integrity-protected=yes", got)
	}
}

func TestBuildRegisterAKAv2MD5BootstrapUsesIPSecSecurityAgreement(t *testing.T) {
	svc := newTestService(t, Config{AuthAlgorithm: security.AlgorithmAKAv2MD5}, newUDPTransport(5062, 5060), stubCard{})

	msg := svc.buildRegister(nil, nil)
	auth := msg.Header("Authorization")
	if !strings.Contains(auth, "algorithm=AKAv2-MD5") {
		t.Fatalf("Authorization = %q, want AKAv2-MD5", auth)
	}
	if !strings.Contains(auth, "integrity-protected=no") {
		t.Fatalf("Authorization = %q, want integrity-protected=no", auth)
	}
	var clients security.Params
	if err := clients.UnmarshalText([]byte(msg.Header("Security-Client"))); err != nil {
		t.Fatalf("parsing Security-Client: %v", err)
	}
	if len(clients) != 2 {
		t.Fatalf("Security-Client count = %d, want 2", len(clients))
	}
	if clients[0].EAlg != "null" || clients[1].EAlg != "aes-cbc" {
		t.Fatalf("Security-Client ealgs = %q/%q, want null/aes-cbc", clients[0].EAlg, clients[1].EAlg)
	}
	if clients[0].Mod != "trans" || clients[1].Mod != "trans" {
		t.Fatalf("Security-Client modes = %q/%q, want trans/trans", clients[0].Mod, clients[1].Mod)
	}
	if got := msg.Header("Require"); got != "sec-agree" {
		t.Fatalf("Require = %q, want sec-agree", got)
	}
	if got := msg.Header("Proxy-Require"); got != "sec-agree" {
		t.Fatalf("Proxy-Require = %q, want sec-agree", got)
	}
}

func TestNormalizeConfigRejectsAKAv2SHA256WithoutTLSTransport(t *testing.T) {
	_, err := normalizeConfig(Config{AuthAlgorithm: security.AlgorithmAKAv2SHA256})
	if err == nil {
		t.Fatal("normalizeConfig() error = nil, want AKAv2-SHA-256 TLS transport error")
	}
	if !strings.Contains(err.Error(), "AKAv2-SHA-256 requires TLS SIP transport") {
		t.Fatalf("normalizeConfig() error = %v, want TLS transport error", err)
	}
}

func TestApplyRegisterChallengeRejectsAKAv2SHA256WithoutSecurityServerTLS(t *testing.T) {
	tests := []struct {
		name    string
		headers []sip.Header
		want    string
	}{
		{
			name: "missing security server",
			headers: []sip.Header{
				{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv2-SHA-256,qop="auth"`},
			},
			want: "requires tls security mechanism",
		},
		{
			name: "tls advertised but unsupported locally",
			headers: []sip.Header{
				{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv2-SHA-256,qop="auth"`},
				{Name: "Security-Server", Value: `tls;q=1.0`},
			},
			want: "over TLS is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newTCPTransport(5062, 5060), stubCard{})

			_, err := svc.applyRegisterChallenge(newResponse(svc.buildRegister(nil, nil), 401, "Unauthorized", tt.headers...))
			if err == nil {
				t.Fatal("applyRegisterChallenge() error = nil, want AKAv2-SHA-256 rejection")
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("applyRegisterChallenge() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRegisterRetriesInitialChallengeWithInvalidSecurityServer(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	var firstCallID string
	var retriedCallID string

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			firstCallID = req.Header("Call-ID")
			transport.queue(newResponse(req, 401, "Unauthorized",
				sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`},
			))
		case 2:
			retriedCallID = req.Header("Call-ID")
			if retriedCallID == "" || retriedCallID == firstCallID {
				t.Fatalf("retried Call-ID = %q, want new value different from %q", retriedCallID, firstCallID)
			}
			if got := req.Header("CSeq"); got != "1 REGISTER" {
				t.Fatalf("retried CSeq = %q, want 1 REGISTER", got)
			}
			transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 5060))
		case 3:
			if got := req.Header("Call-ID"); got != retriedCallID {
				t.Fatalf("authenticated Call-ID = %q, want retried %q", got, retriedCallID)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if got := countWrites(transport); got != 3 {
		t.Fatalf("write count = %d, want initial retry plus authenticated REGISTER", got)
	}
}

func TestRegisterSynchronizationFailureSendsAUTSAndContinues(t *testing.T) {
	auts := []byte{0x33, 0xd5, 0x8d, 0x39, 0x61, 0x9c, 0x21, 0x33, 0x67, 0xe3, 0x76, 0x11, 0x53, 0x15}
	nextNonce := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0x03}, 16), bytes.Repeat([]byte{0x04}, 16)...))
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, &sequenceAKACard{
		results: []usim.AKAResult{
			{AUTS: auts},
			{
				RES: []byte("password"),
				CK:  []byte("client-test-ck"),
				IK:  []byte("client-test-ik"),
			},
		},
	})
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 4060))
		case 2:
			auth := req.Header("Authorization")
			if !strings.Contains(auth, `response=""`) {
				t.Fatalf("synchronization failure Authorization = %q, want empty response", auth)
			}
			if !strings.Contains(auth, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) {
				t.Fatalf("synchronization failure Authorization = %q, want auts", auth)
			}
			transport.queue(newUnauthorizedRegisterResponse(req, nextNonce, 4060))
		case 3:
			auth := req.Header("Authorization")
			if strings.Contains(auth, "auts=") {
				t.Fatalf("resynchronized Authorization = %q, want no auts", auth)
			}
			if strings.Contains(auth, `response=""`) {
				t.Fatalf("resynchronized Authorization = %q, want AKA response", auth)
			}
			transport.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if got := countWrites(transport); got != 3 {
		t.Fatalf("write count = %d, want synchronization failure and retry flow", got)
	}
}

func TestBuildRegisterViaIncludesRFC6223Keep(t *testing.T) {
	tests := []struct {
		name      string
		transport *stubTransport
		wantKeep  bool
	}{
		{name: "udp adds keep", transport: newUDPTransport(5062, 5060), wantKeep: true},
		{name: "tcp adds keep", transport: newTCPTransport(5062, 5060), wantKeep: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, tt.transport, stubCard{})
			msg := svc.buildRegister(nil, nil)
			via := msg.Header("Via")
			if strings.Contains(via, ";keep") != tt.wantKeep {
				t.Fatalf("Via = %q, want keep=%t", via, tt.wantKeep)
			}
		})
	}
}
