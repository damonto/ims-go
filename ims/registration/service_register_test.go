package registration

import (
	"context"
	"errors"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"strings"
	"testing"
	"time"
)

func TestRegisterAppliesChallengeAndSuccessState(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newUnauthorizedRegisterResponse(req, "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=", 0))
		case 2:
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Authentication-Info", Value: `nextnonce="` + testNonce + `"`},
				sip.Header{Name: "P-Associated-URI", Value: "<tel:+15551234567>"},
				sip.Header{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"},
				sip.Header{Name: "Expires", Value: "600"},
			))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	state := svc.State()
	if !state.Registered {
		t.Fatal("Registered = false, want true")
	}
	if state.TelPublicID != "tel:+15551234567" {
		t.Fatalf("TelPublicID = %q, want tel:+15551234567", state.TelPublicID)
	}
	if len(state.ServiceRoutes) != 1 || state.ServiceRoutes[0] != "<sip:pcscf.example.com;lr>" {
		t.Fatalf("ServiceRoutes = %v", state.ServiceRoutes)
	}
	if len(state.Flow.ServiceRoutes) != 1 || state.Flow.ServiceRoutes[0] != "<sip:pcscf.example.com;lr>" {
		t.Fatalf("Flow.ServiceRoutes = %v", state.Flow.ServiceRoutes)
	}
	if state.RegisterExpires != 10*time.Minute {
		t.Fatalf("RegisterExpires = %v, want %v", state.RegisterExpires, 10*time.Minute)
	}
}

func TestRegisterRequiresInitialRegistrationOnInitialRetryStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
	}{
		{name: "forbidden", status: 403, reason: "Forbidden"},
		{name: "timeout", status: 408, reason: "Request Timeout"},
		{name: "server error", status: 500, reason: "Server Internal Error"},
		{name: "gateway timeout", status: 504, reason: "Server Time-out"},
		{name: "busy everywhere", status: 600, reason: "Busy Everywhere"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				transport.queue(newResponse(req, tt.status, tt.reason))
			}

			err := svc.Register(context.Background())
			if err == nil {
				t.Fatal("Register() error = nil, want initial registration required")
			}
			if !errors.Is(err, errInitialRegistrationNeeded) {
				t.Fatalf("Register() error = %v, want %v", err, errInitialRegistrationNeeded)
			}
			if got := countWrites(transport); got != 1 {
				t.Fatalf("write count = %d, want first REGISTER only", got)
			}
		})
	}
}

func TestRegisterRequiresInitialRegistrationOnProtectedRetryStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
	}{
		{name: "forbidden", status: 403, reason: "Forbidden"},
		{name: "timeout", status: 408, reason: "Request Timeout"},
		{name: "server error", status: 500, reason: "Server Internal Error"},
		{name: "gateway timeout", status: 504, reason: "Server Time-out"},
		{name: "busy everywhere", status: 600, reason: "Busy Everywhere"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				switch countWrites(transport) {
				case 1:
					transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
				case 2:
					transport.queue(newResponse(req, tt.status, tt.reason))
				default:
					t.Fatalf("unexpected write count %d", countWrites(transport))
				}
			}

			err := svc.Register(context.Background())
			if err == nil {
				t.Fatal("Register() error = nil, want initial registration required")
			}
			if !errors.Is(err, errInitialRegistrationNeeded) {
				t.Fatalf("Register() error = %v, want %v", err, errInitialRegistrationNeeded)
			}
			if got := countWrites(transport); got != 2 {
				t.Fatalf("write count = %d, want challenge and protected REGISTER", got)
			}
		})
	}
}

func TestRegisterInitialRegistrationErrorCarriesRetryAfter(t *testing.T) {
	tests := []struct {
		name       string
		status     int
		reason     string
		retryAfter string
		want       time.Duration
	}{
		{name: "server error seconds", status: 500, reason: "Server Internal Error", retryAfter: "120", want: 120 * time.Second},
		{name: "service unavailable with duration parameter", status: 503, reason: "Service Unavailable", retryAfter: "180;duration=3600", want: 180 * time.Second},
		{name: "busy with comment", status: 600, reason: "Busy Everywhere", retryAfter: "240 (retry later)", want: 240 * time.Second},
		{name: "malformed retry after is ignored", status: 500, reason: "Server Internal Error", retryAfter: "soon"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				transport.queue(newResponse(req, tt.status, tt.reason, sip.Header{Name: "Retry-After", Value: tt.retryAfter}))
			}

			err := svc.Register(context.Background())
			if err == nil {
				t.Fatal("Register() error = nil, want initial registration required")
			}
			if !errors.Is(err, errInitialRegistrationNeeded) {
				t.Fatalf("Register() error = %v, want %v", err, errInitialRegistrationNeeded)
			}
			got, ok := InitialRegistrationRetryAfter(err)
			if tt.want == 0 {
				if ok {
					t.Fatalf("InitialRegistrationRetryAfter() = %v, true; want false", got)
				}
				return
			}
			if !ok || got != tt.want {
				t.Fatalf("InitialRegistrationRetryAfter() = %v, %v; want %v, true", got, ok, tt.want)
			}
		})
	}
}

func TestRegisterRejectsInvalidAuthenticationInfoRspauth(t *testing.T) {
	tests := []struct {
		name string
		info string
	}{
		{
			name: "rspauth mismatch",
			info: `rspauth="00000000000000000000000000000000"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				switch countWrites(transport) {
				case 1:
					transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
				case 2:
					transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Authentication-Info", Value: tt.info}))
				default:
					t.Fatalf("unexpected write count %d", countWrites(transport))
				}
			}

			err := svc.Register(context.Background())
			if err == nil {
				t.Fatal("Register() error = nil, want rspauth error")
			}
			if !strings.Contains(err.Error(), "authentication-info") {
				t.Fatalf("Register() error = %v, want authentication-info error", err)
			}
			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
		})
	}
}

func TestRegisterInitialRegistrationRequiredStatusClasses(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
	}{
		{name: "client error", status: 403, reason: "Forbidden"},
		{name: "server error", status: 500, reason: "Server Internal Error"},
		{name: "global failure", status: 600, reason: "Busy Everywhere"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				transport.queue(newResponse(req, tt.status, tt.reason))
			}

			err := svc.Register(context.Background())
			if err == nil {
				t.Fatal("Register() error = nil, want initial registration required")
			}
			if !InitialRegistrationRequired(err) {
				t.Fatalf("InitialRegistrationRequired() = false for %v", err)
			}
			if _, ok := InitialRegistrationRetryAfter(err); ok {
				t.Fatal("InitialRegistrationRetryAfter() ok = true, want false")
			}
		})
	}
}

func TestInitialRegistrationRequiredRejectsUnrelatedErrors(t *testing.T) {
	if InitialRegistrationRequired(errors.New("transport closed")) {
		t.Fatal("InitialRegistrationRequired() = true, want false")
	}
	if _, ok := InitialRegistrationRetryAfter(errors.New("transport closed")); ok {
		t.Fatal("InitialRegistrationRetryAfter() ok = true, want false")
	}
	if _, ok := RetryAfterDelay(errors.New("transport closed")); ok {
		t.Fatal("RetryAfterDelay() ok = true, want false")
	}
}

func TestRegisterStoresAssociatedURIsAndExpires(t *testing.T) {
	tests := []struct {
		name       string
		headersFor func(sip.Message) []sip.Header
		checkState func(*testing.T, State)
	}{
		{
			name: "keeps first associated uri as default public identity",
			headersFor: func(sip.Message) []sip.Header {
				return []sip.Header{
					{Name: "P-Associated-URI", Value: "<sip:alice@example.com>,<tel:+15551234567>"},
				}
			},
			checkState: func(t *testing.T, state State) {
				t.Helper()
				if state.DefaultPublicID != "sip:alice@example.com" {
					t.Fatalf("DefaultPublicID = %q, want sip:alice@example.com", state.DefaultPublicID)
				}
				if state.SIPPublicID != "sip:alice@example.com" {
					t.Fatalf("SIPPublicID = %q, want sip:alice@example.com", state.SIPPublicID)
				}
				if state.TelPublicID != "tel:+15551234567" {
					t.Fatalf("TelPublicID = %q, want tel:+15551234567", state.TelPublicID)
				}
			},
		},
		{
			name: "keeps sip alias when tel uri is first",
			headersFor: func(sip.Message) []sip.Header {
				return []sip.Header{
					{Name: "P-Associated-URI", Value: "<tel:+15551234567>,<sip:+15551234567@example.com;user=phone>"},
				}
			},
			checkState: func(t *testing.T, state State) {
				t.Helper()
				if state.DefaultPublicID != "tel:+15551234567" {
					t.Fatalf("DefaultPublicID = %q, want tel:+15551234567", state.DefaultPublicID)
				}
				if state.SIPPublicID != "sip:+15551234567@example.com;user=phone" {
					t.Fatalf("SIPPublicID = %q, want sip:+15551234567@example.com;user=phone", state.SIPPublicID)
				}
				if state.TelPublicID != "tel:+15551234567" {
					t.Fatalf("TelPublicID = %q, want tel:+15551234567", state.TelPublicID)
				}
			},
		},
		{
			name: "prefers matching contact expires over top level expires",
			headersFor: func(req sip.Message) []sip.Header {
				return []sip.Header{
					{Name: "Contact", Value: req.Header("Contact") + `;expires=120`},
					{Name: "Expires", Value: "600"},
				}
			},
			checkState: func(t *testing.T, state State) {
				t.Helper()
				if state.RegisterExpires != 2*time.Minute {
					t.Fatalf("RegisterExpires = %v, want %v", state.RegisterExpires, 2*time.Minute)
				}
			},
		},
		{
			name: "matches registered contact with network user part",
			headersFor: func(req sip.Message) []sip.Header {
				uri, params := sip.AddressURIAndParams(req.Header("Contact"))
				hostPort := strings.TrimPrefix(uri, "sip:")
				return []sip.Header{
					{Name: "Contact", Value: `<sip:001010123456789@` + hostPort + `>` + params + `;expires=1800`},
				}
			},
			checkState: func(t *testing.T, state State) {
				t.Helper()
				if state.RegisterExpires != 30*time.Minute {
					t.Fatalf("RegisterExpires = %v, want %v", state.RegisterExpires, 30*time.Minute)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				switch countWrites(transport) {
				case 1:
					transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
				case 2:
					transport.queue(newResponse(req, 200, "OK", tt.headersFor(req)...))
				default:
					t.Fatalf("unexpected write count %d", countWrites(transport))
				}
			}

			if err := svc.Register(context.Background()); err != nil {
				t.Fatalf("Register() error = %v", err)
			}

			tt.checkState(t, svc.State())
		})
	}
}

func TestRegisterRetries423MinExpires(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{RegisterExpires: time.Minute}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newResponse(req, 423, "Interval Too Brief", sip.Header{Name: "Min-Expires", Value: "300"}))
		case 2:
			if got := req.Header("Expires"); got != "300" {
				t.Fatalf("retry Expires = %q, want 300", got)
			}
			transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
		case 3:
			transport.queue(newResponse(req, 200, "OK"))
		}
	}

	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
}

func TestRegisterHandlesRechallenge401(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	firstNonce := "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="
	secondNonce := "AgICAgICAgICAgICAgICAQMDAwMDAwMDAwMDAwMDAwM="
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newUnauthorizedRegisterResponse(req, firstNonce, 0))
		case 2:
			if got := req.Header("Authorization"); !strings.Contains(got, `nonce="`+firstNonce+`"`) {
				t.Fatalf("Authorization = %q, want first nonce", got)
			}
			transport.queue(newUnauthorizedRegisterResponse(req, secondNonce, 0))
		case 3:
			if got := req.Header("Authorization"); !strings.Contains(got, `nonce="`+secondNonce+`"`) {
				t.Fatalf("Authorization = %q, want second nonce", got)
			}
			transport.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if !svc.State().Registered {
		t.Fatal("Registered = false, want true")
	}
}

func TestRegisterKeepsUDPResponseTransportForTCPFlow(t *testing.T) {
	initial := newTCPTransport(5062, 5060)
	outboundTCP := newTCPTransport(10553, 6000)
	inboundTCP := newTCPTransport(28789, 32813)
	inboundUDP := newUDPTransport(28789, 32813)
	responseUDP := newUDPTransport(10553, 6000)

	var responseCfg session.SecureUDPConfig
	dialUDPCount := 0
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return outboundTCP, nil
		},
		DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			dialUDPCount++
			responseCfg = cfg
			return responseUDP, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return inboundTCP, nil
		},
		ListenSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			return inboundUDP, nil
		},
	}, initial, stubCard{})

	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, testNonce, 32813))
	}
	outboundTCP.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		outboundTCP.queue(newResponse(req, 200, "OK", sip.Header{Name: "Authentication-Info", Value: `nextnonce="` + testNonce + `"`}))
	}

	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if dialUDPCount != 1 {
		t.Fatalf("DialSecureUDP calls = %d, want 1", dialUDPCount)
	}
	flow := svc.CurrentFlow()
	if responseCfg.LocalPort != flow.SecurityClient.PortC {
		t.Fatalf("response local port = %d, want UE protected client port %d", responseCfg.LocalPort, flow.SecurityClient.PortC)
	}
	if responseCfg.RemotePort != flow.SecurityVerify.PortS {
		t.Fatalf("response remote port = %d, want P-CSCF protected server port %d", responseCfg.RemotePort, flow.SecurityVerify.PortS)
	}
	if responseCfg.OutboundSPI != flow.SecurityVerify.SPIS || responseCfg.InboundSPI != flow.SecurityClient.SPIC {
		t.Fatalf("response SPIs = outbound %d inbound %d, want %d/%d", responseCfg.OutboundSPI, responseCfg.InboundSPI, flow.SecurityVerify.SPIS, flow.SecurityClient.SPIC)
	}
	svc.mu.Lock()
	responseAttachments := len(svc.secureResponseAttachments)
	svc.mu.Unlock()
	if responseAttachments != 2 {
		t.Fatalf("secure response attachments = %d, want 2", responseAttachments)
	}
	msg := sip.NewRequest("MESSAGE", "sip:user@example.net")
	msg.Headers.Add("Via", "SIP/2.0/UDP 127.0.0.1:6000;branch=z9hG4bK-submit-report")
	msg.Headers.Add("Call-ID", "submit-report-call")
	msg.Headers.Add("From", "<sip:one.att.net>;tag=network")
	msg.Headers.Add("To", "<sip:user@example.net>")
	msg.Headers.Add("CSeq", "1 MESSAGE")
	req := session.Request{Message: msg, Transport: inboundUDP, PeerAddr: inboundUDP.RemoteAddr()}
	if err := svc.sess.WriteStatus(context.Background(), req, 200, "OK"); err != nil {
		t.Fatalf("WriteStatus() error = %v", err)
	}
	if got := countWrites(inboundUDP); got != 0 {
		t.Fatalf("inbound UDP writes = %d, want 0", got)
	}
	if got := countWrites(responseUDP); got != 1 {
		t.Fatalf("response UDP writes = %d, want 1", got)
	}
}
