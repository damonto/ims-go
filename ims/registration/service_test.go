package registration

import (
	"bytes"
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"github.com/damonto/ims-client/usim"
)

const testNonce = "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="

type stubTransport struct {
	local  net.Addr
	remote net.Addr

	mu         sync.Mutex
	writes     [][]byte
	readCh     chan []byte
	onWrite    func([]byte)
	closeCount int
}

type stubCard struct{}

type identityStubCard struct {
	stubCard
	homeDomain      string
	privateIdentity string
	publicIdentity  string
}

func (t *stubTransport) LocalAddr() net.Addr  { return t.local }
func (t *stubTransport) RemoteAddr() net.Addr { return t.remote }

func (t *stubTransport) WritePacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	t.writes = append(t.writes, append([]byte(nil), data...))
	onWrite := t.onWrite
	t.mu.Unlock()
	if onWrite != nil {
		onWrite(data)
	}
	return nil
}

func (t *stubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}

func (t *stubTransport) Close() error {
	t.mu.Lock()
	t.closeCount++
	t.mu.Unlock()
	return nil
}

func (t *stubTransport) queue(msg sip.Message) {
	t.readCh <- msg.Bytes()
}

func (stubCard) IMSI() string { return "001010123456789" }
func (stubCard) MCC() string  { return "001" }
func (stubCard) MNC() string  { return "001" }
func (stubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		IK:  []byte("client-test-ik"),
	}, nil
}

func (c identityStubCard) HomeDomain() string      { return c.homeDomain }
func (c identityStubCard) PrivateIdentity() string { return c.privateIdentity }
func (c identityStubCard) PublicIdentity() string  { return c.publicIdentity }

func TestNewIdentityResolution(t *testing.T) {
	tests := []struct {
		name                string
		cfg                 Config
		card                Card
		wantPrivateIdentity string
		wantPublicIdentity  string
		wantRegisterURI     string
	}{
		{
			name:                "falls back to IMSI",
			cfg:                 Config{},
			card:                stubCard{},
			wantPrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
			wantPublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
			wantRegisterURI:     "sip:ims.mnc001.mcc001.3gppnetwork.org",
		},
		{
			name: "uses identity provider",
			card: identityStubCard{
				homeDomain:      "ims.example.com",
				privateIdentity: "alice@ims.example.com",
				publicIdentity:  "sip:alice@example.com",
			},
			wantPrivateIdentity: "alice@ims.example.com",
			wantPublicIdentity:  "sip:alice@example.com",
			wantRegisterURI:     "sip:ims.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, tt.cfg, newUDPTransport(5062, 5060), tt.card)
			state := svc.State()
			if state.PrivateIdentity != tt.wantPrivateIdentity {
				t.Fatalf("PrivateIdentity = %q, want %q", state.PrivateIdentity, tt.wantPrivateIdentity)
			}
			if state.PublicIdentity != tt.wantPublicIdentity {
				t.Fatalf("PublicIdentity = %q, want %q", state.PublicIdentity, tt.wantPublicIdentity)
			}
			if state.RegisterURI != tt.wantRegisterURI {
				t.Fatalf("RegisterURI = %q, want %q", state.RegisterURI, tt.wantRegisterURI)
			}
		})
	}
}

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
	if state.RegisterExpires != 10*time.Minute {
		t.Fatalf("RegisterExpires = %v, want %v", state.RegisterExpires, 10*time.Minute)
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

func TestRefreshUsesAuthenticationInfoNextNonce(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	registerService(t, svc, transport)

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if !bytes.Contains([]byte(req.Header("Authorization")), []byte(`nonce="`+testNonce+`"`)) {
			t.Fatalf("Authorization = %q, want next nonce", req.Header("Authorization"))
		}
		transport.queue(newResponse(req, 200, "OK"))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
}

func TestEstablishUpgradesSecureTransportAndSubscribes(t *testing.T) {
	initial := newTCPTransport(5062, 5060)
	secure := newTCPTransport(45000, 5060)
	serverTCP := newTCPTransport(5063, 45000)
	serverUDP := newUDPTransport(5063, 45000)

	var dialCfg session.SecureTCPConfig
	var listenTCPCfg session.SecureTCPConfig
	var listenUDPCfg session.SecureUDPConfig

	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			dialCfg = cfg
			return secure, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			listenTCPCfg = cfg
			return serverTCP, nil
		},
		ListenSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			listenUDPCfg = cfg
			return serverUDP, nil
		},
	}, initial, stubCard{})

	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=", 4060))
	}
	secure.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			secure.queue(newResponse(req, 200, "OK"))
		case "SUBSCRIBE":
			secure.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected method %q", req.Method())
		}
	}

	if err := svc.Establish(context.Background()); err != nil {
		t.Fatalf("Establish() error = %v", err)
	}
	if dialCfg.LocalPort == 0 || listenTCPCfg.LocalPort == 0 || listenUDPCfg.LocalPort == 0 {
		t.Fatalf("secure transport configs not captured: %+v %+v %+v", dialCfg, listenTCPCfg, listenUDPCfg)
	}
	if initial.closeCount != 1 {
		t.Fatalf("initial closeCount = %d, want 1", initial.closeCount)
	}
}

func TestDeregisterHandlesChallenge(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	registerService(t, svc, transport)

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 3:
			if got := req.Header("Expires"); got != "0" {
				t.Fatalf("Expires = %q, want 0", got)
			}
			if got := req.Header("Contact"); got != "*" {
				t.Fatalf("Contact = %q, want *", got)
			}
			transport.queue(newResponse(req, 401, "Unauthorized", sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`}))
		case 4:
			transport.queue(newResponse(req, 200, "OK"))
		}
	}

	if err := svc.Deregister(context.Background()); err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestDeregisterAfterRunExitFallsBackToSynchronousExchange(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	registerService(t, svc, transport)

	runCtx, runCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}
	runCancel()
	if err := <-errCh; err != context.Canceled {
		t.Fatalf("Run() error = %v, want %v", err, context.Canceled)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 3:
			transport.queue(newResponse(req, 401, "Unauthorized", sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`}))
		case 4:
			transport.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Deregister(context.Background()); err != nil {
		t.Fatalf("Deregister() error = %v", err)
	}
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestMaintainRefreshesOnInterval(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{RegisterExpires: 2 * time.Second}, transport, stubCard{})
	registerService(t, svc, transport)

	refreshed := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "REGISTER" && countWrites(transport) >= 3 {
			refreshed <- struct{}{}
		}
		transport.queue(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Maintain(ctx)
	}()

	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("waiting for refresh")
	}
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Fatalf("Maintain() error = %v", err)
	}
}

func newTestService(t *testing.T, cfg Config, transport *stubTransport, card Card) *Service {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	svc, err := New(cfg, sess, card)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return svc
}

func registerService(t *testing.T, svc *Service, transport *stubTransport) {
	t.Helper()
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
		case 2:
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Authentication-Info", Value: `nextnonce="` + testNonce + `"`}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}
	if err := svc.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
}

func newUDPTransport(localPort, remotePort int) *stubTransport {
	return &stubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh: make(chan []byte, 16),
	}
}

func newTCPTransport(localPort, remotePort int) *stubTransport {
	return &stubTransport{
		local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh: make(chan []byte, 16),
	}
}

func mustParseMessage(t *testing.T, data []byte) sip.Message {
	t.Helper()
	msg, err := sip.ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	return msg
}

func newUnauthorizedRegisterResponse(req sip.Message, nonce string, portC int) sip.Message {
	securityServer := `ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222`
	if portC != 0 {
		securityServer = `ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c=` + strconv.Itoa(portC) + `;port-s=4060;prot=esp;spi-c=111;spi-s=222`
	}
	return newResponse(req, 401, "Unauthorized",
		sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + nonce + `",algorithm=AKAv1-MD5,qop="auth"`},
		sip.Header{Name: "Security-Server", Value: securityServer},
	)
}

func newResponse(req sip.Message, code int, reason string, extra ...sip.Header) sip.Message {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req, code)
	resp.Headers = append(resp.Headers, extra...)
	return resp
}

func countWrites(t *stubTransport) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}
