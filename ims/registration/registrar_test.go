package registration

import (
	"bytes"
	"context"

	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/pidf"
	usim "github.com/damonto/wwan-go/sim"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/session"

	"github.com/damonto/ims-go/ims/sip"
	"io"
	"log/slog"
	"net"

	"slices"
	"strconv"
	"strings"

	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testNonce = "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type stubTransport struct {
	local  net.Addr
	remote net.Addr

	mu         sync.Mutex
	writes     [][]byte
	readCh     chan []byte
	onWrite    func([]byte)
	writeErr   error
	closeCount int
}

type stubCard struct{}

type failAfterFirstAKACard struct {
	stubCard
	mu    sync.Mutex
	calls int
}

type sequenceAKACard struct {
	stubCard
	mu      sync.Mutex
	results []usim.AKAResult
}

type identityStubCard struct {
	stubCard
	homeDomain      string
	privateIdentity string
	publicIdentity  string
}

type twoDigitMNCStubCard struct{}

func (t *stubTransport) LocalAddr() net.Addr { return t.local }

func (t *stubTransport) RemoteAddr() net.Addr { return t.remote }

func (t *stubTransport) WritePacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	if t.writeErr != nil {
		err := t.writeErr
		t.mu.Unlock()
		return err
	}
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
	t.readCh <- marshalSIPMessageForTest(msg)
}

func marshalSIPMessageForTest(msg sip.Message) []byte {
	data, err := msg.MarshalText()
	if err != nil {
		panic(err)
	}
	return data
}

func (stubCard) IMSI() string { return "001010123456789" }

func (stubCard) MCC() string { return "001" }

func (stubCard) MNC() string { return "001" }

func (stubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}, nil
}

func (c *failAfterFirstAKACard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	c.mu.Lock()
	c.calls++
	calls := c.calls
	c.mu.Unlock()
	if calls > 1 {
		return usim.AKAResult{}, errors.New("authentication rejected")
	}
	return c.stubCard.AKA(ctx, rand, autn)
}

func (c *sequenceAKACard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.results) == 0 {
		return c.stubCard.AKA(ctx, rand, autn)
	}
	result := c.results[0]
	c.results = c.results[1:]
	return result, nil
}

func (twoDigitMNCStubCard) IMSI() string { return "204020123456789" }

func (twoDigitMNCStubCard) MCC() string { return "204" }

func (twoDigitMNCStubCard) MNC() string { return "02" }

func (twoDigitMNCStubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return stubCard{}.AKA(ctx, rand, autn)
}

func (c identityStubCard) HomeDomain() string { return c.homeDomain }

func (c identityStubCard) PrivateIdentity() string { return c.privateIdentity }

func (c identityStubCard) PublicIdentity() string { return c.publicIdentity }

func newTestService(t *testing.T, cfg Config, transport *stubTransport, card Card) *Registrar {
	t.Helper()
	cfg.Logger = testLogger()
	if cfg.DialSecureTCP == nil {
		cfg.DialSecureTCP = func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return transport, nil
		}
	}
	if cfg.DialSecureUDP == nil {
		cfg.DialSecureUDP = func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			return transport, nil
		}
	}
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

func registerService(t *testing.T, svc *Registrar, transport *stubTransport) {
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
	securityServer := `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`
	if portC != 0 {
		securityServer = `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=` + strconv.Itoa(portC) + `;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`
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

func waitForWriteCount(t *testing.T, transport *stubTransport, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if got := countWrites(transport); got >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("write count = %d, want at least %d", countWrites(transport), want)
		case <-tick.C:
		}
	}
}

func closeCount(t *stubTransport) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeCount
}

func waitForCloseCount(t *testing.T, transport *stubTransport, want int) {
	t.Helper()
	deadline := time.After(time.Second)
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if got := closeCount(transport); got == want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("closeCount = %d, want %d", closeCount(transport), want)
		case <-tick.C:
		}
	}
}

func lastWrite(t *testing.T, transport *stubTransport) sip.Message {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if len(transport.writes) == 0 {
		t.Fatal("transport has no writes")
	}
	msg, err := sip.ParseMessage(transport.writes[len(transport.writes)-1])
	if err != nil {
		t.Fatalf("ParseMessage(last write) error = %v", err)
	}
	return msg
}

func expectRegistrationEvent(t *testing.T, svc *Registrar, want error) {
	t.Helper()
	select {
	case err := <-svc.registrationEvents:
		if !errors.Is(err, want) {
			t.Fatalf("registration event = %v, want %v", err, want)
		}
	default:
		t.Fatalf("registration event missing, want %v", want)
	}
}

func expectNoRegistrationEvent(t *testing.T, svc *Registrar) {
	t.Helper()
	select {
	case err := <-svc.registrationEvents:
		t.Fatalf("registration event = %v, want none", err)
	default:
	}
}
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
			name:                "pads two digit mnc in fallback realm",
			cfg:                 Config{},
			card:                twoDigitMNCStubCard{},
			wantPrivateIdentity: "204020123456789@ims.mnc002.mcc204.3gppnetwork.org",
			wantPublicIdentity:  "sip:204020123456789@ims.mnc002.mcc204.3gppnetwork.org",
			wantRegisterURI:     "sip:ims.mnc002.mcc204.3gppnetwork.org",
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
		{
			name: "explicit private identity overrides card value",
			cfg: Config{
				PrivateIdentity: "bob@ims.example.com",
				PublicIdentity:  "sip:bob@example.com",
				HomeDomain:      "ims.example.com",
			},
			card: identityStubCard{
				homeDomain:      "ignored.example.com",
				privateIdentity: "alice@ignored.example.com",
				publicIdentity:  "sip:alice@ignored.example.com",
			},
			wantPrivateIdentity: "bob@ims.example.com",
			wantPublicIdentity:  "sip:bob@example.com",
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

func TestContactURIFormatting(t *testing.T) {
	tests := []struct {
		name               string
		cfg                Config
		localAddr          net.Addr
		wantRegisterURI    string
		wantRegisterPrefix string
		wantSubscribe      string
	}{
		{
			name:               "ipv4",
			localAddr:          &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
			wantRegisterURI:    "sip:127.0.0.1:5062",
			wantRegisterPrefix: "<sip:127.0.0.1:5062>;",
			wantSubscribe:      "<sip:127.0.0.1:5062>;text",
		},
		{
			name:               "ipv6",
			localAddr:          &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 5062},
			wantRegisterURI:    "sip:[2001:db8::10]:5062",
			wantRegisterPrefix: "<sip:[2001:db8::10]:5062>;",
			wantSubscribe:      "<sip:[2001:db8::10]:5062>;text",
		},
		{
			name:               "subscribe omits sip instance outside REGISTER",
			cfg:                Config{IMEI: "123456789012345"},
			localAddr:          &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
			wantRegisterURI:    "sip:127.0.0.1:5062",
			wantRegisterPrefix: "<sip:127.0.0.1:5062>;",
			wantSubscribe:      "<sip:127.0.0.1:5062>;text",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &stubTransport{
				local:  tt.localAddr,
				remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
				readCh: make(chan []byte, 16),
			}
			svc := newTestService(t, tt.cfg, transport, stubCard{})

			if got := svc.currentRegisterContactURI(); got != tt.wantRegisterURI {
				t.Fatalf("currentRegisterContactURI() = %q, want %q", got, tt.wantRegisterURI)
			}

			if got := svc.buildRegister(nil, nil).Header("Contact"); !strings.HasPrefix(got, tt.wantRegisterPrefix) {
				t.Fatalf("REGISTER Contact = %q, want prefix %q", got, tt.wantRegisterPrefix)
			} else if !strings.Contains(got, "+g.3gpp.smsip") || !strings.Contains(got, "+g.3gpp.smsip-msisdn-less") {
				t.Fatalf("REGISTER Contact = %q, want SMS over IP and MSISDN-less feature tags", got)
			}
			if got := svc.buildRegister(nil, nil).Header("Supported"); !sip.TokenListContains(got, "path") {
				t.Fatalf("REGISTER Supported = %q, want path", got)
			}

			if got := svc.buildSubscribe().Header("Contact"); got != tt.wantSubscribe {
				t.Fatalf("SUBSCRIBE Contact = %q, want %q", got, tt.wantSubscribe)
			} else if strings.Contains(got, "+sip.instance") {
				t.Fatalf("SUBSCRIBE Contact = %q, want no +sip.instance", got)
			}
		})
	}
}

func TestAccessNetworkInfo(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "omits unknown access network",
			cfg:  Config{},
			want: "",
		},
		{
			name: "explicit value wins",
			cfg: Config{
				AccessNetworkInfo: "IEEE-802.11ac;i-wlan-node-id=aabbcc",
			},
			want: "IEEE-802.11ac;i-wlan-node-id=aabbcc",
		},
		{
			name: "wlan node id adds access info",
			cfg: Config{
				WLANNodeID: "AA:BB:CC",
			},
			want: "IEEE-802.11;i-wlan-node-id=aabbcc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := accessNetworkInfo(tt.cfg)
			if got != tt.want {
				t.Fatalf("accessNetworkInfo() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildRegisterAccessNetworkInfoFollowsSecurityState(t *testing.T) {
	tests := []struct {
		name    string
		auth    *security.Authorization
		verify  *security.Param
		prepare func(*Registrar)
		want    string
	}{
		{
			name: "unprotected initial register omits access network info",
		},
		{
			name: "protected register includes access network info",
			auth: &security.Authorization{
				Username:           "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				Realm:              "ims.mnc001.mcc001.3gppnetwork.org",
				URI:                "sip:ims.mnc001.mcc001.3gppnetwork.org",
				Nonce:              testNonce,
				Response:           "response",
				IntegrityProtected: "yes",
			},
			verify: &security.Param{Mechanism: "ipsec-3gpp"},
			want:   "IEEE-802.11;i-wlan-node-id=aabbcc",
		},
		{
			name: "existing security association allows access network info",
			prepare: func(svc *Registrar) {
				svc.mu.Lock()
				verify := security.Param{Mechanism: "ipsec-3gpp"}
				svc.flow.SecurityVerify = &verify
				svc.mu.Unlock()
			},
			want: "IEEE-802.11;i-wlan-node-id=aabbcc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{WLANNodeID: "AA:BB:CC"}, newUDPTransport(5062, 5060), stubCard{})
			if tt.prepare != nil {
				tt.prepare(svc)
			}
			msg := svc.buildRegister(tt.auth, tt.verify)
			if got := msg.Header("P-Access-Network-Info"); got != tt.want {
				t.Fatalf("P-Access-Network-Info = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUserAgent(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "empty by default",
		},
		{
			name: "explicit value",
			cfg:  Config{UserAgent: "custom-agent"},
			want: "custom-agent",
		},
		{
			name: "trims explicit value",
			cfg:  Config{UserAgent: " custom-agent "},
			want: "custom-agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, tt.cfg, transport, stubCard{})

			if got := svc.RequestPolicy().UserAgent; got != tt.want {
				t.Fatalf("RequestPolicy().UserAgent = %q, want %q", got, tt.want)
			}
			if got := svc.buildRegister(nil, nil).Header("User-Agent"); got != tt.want {
				t.Fatalf("REGISTER User-Agent = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDialogRequestPolicyDoesNotFallbackToServiceRoute(t *testing.T) {
	tests := []struct {
		name       string
		dialog     []string
		wantRoutes []string
	}{
		{
			name: "empty dialog route set stays empty",
		},
		{
			name:       "dialog route set is preserved",
			dialog:     []string{"<sip:record-route.example.com;lr>"},
			wantRoutes: []string{"<sip:record-route.example.com;lr>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
			svc.mu.Lock()
			svc.flow.ServiceRoutes = []string{"<sip:service-route.example.com;lr>"}
			svc.mu.Unlock()

			msg := sip.NewRequest("BYE", "sip:remote@example.com")
			svc.DialogRequestPolicy(tt.dialog).Apply(&msg)

			if got := msg.HeadersByName("Route"); !slices.Equal(got, tt.wantRoutes) {
				t.Fatalf("Route = %v, want %v", got, tt.wantRoutes)
			}
		})
	}
}

func TestRequestPolicyBuildsPreloadedRoutes(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Registrar)
		want   []string
	}{
		{
			name: "pcscf route without service route",
			want: []string{"<sip:127.0.0.1:5060;lr>"},
		},
		{
			name: "pcscf before service routes",
			mutate: func(svc *Registrar) {
				svc.flow.ServiceRoutes = []string{"<sip:scscf.example.com;lr>"}
			},
			want: []string{"<sip:127.0.0.1:5060;lr>", "<sip:scscf.example.com;lr>"},
		},
		{
			name: "protected pcscf port",
			mutate: func(svc *Registrar) {
				svc.flow.SecurityVerify = &security.Param{PortS: 4060}
				svc.flow.ServiceRoutes = []string{"<sip:scscf.example.com;lr>"}
			},
			want: []string{"<sip:127.0.0.1:4060;lr>", "<sip:scscf.example.com;lr>"},
		},
		{
			name: "duplicate pcscf service route omitted",
			mutate: func(svc *Registrar) {
				svc.flow.ServiceRoutes = []string{"<sip:127.0.0.1:5060;lr>", "<sip:scscf.example.com;lr>"}
			},
			want: []string{"<sip:127.0.0.1:5060;lr>", "<sip:scscf.example.com;lr>"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
			if tt.mutate != nil {
				svc.mu.Lock()
				tt.mutate(svc)
				svc.mu.Unlock()
			}

			msg := sip.NewRequest("MESSAGE", "sip:remote@example.com")
			svc.RequestPolicy().Apply(&msg)

			if got := msg.HeadersByName("Route"); !slices.Equal(got, tt.want) {
				t.Fatalf("Route = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildRegisterOmitsGeolocationByDefault(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})

	msg := svc.buildRegister(nil, nil)
	if got := msg.Header("Geolocation"); got != "" {
		t.Fatalf("Geolocation = %q, want empty", got)
	}
	if got := msg.Header("Content-Type"); got != "" {
		t.Fatalf("Content-Type = %q, want empty", got)
	}
	if len(msg.Body) != 0 {
		t.Fatalf("Body length = %d, want 0", len(msg.Body))
	}
}

func TestBuildRegisterIncludesGeolocationPIDFWhenConfigured(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "non emergency wifi register",
			cfg: Config{
				GeolocationPIDFRegister: []int{pidf.GeolocationPIDFNonEmergencyWiFi},
				GeolocationCountry:      "US",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, tt.cfg, newUDPTransport(5062, 5060), stubCard{})

			msg := svc.buildRegister(nil, nil)
			if got := msg.Header("Geolocation"); !strings.HasPrefix(got, "<cid:pidf-") {
				t.Fatalf("Geolocation = %q, want cid PIDF reference", got)
			}
			if got := msg.Header("Geolocation-Routing"); got != "yes" {
				t.Fatalf("Geolocation-Routing = %q, want yes", got)
			}
			if got := msg.Header("Content-Type"); got != "application/pidf+xml" {
				t.Fatalf("Content-Type = %q, want application/pidf+xml", got)
			}
			if got := msg.Header("Content-Disposition"); got != "render;handling=optional" {
				t.Fatalf("Content-Disposition = %q, want render;handling=optional", got)
			}
			if !strings.Contains(string(msg.Body), "<country>US</country>") {
				t.Fatalf("REGISTER body missing PIDF country:\n%s", string(msg.Body))
			}
		})
	}
}

func TestApplyServiceRoutes(t *testing.T) {
	tests := []struct {
		name    string
		headers []sip.Header
		want    []string
	}{
		{
			name: "replaces stored routes with empty list",
		},
		{
			name: "splits comma separated service route values",
			headers: []sip.Header{
				{Name: "Service-Route", Value: `<sip:pcscf-1.example.com;lr>, <sip:pcscf-2.example.com;lr>`},
			},
			want: []string{"<sip:pcscf-1.example.com;lr>", "<sip:pcscf-2.example.com;lr>"},
		},
		{
			name: "preserves header order after splitting",
			headers: []sip.Header{
				{Name: "Service-Route", Value: `<sip:pcscf-1.example.com;lr>, <sip:pcscf-2.example.com;lr>`},
				{Name: "Service-Route", Value: `<sip:pcscf-3.example.com;lr>`},
			},
			want: []string{
				"<sip:pcscf-1.example.com;lr>",
				"<sip:pcscf-2.example.com;lr>",
				"<sip:pcscf-3.example.com;lr>",
			},
		},
		{
			name: "ignores non sip service routes",
			headers: []sip.Header{
				{Name: "Service-Route", Value: `<sip:pcscf-1.example.com;lr>, <http://bad.example.com>, not-a-route, <sips:pcscf-2.example.com;lr>`},
			},
			want: []string{"<sip:pcscf-1.example.com;lr>", "<sips:pcscf-2.example.com;lr>"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
			svc.mu.Lock()
			svc.flow.ServiceRoutes = []string{"<sip:old.example.com;lr>"}
			svc.mu.Unlock()
			msg := sip.Message{Headers: tt.headers}

			svc.applyServiceRoutes(msg)

			if got := svc.State().ServiceRoutes; !slices.Equal(got, tt.want) {
				t.Fatalf("ServiceRoutes = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestSecureResponseTransportSkipsDuplicateSessionEndpoint(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "duplicates session udp endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newUDPTransport(10553, 6000)
			outboundTCP := newTCPTransport(10553, 6000)
			responseUDP := newUDPTransport(10553, 6000)
			dialUDPCount := 0
			svc := newTestService(t, Config{
				DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
					dialUDPCount++
					return responseUDP, nil
				},
			}, primary, stubCard{})
			verify := security.Param{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", PortS: 6000, SPIS: 20}
			flow := Flow{
				SecurityClient: security.Param{PortC: 10553, SPIC: 10},
				SecurityVerify: &verify,
			}

			attachments, err := svc.startSecureResponseTransportsWithKeys(context.Background(), &verify, flow, outboundTCP, []session.Transport{newUDPTransport(28789, 32813)}, []byte("ck"), []byte("ik"))
			if err != nil {
				t.Fatalf("startSecureResponseTransportsWithKeys() error = %v", err)
			}
			if len(attachments) != 0 {
				t.Fatalf("attachments = %d, want 0", len(attachments))
			}
			if dialUDPCount != 0 {
				t.Fatalf("DialSecureUDP calls = %d, want 0", dialUDPCount)
			}
			responseUDP.mu.Lock()
			closeCount := responseUDP.closeCount
			responseUDP.mu.Unlock()
			if closeCount != 0 {
				t.Fatalf("response transport closes = %d, want 0", closeCount)
			}
		})
	}
}

func TestSecureTransportConfigExpandsHMACSHA1IntegrityKey(t *testing.T) {
	ik := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
	ck := []byte{0x20, 0x21, 0x22, 0x23}
	tests := []struct {
		name string
		alg  string
		want []byte
	}{
		{
			name: "spec spelling",
			alg:  "hmac-sha-1-96",
			want: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0, 0, 0, 0},
		},
		{
			name: "codec spelling",
			alg:  "hmac-sha1-96",
			want: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0, 0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := secureTransportConfigWithKeys(&security.Param{Alg: tt.alg, EAlg: "null"}, 40000, 5060, 1111, 2222, ck, ik)
			if !bytes.Equal(cfg.IntegrityKey, tt.want) {
				t.Fatalf("IntegrityKey = %X, want %X", cfg.IntegrityKey, tt.want)
			}
			if !bytes.Equal(cfg.EncryptionKey, ck) {
				t.Fatalf("EncryptionKey = %X, want %X", cfg.EncryptionKey, ck)
			}
			cfg.IntegrityKey[0] = 0
			if ik[0] == 0 {
				t.Fatal("input IK was mutated")
			}
		})
	}
}

func TestRegisterRebuildsSecureTransportAfterProtectedRechallenge(t *testing.T) {
	initial := newUDPTransport(5062, 5060)
	firstOutbound := newUDPTransport(45000, 4060)
	firstInbound := newUDPTransport(5063, 45000)
	nextOutbound := newUDPTransport(45001, 4600)
	nextInbound := newUDPTransport(5063, 45001)

	dialed := 0
	listened := 0
	var secondDialCfg session.SecureUDPConfig
	var secondListenCfg session.SecureUDPConfig
	svc := newTestService(t, Config{
		DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			dialed++
			if dialed == 2 {
				secondDialCfg = cfg
				return nextOutbound, nil
			}
			return firstOutbound, nil
		},
		ListenSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			listened++
			if listened == 2 {
				secondListenCfg = cfg
				return nextInbound, nil
			}
			return firstInbound, nil
		},
	}, initial, stubCard{})

	firstNonce := "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="
	secondNonce := "AgICAgICAgICAgICAgICAQMDAwMDAwMDAwMDAwMDAwM="
	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, firstNonce, 4060))
	}
	firstOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "REGISTER" {
			t.Fatalf("first secure method = %q, want REGISTER", req.Method())
		}
		firstInbound.queue(newUnauthorizedRegisterResponse(req, secondNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if got := req.Header("Authorization"); !strings.Contains(got, `nonce="`+secondNonce+`"`) {
			t.Fatalf("Authorization = %q, want second nonce", got)
		}
		if got := req.Header("Security-Verify"); !strings.Contains(got, "port-c=4600") {
			t.Fatalf("Security-Verify = %q, want refreshed Security-Server", got)
		}
		nextInbound.queue(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := svc.Register(ctx); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if dialed != 2 || listened != 2 {
		t.Fatalf("secure transports dialed/listened = %d/%d, want 2/2", dialed, listened)
	}
	if secondDialCfg.RemotePort != 4060 {
		t.Fatalf("second dial remote port = %d, want P-CSCF protected server port 4060", secondDialCfg.RemotePort)
	}
	if secondListenCfg.RemotePort != 4600 {
		t.Fatalf("second listen remote port = %d, want refreshed P-CSCF protected client port 4600", secondListenCfg.RemotePort)
	}
	if got := countWrites(firstOutbound); got != 1 {
		t.Fatalf("first outbound writes = %d, want 1", got)
	}
	if got := countWrites(nextOutbound); got != 1 {
		t.Fatalf("next outbound writes = %d, want 1", got)
	}
}

func TestRegisterSuccessMaintainsSecureAssociationLifetime(t *testing.T) {
	tests := []struct {
		name          string
		initial       time.Duration
		response      time.Duration
		wantZero      bool
		wantUnchanged bool
		wantExtended  bool
	}{
		{
			name:         "authenticated success starts lifetime",
			response:     time.Minute,
			wantExtended: true,
		},
		{
			name:          "shorter unauthenticated refresh does not decrease lifetime",
			initial:       10 * time.Minute,
			response:      time.Second,
			wantUnchanged: true,
		},
		{
			name:         "longer unauthenticated refresh extends lifetime",
			initial:      time.Minute,
			response:     10 * time.Minute,
			wantExtended: true,
		},
		{
			name:     "unsecured success does not start lifetime",
			response: time.Minute,
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 4060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			defer svc.closeSecureResources()
			if !tt.wantZero {
				if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
					t.Fatalf("applyRegisterChallenge() error = %v", err)
				}
			}
			var initialExpiresAt time.Time
			if tt.initial > 0 {
				initialExpiresAt = time.Now().Add(tt.initial)
				svc.extendActiveSecureAssociationLifetime(initialExpiresAt)
			}

			resp := newResponse(svc.buildRegister(nil, nil), 200, "OK", sip.Header{Name: "Expires", Value: strconv.Itoa(int(tt.response / time.Second))})
			svc.applyRegisterSuccess(resp)
			got := svc.currentSecureAssociationExpiresAt()

			switch {
			case tt.wantZero:
				if !got.IsZero() {
					t.Fatalf("secure association expires at = %v, want zero", got)
				}
			case tt.wantUnchanged:
				if !got.Equal(initialExpiresAt) {
					t.Fatalf("secure association expires at = %v, want unchanged %v", got, initialExpiresAt)
				}
			case tt.wantExtended:
				if got.IsZero() {
					t.Fatal("secure association expires at is zero, want scheduled lifetime")
				}
				if !initialExpiresAt.IsZero() && !got.After(initialExpiresAt) {
					t.Fatalf("secure association expires at = %v, want after %v", got, initialExpiresAt)
				}
			}
		})
	}
}

func TestSecureAssociationLifetimeUsesIMSGrace(t *testing.T) {
	tests := []struct {
		name    string
		secured bool
		expires time.Duration
		want    time.Duration
	}{
		{name: "secured registration lifetime adds ims grace", secured: true, expires: 2 * time.Minute, want: 2*time.Minute + secureAssociationLifetimeGrace},
		{name: "unsecured registration has no secure lifetime", expires: 2 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 4060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			if tt.secured {
				if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
					t.Fatalf("applyRegisterChallenge() error = %v", err)
				}
			}
			svc.setRegisterExpires(tt.expires)

			now := time.Unix(1000, 0)
			got := svc.secureAssociationExpiresAt(now)
			if tt.want == 0 {
				if !got.IsZero() {
					t.Fatalf("secureAssociationExpiresAt() = %v, want zero", got)
				}
				return
			}
			want := now.Add(tt.want)
			if !got.Equal(want) {
				t.Fatalf("secureAssociationExpiresAt() = %v, want %v", got, want)
			}
		})
	}
}

func TestSecureAssociationLifetimeExpiryClosesSecureResources(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "active secure resources close and registration event is published"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newTCPTransport(5062, 4060)
			activeInbound := newTCPTransport(5063, 4060)
			sess, err := session.Open(session.Config{}, primary)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			activeAttachment, err := sess.AddTransport(activeInbound)
			if err != nil {
				t.Fatalf("AddTransport(active) error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			svc.setRegistered(true)
			svc.replaceSecureServerAttachments([]session.Attachment{activeAttachment})
			svc.extendActiveSecureAssociationLifetime(time.Now().Add(10 * time.Millisecond))

			select {
			case err := <-svc.registrationEvents:
				if !errors.Is(err, errSecureSAExpired) {
					t.Fatalf("registration event = %v, want %v", err, errSecureSAExpired)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for secure association expiry event")
			}

			waitForCloseCount(t, activeInbound, 1)
			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
			if got := svc.currentSecureAssociationExpiresAt(); !got.IsZero() {
				t.Fatalf("secure association expires at = %v, want zero", got)
			}
			if got := closeCount(primary); got != 0 {
				t.Fatalf("primary closeCount = %d, want 0", got)
			}
		})
	}
}

func TestSecureAssociationLifetimeExtensionCancelsStaleExpiry(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "extended lifetime keeps resources active"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newTCPTransport(5062, 4060)
			activeInbound := newTCPTransport(5063, 4060)
			sess, err := session.Open(session.Config{}, primary)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			activeAttachment, err := sess.AddTransport(activeInbound)
			if err != nil {
				t.Fatalf("AddTransport(active) error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer svc.closeSecureResources()

			svc.setRegistered(true)
			svc.replaceSecureServerAttachments([]session.Attachment{activeAttachment})
			svc.extendActiveSecureAssociationLifetime(time.Now().Add(20 * time.Millisecond))
			svc.extendActiveSecureAssociationLifetime(time.Now().Add(time.Hour))

			select {
			case err := <-svc.registrationEvents:
				t.Fatalf("registration event = %v, want none", err)
			case <-time.After(80 * time.Millisecond):
			}
			if !svc.State().Registered {
				t.Fatal("Registered = false, want true")
			}
			if got := closeCount(activeInbound); got != 0 {
				t.Fatalf("active inbound closeCount = %d, want 0", got)
			}
		})
	}
}

func TestSADrainDelayBeforeLifetimeExpiry(t *testing.T) {
	timers := session.TransactionTimers{
		T4: 100 * time.Millisecond,
		TB: 100 * time.Millisecond,
		TD: 100 * time.Millisecond,
		TF: 100 * time.Millisecond,
		TH: 100 * time.Millisecond,
		TJ: 100 * time.Millisecond,
	}
	tests := []struct {
		name      string
		expiresAt time.Time
		want      time.Duration
	}{
		{name: "no lifetime uses transaction drain", want: 100 * time.Millisecond},
		{name: "expired lifetime closes immediately", expiresAt: time.Now().Add(-time.Second), want: 0},
		{name: "later lifetime keeps transaction drain", expiresAt: time.Now().Add(time.Second), want: 100 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := saDrainDelayBefore(tt.expiresAt, timers); got != tt.want {
				t.Fatalf("saDrainDelayBefore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloseClosesSecureResources(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "active and draining secure attachments are closed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newTCPTransport(5062, 4060)
			activeInbound := newTCPTransport(5063, 4060)
			drainingInbound := newTCPTransport(5064, 4060)
			sess, err := session.Open(session.Config{}, primary)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			activeAttachment, err := sess.AddTransport(activeInbound)
			if err != nil {
				t.Fatalf("AddTransport(active) error = %v", err)
			}
			drainAttachment, err := sess.AddTransport(drainingInbound)
			if err != nil {
				t.Fatalf("AddTransport(draining) error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			svc.setRegistered(true)
			svc.replaceSecureServerAttachments([]session.Attachment{activeAttachment})
			svc.closeAttachmentsAfter([]session.Attachment{drainAttachment}, time.Hour)

			if err := svc.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}

			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
			if got := closeCount(primary); got != 0 {
				t.Fatalf("primary closeCount = %d, want 0", got)
			}
			if got := closeCount(activeInbound); got != 1 {
				t.Fatalf("active inbound closeCount = %d, want 1", got)
			}
			if got := closeCount(drainingInbound); got != 1 {
				t.Fatalf("draining inbound closeCount = %d, want 1", got)
			}
			svc.mu.Lock()
			gotActive := len(svc.secureServerAttachments)
			gotDrains := len(svc.drainTimers)
			svc.mu.Unlock()
			if gotActive != 0 || gotDrains != 0 {
				t.Fatalf("secure resources = active %d drains %d, want 0", gotActive, gotDrains)
			}
		})
	}
}

func TestCloseAttachmentsAfterClosedServiceClosesImmediately(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "closed service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newTCPTransport(5062, 4060)
			draining := newTCPTransport(5064, 4060)
			sess, err := session.Open(session.Config{}, primary)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			attachment, err := sess.AddTransport(draining)
			if err != nil {
				t.Fatalf("AddTransport() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			if err := svc.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			svc.closeAttachmentsAfter([]session.Attachment{attachment}, time.Hour)
			svc.extendActiveSecureAssociationLifetime(time.Now().Add(time.Hour))

			if got := closeCount(draining); got != 1 {
				t.Fatalf("draining closeCount = %d, want 1", got)
			}
			svc.mu.Lock()
			gotDrains := len(svc.drainTimers)
			expiry := svc.activeSecureSAExpiry
			expiresAt := svc.activeSecureSAExpiresAt
			closed := svc.closed
			svc.mu.Unlock()
			if !closed {
				t.Fatal("closed = false, want true")
			}
			if gotDrains != 0 {
				t.Fatalf("drainTimers = %d, want 0", gotDrains)
			}
			if expiry != nil {
				t.Fatal("activeSecureSAExpiry != nil, want nil")
			}
			if !expiresAt.IsZero() {
				t.Fatalf("activeSecureSAExpiresAt = %v, want zero", expiresAt)
			}
		})
	}
}

func TestEstablishUpgradesSecureTransport(t *testing.T) {
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
		if req.Method() != "REGISTER" {
			t.Fatalf("unexpected method %q", req.Method())
		}
		secure.queue(newResponse(req, 200, "OK"))
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

func TestEstablishKeepsPlainTransportWhenSecureInboundSetupFails(t *testing.T) {
	initial := newTCPTransport(5062, 5060)
	secure := newTCPTransport(45000, 5060)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return secure, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nil, errors.New("listen rejected")
		},
	}, initial, stubCard{})

	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, testNonce, 4060))
	}

	err := svc.Establish(context.Background())
	if err == nil {
		t.Fatal("Establish() error = nil, want secure inbound setup error")
	}
	if !strings.Contains(err.Error(), "listen rejected") {
		t.Fatalf("Establish() error = %v, want listen rejected", err)
	}
	if svc.sess.LocalAddr() != initial.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want initial transport %v", svc.sess.LocalAddr(), initial.LocalAddr())
	}
	if got := closeCount(initial); got != 0 {
		t.Fatalf("initial closeCount = %d, want 0", got)
	}
	if got := closeCount(secure); got != 1 {
		t.Fatalf("secure closeCount = %d, want 1", got)
	}
}

func TestRegisterFailureDeletesIncompleteSecurityAssociations(t *testing.T) {
	initial := newTCPTransport(5062, 5060)
	outbound := newTCPTransport(45000, 4060)
	inbound := newTCPTransport(5063, 45000)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return outbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return inbound, nil
		},
	}, initial, stubCard{})

	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, testNonce, 4060))
	}
	outbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		outbound.queue(newResponse(req, 403, "Forbidden"))
	}

	err := svc.Register(context.Background())
	if err == nil {
		t.Fatal("Register() error = nil, want registration failure")
	}
	if !errors.Is(err, errInitialRegistrationNeeded) {
		t.Fatalf("Register() error = %v, want %v", err, errInitialRegistrationNeeded)
	}
	if got := closeCount(outbound); got != 1 {
		t.Fatalf("outbound closeCount = %d, want incomplete SA closed", got)
	}
	if got := closeCount(inbound); got != 1 {
		t.Fatalf("inbound closeCount = %d, want incomplete SA closed", got)
	}
	if got := closeCount(initial); got != 0 {
		t.Fatalf("initial closeCount = %d, want plain transport retained", got)
	}
	if svc.sess.LocalAddr() != initial.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want initial transport %v", svc.sess.LocalAddr(), initial.LocalAddr())
	}
}

func TestEstablishUpgradesSecureUDPTransport(t *testing.T) {
	initial := newUDPTransport(5062, 5060)
	secure := newUDPTransport(45000, 5060)
	serverUDP := newUDPTransport(5063, 45000)

	var dialCfg session.SecureUDPConfig
	var listenUDPCfg session.SecureUDPConfig

	svc := newTestService(t, Config{
		DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			dialCfg = cfg
			return secure, nil
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
		if req.Method() != "REGISTER" {
			t.Fatalf("unexpected method %q", req.Method())
		}
		serverUDP.queue(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := svc.Establish(ctx); err != nil {
		t.Fatalf("Establish() error = %v", err)
	}
	if dialCfg.LocalPort == 0 || listenUDPCfg.LocalPort == 0 {
		t.Fatalf("secure UDP configs not captured: %+v %+v", dialCfg, listenUDPCfg)
	}
	if initial.closeCount != 1 {
		t.Fatalf("initial closeCount = %d, want 1", initial.closeCount)
	}
}
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

func TestRegisterRequiresPCSCFReselectionOnUseProxy(t *testing.T) {
	tests := []struct {
		name      string
		protected bool
	}{
		{name: "initial register", protected: false},
		{name: "protected register", protected: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				if !tt.protected {
					transport.queue(newResponse(req, sipStatusUseProxy, "Use Proxy"))
					return
				}
				switch countWrites(transport) {
				case 1:
					transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
				case 2:
					transport.queue(newResponse(req, sipStatusUseProxy, "Use Proxy"))
				default:
					t.Fatalf("unexpected write count %d", countWrites(transport))
				}
			}

			err := svc.Register(context.Background())
			if err == nil {
				t.Fatal("Register() error = nil, want P-CSCF reselection")
			}
			if !PCSCFReselectionRequired(err) {
				t.Fatalf("PCSCFReselectionRequired() = false for %v", err)
			}
			wantWrites := 1
			if tt.protected {
				wantWrites = 2
			}
			if got := countWrites(transport); got != wantWrites {
				t.Fatalf("write count = %d, want %d", got, wantWrites)
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

func TestRefreshRequiresInitialRegistrationOnRestartStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
	}{
		{name: "forbidden", status: 403, reason: "Forbidden"},
		{name: "timeout", status: 408, reason: "Request Timeout"},
		{name: "server error", status: 500, reason: "Server Internal Error"},
		{name: "gateway timeout", status: 504, reason: "Server Time-out"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			registerService(t, svc, transport)

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				transport.queue(newResponse(req, tt.status, tt.reason))
			}

			err := svc.Refresh(context.Background())
			if err == nil {
				t.Fatal("Refresh() error = nil, want initial registration required")
			}
			if !errors.Is(err, errInitialRegistrationNeeded) {
				t.Fatalf("Refresh() error = %v, want %v", err, errInitialRegistrationNeeded)
			}
			if !strings.Contains(err.Error(), "initial registration required") {
				t.Fatalf("Refresh() error = %v, want initial registration required", err)
			}
			if got := countWrites(transport); got != 3 {
				t.Fatalf("write count = %d, want one refresh attempt after registration", got)
			}
		})
	}
}

func TestRefreshReauthenticationRequiresSecureDialer(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}

	err = svc.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() error = nil, want missing secure dialer")
	}
	if !strings.Contains(err.Error(), "UDP dialer is not configured") {
		t.Fatalf("Refresh() error = %v, want missing UDP dialer", err)
	}
}

func TestRefreshReauthenticationRequiresSecureInboundTransport(t *testing.T) {
	old := newTCPTransport(5062, 5060)
	nextOutbound := newTCPTransport(45000, 4060)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
	}, old, stubCard{})

	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}

	err := svc.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() error = nil, want missing secure inbound transport")
	}
	if !strings.Contains(err.Error(), "secure inbound transport is not configured") {
		t.Fatalf("Refresh() error = %v, want missing secure inbound transport", err)
	}
}

func TestRefreshReauthenticatesWithNewSecurityAssociation(t *testing.T) {
	old := newTCPTransport(5062, 5060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)

	var dialCfg session.SecureTCPConfig
	var listenCfg session.SecureTCPConfig
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			dialCfg = cfg
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			listenCfg = cfg
			return nextInbound, nil
		},
	}, old, stubCard{})

	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	oldSecurityClient := svc.CurrentFlow().SecurityClient

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if countWrites(old) != 1 {
			t.Fatalf("old write count = %d, want 1", countWrites(old))
		}
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if countWrites(nextOutbound) > 1 {
			return
		}
		if req.Method() != "REGISTER" {
			t.Fatalf("new outbound method = %q, want REGISTER", req.Method())
		}
		if got := req.Header("Security-Verify"); !strings.Contains(got, "port-c=4600") {
			t.Fatalf("Security-Verify = %q, want new Security-Server", got)
		}
		var securityClients security.Params
		if err := securityClients.UnmarshalText([]byte(req.Header("Security-Client"))); err != nil {
			t.Fatalf("parsing Security-Client: %v", err)
		}
		if len(securityClients) != 2 {
			t.Fatalf("Security-Client count = %d, want 2", len(securityClients))
		}
		if strings.Contains(req.Header("Security-Client"), "mod=UDP-enc-tun") {
			t.Fatalf("Security-Client = %q, want conservative trans-only capabilities", req.Header("Security-Client"))
		}
		securityClient := securityClients[0]
		if securityClient.PortS != oldSecurityClient.PortS {
			t.Fatalf("Security-Client port-s = %d, want unchanged protected server port %d", securityClient.PortS, oldSecurityClient.PortS)
		}
		if securityClient.PortC == oldSecurityClient.PortC {
			t.Fatalf("Security-Client port-c = %d, want changed protected client port", securityClient.PortC)
		}
		if securityClient.SPIC == oldSecurityClient.SPIC || securityClient.SPIS == oldSecurityClient.SPIS {
			t.Fatalf("Security-Client SPIs = (%d, %d), want changed from (%d, %d)", securityClient.SPIC, securityClient.SPIS, oldSecurityClient.SPIC, oldSecurityClient.SPIS)
		}
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if dialCfg.RemotePort != 4060 || listenCfg.RemotePort != 4600 {
		t.Fatalf("secure cfg remote ports = dial %d listen %d, want 4060 and 4600", dialCfg.RemotePort, listenCfg.RemotePort)
	}
	if dialCfg.LocalPort == oldSecurityClient.PortC {
		t.Fatalf("dial local port = %d, want changed UE protected client port", dialCfg.LocalPort)
	}
	if listenCfg.LocalPort != oldSecurityClient.PortS {
		t.Fatalf("listen local port = %d, want unchanged UE protected server port %d", listenCfg.LocalPort, oldSecurityClient.PortS)
	}
	if dialCfg.InboundSPI == oldSecurityClient.SPIC || listenCfg.InboundSPI == oldSecurityClient.SPIS {
		t.Fatalf("inbound SPIs = dial %d listen %d, want new UE SPIs", dialCfg.InboundSPI, listenCfg.InboundSPI)
	}
	if got := countWrites(nextOutbound); got != 1 {
		t.Fatalf("next outbound write count = %d, want 1", got)
	}
	if err := svc.sess.Send(context.Background(), svc.buildSubscribe()); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if got := countWrites(nextOutbound); got != 2 {
		t.Fatalf("next outbound write count after promote = %d, want 2", got)
	}
	waitForCloseCount(t, old, 1)

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRefreshReauthenticationCompletesBeforeSessionRun(t *testing.T) {
	old := newTCPTransport(5062, 5060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, old, stubCard{})

	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := svc.Refresh(ctx); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if svc.sess.LocalAddr() != nextOutbound.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want promoted transport %v", svc.sess.LocalAddr(), nextOutbound.LocalAddr())
	}
	waitForCloseCount(t, old, 1)
}

func TestRefreshReauthenticationAcceptsTCPResponseOnOutboundSecurityAssociation(t *testing.T) {
	old := newTCPTransport(5062, 5060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, old, stubCard{})

	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextOutbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if svc.sess.LocalAddr() != nextOutbound.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want promoted transport %v", svc.sess.LocalAddr(), nextOutbound.LocalAddr())
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestReauthResponseTransportsFollowProtectedFlowRules(t *testing.T) {
	tests := []struct {
		name         string
		newTransport func(localPort, remotePort int) *stubTransport
		wantOutbound bool
	}{
		{
			name:         "tcp reuses UE established connection",
			newTransport: newTCPTransport,
			wantOutbound: true,
		},
		{
			name:         "udp receives on protected server flow",
			newTransport: newUDPTransport,
			wantOutbound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outbound := tt.newTransport(45000, 4060)
			inbound := tt.newTransport(5063, 45000)
			got := reauthResponseTransports(outbound, []session.Transport{inbound})
			want := []session.Transport{inbound}
			if tt.wantOutbound {
				want = []session.Transport{outbound, inbound}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("reauthResponseTransports() = %v, want %v", got, want)
			}
		})
	}
}

func TestRefreshReauthenticationDrainsOldInboundSecurityAssociations(t *testing.T) {
	oldOutbound := newTCPTransport(5062, 4060)
	oldInbound := newTCPTransport(5063, 4060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	timers := session.TransactionTimers{
		T1: 100 * time.Millisecond,
		T2: 100 * time.Millisecond,
		T4: 100 * time.Millisecond,
		TB: 100 * time.Millisecond,
		TD: 100 * time.Millisecond,
		TF: 100 * time.Millisecond,
		TH: 100 * time.Millisecond,
		TJ: 100 * time.Millisecond,
	}
	sess, err := session.Open(session.Config{TransactionTimers: timers}, oldOutbound)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	svc, err := New(Config{
		Logger: testLogger(),
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, sess, stubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	oldInboundAttachment, err := sess.AddTransport(oldInbound)
	if err != nil {
		t.Fatalf("AddTransport(oldInbound) error = %v", err)
	}
	svc.replaceSecureServerAttachments([]session.Attachment{oldInboundAttachment})

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	oldOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		oldOutbound.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	waitForCloseCount(t, oldOutbound, 1)
	waitForCloseCount(t, oldInbound, 1)
	if got := closeCount(nextInbound); got != 0 {
		t.Fatalf("next inbound closeCount = %d, want active new inbound SA", got)
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRefreshReauthenticationKeepsOldSAsUntilPendingTransactionCompletes(t *testing.T) {
	oldOutbound := newTCPTransport(5062, 4060)
	oldInbound := newTCPTransport(5063, 4060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	timers := session.TransactionTimers{
		T1: 500 * time.Millisecond,
		T2: 500 * time.Millisecond,
		T4: 500 * time.Millisecond,
		TB: 500 * time.Millisecond,
		TD: 500 * time.Millisecond,
		TF: 500 * time.Millisecond,
		TH: 500 * time.Millisecond,
		TJ: 500 * time.Millisecond,
	}
	sess, err := session.Open(session.Config{TransactionTimers: timers}, oldOutbound)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	svc, err := New(Config{
		Logger: testLogger(),
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, sess, stubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	oldInboundAttachment, err := sess.AddTransport(oldInbound)
	if err != nil {
		t.Fatalf("AddTransport(oldInbound) error = %v", err)
	}
	svc.replaceSecureServerAttachments([]session.Attachment{oldInboundAttachment})

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	pending := sip.NewRequest("MESSAGE", "sip:ims.mnc001.mcc001.3gppnetwork.org")
	pending.Headers = sip.Headers{
		{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5062;branch=z9hG4bK-old-pending"},
		{Name: "From", Value: `<sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>;tag=old`},
		{Name: "To", Value: `<sip:ims.mnc001.mcc001.3gppnetwork.org>`},
		{Name: "Call-ID", Value: "old-pending"},
		{Name: "CSeq", Value: "1 MESSAGE"},
	}
	oldOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(oldOutbound) {
		case 1:
		case 2:
			oldOutbound.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
		default:
			t.Fatalf("unexpected old outbound write count %d", countWrites(oldOutbound))
		}
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}
	pendingErrCh := make(chan error, 1)
	go func() {
		_, err := sess.ExchangeWithTransport(context.Background(), oldOutbound, pending, session.ExchangeOptions{})
		pendingErrCh <- err
	}()
	waitForWriteCount(t, oldOutbound, 1)

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := closeCount(oldOutbound); got != 0 {
		t.Fatalf("old outbound closeCount = %d, want 0 while old transaction is pending", got)
	}
	if got := closeCount(oldInbound); got != 0 {
		t.Fatalf("old inbound closeCount = %d, want 0 while old transaction is pending", got)
	}

	oldOutbound.queue(newResponse(pending, 200, "OK"))
	if err := <-pendingErrCh; err != nil {
		t.Fatalf("pending Exchange() error = %v", err)
	}
	waitForCloseCount(t, oldOutbound, 1)
	waitForCloseCount(t, oldInbound, 1)

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRefreshReauthenticationFailureDeletesIncompleteSecurityAssociations(t *testing.T) {
	old := newTCPTransport(5062, 4060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, old, stubCard{})
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextInbound.queue(newResponse(req, 403, "Forbidden"))
	}

	err := svc.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() error = nil, want re-authentication failure")
	}
	if !errors.Is(err, errInitialRegistrationNeeded) {
		t.Fatalf("Refresh() error = %v, want %v", err, errInitialRegistrationNeeded)
	}
	if got := closeCount(nextOutbound); got != 1 {
		t.Fatalf("next outbound closeCount = %d, want incomplete SA closed", got)
	}
	if got := closeCount(nextInbound); got != 1 {
		t.Fatalf("next inbound closeCount = %d, want incomplete SA closed", got)
	}
	if got := closeCount(old); got != 0 {
		t.Fatalf("old closeCount = %d, want old SA retained", got)
	}
	if svc.sess.LocalAddr() != old.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want old transport %v", svc.sess.LocalAddr(), old.LocalAddr())
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestMaintainReturnsRegistrationEvent(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
	want := errors.New("network deregistered")
	svc.publishRegistrationEvent(want)

	if err := svc.Maintain(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Maintain() error = %v, want %v", err, want)
	}
}

func TestRefreshReauthenticationSynchronizationFailureRetriesWithAUTS(t *testing.T) {
	auts := []byte{0x33, 0xd5, 0x8d, 0x39, 0x61, 0x9c, 0x21, 0x33, 0x67, 0xe3, 0x76, 0x11, 0x53, 0x15}
	nextNonce := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0x05}, 16), bytes.Repeat([]byte{0x06}, 16)...))
	old := newTCPTransport(5062, 4060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	successAKA := usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, old, &sequenceAKACard{
		results: []usim.AKAResult{
			successAKA,
			{AUTS: auts},
			successAKA,
		},
	})
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(old) {
		case 1:
			old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
		case 2:
			auth := req.Header("Authorization")
			if !strings.Contains(auth, `response=""`) {
				t.Fatalf("synchronization failure Authorization = %q, want empty response", auth)
			}
			if !strings.Contains(auth, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) {
				t.Fatalf("synchronization failure Authorization = %q, want auts", auth)
			}
			old.queue(newUnauthorizedRegisterResponse(req, nextNonce, 4600))
		default:
			t.Fatalf("unexpected old write count %d", countWrites(old))
		}
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if countWrites(nextOutbound) != 1 {
			t.Fatalf("unexpected next outbound write count %d", countWrites(nextOutbound))
		}
		if strings.Contains(req.Header("Authorization"), "auts=") {
			t.Fatalf("recovered Authorization = %q, want no auts", req.Header("Authorization"))
		}
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := countWrites(old); got != 2 {
		t.Fatalf("old write count = %d, want refresh and synchronization failure REGISTER", got)
	}
	if got := countWrites(nextOutbound); got != 1 {
		t.Fatalf("next outbound write count = %d, want recovered SM7 on new outbound SA", got)
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRegistrationRefreshRejectsConcurrentRefresh(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	started := make(chan struct{})
	unblock := make(chan struct{})
	var startedOnce sync.Once
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			startedOnce.Do(func() { close(started) })
			<-unblock
			transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 4060))
		case 2:
			transport.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	registerErr := make(chan error, 1)
	go func() {
		registerErr <- svc.Register(context.Background())
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := svc.Refresh(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Refresh() error = %v, want %v", err, context.DeadlineExceeded)
	}
	close(unblock)
	if err := <-registerErr; err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if got := countWrites(transport); got != 2 {
		t.Fatalf("write count = %d, want only Register writes", got)
	}
}

func TestMaintainRefreshesOnInterval(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{RegisterExpires: 2 * time.Second}, transport, stubCard{})
	registerService(t, svc, transport)

	refreshed := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		transport.queue(newResponse(req, 200, "OK"))
		if req.Method() == "REGISTER" && countWrites(transport) >= 3 {
			refreshed <- struct{}{}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Maintain(ctx)
	}()

	select {
	case <-refreshed:
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for refresh")
	}
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Fatalf("Maintain() error = %v", err)
	}
}

func TestMaintainRefreshesRegistrationEventSubscription(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setSubscribeExpires(2 * time.Second)

	refreshed := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			refreshed <- struct{}{}
		}
		transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "2"}))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Maintain(ctx)
	}()

	select {
	case <-refreshed:
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for subscription refresh")
	}
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Fatalf("Maintain() error = %v", err)
	}
}

func TestMaintainIgnoresRegistrationEventSubscriptionRefreshError(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setSubscribeExpires(2 * time.Second)

	attempted := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			attempted <- struct{}{}
			transport.queue(newResponse(req, 500, "Server Internal Error"))
			return
		}
		transport.queue(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Maintain(ctx)
	}()

	select {
	case <-attempted:
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for subscription refresh")
	}

	select {
	case err := <-errCh:
		t.Fatalf("Maintain() returned after subscription refresh error: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Fatalf("Maintain() error = %v", err)
	}
}

func TestRefreshIntervalFollowsIMSRegistrationExpiryRules(t *testing.T) {
	tests := []struct {
		name    string
		expires time.Duration
		want    time.Duration
	}{
		{name: "minimum interval", expires: 500 * time.Millisecond, want: time.Second},
		{name: "half below threshold", expires: 2 * time.Second, want: time.Second},
		{name: "half at threshold", expires: 1200 * time.Second, want: 600 * time.Second},
		{name: "six hundred seconds before expiry above threshold", expires: 1201 * time.Second, want: 601 * time.Second},
		{name: "default ims expiry", expires: 600000 * time.Second, want: 599400 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{RegisterExpires: tt.expires}, newUDPTransport(5062, 5060), stubCard{})
			if got := svc.refreshInterval(); got != tt.want {
				t.Fatalf("refreshInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestDeregisterRetriesAfterChallenge(t *testing.T) {
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
	if got := countWrites(transport); got != 4 {
		t.Fatalf("write count = %d, want 4", got)
	}
}

func TestDeregisterReusesDigestCredential(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	card := &failAfterFirstAKACard{}
	svc := newTestService(t, Config{}, transport, card)
	registerService(t, svc, transport)

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 3:
			if got := req.Header("Authorization"); !strings.Contains(got, `nonce="`+testNonce+`"`) {
				t.Fatalf("Authorization = %q, want cached nonce", got)
			}
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
	if got := countWrites(transport); got != 3 {
		t.Fatalf("write count = %d, want 3", got)
	}
	card.mu.Lock()
	calls := card.calls
	card.mu.Unlock()
	if calls != 1 {
		t.Fatalf("AKA calls = %d, want 1", calls)
	}
}
func TestBuildSubscribeUsesSpecDefaultExpires(t *testing.T) {
	svc := newTestService(t, Config{RegisterExpires: 30 * time.Second}, newUDPTransport(5062, 5060), stubCard{})

	msg := svc.buildSubscribe()
	if got := msg.Header("Expires"); got != "600000" {
		t.Fatalf("Expires = %q, want 600000", got)
	}
	if got := msg.Header("Accept"); got != "application/reginfo+xml" {
		t.Fatalf("Accept = %q, want application/reginfo+xml", got)
	}
}

func TestBuildSubscribeUsesSubscriptionIdentity(t *testing.T) {
	tests := []struct {
		name            string
		publicIdentity  string
		defaultPublicID string
		wantIdentity    string
	}{
		{
			name:            "prefers default public identity from registration success",
			publicIdentity:  "sip:530011120348761@ims.mnc001.mcc530.3gppnetwork.org",
			defaultPublicID: "sip:+64210647889@ims.mnc001.mcc530.3gppnetwork.org",
			wantIdentity:    "sip:+64210647889@ims.mnc001.mcc530.3gppnetwork.org",
		},
		{
			name:           "falls back to registration identity when default is absent",
			publicIdentity: "sip:alice@example.com",
			wantIdentity:   "sip:alice@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{}, newTCPTransport(5062, 5060), stubCard{})
			svc.mu.Lock()
			svc.state.PublicIdentity = tt.publicIdentity
			svc.state.DefaultPublicID = tt.defaultPublicID
			svc.mu.Unlock()

			msg := svc.buildSubscribe()
			if msg.StartLine != fmt.Sprintf("SUBSCRIBE %s SIP/2.0", tt.wantIdentity) {
				t.Fatalf("StartLine = %q, want SUBSCRIBE %s SIP/2.0", msg.StartLine, tt.wantIdentity)
			}
			if got := msg.Header("To"); got != fmt.Sprintf("<%s>", tt.wantIdentity) {
				t.Fatalf("To = %q, want <%s>", got, tt.wantIdentity)
			}
			from := msg.Header("From")
			if !strings.HasPrefix(from, fmt.Sprintf("<%s>;tag=", tt.wantIdentity)) {
				t.Fatalf("From = %q, want prefix <%s>;tag=", from, tt.wantIdentity)
			}
		})
	}
}

func TestSubscribeIgnoresUnsupportedRegistrationEventPackage(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("method = %q, want SUBSCRIBE", req.Method())
		}
		transport.queue(newResponse(req, 489, "Bad Event"))
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	if !svc.isSubscribeUnsupported() {
		t.Fatal("subscribeUnsupported = false, want true")
	}
}

func TestSubscribeStoresExpires(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("method = %q, want SUBSCRIBE", req.Method())
		}
		transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	if got := svc.currentSubscribeExpires(); got != 2*time.Minute {
		t.Fatalf("currentSubscribeExpires() = %v, want 2m", got)
	}
	if svc.isSubscribeUnsupported() {
		t.Fatal("subscribeUnsupported = true, want false")
	}
}

func TestSubscribeAndNotifyUseProtectedServerFlows(t *testing.T) {
	clientUDP := newUDPTransport(5062, 4060)
	serverUDP := newUDPTransport(5063, 4061)
	serverTCP := newTCPTransport(5063, 4061)
	svc := newTestService(t, Config{}, clientUDP, stubCard{})

	serverUDPAttachment, err := svc.sess.AddTransport(serverUDP)
	if err != nil {
		t.Fatalf("AddTransport(serverUDP) error = %v", err)
	}
	serverTCPAttachment, err := svc.sess.AddTransport(serverTCP)
	if err != nil {
		t.Fatalf("AddTransport(serverTCP) error = %v", err)
	}
	svc.replaceSecureServerAttachments([]session.Attachment{serverUDPAttachment, serverTCPAttachment})

	clientUDP.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("client flow method = %q, want SUBSCRIBE", req.Method())
		}
		serverUDP.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	if countWrites(serverUDP) != 0 {
		t.Fatalf("server UDP writes = %d before NOTIFY, want 0", countWrites(serverUDP))
	}

	subscription := svc.currentSubscription()
	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:4061;branch=z9hG4bK-protected-notify")
	notify.Headers.Add("From", subscription.remoteHeader)
	notify.Headers.Add("To", subscription.localHeader)
	notify.Headers.Add("Call-ID", subscription.callID)
	notify.Headers.Add("CSeq", "1 NOTIFY")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Subscription-State", "active;expires=90")

	handled, err := svc.HandleRequest(context.Background(), session.Request{
		Message:   notify,
		Transport: serverTCP,
		PeerAddr:  serverTCP.RemoteAddr(),
	})
	if err != nil {
		t.Fatalf("HandleRequest(NOTIFY) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(NOTIFY) handled = false, want true")
	}
	if got := lastWrite(t, serverTCP).StatusCode(); got != 200 {
		t.Fatalf("NOTIFY response status = %d, want 200", got)
	}
	if countWrites(clientUDP) != 1 {
		t.Fatalf("client UDP writes = %d, want only SUBSCRIBE", countWrites(clientUDP))
	}
}

func TestSubscribeServiceUnavailableCarriesRetryAfter(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("method = %q, want SUBSCRIBE", req.Method())
		}
		transport.queue(newResponse(req, sipStatusServiceUnavailable, "Service Unavailable", sip.Header{Name: "Retry-After", Value: "75"}))
	}

	err := svc.Subscribe(context.Background())
	if err == nil {
		t.Fatal("Subscribe() error = nil, want retry-after error")
	}
	if retryAfter, ok := RetryAfterDelay(err); !ok || retryAfter != 75*time.Second {
		t.Fatalf("RetryAfterDelay() = %v, %v; want 75s, true", retryAfter, ok)
	}
	if _, ok := InitialRegistrationRetryAfter(err); ok {
		t.Fatal("InitialRegistrationRetryAfter() ok = true, want false")
	}
}

func TestSubscribeRefreshUsesEstablishedDialog(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	var callID, fromTag, toTag string
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			callID = req.Header("Call-ID")
			fromTag = sip.HeaderTag(req.Header("From"))
			resp := newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com;transport=tcp>"},
				sip.Header{Name: "Record-Route", Value: "<sip:pcscf-1.example.com;lr>"},
				sip.Header{Name: "Record-Route", Value: "<sip:pcscf-2.example.com;lr>"},
			)
			toTag = sip.HeaderTag(resp.Header("To"))
			transport.queue(resp)
		case 2:
			if got := req.Header("Call-ID"); got != callID {
				t.Fatalf("refresh Call-ID = %q, want %q", got, callID)
			}
			if got := sip.HeaderTag(req.Header("From")); got != fromTag {
				t.Fatalf("refresh From tag = %q, want %q", got, fromTag)
			}
			if got := sip.HeaderTag(req.Header("To")); got != toTag {
				t.Fatalf("refresh To tag = %q, want %q", got, toTag)
			}
			if got := req.Header("CSeq"); got != "2 SUBSCRIBE" {
				t.Fatalf("refresh CSeq = %q, want 2 SUBSCRIBE", got)
			}
			if got := sip.RequestURI(req); got != "sip:scscf.example.com;transport=tcp" {
				t.Fatalf("refresh request URI = %q, want remote target", got)
			}
			routes := req.HeadersByName("Route")
			wantRoutes := []string{"<sip:pcscf-2.example.com;lr>", "<sip:pcscf-1.example.com;lr>"}
			if !slices.Equal(routes, wantRoutes) {
				t.Fatalf("refresh Route = %v, want %v", routes, wantRoutes)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	atomic.StoreInt64(&svc.cseq, 99)
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(refresh) error = %v", err)
	}
}

func TestSubscribeRefreshUsesDialogCSeqAndEmptyRouteSet(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.mu.Lock()
	svc.flow.ServiceRoutes = []string{"<sip:service-route.example.com;lr>"}
	svc.mu.Unlock()

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com>"},
			))
		case 2:
			if got := req.Header("CSeq"); got != "2 SUBSCRIBE" {
				t.Fatalf("refresh CSeq = %q, want 2 SUBSCRIBE", got)
			}
			if routes := req.HeadersByName("Route"); len(routes) != 0 {
				t.Fatalf("refresh Route = %v, want empty route set", routes)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	atomic.StoreInt64(&svc.cseq, 99)
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(refresh) error = %v", err)
	}
}

func TestSubscribeRefreshFailureAdvancesDialogCSeq(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com>"},
			))
		case 2:
			if got := req.Header("CSeq"); got != "2 SUBSCRIBE" {
				t.Fatalf("failed refresh CSeq = %q, want 2 SUBSCRIBE", got)
			}
			transport.queue(newResponse(req, 500, "Server Internal Error"))
		case 3:
			if got := req.Header("CSeq"); got != "3 SUBSCRIBE" {
				t.Fatalf("retry refresh CSeq = %q, want 3 SUBSCRIBE", got)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	if err := svc.Subscribe(context.Background()); err == nil {
		t.Fatal("Subscribe(failed refresh) error = nil, want non-nil")
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(retry refresh) error = %v", err)
	}
}

func TestSubscribeRefreshExchangeErrorStartsNewInitialSubscription(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	var firstCallID string
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			firstCallID = req.Header("Call-ID")
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com>"},
			))
		case 2:
			if got := req.Header("Call-ID"); got != firstCallID {
				t.Fatalf("dialog refresh Call-ID = %q, want %q", got, firstCallID)
			}
			if got := sip.HeaderTag(req.Header("To")); got == "" {
				t.Fatal("dialog refresh To tag is empty")
			}

		case 3:
			if got := req.Header("Call-ID"); got == firstCallID {
				t.Fatalf("new initial Call-ID reused old dialog: %q", got)
			}
			if got := sip.HeaderTag(req.Header("To")); got != "" {
				t.Fatalf("new initial To tag = %q, want empty", got)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := svc.Subscribe(ctx); err == nil {
		t.Fatal("Subscribe(timed out refresh) error = nil, want non-nil")
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(new initial) error = %v", err)
	}
}

func TestSubscribeRefresh481StartsNewInitialSubscription(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	var firstCallID string
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			firstCallID = req.Header("Call-ID")
			transport.queue(newResponse(req, 200, "OK",
				sip.Header{Name: "Expires", Value: "120"},
				sip.Header{Name: "Contact", Value: "<sip:scscf.example.com>"},
			))
		case 2:
			if got := req.Header("Call-ID"); got != firstCallID {
				t.Fatalf("dialog refresh Call-ID = %q, want %q", got, firstCallID)
			}
			if got := sip.HeaderTag(req.Header("To")); got == "" {
				t.Fatal("dialog refresh To tag is empty")
			}
			transport.queue(newResponse(req, 481, "Call/Transaction Does Not Exist"))
		case 3:
			if got := req.Header("Call-ID"); got == firstCallID {
				t.Fatalf("new initial Call-ID reused old dialog: %q", got)
			}
			if got := sip.HeaderTag(req.Header("To")); got != "" {
				t.Fatalf("new initial To tag = %q, want empty", got)
			}
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(initial) error = %v", err)
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe(refresh) error = %v", err)
	}
	if got := countWrites(transport); got != 3 {
		t.Fatalf("write count = %d, want 3", got)
	}
}

func TestNotifyStoresSubscriptionStateExpires(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Subscription-State", "active;expires=90")
	req := session.Request{Message: notify, Transport: transport}

	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if got := svc.currentSubscribeExpires(); got != 90*time.Second {
		t.Fatalf("currentSubscribeExpires() = %v, want 90s", got)
	}
}

func TestSubscriptionStateHeaderText(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantState   string
		wantExpires time.Duration
		wantErr     bool
	}{
		{name: "active with expires", value: "active;expires=90", wantState: "active", wantExpires: 90 * time.Second},
		{name: "terminated with reason", value: "terminated;reason=timeout", wantState: "terminated"},
		{name: "empty", value: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got subscriptionStateHeader
			err := got.UnmarshalText([]byte(tt.value))
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalText() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got.state != tt.wantState || got.expires != tt.wantExpires {
				t.Fatalf("UnmarshalText() = %+v, want state %q expires %v", got, tt.wantState, tt.wantExpires)
			}
		})
	}
}

func TestNotifyOutsideSubscriptionDialogGets481(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		}
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}

	transport.onWrite = nil
	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnotify")
	notify.Headers.Add("From", "<sip:server@example.com>;tag=remote")
	notify.Headers.Add("To", sip.WithTag("", svc.State().PublicIdentity, svc.currentSubscription().localTag))
	notify.Headers.Add("Call-ID", "wrong-call-id")
	notify.Headers.Add("CSeq", "1 NOTIFY")
	notify.Headers.Add("Event", "reg")

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	resp := lastWrite(t, transport)
	if got := resp.StatusCode(); got != 481 {
		t.Fatalf("status = %d, want 481", got)
	}
}

func TestNotifyMissingDialogTagGets481(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		}
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	subscription := svc.currentSubscription()

	transport.onWrite = nil
	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnotify")
	notify.Headers.Add("From", "<sip:server@example.com>")
	notify.Headers.Add("To", subscription.localHeader)
	notify.Headers.Add("Call-ID", subscription.callID)
	notify.Headers.Add("CSeq", "1 NOTIFY")
	notify.Headers.Add("Event", "reg")

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	resp := lastWrite(t, transport)
	if got := resp.StatusCode(); got != 481 {
		t.Fatalf("status = %d, want 481", got)
	}
}

func TestNotifyStaleRemoteCSeqGets500(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		}
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	subscription := svc.currentSubscription()

	buildNotify := func(cseq string) sip.Message {
		notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
		notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnotify"+cseq)
		notify.Headers.Add("From", subscription.remoteHeader)
		notify.Headers.Add("To", subscription.localHeader)
		notify.Headers.Add("Call-ID", subscription.callID)
		notify.Headers.Add("CSeq", cseq+" NOTIFY")
		notify.Headers.Add("Event", "reg")
		notify.Headers.Add("Subscription-State", "active;expires=120")
		return notify
	}

	transport.onWrite = nil
	if _, err := svc.HandleRequest(context.Background(), session.Request{Message: buildNotify("2"), Transport: transport}); err != nil {
		t.Fatalf("HandleRequest() first error = %v", err)
	}
	if _, err := svc.HandleRequest(context.Background(), session.Request{Message: buildNotify("1"), Transport: transport}); err != nil {
		t.Fatalf("HandleRequest() second error = %v", err)
	}
	resp := lastWrite(t, transport)
	if got := resp.StatusCode(); got != 500 {
		t.Fatalf("status = %d, want 500", got)
	}
	if !svc.currentSubscription().active {
		t.Fatal("subscription active = false, want stale NOTIFY ignored")
	}
}

func TestNotifySubscriptionStateTerminatedRequestsNewSubscription(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "120"}))
		}
	}
	if err := svc.Subscribe(context.Background()); err != nil {
		t.Fatalf("Subscribe() error = %v", err)
	}
	subscription := svc.currentSubscription()

	transport.onWrite = nil
	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKnotify")
	notify.Headers.Add("From", subscription.remoteHeader)
	notify.Headers.Add("To", subscription.localHeader)
	notify.Headers.Add("Call-ID", subscription.callID)
	notify.Headers.Add("CSeq", "1 NOTIFY")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Subscription-State", "terminated;reason=timeout")

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if svc.currentSubscription().active {
		t.Fatal("subscription active = true, want false")
	}
	select {
	case <-svc.subscribeRefreshRequests:
	default:
		t.Fatal("subscription refresh request missing")
	}
	resp := lastWrite(t, transport)
	if got := resp.StatusCode(); got != 200 {
		t.Fatalf("status = %d, want 200", got)
	}
}

func TestNotifyRegInfoRefreshesRegistrationExpires(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="refreshed" expires="120">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, svc.currentRegisterContactURI()))
	req := session.Request{Message: notify, Transport: transport}

	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	state := svc.State()
	if !state.Registered {
		t.Fatal("Registered = false, want true")
	}
	if state.RegisterExpires != 2*time.Minute {
		t.Fatalf("RegisterExpires = %v, want 2m", state.RegisterExpires)
	}
	if got := countWrites(transport); got != 1 {
		t.Fatalf("write count = %d, want NOTIFY 200 response", got)
	}
}

func TestNotifyRegInfoMatchesTokenizedContactBySIPInstance(t *testing.T) {
	tests := []struct {
		name           string
		contactState   string
		contactEvent   string
		wantRegistered bool
		wantEvent      error
	}{
		{
			name:           "active",
			contactState:   "active",
			contactEvent:   "registered",
			wantRegistered: true,
		},
		{
			name:         "terminated",
			contactState: "terminated",
			contactEvent: "deactivated",
			wantEvent:    errNetworkDeregistered,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{IMEI: "869710031623444"}, transport, stubCard{})
			svc.setRegistered(true)

			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="%s" event="%s" expires="3600">
      <uri>sip:192048834622471@10.160.92.1:5060;transport=udp;EriBindingId=192048834622471;eribind-generated-at=10.160.92.1</uri>
      <unknown-param name="+sip.instance">&quot;&lt;urn:gsma:imei:869710031623444&gt;&quot; </unknown-param>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, tt.contactState, tt.contactEvent))

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			if got := svc.State().Registered; got != tt.wantRegistered {
				t.Fatalf("Registered = %v, want %v", got, tt.wantRegistered)
			}
			if tt.wantEvent != nil {
				expectRegistrationEvent(t, svc, tt.wantEvent)
			} else {
				expectNoRegistrationEvent(t, svc)
			}
			if got := countWrites(transport); got != 1 {
				t.Fatalf("write count = %d, want NOTIFY 200 response", got)
			}
		})
	}
}

func TestNotifyRegInfoMaintainsTableAcrossPartialUpdates(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)
	ownAOR := svc.State().PublicIdentity
	ownContact := svc.currentRegisterContactURI()

	tests := []struct {
		name           string
		body           string
		wantRegistered bool
		wantExpires    time.Duration
		wantEvent      error
	}{
		{
			name: "full seeds own contact",
			body: fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="registered" expires="120">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, ownAOR, ownContact),
			wantRegistered: true,
			wantExpires:    2 * time.Minute,
		},
		{
			name: "partial foreign contact keeps own contact",
			body: `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="2" state="partial">
  <registration aor="sip:other@example.com" id="reg-2" state="active">
    <contact id="contact-2" state="active" event="registered" expires="300">
      <uri>sip:other@192.0.2.10:5060</uri>
    </contact>
  </registration>
</reginfo>`,
			wantRegistered: true,
			wantExpires:    2 * time.Minute,
		},
		{
			name: "partial own contact refreshes expires",
			body: fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="3" state="partial">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="shortened" expires="60">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, ownAOR, ownContact),
			wantRegistered: true,
			wantExpires:    time.Minute,
		},
		{
			name: "partial own contact expired requires initial registration",
			body: fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="4" state="partial">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="terminated" event="expired">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, ownAOR, ownContact),
			wantEvent: errInitialRegistrationNeeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(tt.body)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			if got := svc.State().Registered; got != tt.wantRegistered {
				t.Fatalf("Registered = %v, want %v", got, tt.wantRegistered)
			}
			if tt.wantExpires > 0 && svc.State().RegisterExpires != tt.wantExpires {
				t.Fatalf("RegisterExpires = %v, want %v", svc.State().RegisterExpires, tt.wantExpires)
			}
			if tt.wantEvent != nil {
				expectRegistrationEvent(t, svc, tt.wantEvent)
			} else {
				expectNoRegistrationEvent(t, svc)
			}
		})
	}
}

func TestNotifyRegInfoAcceptsContentTypeParameters(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", `Application/RegInfo+XML; charset="utf-8"`)
	notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="refreshed">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, svc.currentRegisterContactURI()))

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if !svc.regInfoVersionSet {
		t.Fatal("regInfoVersionSet = false, want true")
	}
}

func TestNotifyRegInfoTerminatedContactPublishesRegistrationEvent(t *testing.T) {
	tests := []struct {
		name      string
		event     string
		wantEvent error
	}{
		{name: "deactivated", event: "deactivated", wantEvent: errNetworkDeregistered},
		{name: "rejected", event: "rejected", wantEvent: errNetworkDeregistered},
		{name: "expired", event: "expired", wantEvent: errInitialRegistrationNeeded},
		{name: "unregistered", event: "unregistered", wantEvent: errInitialRegistrationNeeded},
		{name: "probation", event: "probation", wantEvent: errInitialRegistrationNeeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			svc.setRegistered(true)

			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="2" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="terminated" event="%s">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, tt.event, svc.currentRegisterContactURI()))
			req := session.Request{Message: notify, Transport: transport}

			handled, err := svc.HandleRequest(context.Background(), req)
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			expectRegistrationEvent(t, svc, tt.wantEvent)
			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
			if got := countWrites(transport); got != 1 {
				t.Fatalf("write count = %d, want NOTIFY 200 response", got)
			}
		})
	}
}

func TestNotifyRegInfoTerminatedRegistrationPublishesRegistrationEvent(t *testing.T) {
	tests := []struct {
		name      string
		event     string
		wantEvent error
	}{
		{name: "deactivated", event: "deactivated", wantEvent: errNetworkDeregistered},
		{name: "rejected", event: "rejected", wantEvent: errNetworkDeregistered},
		{name: "expired", event: "expired", wantEvent: errInitialRegistrationNeeded},
		{name: "unknown", event: "unknown", wantEvent: errInitialRegistrationNeeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			svc.setRegistered(true)

			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="2" state="full">
  <registration aor="%s" id="reg-1" state="terminated" event="%s"/>
</reginfo>`, svc.State().PublicIdentity, tt.event))

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			expectRegistrationEvent(t, svc, tt.wantEvent)
			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
		})
	}
}

func TestNotifyRegInfoFullStateWithoutOwnContactRequiresInitialRegistration(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="3" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-2" state="active" event="registered" expires="300">
      <uri>sip:192.0.2.10:5060</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity))
	req := session.Request{Message: notify, Transport: transport}

	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	expectRegistrationEvent(t, svc, errInitialRegistrationNeeded)
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestNotifyRegInfoFullStateWithoutOwnRegistrationRequiresInitialRegistration(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", "application/reginfo+xml")
	notify.Body = []byte(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="4" state="full">
  <registration aor="sip:other@example.com" id="reg-2" state="active">
    <contact id="contact-2" state="active" event="registered">
      <uri>sip:192.0.2.10:5060</uri>
    </contact>
  </registration>
</reginfo>`)
	req := session.Request{Message: notify, Transport: transport}

	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	expectRegistrationEvent(t, svc, errInitialRegistrationNeeded)
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestNotifyRegInfoEmptyFullStateRequiresInitialRegistration(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "empty reginfo",
			body: `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="5" state="full">
</reginfo>`,
		},
		{
			name: "foreign namespace registration ignored",
			body: `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" xmlns:x="urn:example:extension" version="5" state="full">
  <x:registration aor="sip:other@example.com" id="reg-1" state="active">
    <x:contact id="contact-1" state="active" event="registered"><x:uri>sip:other@192.0.2.10</x:uri></x:contact>
  </x:registration>
</reginfo>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			svc.setRegistered(true)

			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(tt.body)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			expectRegistrationEvent(t, svc, errInitialRegistrationNeeded)
			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
		})
	}
}

func TestNotifyRegInfoIgnoresStaleVersion(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	active := sip.NewRequest("NOTIFY", "sip:user@example.com")
	active.Headers.Add("Event", "reg")
	active.Headers.Add("Content-Type", "application/reginfo+xml")
	active.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="2" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="refreshed">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, svc.currentRegisterContactURI()))
	if _, err := svc.HandleRequest(context.Background(), session.Request{Message: active, Transport: transport}); err != nil {
		t.Fatalf("HandleRequest(active) error = %v", err)
	}

	stale := sip.NewRequest("NOTIFY", "sip:user@example.com")
	stale.Headers.Add("Event", "reg")
	stale.Headers.Add("Content-Type", "application/reginfo+xml")
	stale.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="terminated">
    <contact id="contact-1" state="terminated" event="expired">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, svc.currentRegisterContactURI()))

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: stale, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(stale) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(stale) handled = false, want true")
	}
	if !svc.State().Registered {
		t.Fatal("Registered = false, want stale NOTIFY ignored")
	}
}

func TestNotifyRegInfoRejectsInvalidEnvelope(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing namespace",
			body: `<reginfo version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "wrong namespace",
			body: `<reginfo xmlns="urn:example:wrong" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "missing version",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "negative version",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="-1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "overflow version",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="4294967296" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "missing state",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "invalid state",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="delta">
  <registration aor="sip:other@example.com" id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "missing registration id",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" state="active"/>
</reginfo>`,
		},
		{
			name: "missing registration aor",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration id="reg-1" state="active"/>
</reginfo>`,
		},
		{
			name: "invalid registration state",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="bad"/>
</reginfo>`,
		},
		{
			name: "missing contact id",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active">
    <contact state="active" event="registered"><uri>sip:other@192.0.2.10</uri></contact>
  </registration>
</reginfo>`,
		},
		{
			name: "invalid contact state",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active">
    <contact id="contact-1" state="bad" event="registered"><uri>sip:other@192.0.2.10</uri></contact>
  </registration>
</reginfo>`,
		},
		{
			name: "invalid contact event",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="bad"><uri>sip:other@192.0.2.10</uri></contact>
  </registration>
</reginfo>`,
		},
		{
			name: "missing contact uri",
			body: `<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="sip:other@example.com" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="registered"/>
  </registration>
</reginfo>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			svc.setRegistered(true)

			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", "reg")
			notify.Headers.Add("Content-Type", "application/reginfo+xml")
			notify.Body = []byte(tt.body)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			if !svc.State().Registered {
				t.Fatal("Registered = false, want invalid reginfo ignored")
			}
			if svc.regInfoVersionSet {
				t.Fatal("regInfoVersionSet = true, want false")
			}
		})
	}
}

func TestRegInfoTextAndIO(t *testing.T) {
	tests := []struct {
		name string
		info regInfo
	}{
		{
			name: "full state document",
			info: regInfo{
				Version: "7",
				State:   regInfoStateFull,
				Registration: []regInfoRegistration{{
					ID:    "reg-1",
					AOR:   "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
					State: regInfoRegistrationStateActive,
					Contact: []regInfoContact{{
						ID:          "contact-1",
						State:       regInfoContactStateActive,
						Event:       regInfoContactEventRegistered,
						ExpiresAttr: "600",
						URI:         "sip:001010123456789@192.0.2.10:5060",
					}},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := tt.info.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if !bytes.Contains(text, []byte(`xmlns="urn:ietf:params:xml:ns:reginfo"`)) {
				t.Fatalf("MarshalText() = %s, want reginfo namespace", text)
			}

			var parsed regInfo
			n, err := parsed.ReadFrom(bytes.NewReader(text))
			if err != nil {
				t.Fatalf("ReadFrom() error = %v", err)
			}
			if n != int64(len(text)) {
				t.Fatalf("ReadFrom() bytes = %d, want %d", n, len(text))
			}
			if parsed.Version != tt.info.Version || parsed.State != tt.info.State || len(parsed.Registration) != 1 {
				t.Fatalf("ReadFrom() parsed = %+v, want %+v", parsed, tt.info)
			}

			var out bytes.Buffer
			n, err = parsed.WriteTo(&out)
			if err != nil {
				t.Fatalf("WriteTo() error = %v", err)
			}
			if n != int64(out.Len()) || !bytes.Equal(out.Bytes(), text) {
				t.Fatalf("WriteTo() bytes = %d body=%s, want %d %s", n, out.Bytes(), len(text), text)
			}
		})
	}
}

func TestNotifyRegInfoVersionGapRequestsSubscriptionRefresh(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setRegistered(true)

	for _, version := range []string{"1", "3"} {
		notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
		notify.Headers.Add("Event", "reg")
		notify.Headers.Add("Content-Type", "application/reginfo+xml")
		notify.Body = []byte(fmt.Sprintf(`<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="%s" state="partial">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="active" event="refreshed">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, version, svc.State().PublicIdentity, svc.currentRegisterContactURI()))
		if handled, err := svc.HandleRequest(context.Background(), session.Request{Message: notify, Transport: transport}); err != nil {
			t.Fatalf("HandleRequest(version %s) error = %v", version, err)
		} else if !handled {
			t.Fatalf("HandleRequest(version %s) handled = false, want true", version)
		}
	}

	select {
	case <-svc.subscribeRefreshRequests:
	default:
		t.Fatal("subscription refresh request missing after reginfo version gap")
	}
}
func TestRegisterSuccessStartsRFC6223KeepAlive(t *testing.T) {
	tests := []struct {
		name       string
		transport  *stubTransport
		assertData func(*testing.T, []byte)
	}{
		{
			name:      "tcp crlf",
			transport: newTCPTransport(5062, 5060),
			assertData: func(t *testing.T, data []byte) {
				t.Helper()
				if string(data) != "\r\n\r\n" {
					t.Fatalf("keepalive packet = %q, want CRLF keepalive", string(data))
				}
			},
		},
		{
			name:      "udp stun binding indication",
			transport: newUDPTransport(5062, 5060),
			assertData: func(t *testing.T, data []byte) {
				t.Helper()
				if len(data) != 20 {
					t.Fatalf("STUN packet length = %d, want 20", len(data))
				}
				if got := binary.BigEndian.Uint16(data[0:2]); got != 0x0011 {
					t.Fatalf("STUN message type = %#x, want Binding Indication", got)
				}
				if got := binary.BigEndian.Uint16(data[2:4]); got != 0 {
					t.Fatalf("STUN message length = %d, want 0", got)
				}
				if got := binary.BigEndian.Uint32(data[4:8]); got != 0x2112a442 {
					t.Fatalf("STUN magic cookie = %#x, want 0x2112a442", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useRegistrationKeepAliveInterval(t, 10*time.Millisecond)
			svc := newTestService(t, Config{}, tt.transport, stubCard{})
			t.Cleanup(func() {
				_ = svc.Close()
			})

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))
			waitForWriteCount(t, tt.transport, 1)
			tt.assertData(t, transportWriteAt(t, tt.transport, 0))
		})
	}
}

func TestRegisterSuccessStopsRFC6223KeepAliveWhenNotRenegotiated(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "refresh response omits keep"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			t.Cleanup(func() {
				_ = svc.Close()
			})

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))
			keepalive := currentRegistrationKeepAlive(t, svc)
			if keepalive == nil {
				t.Fatal("registrationKeepAlive = nil, want active keepalive")
			}

			svc.applyRegisterSuccess(registerResponseWithoutViaKeep(svc))
			if got := currentRegistrationKeepAlive(t, svc); got != nil {
				t.Fatal("registrationKeepAlive is still active after response without keep")
			}
			select {
			case <-keepalive.done():
			default:
				t.Fatal("previous keepalive was not stopped")
			}
		})
	}
}

func TestMaintainReturnsRFC6223KeepAliveFailure(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "tcp write failure"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			useRegistrationKeepAliveInterval(t, 10*time.Millisecond)
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			t.Cleanup(func() {
				_ = svc.Close()
			})

			want := errors.New("tcp connection reset")
			transport.mu.Lock()
			transport.writeErr = want
			transport.mu.Unlock()

			errCh := make(chan error, 1)
			go func() {
				errCh <- svc.Maintain(context.Background())
			}()

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))

			select {
			case err := <-errCh:
				if !errors.Is(err, want) {
					t.Fatalf("Maintain() error = %v, want wrapped %v", err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for Maintain() keepalive failure")
			}
		})
	}
}

func TestDeregisterStopsRFC6223KeepAlive(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "successful deregistration"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			registerService(t, svc, transport)

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))
			keepalive := currentRegistrationKeepAlive(t, svc)
			if keepalive == nil {
				t.Fatal("registrationKeepAlive = nil, want active keepalive")
			}

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				switch countWrites(transport) {
				case 3:
					transport.queue(newResponse(req, 200, "OK"))
				default:
					t.Fatalf("unexpected write count %d", countWrites(transport))
				}
			}

			if err := svc.Deregister(context.Background()); err != nil {
				t.Fatalf("Deregister() error = %v", err)
			}
			if got := currentRegistrationKeepAlive(t, svc); got != nil {
				t.Fatal("registrationKeepAlive is still active after deregistration")
			}
			select {
			case <-keepalive.done():
			default:
				t.Fatal("previous keepalive was not stopped")
			}
		})
	}
}

func TestCloseStopsRFC6223KeepAlive(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "service close"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})

			svc.applyRegisterSuccess(registerResponseWithViaKeep(svc, "30"))
			keepalive := currentRegistrationKeepAlive(t, svc)
			if keepalive == nil {
				t.Fatal("registrationKeepAlive = nil, want active keepalive")
			}

			if err := svc.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			if got := currentRegistrationKeepAlive(t, svc); got != nil {
				t.Fatal("registrationKeepAlive is still active after close")
			}
			select {
			case <-keepalive.done():
			default:
				t.Fatal("previous keepalive was not stopped")
			}
		})
	}
}

func TestRegisterKeepAliveIntervalFromResponse(t *testing.T) {
	useRegistrationKeepAliveInterval(t, 24*time.Second)

	tests := []struct {
		name string
		via  string
		want time.Duration
		ok   bool
	}{
		{
			name: "positive keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep=30",
			want: 24 * time.Second,
			ok:   true,
		},
		{
			name: "bare keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep",
		},
		{
			name: "zero keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep=0",
		},
		{
			name: "missing keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sip.NewResponse(200, "OK")
			resp.Headers.Set("Via", tt.via)
			got, ok := registerKeepAliveIntervalFromResponse(resp)
			if ok != tt.ok {
				t.Fatalf("registerKeepAliveIntervalFromResponse() ok = %t, want %t", ok, tt.ok)
			}
			if got != tt.want {
				t.Fatalf("registerKeepAliveIntervalFromResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRandomizedRegistrationKeepAliveIntervalUsesRFC6223Window(t *testing.T) {
	tests := []struct {
		name        string
		recommended time.Duration
		min         time.Duration
		max         time.Duration
	}{
		{
			name:        "thirty seconds",
			recommended: 30 * time.Second,
			min:         24 * time.Second,
			max:         30 * time.Second,
		},
		{
			name:        "one second",
			recommended: time.Second,
			min:         800 * time.Millisecond,
			max:         time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for range 20 {
				got := randomizedRegistrationKeepAliveInterval(tt.recommended)
				if got < tt.min || got > tt.max {
					t.Fatalf("randomizedRegistrationKeepAliveInterval(%v) = %v, want [%v, %v]", tt.recommended, got, tt.min, tt.max)
				}
			}
		})
	}
}

func useRegistrationKeepAliveInterval(t *testing.T, interval time.Duration) {
	t.Helper()
	old := registrationKeepAliveInterval
	registrationKeepAliveInterval = func(time.Duration) time.Duration {
		return interval
	}
	t.Cleanup(func() {
		registrationKeepAliveInterval = old
	})
}

func registerResponseWithViaKeep(svc *Registrar, keep string) sip.Message {
	req := svc.buildRegister(nil, nil)
	resp := newResponse(req, 200, "OK")
	resp.Headers.Set("Via", strings.Replace(req.Header("Via"), ";keep", ";keep="+keep, 1))
	return resp
}

func registerResponseWithoutViaKeep(svc *Registrar) sip.Message {
	req := svc.buildRegister(nil, nil)
	resp := newResponse(req, 200, "OK")
	resp.Headers.Set("Via", strings.Replace(req.Header("Via"), ";keep", "", 1))
	return resp
}

func currentRegistrationKeepAlive(t *testing.T, svc *Registrar) *registrationKeepAlive {
	t.Helper()
	svc.mu.Lock()
	defer svc.mu.Unlock()
	return svc.registrationKeepAlive
}

func transportWriteAt(t *testing.T, transport *stubTransport, index int) []byte {
	t.Helper()
	transport.mu.Lock()
	defer transport.mu.Unlock()
	if index < 0 || index >= len(transport.writes) {
		t.Fatalf("write index %d out of range, len=%d", index, len(transport.writes))
	}
	return append([]byte(nil), transport.writes[index]...)
}
