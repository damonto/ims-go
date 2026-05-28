package registration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/vowifi-go/ims/pidf"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"github.com/damonto/vowifi-go/usim"
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

type failAfterFirstAKACard struct {
	stubCard
	mu    sync.Mutex
	calls int
}

type identityStubCard struct {
	stubCard
	homeDomain      string
	privateIdentity string
	publicIdentity  string
}

type twoDigitMNCStubCard struct{}

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

func (twoDigitMNCStubCard) IMSI() string { return "204020123456789" }
func (twoDigitMNCStubCard) MCC() string  { return "204" }
func (twoDigitMNCStubCard) MNC() string  { return "02" }
func (twoDigitMNCStubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return stubCard{}.AKA(ctx, rand, autn)
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

func TestApplyRegisterChallengeSelectsHighestQSecurityServer(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})

	req := svc.buildRegister(nil, nil)
	resp := newResponse(req, 401, "Unauthorized",
		sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="` + testNonce + `",algorithm=AKAv1-MD5,qop="auth"`},
		sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222;q=0.1`},
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
	wantVerify := `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222;q=0.1,ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=333;spi-s=444;q=0.9`
	if got := svc.SecurityVerifyValue(); got != wantVerify {
		t.Fatalf("SecurityVerifyValue() = %q, want %q", got, wantVerify)
	}
	if got := len(state.Flow.SecurityServerRaw); got != 2 {
		t.Fatalf("len(Flow.SecurityServerRaw) = %d, want 2", got)
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

	auth, err := svc.buildRegisterAuthorization(context.Background(), "ims.mnc001.mcc001.3gppnetwork.org", testNonce, "auth")
	if err != nil {
		t.Fatalf("buildRegisterAuthorization() error = %v", err)
	}
	protected := svc.buildRegister(auth, nil)
	if got := protected.Header("Authorization"); !strings.Contains(got, "integrity-protected=yes") {
		t.Fatalf("protected Authorization = %q, want integrity-protected=yes", got)
	}
}

func TestBuildRegisterViaKeepsIMSUDPProfile(t *testing.T) {
	tests := []struct {
		name      string
		transport *stubTransport
		wantKeep  bool
	}{
		{name: "udp adds keep", transport: newUDPTransport(5062, 5060), wantKeep: true},
		{name: "tcp omits keep", transport: newTCPTransport(5062, 5060), wantKeep: false},
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

func TestContactURIFormatting(t *testing.T) {
	tests := []struct {
		name               string
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &stubTransport{
				local:  tt.localAddr,
				remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
				readCh: make(chan []byte, 16),
			}
			svc := newTestService(t, Config{}, transport, stubCard{})

			if got := svc.currentRegisterContactURI(); got != tt.wantRegisterURI {
				t.Fatalf("currentRegisterContactURI() = %q, want %q", got, tt.wantRegisterURI)
			}

			if got := svc.buildRegister(nil, nil).Header("Contact"); !strings.HasPrefix(got, tt.wantRegisterPrefix) {
				t.Fatalf("REGISTER Contact = %q, want prefix %q", got, tt.wantRegisterPrefix)
			}

			if got := svc.buildSubscribe().Header("Contact"); got != tt.wantSubscribe {
				t.Fatalf("SUBSCRIBE Contact = %q, want %q", got, tt.wantSubscribe)
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

func TestDefaultUserAgent(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "default",
			want: defaultUserAgent,
		},
		{
			name: "explicit value wins",
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

func TestApplyServiceRoutesReplacesStoredRoutesWithEmptyList(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
	svc.mu.Lock()
	svc.state.ServiceRoutes = []string{"<sip:old.example.com;lr>"}
	svc.mu.Unlock()

	svc.applyServiceRoutes(sip.Message{})

	if got := svc.State().ServiceRoutes; len(got) != 0 {
		t.Fatalf("ServiceRoutes = %v, want empty", got)
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
		secure.queue(newResponse(req, 200, "OK"))
	}

	if err := svc.Establish(context.Background()); err != nil {
		t.Fatalf("Establish() error = %v", err)
	}
	if dialCfg.LocalPort == 0 || listenUDPCfg.LocalPort == 0 {
		t.Fatalf("secure UDP configs not captured: %+v %+v", dialCfg, listenUDPCfg)
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

func TestCloseContextAttemptsDeregister(t *testing.T) {
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

	if err := svc.CloseContext(context.Background()); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
	if got := countWrites(transport); got != 4 {
		t.Fatalf("write count = %d, want 4", got)
	}
}

func TestCloseContextReturnsDeregisterAuthenticationErrorAndClearsState(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, &failAfterFirstAKACard{})
	registerService(t, svc, transport)

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		t.Fatalf("unexpected %s during CloseContext", req.StartLine)
	}

	if err := svc.CloseContext(context.Background()); err == nil {
		t.Fatal("CloseContext() error = nil, want non-nil")
	}
	if svc.State().Registered {
		t.Fatal("Registered = true, want false")
	}
	if got := countWrites(transport); got != 2 {
		t.Fatalf("write count = %d, want 2", got)
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
	securityServer := `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222`
	if portC != 0 {
		securityServer = `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=` + strconv.Itoa(portC) + `;port-s=4060;prot=esp;spi-c=111;spi-s=222`
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
