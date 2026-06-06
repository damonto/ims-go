package registration

import (
	"github.com/damonto/vowifi-go/ims/pidf"
	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/sip"
	"net"
	"slices"
	"strings"
	"testing"
)

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
		prepare func(*Service)
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
			prepare: func(svc *Service) {
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
		mutate func(*Service)
		want   []string
	}{
		{
			name: "pcscf route without service route",
			want: []string{"<sip:127.0.0.1:5060;lr>"},
		},
		{
			name: "pcscf before service routes",
			mutate: func(svc *Service) {
				svc.flow.ServiceRoutes = []string{"<sip:scscf.example.com;lr>"}
			},
			want: []string{"<sip:127.0.0.1:5060;lr>", "<sip:scscf.example.com;lr>"},
		},
		{
			name: "protected pcscf port",
			mutate: func(svc *Service) {
				svc.flow.SecurityVerify = &security.Param{PortS: 4060}
				svc.flow.ServiceRoutes = []string{"<sip:scscf.example.com;lr>"}
			},
			want: []string{"<sip:127.0.0.1:4060;lr>", "<sip:scscf.example.com;lr>"},
		},
		{
			name: "duplicate pcscf service route omitted",
			mutate: func(svc *Service) {
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
