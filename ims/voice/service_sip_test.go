package voice

import (
	"bytes"
	"context"
	"fmt"
	"github.com/damonto/vowifi-go/ims/pidf"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"mime/multipart"
	"net/textproto"
	"strings"
	"testing"
)

func TestTargetURI(t *testing.T) {
	transport := newVoiceStubTransport()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		_ = sess.Close()
	}()
	reg, err := registration.New(registration.Config{Logger: testLogger(),
		PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
		IMEI:            "123456789012345",
	}, sess, voiceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	svc := &Service{reg: reg}

	tests := []struct {
		name string
		to   string
		want string
	}{
		{
			name: "global number",
			to:   "+12242255559",
			want: "sip:+12242255559@ims.mnc001.mcc001.3gppnetwork.org;user=phone",
		},
		{
			name: "local number",
			to:   "55559",
			want: "sip:55559;phone-context=ims.mnc001.mcc001.3gppnetwork.org@ims.mnc001.mcc001.3gppnetwork.org;user=phone",
		},
		{
			name: "sip uri",
			to:   "sip:remote@example.com",
			want: "sip:remote@example.com",
		},
		{
			name: "tel uri",
			to:   "tel:+12242255559",
			want: "tel:+12242255559",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := svc.targetURI(tt.to); got != tt.want {
				t.Fatalf("targetURI() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIncomingCallerNumber(t *testing.T) {
	tests := []struct {
		name    string
		headers sip.Headers
		want    string
	}{
		{
			name: "att sip uri",
			headers: sip.Headers{
				{Name: "From", Value: "<sip:+12242255559@one.att.net;user=phone;isup-oli=00>;tag=remote"},
			},
			want: "+12242255559",
		},
		{
			name: "tel uri",
			headers: sip.Headers{
				{Name: "From", Value: "<tel:+12242255559>;tag=remote"},
			},
			want: "+12242255559",
		},
		{
			name: "local sip user with phone context",
			headers: sip.Headers{
				{Name: "From", Value: "<sip:55559;phone-context=one.att.net@one.att.net;user=phone>;tag=remote"},
			},
			want: "55559",
		},
		{
			name: "asserted identity wins",
			headers: sip.Headers{
				{Name: "P-Asserted-Identity", Value: "<sip:+12242255558@one.att.net;user=phone>"},
				{Name: "From", Value: "<sip:+12242255559@one.att.net;user=phone>;tag=remote"},
			},
			want: "+12242255558",
		},
		{
			name:    "sip user without phone params",
			headers: sip.Headers{{Name: "From", Value: "<sip:anonymous@anonymous.invalid>;tag=remote"}},
			want:    "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewRequest("INVITE", "sip:callee@example.com")
			msg.Headers = tt.headers
			if got := incomingCallerNumber(msg); got != tt.want {
				t.Fatalf("incomingCallerNumber() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDialUsesSIPAssociatedURIForOriginatingIdentity(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "tel default public identity has sip alias"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(secureRegistrationConfig(transport, registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}), sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "REGISTER" {
					return
				}
				if transport.countMethod("REGISTER") == 1 {
					resp := callStatus(msg, 401, "Unauthorized")
					resp.Headers.Add("WWW-Authenticate", `Digest realm="one.att.net",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`)
					resp.Headers.Add("Security-Server", `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`)
					transport.queue(resp)
					return
				}
				resp := callStatus(msg, 200, "OK")
				resp.Headers.Add("Authentication-Info", `nextnonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="`)
				resp.Headers.Add("P-Associated-URI", "<tel:+15551234567>,<sip:+15551234567@one.att.net;user=phone>")
				resp.Headers.Add("Service-Route", "<sip:pcscf.example.com;lr>")
				transport.queue(resp)
			}
			if err := reg.Register(context.Background()); err != nil {
				t.Fatalf("Register() error = %v", err)
			}

			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				const want = "sip:+15551234567@one.att.net;user=phone"
				if got := msg.Header("From"); !strings.Contains(got, "<"+want+">;") {
					t.Fatalf("INVITE From = %q, want SIP associated URI", got)
				}
				if got := msg.Header("P-Preferred-Identity"); got != "<"+want+">" {
					t.Fatalf("INVITE P-Preferred-Identity = %q, want <%s>", got, want)
				}
				transport.queue(callOK(msg))
			}
			if _, err := svc.Dial(context.Background(), DialRequest{To: "+12242255559"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
		})
	}
}

func TestDialIncludesGeolocationPIDFWhenConfigured(t *testing.T) {
	tests := []struct {
		name                string
		cfg                 Config
		req                 DialRequest
		wantPIDF            bool
		wantCurrentLocation bool
		wantRequestURI      string
	}{
		{
			name: "non emergency wifi setting adds pidf",
			cfg: Config{
				GeolocationPIDFInvite: []int{GeolocationPIDFNonEmergencyWiFi},
				GeolocationCountry:    "US",
			},
			req:      DialRequest{To: "+12242255559"},
			wantPIDF: true,
		},
		{
			name: "pixel emergency-only setting omits pidf for normal calls",
			cfg: Config{
				GeolocationPIDFInvite: []int{GeolocationPIDFEmergencyCell, GeolocationPIDFEmergencyWiFi},
				GeolocationCountry:    "US",
			},
			req: DialRequest{To: "+12242255559"},
		},
		{
			name: "emergency wifi setting adds pidf for emergency calls",
			cfg: Config{
				GeolocationPIDFInvite: []int{GeolocationPIDFEmergencyWiFi},
				GeolocationCountry:    "US",
			},
			req:                 DialRequest{To: "911", Emergency: true},
			wantPIDF:            true,
			wantCurrentLocation: true,
			wantRequestURI:      emergencyServiceURNSOS,
		},
		{
			name: "emergency urn setting selects sub service urn",
			cfg: Config{
				GeolocationPIDFInvite: []int{GeolocationPIDFEmergencyWiFi},
				GeolocationCountry:    "US",
			},
			req: DialRequest{
				To:           "911",
				Emergency:    true,
				EmergencyURN: "urn:service:sos.police",
			},
			wantPIDF:            true,
			wantCurrentLocation: true,
			wantRequestURI:      "urn:service:sos.police",
		},
		{
			name: "short code adds pidf for carrier service numbers",
			cfg: Config{
				GeolocationPIDFInvite: []int{GeolocationPIDFEmergencyCell, GeolocationPIDFEmergencyWiFi},
				PIDFShortCodes:        []string{"211"},
				GeolocationCountry:    "US",
			},
			req:      DialRequest{To: "tel:211"},
			wantPIDF: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			cfg := tt.cfg
			cfg.Logger = testLogger()
			svc, err := New(cfg, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				if tt.wantRequestURI != "" {
					if got := sip.RequestURI(msg); got != tt.wantRequestURI {
						t.Fatalf("INVITE Request-URI = %q, want %q", got, tt.wantRequestURI)
					}
					if got := msg.Header("To"); got != "<"+tt.wantRequestURI+">" {
						t.Fatalf("INVITE To = %q, want <%s>", got, tt.wantRequestURI)
					}
				}
				body, ok := sdpBody(msg)
				if !ok {
					t.Fatal("sdpBody() ok = false, want SDP part")
				}
				if !strings.Contains(string(body), "m=audio ") {
					t.Fatalf("SDP body = %q, want audio media", string(body))
				}
				if tt.wantPIDF {
					if got := msg.Header("Accept"); !strings.Contains(got, "application/pidf+xml") {
						t.Fatalf("INVITE Accept = %q, want PIDF support", got)
					}
					if got := msg.Header("Geolocation"); !strings.HasPrefix(got, "<cid:pidf-") {
						t.Fatalf("INVITE Geolocation = %q, want cid PIDF reference", got)
					}
					if got := msg.Header("Geolocation-Routing"); got != "yes" {
						t.Fatalf("INVITE Geolocation-Routing = %q, want yes", got)
					}
					if !strings.Contains(string(msg.Body), "application/pidf+xml") || !strings.Contains(string(msg.Body), "<country>US</country>") {
						t.Fatalf("INVITE body missing PIDF country:\n%s", string(msg.Body))
					}
				} else {
					if got := msg.Header("Accept"); got != "application/sdp" {
						t.Fatalf("INVITE Accept = %q, want application/sdp", got)
					}
					if got := msg.Header("Geolocation"); got != "" {
						t.Fatalf("INVITE Geolocation = %q, want empty", got)
					}
					if strings.Contains(string(msg.Body), "application/pidf+xml") {
						t.Fatalf("INVITE body contains PIDF, want SDP only:\n%s", string(msg.Body))
					}
				}
				if tt.wantCurrentLocation {
					if got := msg.Header("Recv-Info"); !sip.TokenListContains(got, currentLocationDiscoveryInfoPackage) {
						t.Fatalf("INVITE Recv-Info = %q, want %q", got, currentLocationDiscoveryInfoPackage)
					}
					if got := msg.Header("Accept"); !strings.Contains(got, currentLocationDiscoveryContentType) {
						t.Fatalf("INVITE Accept = %q, want current location discovery MIME", got)
					}
				} else if got := msg.Header("Recv-Info"); got != "" {
					t.Fatalf("INVITE Recv-Info = %q, want empty", got)
				}
				transport.queue(callOK(msg))
			}
			if _, err := svc.Dial(context.Background(), tt.req); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
		})
	}
}

func TestVoiceContactValueOmitsSipInstanceOutsideRegister(t *testing.T) {
	tests := []struct {
		name  string
		state registration.State
	}{
		{
			name: "imei available",
			state: registration.State{
				ContactHost: "127.0.0.1",
				MessagePort: 5062,
				IMEI:        "123456789012345",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contactValue(tt.state)
			if strings.Contains(got, "+sip.instance") {
				t.Fatalf("contactValue() = %q, want no +sip.instance", got)
			}
		})
	}
}

func TestEmergencyCurrentLocationDiscoveryOneShotPublishesPIDF(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "oneShot request",
			body: `<?xml version="1.0" encoding="UTF-8"?><requestForLocationInformation><oneShot/></requestForLocationInformation>`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{
				GeolocationPIDFInvite: []int{GeolocationPIDFEmergencyWiFi},
				GeolocationCountry:    "US",
				Logger:                testLogger(),
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "PUBLISH":
					if got := msg.Header("Event"); got != presenceEventPackage {
						t.Errorf("PUBLISH Event = %q, want %q", got, presenceEventPackage)
					}
					if got := msg.Header("Content-Type"); got != "application/pidf+xml" {
						t.Errorf("PUBLISH Content-Type = %q, want application/pidf+xml", got)
					}
					if !strings.Contains(string(msg.Body), "<country>US</country>") {
						t.Errorf("PUBLISH body = %q, want PIDF country", string(msg.Body))
					}
					transport.queue(okForRequest(msg))
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "911", Emergency: true})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.mu.Lock()
			info := sip.NewRequest("INFO", call.targetURI)
			info.Headers.Add("Via", "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKcurrentlocation")
			info.Headers.Add("From", call.remoteTo)
			info.Headers.Add("To", fmt.Sprintf("<%s>;tag=%s", call.localURI, call.localTag))
			info.Headers.Add("Call-ID", call.id)
			call.mu.Unlock()
			info.Headers.Add("CSeq", "2 INFO")
			info.Headers.Add("Info-Package", currentLocationDiscoveryInfoPackage)
			info.Headers.Add("Content-Type", currentLocationDiscoveryContentType)
			info.Headers.Add("Content-Disposition", currentLocationDiscoveryDisposition)
			info.Body = []byte(tt.body)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: info, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest(INFO) error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest(INFO) handled = false, want true")
			}
			if got := transport.messagesByStatus(sipStatusOK, "INFO"); len(got) != 1 {
				t.Fatalf("200 INFO response count = %d, want 1", len(got))
			}
			if got := transport.messagesByMethod("PUBLISH"); len(got) != 1 {
				t.Fatalf("PUBLISH count = %d, want 1", len(got))
			}
		})
	}
}

func TestDialAcceptsMultipartAnswerSDP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "final answer carries SDP inside multipart body"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				resp := callOK(msg)
				boundary := "answer-boundary"
				body, err := buildMultipartInviteBody(boundary, "pidf-answer", resp.Body, pidf.Build("sip:remote@one.att.net", "US"))
				if err != nil {
					t.Fatalf("buildMultipartInviteBody() error = %v", err)
				}
				resp.Headers = sip.UpsertHeader(resp.Headers, "Content-Type", `multipart/mixed; boundary=`+boundary)
				resp.Body = body
				transport.queue(resp)
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "+12242255559"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if call.State() != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", call.State(), CallStateConfirmed)
			}
		})
	}
}

func TestSDPBodyMultipartSessionPart(t *testing.T) {
	const boundary = "session-boundary"
	const wantSDP = "v=0\r\nm=audio 49170 RTP/AVP 0\r\n"

	multipartBody := func(t *testing.T, parts ...textproto.MIMEHeader) []byte {
		t.Helper()
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)
		if err := writer.SetBoundary(boundary); err != nil {
			t.Fatalf("SetBoundary() error = %v", err)
		}
		for _, header := range parts {
			body := header.Get("X-Test-Body")
			header.Del("X-Test-Body")
			part, err := writer.CreatePart(header)
			if err != nil {
				t.Fatalf("CreatePart() error = %v", err)
			}
			if _, err := part.Write([]byte(body)); err != nil {
				t.Fatalf("part.Write() error = %v", err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		return buf.Bytes()
	}
	part := func(mediaType, body string) textproto.MIMEHeader {
		header := textproto.MIMEHeader{}
		header.Set("Content-Type", mediaType)
		header.Set("X-Test-Body", body)
		return header
	}

	tests := []struct {
		name string
		body []byte
		ok   bool
		want string
	}{
		{
			name: "one SDP session part",
			body: multipartBody(t,
				part("application/sdp", wantSDP),
				part("application/pidf+xml", "<presence/>"),
			),
			ok:   true,
			want: wantSDP,
		},
		{
			name: "duplicate SDP session parts",
			body: multipartBody(t,
				part("application/sdp", wantSDP),
				part("application/sdp", "v=0\r\nm=audio 50000 RTP/AVP 8\r\n"),
			),
		},
		{
			name: "no SDP session part",
			body: multipartBody(t,
				part("application/pidf+xml", "<presence/>"),
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sdpBody(sip.Message{
				Headers: sip.Headers{{Name: "Content-Type", Value: `multipart/mixed; boundary=` + boundary}},
				Body:    tt.body,
			})
			if ok != tt.ok {
				t.Fatalf("sdpBody() ok = %v, want %v", ok, tt.ok)
			}
			if string(got) != tt.want {
				t.Fatalf("sdpBody() body = %q, want %q", string(got), tt.want)
			}
		})
	}
}

func TestAddInviteFeatureTags(t *testing.T) {
	tests := []struct {
		name          string
		cfg           Config
		wantSupported string
	}{
		{
			name:          "disabled",
			cfg:           Config{},
			wantSupported: sip.DefaultClientSupported,
		},
		{
			name: "reliable provisional enabled",
			cfg: Config{
				ReliableProvisional: true,
			},
			wantSupported: sip.DefaultClientSupported + ",100rel",
		},
		{
			name: "preconditions enabled",
			cfg: Config{
				Preconditions: true,
			},
			wantSupported: sip.DefaultClientSupported + ",100rel,precondition",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewRequest("INVITE", "sip:remote@example.com")
			msg.Headers.Add("Supported", sip.DefaultClientSupported)

			addInviteFeatureTags(&msg, tt.cfg)

			if got := msg.Header("Supported"); got != tt.wantSupported {
				t.Fatalf("Supported = %q, want %q", got, tt.wantSupported)
			}
		})
	}
}

func TestDialogSnapshotAddsSessionTimerSupportToNonACKRequests(t *testing.T) {
	snap := dialogSnapshot{
		id:           "call-1",
		localURI:     "sip:user@example.com",
		localTag:     "local-1",
		remoteTo:     "<sip:remote@example.com>;tag=remote-1",
		targetURI:    "sip:remote@example.com",
		routeSet:     []string{"<sip:pcscf.example.com;lr>"},
		inviteSeq:    1,
		sessionTimer: true,
		transport:    "TCP",
		contactHost:  "192.0.2.20",
		messagePort:  5062,
		contact:      "<sip:user@192.0.2.20:5062>",
	}
	tests := []struct {
		name      string
		msg       sip.Message
		wantTimer bool
	}{
		{
			name:      "BYE advertises timer",
			msg:       snap.buildDialogRequest("BYE", 2),
			wantTimer: true,
		},
		{
			name: "ACK keeps timer out",
			msg:  snap.buildACK(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sip.TokenListContains(tt.msg.Header("Supported"), sessionTimerOption)
			if got != tt.wantTimer {
				t.Fatalf("Supported = %q, timer present %t, want %t", tt.msg.Header("Supported"), got, tt.wantTimer)
			}
		})
	}
}

func TestACKMatchesRetransmittedInviteOKCSeq(t *testing.T) {
	tests := []struct {
		name        string
		inviteSeq   int64
		okCSeq      int64
		ackCSeq     string
		retransmit  bool
		wantMatches bool
	}{
		{
			name:        "initial invite without retransmit state",
			inviteSeq:   1,
			ackCSeq:     "1 ACK",
			wantMatches: true,
		},
		{
			name:        "reinvite ack matches current 2xx retransmit",
			inviteSeq:   1,
			okCSeq:      7,
			ackCSeq:     "7 ACK",
			retransmit:  true,
			wantMatches: true,
		},
		{
			name:       "initial ack does not stop reinvite retransmit",
			inviteSeq:  1,
			okCSeq:     7,
			ackCSeq:    "1 ACK",
			retransmit: true,
		},
		{
			name:      "method must be ack",
			inviteSeq: 1,
			ackCSeq:   "1 INVITE",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{inviteSeq: tt.inviteSeq}
			if tt.retransmit {
				call.inviteOKStop = make(chan struct{})
				call.inviteOKCSeq = tt.okCSeq
			}
			msg := sip.NewRequest("ACK", "sip:remote@example.com")
			msg.Headers.Add("CSeq", tt.ackCSeq)

			if got := call.ackMatchesInvite(msg); got != tt.wantMatches {
				t.Fatalf("ackMatchesInvite() = %v, want %v", got, tt.wantMatches)
			}
		})
	}
}
