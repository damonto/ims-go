package call

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"github.com/damonto/ims-client/usim"
)

type callStubCard struct{}

type callStubTransport struct {
	local  net.Addr
	remote net.Addr

	mu      sync.Mutex
	writes  [][]byte
	readCh  chan []byte
	closed  chan struct{}
	onWrite func(sip.Message)
}

type callMediaTransport struct {
	local *net.UDPAddr

	mu       sync.Mutex
	remote   net.Addr
	onPacket func(MediaPacket)
	closed   bool
}

func newCallStubTransport() *callStubTransport {
	return &callStubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		readCh: make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func (callStubCard) IMSI() string { return "001010123456789" }
func (callStubCard) MCC() string  { return "001" }
func (callStubCard) MNC() string  { return "001" }
func (callStubCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("call-test-ck"),
		IK:  []byte("call-test-ik"),
	}, nil
}

func (t *callStubTransport) LocalAddr() net.Addr  { return t.local }
func (t *callStubTransport) RemoteAddr() net.Addr { return t.remote }

func (t *callStubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-t.closed:
		return nil, nil, errors.New("transport is closed")
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}

func (t *callStubTransport) WritePacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	t.writes = append(t.writes, append([]byte(nil), data...))
	onWrite := t.onWrite
	t.mu.Unlock()
	if onWrite != nil {
		var msg sip.Message
		if _, err := msg.ReadFrom(bytes.NewReader(data)); err == nil {
			onWrite(msg)
		}
	}
	return nil
}

func (t *callStubTransport) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func (t *callStubTransport) queue(msg sip.Message) {
	t.readCh <- msg.Bytes()
}

func (t *callStubTransport) countMethod(method string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	count := 0
	for _, data := range t.writes {
		var msg sip.Message
		if _, err := msg.ReadFrom(bytes.NewReader(data)); err != nil {
			continue
		}
		if msg.Method() == method {
			count++
		}
	}
	return count
}

func (t *callStubTransport) messagesByMethod(method string) []sip.Message {
	t.mu.Lock()
	defer t.mu.Unlock()
	var messages []sip.Message
	for _, data := range t.writes {
		var msg sip.Message
		if _, err := msg.ReadFrom(bytes.NewReader(data)); err != nil {
			continue
		}
		if msg.Method() == method {
			messages = append(messages, msg)
		}
	}
	return messages
}

func (t *callMediaTransport) LocalAddr() net.Addr { return t.local }

func (t *callMediaTransport) RemoteAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remote
}

func (t *callMediaTransport) ConfigureRemote(ctx context.Context, cfg MediaConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.remote = &net.UDPAddr{IP: append(net.IP(nil), cfg.RemoteIP...), Port: cfg.RemotePort}
	t.onPacket = cfg.OnPacket
	return nil
}

func (t *callMediaTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (t *callMediaTransport) WritePacket(ctx context.Context, data []byte) error { return nil }

func (t *callMediaTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

func (t *callMediaTransport) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *callMediaTransport) notify(packet MediaPacket) {
	t.mu.Lock()
	onPacket := t.onPacket
	t.mu.Unlock()
	if onPacket != nil {
		onPacket(packet)
	}
}

func TestTargetURI(t *testing.T) {
	transport := newCallStubTransport()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer func() {
		_ = sess.Close()
	}()
	reg, err := registration.New(registration.Config{
		PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
		IMEI:            "123456789012345",
	}, sess, callStubCard{})
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

func TestDialUsesSIPAssociatedURIForOriginatingIdentity(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "tel default public identity has sip alias"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, callStubCard{})
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
					resp.Headers.Add("Security-Server", `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222`)
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

			svc, err := New(Config{}, sess, reg)
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
			if _, err := svc.Dial(context.Background(), Request{To: "+12242255559"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
		})
	}
}

func TestDialIncludesGeolocationPIDFWhenConfigured(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "multipart invite carries sdp and pidf location"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{IncludeGeolocationPIDF: true, GeolocationCountry: "US"}, sess, reg)
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
				if got := msg.Header("Accept"); !strings.Contains(got, "application/pidf+xml") {
					t.Fatalf("INVITE Accept = %q, want PIDF support", got)
				}
				if got := msg.Header("Geolocation"); !strings.HasPrefix(got, "<cid:pidf-") {
					t.Fatalf("INVITE Geolocation = %q, want cid PIDF reference", got)
				}
				if got := msg.Header("Geolocation-Routing"); got != "yes" {
					t.Fatalf("INVITE Geolocation-Routing = %q, want yes", got)
				}
				body, ok := sdpBody(msg)
				if !ok {
					t.Fatal("sdpBody() ok = false, want SDP part")
				}
				if !strings.Contains(string(body), "m=audio ") {
					t.Fatalf("SDP body = %q, want audio media", string(body))
				}
				if !strings.Contains(string(msg.Body), "application/pidf+xml") || !strings.Contains(string(msg.Body), "<country>US</country>") {
					t.Fatalf("INVITE body missing PIDF country:\n%s", string(msg.Body))
				}
				transport.queue(callOK(msg))
			}
			if _, err := svc.Dial(context.Background(), Request{To: "+12242255559"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
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
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{}, sess, reg)
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
				body, err := buildMultipartInviteBody(boundary, "pidf-answer", resp.Body, buildPIDF("sip:remote@one.att.net", "US"))
				if err != nil {
					t.Fatalf("buildMultipartInviteBody() error = %v", err)
				}
				resp.Headers = sip.UpsertHeader(resp.Headers, "Content-Type", `multipart/mixed; boundary=`+boundary)
				resp.Body = body
				transport.queue(resp)
			}
			call, err := svc.Dial(context.Background(), Request{To: "+12242255559"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if call.State() != StateActive {
				t.Fatalf("call.State() = %q, want %q", call.State(), StateActive)
			}
		})
	}
}

func TestIncomingInviteRingingResponseIncludesContact(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "ringing response carries voice contact"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer func() {
				_ = sess.Close()
			}()
			reg, err := registration.New(registration.Config{
				PrivateIdentity:   "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:    "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:        "ims.mnc001.mcc001.3gppnetwork.org",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
			}()

			var ringing sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 180 {
					ringing = msg
				}
			}
			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: delayedInvite(), Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}

			if ringing.StartLine == "" {
				t.Fatal("180 Ringing was not sent")
			}
			if got := ringing.Header("Contact"); !strings.Contains(got, `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`) {
				t.Fatalf("180 Contact = %q, want MMTEL feature tag", got)
			}
			if got := ringing.Header("Accept"); got != "application/sdp" {
				t.Fatalf("180 Accept = %q, want application/sdp", got)
			}
			if got := ringing.Header("P-Access-Network-Info"); got != "IEEE-802.11;i-wlan-node-id=aabbcc" {
				t.Fatalf("180 P-Access-Network-Info = %q, want access network", got)
			}
		})
	}
}

func TestDialHandlesRetransmittedInvite2xx(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "repeated 200 OK sends another ACK and preserves DTMF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{
				TransactionTimers: session.TransactionTimers{T1: 10 * time.Millisecond, T2: 20 * time.Millisecond},
			}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{}, sess, reg)
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

			var ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" || ok200.StartLine != "" {
					return
				}
				ok200 = callOK(msg)
				transport.queue(ok200)
			}

			dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
			defer dialCancel()
			call, err := svc.Dial(dialCtx, Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			media := call.Media()
			if media.DTMFPayloadType != 101 || media.DTMFClockRate != 8000 {
				t.Fatalf("Media() DTMF = %d/%d, want 101/8000", media.DTMFPayloadType, media.DTMFClockRate)
			}
			if !waitForCallTest(func() bool { return transport.countMethod("ACK") == 1 }) {
				t.Fatalf("ACK count = %d, want 1", transport.countMethod("ACK"))
			}

			transport.queue(ok200)
			if !waitForCallTest(func() bool { return transport.countMethod("ACK") == 2 }) {
				t.Fatalf("ACK count after retransmitted 2xx = %d, want 2", transport.countMethod("ACK"))
			}
		})
	}
}

func TestDialPreparesMediaBeforeInvite(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "prepare media sees local port before invite is written"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			prepared := false
			svc, err := New(Config{
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.LocalPort != 40000 {
						t.Fatalf("PrepareMedia LocalPort = %d, want 40000", cfg.LocalPort)
					}
					if len(cfg.RemoteIP) != 0 || cfg.RemotePort != 0 {
						t.Fatalf("PrepareMedia remote = %v:%d, want empty", cfg.RemoteIP, cfg.RemotePort)
					}
					prepared = true
					return nil, nil
				},
			}, sess, reg)
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
				if !prepared {
					t.Fatal("INVITE was written before PrepareMedia")
				}
				if got := msg.Header("P-Early-Media"); got != "supported" {
					t.Fatalf("INVITE P-Early-Media = %q, want supported", got)
				}
				if got := msg.Header("Supported"); !strings.Contains(got, "100rel") {
					t.Fatalf("INVITE Supported = %q, want 100rel option tag", got)
				}
				if got := msg.Header("Session-Expires"); got != "" {
					t.Fatalf("INVITE Session-Expires = %q, want empty initial session interval", got)
				}
				if got := msg.Header("Allow"); !strings.Contains(got, "PRACK") {
					t.Fatalf("INVITE Allow = %q, want PRACK", got)
				}
				if got := msg.Header("P-Preferred-Service"); got != mmtelICSI {
					t.Fatalf("INVITE P-Preferred-Service = %q, want %q", got, mmtelICSI)
				}
				if got := msg.Header("Accept-Contact"); !strings.Contains(got, `+g.3gpp.icsi-ref="`+mmtelICSIEncoded+`"`) {
					t.Fatalf("INVITE Accept-Contact = %q, want MMTEL ICSI", got)
				}
				transport.queue(callOK(msg))
			}
			if _, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
		})
	}
}

func TestDialEndsAfterRTPInactivity(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "rtp packet resets inactivity timer before call ends"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			timeout := 80 * time.Millisecond
			events := make(chan Event, 16)
			media := &callMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{
				RTPInactivityTimeout:  timeout,
				RTCPInactivityTimeout: time.Second,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnEvent: func(event Event) { events <- event },
			}, sess, reg)
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

			mediaClosedBeforeBYE := make(chan bool, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					mediaClosedBeforeBYE <- media.isClosed()
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			time.Sleep(timeout / 2)
			media.notify(MediaPacket{})
			if waitForCallEvent(events, StateEnded, "rtp inactivity timeout", timeout*3/4) {
				t.Fatal("call ended before reset RTP inactivity timeout elapsed")
			}
			if !waitForCallEvent(events, StateEnded, "rtp inactivity timeout", 2*timeout) {
				t.Fatalf("call state = %s, want %s after RTP inactivity", call.State(), StateEnded)
			}
			select {
			case closed := <-mediaClosedBeforeBYE:
				if !closed {
					t.Fatal("media transport was open while sending inactivity BYE")
				}
			default:
				t.Fatal("BYE was not sent after RTP inactivity")
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaBearerReleased {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaBearerReleased)
			}
		})
	}
}

func TestDialEndsAfterRTCPBye(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "rtcp bye releases dialog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			events := make(chan Event, 16)
			media := &callMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{
				RTPInactivityTimeout:  time.Second,
				RTCPInactivityTimeout: time.Second,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnEvent: func(event Event) { events <- event },
			}, sess, reg)
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

			mediaClosedBeforeBYE := make(chan bool, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					mediaClosedBeforeBYE <- media.isClosed()
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			media.notify(MediaPacket{RTCP: true, RTCPBye: true})
			if !waitForCallEvent(events, StateEnded, "rtcp bye", time.Second) {
				t.Fatalf("call state = %s, want %s after RTCP BYE", call.State(), StateEnded)
			}
			select {
			case closed := <-mediaClosedBeforeBYE:
				if !closed {
					t.Fatal("media transport was open while sending RTCP BYE release")
				}
			default:
				t.Fatal("BYE was not sent after RTCP BYE")
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaBearerReleased {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaBearerReleased)
			}
		})
	}
}

func TestIncomingCancelEndsRingingCall(t *testing.T) {
	tests := []struct {
		name      string
		wantState State
		wantCause string
	}{
		{name: "cancel before answer", wantState: StateEnded, wantCause: "remote cancel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration New() error = %v", err)
			}
			events := make(chan Event, 4)
			svc, err := New(Config{
				OnEvent: func(event Event) {
					events <- event
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			invite := delayedInvite()
			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: invite, Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}
			cancel := cancelForInvite(invite)
			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: cancel, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest(CANCEL) error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest(CANCEL) = false, want true")
			}
			call := svc.lookupCall(invite.Header("Call-ID"))
			if call != nil {
				t.Fatalf("lookupCall() = %v, want nil after CANCEL", call)
			}
			if !waitForCallEvent(events, tt.wantState, tt.wantCause, time.Second) {
				t.Fatalf("event %s/%q not observed", tt.wantState, tt.wantCause)
			}
		})
	}
}

func TestDialSendsPRACKForReliableProvisionalResponse(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 with 100rel is acknowledged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration New() error = %v", err)
			}

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "REGISTER" {
					return
				}
				if transport.countMethod("REGISTER") == 1 {
					resp := callStatus(msg, 401, "Unauthorized")
					resp.Headers.Add("WWW-Authenticate", `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`)
					resp.Headers.Add("Security-Server", `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222`)
					transport.queue(resp)
					return
				}
				resp := callStatus(msg, 200, "OK")
				resp.Headers.Add("Authentication-Info", `nextnonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="`)
				resp.Headers.Add("Service-Route", "<sip:pcscf.example.com;lr>")
				transport.queue(resp)
			}
			if err := reg.Register(context.Background()); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			svc, err := New(Config{
				OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &callMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
				},
			}, sess, reg)
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

			var invite sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					transport.queue(reliableCallProgress(msg))
				case "PRACK":
					transport.queue(callStatus(msg, 200, "OK"))
					transport.queue(callOKWithoutSDP(invite, "early-tag"))
				}
			}

			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if call.State() != StateActive {
				t.Fatalf("call.State() = %q, want %q", call.State(), StateActive)
			}
			pracks := transport.messagesByMethod("PRACK")
			if len(pracks) != 1 {
				t.Fatalf("PRACK count = %d, want 1", len(pracks))
			}
			prack := pracks[0]
			if got := prack.Header("RAck"); got != "7 1 INVITE" {
				t.Fatalf("PRACK RAck = %q, want %q", got, "7 1 INVITE")
			}
			if got := sip.RequestURI(prack); got != "sip:early@192.0.2.10:5060" {
				t.Fatalf("PRACK Request-URI = %q, want early Contact URI", got)
			}
			if got := sip.HeaderTag(prack.Header("To")); got != "early-tag" {
				t.Fatalf("PRACK To tag = %q, want early-tag", got)
			}
			if got := prack.Header("Require"); got != "sec-agree" {
				t.Fatalf("PRACK Require = %q, want sec-agree", got)
			}
			media := call.Media()
			if !media.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) || media.RemotePort != 50000 {
				t.Fatalf("call media = %+v, want early SDP answer media", media)
			}
		})
	}
}

func TestDialEndsAfterRTCPInactivity(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "missing rtcp releases media dialog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			timeout := 80 * time.Millisecond
			events := make(chan Event, 16)
			media := &callMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{
				RTPInactivityTimeout:  time.Second,
				RTCPInactivityTimeout: timeout,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnEvent: func(event Event) { events <- event },
			}, sess, reg)
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

			mediaClosedBeforeBYE := make(chan bool, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					mediaClosedBeforeBYE <- media.isClosed()
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			time.Sleep(timeout / 2)
			media.notify(MediaPacket{RTCP: true})
			if waitForCallEvent(events, StateEnded, "rtcp inactivity timeout", timeout*3/4) {
				t.Fatal("call ended before reset RTCP inactivity timeout elapsed")
			}
			if !waitForCallEvent(events, StateEnded, "rtcp inactivity timeout", 2*timeout) {
				t.Fatalf("call state = %s, want %s after RTCP inactivity", call.State(), StateEnded)
			}
			select {
			case closed := <-mediaClosedBeforeBYE:
				if !closed {
					t.Fatal("media transport was open while sending RTCP inactivity BYE")
				}
			default:
				t.Fatal("BYE was not sent after RTCP inactivity")
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaBearerReleased {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaBearerReleased)
			}
		})
	}
}

func TestDialReleasesForkedInvite2xx(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "different final dialog is acked then released"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{}, sess, reg)
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

			var firstOK, forkedOK sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					if firstOK.StartLine != "" {
						return
					}
					firstOK = callOK(msg)
					forkedOK = callOK(msg)
					forkedOK.Headers = sip.UpsertHeader(forkedOK.Headers, "To", sip.WithTag(msg.Header("To"), "", "forked-tag"))
					forkedOK.Headers = sip.UpsertHeader(forkedOK.Headers, "Contact", "<sip:forked@192.0.2.11:5060>")
					transport.queue(firstOK)
				case "BYE":
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}

			if _, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			transport.queue(forkedOK)

			if !waitForCallTest(func() bool { return transport.countMethod("ACK") == 2 && transport.countMethod("BYE") == 1 }) {
				t.Fatalf("ACK/BYE count = %d/%d, want 2/1", transport.countMethod("ACK"), transport.countMethod("BYE"))
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("To"); !strings.Contains(got, "forked-tag") {
				t.Fatalf("forked BYE To = %q, want forked tag", got)
			}
			if got := byes[0].Header("Reason"); got != reasonUserTriggered {
				t.Fatalf("forked BYE Reason = %q, want %q", got, reasonUserTriggered)
			}
		})
	}
}

func TestHangupIsIdempotentForTerminalStates(t *testing.T) {
	tests := []struct {
		name  string
		state State
	}{
		{name: "ending", state: StateEnding},
		{name: "ended", state: StateEnded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{state: tt.state}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
		})
	}
}

func TestIncomingDelayedOfferCall(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "invite without sdp is answered with offer and ack answer activates call"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			incoming := make(chan Incoming, 1)
			events := make(chan Event, 16)
			media := &callMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.RemotePort != 0 || len(cfg.RemoteIP) != 0 {
						t.Fatalf("PrepareMedia remote = %v:%d, want empty", cfg.RemoteIP, cfg.RemotePort)
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncoming: func(event Incoming) { incoming <- event },
				OnEvent:    func(event Event) { events <- event },
			}, sess, reg)
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

			invite := delayedInvite()
			var ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					ok200 = msg
				}
			}
			transport.queue(invite)

			var got Incoming
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			if len(got.Offer.Codecs) != 0 {
				t.Fatalf("incoming offer codecs = %v, want empty delayed offer", got.Offer.Codecs)
			}
			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			if !waitForCallTest(func() bool { return ok200.StartLine != "" }) {
				t.Fatal("200 OK with SDP offer was not sent")
			}
			if len(ok200.Body) == 0 || !strings.Contains(ok200.Header("Content-Type"), "application/sdp") {
				t.Fatalf("200 OK SDP = content-type %q body len %d, want application/sdp body", ok200.Header("Content-Type"), len(ok200.Body))
			}

			transport.queue(delayedOfferACK(invite, ok200))
			if !waitForCallEvent(events, StateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK SDP answer", got.Call.State())
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("media remote = %v, want 192.0.2.10:50000", remote)
			}
		})
	}
}

func TestIncomingInviteAnswerIncludesGeolocationPIDFWhenConfigured(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "200 OK carries multipart sdp and pidf location"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			incoming := make(chan Incoming, 1)
			svc, err := New(Config{
				IncludeGeolocationPIDF: true,
				GeolocationCountry:     "US",
				OnIncoming:             func(event Incoming) { incoming <- event },
			}, sess, reg)
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

			var ringing, ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					ringing = msg
				}
				if msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					ok200 = msg
				}
			}
			transport.queue(delayedInvite())

			var got Incoming
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			if !waitForCallTest(func() bool { return ok200.StartLine != "" }) {
				t.Fatal("200 OK was not sent")
			}
			if ringing.StartLine == "" {
				t.Fatal("180 Ringing was not sent")
			}
			if got, want := sip.HeaderTag(ok200.Header("To")), sip.HeaderTag(ringing.Header("To")); got != want {
				t.Fatalf("200 OK To tag = %q, want same tag as 180 Ringing %q", got, want)
			}
			if got := ok200.Header("Allow"); got != sip.DefaultClientAllow {
				t.Fatalf("200 OK Allow = %q, want %q", got, sip.DefaultClientAllow)
			}
			if got := ok200.Header("Accept"); !strings.Contains(got, "application/pidf+xml") {
				t.Fatalf("200 OK Accept = %q, want PIDF support", got)
			}
			if got := ok200.Header("Geolocation"); !strings.HasPrefix(got, "<cid:pidf-") {
				t.Fatalf("200 OK Geolocation = %q, want cid PIDF reference", got)
			}
			if got := ok200.Header("Geolocation-Routing"); got != "yes" {
				t.Fatalf("200 OK Geolocation-Routing = %q, want yes", got)
			}
			body, ok := sdpBody(ok200)
			if !ok {
				t.Fatal("sdpBody() ok = false, want SDP part")
			}
			if !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("SDP body = %q, want audio media", string(body))
			}
			if !strings.Contains(ok200.Header("Content-Type"), "multipart/mixed") {
				t.Fatalf("200 OK Content-Type = %q, want multipart/mixed", ok200.Header("Content-Type"))
			}
			if !strings.Contains(string(ok200.Body), "application/pidf+xml") || !strings.Contains(string(ok200.Body), "<country>US</country>") {
				t.Fatalf("200 OK body missing PIDF country:\n%s", string(ok200.Body))
			}
		})
	}
}

func TestIncomingDelayedOfferAnswersInFinalOK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "final 200 carries delayed-offer SDP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newCallStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, callStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			incoming := make(chan Incoming, 1)
			events := make(chan Event, 8)
			media := &callMediaTransport{}
			svc, err := New(Config{
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncoming: func(event Incoming) { incoming <- event },
				OnEvent:    func(event Event) { events <- event },
			}, sess, reg)
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

			invite := reliableDelayedInvite()
			var ringing, inviteOK sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					ringing = msg
				}
				if msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					inviteOK = msg
				}
			}
			transport.queue(invite)

			var got Incoming
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			if !waitForCallTest(func() bool { return ringing.StartLine != "" }) {
				t.Fatal("180 Ringing was not sent")
			}
			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			if !waitForCallTest(func() bool { return inviteOK.StartLine != "" }) {
				t.Fatal("200 OK for INVITE was not sent")
			}
			if body, ok := sdpBody(inviteOK); !ok || !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("200 OK INVITE SDP present = %v body=%q, want audio offer", ok, string(body))
			}
			if got := inviteOK.Header("Session-Expires"); got != "" {
				t.Fatalf("200 OK INVITE Session-Expires = %q, want empty", got)
			}

			transport.queue(delayedOfferACK(invite, inviteOK))
			if !waitForCallEvent(events, StateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK", got.Call.State())
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("media remote = %v, want 192.0.2.10:50000", remote)
			}
		})
	}
}

func callOK(req sip.Message) sip.Message {
	resp := sip.NewResponse(200, "OK")
	resp.Headers = sip.ResponseHeaders(req, 200)
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Header("To"), "", "remote-tag"))
	resp.Headers.Add("Contact", "<sip:remote@192.0.2.10:5060>")
	resp.Headers.Add("Content-Type", "application/sdp")
	resp.Body = []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 50000 RTP/AVP 104 101\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=ptime:20\r\n")
	return resp
}

func callOKWithoutSDP(req sip.Message, tag string) sip.Message {
	resp := sip.NewResponse(200, "OK")
	resp.Headers = sip.ResponseHeaders(req, 200)
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Header("To"), "", tag))
	resp.Headers.Add("Contact", "<sip:remote@192.0.2.10:5060>")
	return resp
}

func reliableCallProgress(req sip.Message) sip.Message {
	resp := sip.NewResponse(183, "Session Progress")
	resp.Headers = sip.ResponseHeaders(req, 183)
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Header("To"), "", "early-tag"))
	resp.Headers.Add("Require", "100rel")
	resp.Headers.Add("RSeq", "7")
	resp.Headers.Add("Contact", "<sip:early@192.0.2.10:5060>")
	resp.Headers.Add("Record-Route", "<sip:pcscf.example.com;lr>")
	resp.Headers.Add("Content-Type", "application/sdp")
	resp.Body = []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 50000 RTP/AVP 104 101\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=ptime:20\r\n")
	return resp
}

func callStatus(req sip.Message, code int, reason string) sip.Message {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req, code)
	return resp
}

func delayedInvite() sip.Message {
	msg := sip.NewRequest("INVITE", "sip:001010123456789@192.0.2.20:5062")
	msg.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKdelayed")
	msg.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
	msg.Headers.Add("To", "<sip:001010123456789@example.com>")
	msg.Headers.Add("Call-ID", "delayed-offer-call")
	msg.Headers.Add("CSeq", "1 INVITE")
	msg.Headers.Add("Contact", "<sip:caller@192.0.2.10:5060>")
	return msg
}

func reliableDelayedInvite() sip.Message {
	msg := delayedInvite()
	msg.Headers.Add("Supported", "100rel")
	msg.Headers.Add("Allow", sip.DefaultClientAllow)
	return msg
}

func prackForReliableProvisional(invite, provisional sip.Message) sip.Message {
	msg := sip.NewRequest("PRACK", sip.AddressURI(provisional.Header("Contact")))
	msg.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKprack")
	msg.Headers.Add("From", invite.Header("From"))
	msg.Headers.Add("To", provisional.Header("To"))
	msg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	msg.Headers.Add("CSeq", "2 PRACK")
	msg.Headers.Add("RAck", provisional.Header("RSeq")+" 1 INVITE")
	msg.Headers.Add("Content-Type", "application/sdp")
	msg.Body = []byte("v=0\r\n" +
		"o=- 2 1 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 50000 RTP/AVP 104 101\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=ptime:20\r\n")
	return msg
}

func cancelForInvite(invite sip.Message) sip.Message {
	msg := sip.NewRequest("CANCEL", sip.RequestURI(invite))
	msg.Headers.Add("Via", invite.Header("Via"))
	msg.Headers.Add("From", invite.Header("From"))
	msg.Headers.Add("To", invite.Header("To"))
	msg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	msg.Headers.Add("CSeq", "1 CANCEL")
	return msg
}

func ackWithoutSDP(invite, ok sip.Message) sip.Message {
	msg := sip.NewRequest("ACK", sip.AddressURI(ok.Header("Contact")))
	msg.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKack")
	msg.Headers.Add("From", invite.Header("From"))
	msg.Headers.Add("To", ok.Header("To"))
	msg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	msg.Headers.Add("CSeq", "1 ACK")
	return msg
}

func delayedOfferACK(invite, ok sip.Message) sip.Message {
	msg := sip.NewRequest("ACK", sip.AddressURI(ok.Header("Contact")))
	msg.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKdelayedack")
	msg.Headers.Add("From", invite.Header("From"))
	msg.Headers.Add("To", ok.Header("To"))
	msg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	msg.Headers.Add("CSeq", "1 ACK")
	msg.Headers.Add("Content-Type", "application/sdp")
	msg.Body = []byte("v=0\r\n" +
		"o=- 2 1 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 50000 RTP/AVP 104 101\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=ptime:20\r\n")
	return msg
}

func waitForCallEvent(events <-chan Event, state State, cause string, timeout time.Duration) bool {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if event.State == state && event.Cause == cause {
				return true
			}
		case <-timer.C:
			return false
		}
	}
}

func waitForCallTest(fn func() bool) bool {
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fn()
}
