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
	rtcpCh   chan []byte
}

type callRTPOnlyMediaTransport struct {
	local *net.UDPAddr

	mu       sync.Mutex
	remote   net.Addr
	onPacket func(MediaPacket)
	closed   bool
	writeCh  chan []byte
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

func (t *callStubTransport) messagesByStatus(code int, cseqMethod string) []sip.Message {
	t.mu.Lock()
	defer t.mu.Unlock()
	var messages []sip.Message
	for _, data := range t.writes {
		var msg sip.Message
		if _, err := msg.ReadFrom(bytes.NewReader(data)); err != nil {
			continue
		}
		if msg.StatusCode() == code && (cseqMethod == "" || sip.CSeqMethod(msg.Header("CSeq")) == cseqMethod) {
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

func (t *callMediaTransport) WriteRTCP(ctx context.Context, data []byte) error {
	t.mu.Lock()
	ch := t.rtcpCh
	t.mu.Unlock()
	if ch == nil {
		return nil
	}
	select {
	case ch <- append([]byte(nil), data...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

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

func (t *callRTPOnlyMediaTransport) LocalAddr() net.Addr { return t.local }

func (t *callRTPOnlyMediaTransport) RemoteAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remote
}

func (t *callRTPOnlyMediaTransport) ConfigureRemote(ctx context.Context, cfg MediaConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.remote = &net.UDPAddr{IP: append(net.IP(nil), cfg.RemoteIP...), Port: cfg.RemotePort}
	t.onPacket = cfg.OnPacket
	return nil
}

func (t *callRTPOnlyMediaTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (t *callRTPOnlyMediaTransport) WritePacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	ch := t.writeCh
	t.mu.Unlock()
	if ch == nil {
		return nil
	}
	select {
	case ch <- append([]byte(nil), data...):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *callRTPOnlyMediaTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
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
			if call.State() != StateConfirmed {
				t.Fatalf("call.State() = %q, want %q", call.State(), StateConfirmed)
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
				if got := msg.Header("Supported"); !strings.Contains(got, "199") {
					t.Fatalf("INVITE Supported = %q, want 199 option tag", got)
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
				if got := msg.Header("Contact"); !strings.Contains(got, ";audio;") {
					t.Fatalf("INVITE Contact = %q, want audio media feature tag", got)
				}
				transport.queue(callOK(msg))
			}
			if _, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
		})
	}
}

func TestHangupCancelsOutgoingDialBeforeFinalResponse(t *testing.T) {
	tests := []struct {
		name        string
		finalInvite func(sip.Message) sip.Message
		wantBYE     bool
	}{
		{
			name: "487 after cancel",
			finalInvite: func(invite sip.Message) sip.Message {
				return inviteTerminated(invite)
			},
		},
		{
			name: "2xx races with cancel",
			finalInvite: func(invite sip.Message) sip.Message {
				return callOK(invite)
			},
			wantBYE: true,
		},
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
			events := make(chan Event, 8)
			svc, err := New(Config{OnEvent: func(event Event) { events <- event }}, sess, reg)
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
					transport.queue(trying(msg))
				case "CANCEL":
					transport.queue(cancelOK(msg))
					transport.queue(tt.finalInvite(invite))
				case "BYE":
					transport.queue(okForRequest(msg))
				}
			}

			dialErr := make(chan error, 1)
			go func() {
				_, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
				dialErr <- err
			}()

			event := nextCallEvent(t, events, StateDialing, "", time.Second)
			call := svc.lookupCall(event.CallID)
			if call == nil {
				t.Fatalf("lookupCall(%q) = nil", event.CallID)
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}

			if !waitForCallEvent(events, StateEnded, "cancelled", time.Second) {
				t.Fatalf("call state = %s, want ended after cancel", call.State())
			}
			select {
			case err := <-dialErr:
				if err == nil || !strings.Contains(err.Error(), "cancelled") {
					t.Fatalf("Dial() error = %v, want cancelled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Dial() did not return after cancel")
			}

			cancels := transport.messagesByMethod("CANCEL")
			if len(cancels) != 1 {
				t.Fatalf("CANCEL count = %d, want 1", len(cancels))
			}
			if got := cancels[0].Header("Reason"); got != reasonUserTriggered {
				t.Fatalf("CANCEL Reason = %q, want %q", got, reasonUserTriggered)
			}
			if got, want := sip.CSeqNumber(cancels[0].Header("CSeq")), sip.CSeqNumber(invite.Header("CSeq")); got != want {
				t.Fatalf("CANCEL CSeq number = %d, want %d", got, want)
			}
			if tt.wantBYE {
				if !waitForCallTest(func() bool { return transport.countMethod("BYE") == 1 }) {
					t.Fatalf("BYE count = %d, want 1", transport.countMethod("BYE"))
				}
			}
		})
	}
}

func TestAddInviteSessionTimer(t *testing.T) {
	tests := []struct {
		name                string
		cfg                 Config
		wantSupported       string
		wantSessionExpires  string
		wantMinSE           string
		wantNoSessionHeader bool
	}{
		{
			name:               "disabled",
			cfg:                Config{},
			wantSupported:      sip.DefaultClientSupported,
			wantSessionExpires: "",
		},
		{
			name: "timer support only",
			cfg: Config{
				SessionTimer: true,
			},
			wantSupported:       sip.DefaultClientSupported + ",timer",
			wantNoSessionHeader: true,
		},
		{
			name: "configured interval omitted in initial invite",
			cfg: Config{
				SessionTimer:      true,
				SessionExpires:    3600 * time.Second,
				MinSessionExpires: 600 * time.Second,
			},
			wantSupported:       sip.DefaultClientSupported + ",timer",
			wantNoSessionHeader: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewRequest("INVITE", "sip:remote@example.com")
			msg.Headers.Add("Supported", sip.DefaultClientSupported)

			addInviteSessionTimer(&msg, tt.cfg)

			if got := msg.Header("Supported"); got != tt.wantSupported {
				t.Fatalf("Supported = %q, want %q", got, tt.wantSupported)
			}
			if got := msg.Header("Min-SE"); got != tt.wantMinSE {
				t.Fatalf("Min-SE = %q, want %q", got, tt.wantMinSE)
			}
			if got := msg.Header("Session-Expires"); got != tt.wantSessionExpires {
				t.Fatalf("Session-Expires = %q, want %q", got, tt.wantSessionExpires)
			}
			if tt.wantNoSessionHeader && msg.Header("Session-Expires") != "" {
				t.Fatalf("Session-Expires = %q, want omitted", msg.Header("Session-Expires"))
			}
		})
	}
}

func TestAddInviteOKSessionTimerUsesIR92Default(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		min  string
		want string
	}{
		{
			name: "configured shorter interval ignored",
			cfg:  Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			want: "1800;refresher=uac",
		},
		{
			name: "min se above default",
			cfg:  Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			min:  "3600",
			want: "3600;refresher=uac",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invite := sip.NewRequest("INVITE", "sip:local@example.com")
			invite.Headers.Add("Supported", "timer")
			if tt.min != "" {
				invite.Headers.Add("Min-SE", tt.min)
			}
			resp := sip.NewResponse(200, "OK")

			addInviteOKSessionTimer(&resp, invite, tt.cfg)

			if got := resp.Header("Session-Expires"); got != tt.want {
				t.Fatalf("Session-Expires = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDialRetriesInviteAfterSessionIntervalTooSmall(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "422 with Min-SE"},
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
			svc, err := New(Config{SessionTimer: true}, sess, reg)
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				switch invites {
				case 1:
					if got := msg.Header("Session-Expires"); got != "" {
						t.Fatalf("initial Session-Expires = %q, want omitted", got)
					}
					resp := callStatus(msg, 422, "Session Interval Too Small")
					resp.Headers.Add("Min-SE", "3600")
					transport.queue(resp)
				case 2:
					if got := msg.Header("Session-Expires"); got != "3600" {
						t.Fatalf("retry Session-Expires = %q, want 3600", got)
					}
					if got := msg.Header("Min-SE"); got != "3600" {
						t.Fatalf("retry Min-SE = %q, want 3600", got)
					}
					transport.queue(callOK(msg))
				default:
					t.Fatalf("INVITE count = %d, want 2", invites)
				}
			}

			if _, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if invites != 2 {
				t.Fatalf("INVITE count = %d, want 2", invites)
			}
		})
	}
}

func TestDialSkipsSessionTimerRetryAfterCancel(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "cancelled call does not retry after 422"},
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
			svc, err := New(Config{SessionTimer: true}, sess, reg)
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				if invites != 1 {
					t.Fatalf("INVITE count = %d, want no retry after cancel", invites)
				}
				call := svc.lookupCall(msg.Header("Call-ID"))
				if call == nil {
					t.Fatalf("lookupCall(%q) = nil", msg.Header("Call-ID"))
				}
				if err := call.Hangup(context.Background()); err != nil {
					t.Fatalf("Hangup() error = %v", err)
				}
				resp := callStatus(msg, 422, "Session Interval Too Small")
				resp.Headers.Add("Min-SE", "3600")
				transport.queue(resp)
			}

			if _, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
				t.Fatalf("Dial() error = %v, want cancelled", err)
			}
			if invites != 1 {
				t.Fatalf("INVITE count = %d, want 1", invites)
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

func TestOpenMediaRequiresTransport(t *testing.T) {
	tests := []struct {
		name   string
		closed bool
	}{
		{name: "active call"},
		{name: "closed call", closed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{
				service: &Service{cfg: Config{
					OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
						return nil, nil
					},
				}},
				media:  NegotiatedMedia{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000},
				closed: tt.closed,
			}

			err := call.openMedia(context.Background())
			if err == nil || !strings.Contains(err.Error(), "media transport is nil") {
				t.Fatalf("openMedia() error = %v, want nil transport error", err)
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
			if call.State() != StateConfirmed {
				t.Fatalf("call.State() = %q, want %q", call.State(), StateConfirmed)
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

func TestDialMOCallRequestTimeoutStopsAfterFirstProvisional(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "100 Trying stops first provisional timer"},
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
			svc, err := New(Config{
				MOCallRequestTimeout: 50 * time.Millisecond,
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

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				transport.queue(trying(msg))
				go func() {
					time.Sleep(100 * time.Millisecond)
					transport.queue(callOK(msg))
				}()
			}
			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if call.State() != StateConfirmed {
				t.Fatalf("call.State() = %q, want %q", call.State(), StateConfirmed)
			}
		})
	}
}

func TestDialMOCallRequestTimeoutBeforeFirstProvisional(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "no 1xx aborts invite wait"},
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
			svc, err := New(Config{MOCallRequestTimeout: 40 * time.Millisecond}, sess, reg)
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

			_, err = svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err == nil || !strings.Contains(err.Error(), "first provisional") {
				t.Fatalf("Dial() error = %v, want first provisional timeout", err)
			}
		})
	}
}

func TestDialRingbackTimeoutCancelsInvite(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "180 ringing without final response is cancelled"},
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
			events := make(chan Event, 8)
			svc, err := New(Config{
				RingbackTimeout: 50 * time.Millisecond,
				OnEvent:         func(event Event) { events <- event },
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
					resp := callStatus(msg, 180, "Ringing")
					resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(msg.Header("To"), "", "remote-tag"))
					transport.queue(resp)
				case "CANCEL":
					transport.queue(cancelOK(msg))
					transport.queue(inviteTerminated(invite))
				}
			}

			_, err = svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err == nil || !strings.Contains(err.Error(), "cancelled") {
				t.Fatalf("Dial() error = %v, want cancelled", err)
			}
			if transport.countMethod("CANCEL") != 1 {
				t.Fatalf("CANCEL count = %d, want 1", transport.countMethod("CANCEL"))
			}
			if !waitForCallEvent(events, StateEnded, "cancelled", time.Second) {
				t.Fatal("cancelled event was not observed")
			}
		})
	}
}

func TestIncomingRingingTimeoutRejectsInvite(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "unanswered ringing call receives 486"},
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
			events := make(chan Event, 8)
			svc, err := New(Config{
				RingingTimeout: 50 * time.Millisecond,
				OnEvent:        func(event Event) { events <- event },
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

			transport.queue(delayedInvite())
			if !waitForCallTest(func() bool { return len(transport.messagesByStatus(486, "INVITE")) == 1 }) {
				t.Fatalf("486 count = %d, want 1", len(transport.messagesByStatus(486, "INVITE")))
			}
			if !waitForCallEvent(events, StateEnded, "ringing timeout", time.Second) {
				t.Fatal("ringing timeout event was not observed")
			}
			resp := transport.messagesByStatus(486, "INVITE")[0]
			if got := resp.Header("Server"); got == "" {
				t.Fatal("486 Server header is empty")
			}
		})
	}
}

func TestIncomingReliableDelayedOfferUsesPRACKAnswer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 carries offer and PRACK answer opens media"},
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
			events := make(chan Event, 16)
			media := &callMediaTransport{}
			svc, err := New(Config{
				ReliableProvisional: true,
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

			progressCh := make(chan sip.Message, 1)
			ringingCh := make(chan sip.Message, 1)
			prackOKCh := make(chan sip.Message, 2)
			inviteOKCh := make(chan sip.Message, 1)
			transport.onWrite = func(msg sip.Message) {
				switch {
				case msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					progressCh <- msg
				case msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					ringingCh <- msg
				case msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "PRACK":
					prackOKCh <- msg
				case msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					inviteOKCh <- msg
				}
			}

			invite := reliableDelayedInvite()
			transport.queue(invite)
			var got Incoming
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			var progress sip.Message
			select {
			case progress = <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress timed out")
			}
			if got := progress.Header("Require"); got != "100rel" {
				t.Fatalf("183 Require = %q, want 100rel", got)
			}
			if got := progress.Header("RSeq"); got != "1" {
				t.Fatalf("183 RSeq = %q, want 1", got)
			}
			if got := progress.Header("Server"); got == "" {
				t.Fatal("183 Server header is empty")
			}
			if body, ok := sdpBody(progress); !ok || !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("183 SDP present = %v body=%q, want audio offer", ok, string(body))
			}
			if len(transport.messagesByStatus(180, "INVITE")) != 0 {
				t.Fatal("180 Ringing was sent before PRACK")
			}

			goodPRACK := prackForReliableProvisional(invite, progress)
			transport.queue(goodPRACK)
			select {
			case <-prackOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for PRACK timed out")
			}
			var ringing sip.Message
			select {
			case ringing = <-ringingCh:
			case <-time.After(time.Second):
				t.Fatal("180 Ringing after PRACK timed out")
			}
			if got := ringing.Header("Require"); got != "100rel" {
				t.Fatalf("180 Require = %q, want 100rel", got)
			}
			if got := ringing.Header("RSeq"); got != "2" {
				t.Fatalf("180 RSeq = %q, want 2", got)
			}
			ringingPRACK := prackWithoutSDPForReliableProvisional(invite, ringing)
			ringingPRACK.Headers.Set("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKprack2")
			ringingPRACK.Headers.Set("CSeq", "3 PRACK")
			transport.queue(ringingPRACK)
			select {
			case <-prackOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for 180 PRACK timed out")
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("media remote = %v, want 192.0.2.10:50000", remote)
			}

			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			var inviteOK sip.Message
			select {
			case inviteOK = <-inviteOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for INVITE timed out")
			}
			if len(inviteOK.Body) != 0 {
				t.Fatalf("200 OK INVITE body len = %d, want no SDP after PRACK answer", len(inviteOK.Body))
			}
			transport.queue(ackWithoutSDP(invite, inviteOK))
			if !waitForCallEvent(events, StateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK", got.Call.State())
			}
		})
	}
}

func TestIncomingReliableDelayedOfferRejectsMismatchedPRACK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "wrong RAck does not complete reliable provisional"},
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
			media := &callMediaTransport{}
			svc, err := New(Config{
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
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

			progressCh := make(chan sip.Message, 1)
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					progressCh <- msg
				}
			}

			invite := reliableDelayedInvite()
			transport.queue(invite)
			var progress sip.Message
			select {
			case progress = <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress timed out")
			}
			badPRACK := prackForReliableProvisional(invite, progress)
			badPRACK.Headers.Set("RAck", "99 1 INVITE")
			transport.queue(badPRACK)

			if !waitForCallTest(func() bool { return len(transport.messagesByStatus(481, "PRACK")) == 1 }) {
				t.Fatalf("481 PRACK count = %d, want 1", len(transport.messagesByStatus(481, "PRACK")))
			}
			if len(transport.messagesByStatus(180, "INVITE")) != 0 {
				t.Fatal("180 Ringing was sent after mismatched PRACK")
			}
			if media.RemoteAddr() != nil {
				t.Fatalf("media remote = %v, want nil after rejected PRACK", media.RemoteAddr())
			}

			goodPRACK := prackForReliableProvisional(invite, progress)
			goodPRACK.Headers.Set("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKprack2")
			goodPRACK.Headers.Set("CSeq", "3 PRACK")
			transport.queue(goodPRACK)
			if !waitForCallTest(func() bool { return len(transport.messagesByStatus(200, "PRACK")) == 1 }) {
				t.Fatalf("200 PRACK count = %d, 400=%d 481=%d, want 1", len(transport.messagesByStatus(200, "PRACK")), len(transport.messagesByStatus(400, "PRACK")), len(transport.messagesByStatus(481, "PRACK")))
			}
			if !waitForCallTest(func() bool { return len(transport.messagesByStatus(180, "INVITE")) == 1 }) {
				t.Fatalf("180 count = %d, want 1 after matching PRACK", len(transport.messagesByStatus(180, "INVITE")))
			}
		})
	}
}

func TestDialDoesNotOpenUnauthorizedEarlyMedia(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "provisional SDP without P-Early-Media is stored but not rendered"},
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
			opened := make(chan MediaConfig, 2)
			svc, err := New(Config{
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					opened <- cfg
					return &callMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: cfg.LocalPort}}, nil
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
			prackSeen := make(chan struct{}, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					transport.queue(reliableCallProgress(msg))
				case "PRACK":
					prackSeen <- struct{}{}
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}

			errCh := make(chan error, 1)
			go func() {
				_, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
				errCh <- err
			}()
			select {
			case <-prackSeen:
			case <-time.After(time.Second):
				t.Fatal("PRACK was not sent")
			}
			select {
			case cfg := <-opened:
				t.Fatalf("OpenMedia before authorized early media/final response = %+v", cfg)
			case <-time.After(80 * time.Millisecond):
			}

			transport.queue(callOKWithoutSDP(invite, "early-tag"))
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("Dial() error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Dial() did not complete after final response")
			}
			select {
			case cfg := <-opened:
				if cfg.RemotePort != 50000 || !cfg.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) {
					t.Fatalf("OpenMedia remote = %v:%d, want 192.0.2.10:50000", cfg.RemoteIP, cfg.RemotePort)
				}
			case <-time.After(time.Second):
				t.Fatal("OpenMedia was not called after final response")
			}
		})
	}
}

func TestDialOpensAuthorizedEarlyMediaBeforeConfirmed(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 with P-Early-Media sendrecv opens early media"},
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
			events := make(chan Event, 16)
			opened := make(chan MediaConfig, 2)
			svc, err := New(Config{
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					opened <- cfg
					return &callMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: cfg.LocalPort}}, nil
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

			var invite sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					progress := reliableCallProgress(msg)
					progress.Headers.Add("P-Early-Media", "sendrecv")
					transport.queue(progress)
				case "PRACK":
					transport.queue(callStatus(msg, 200, "OK"))
					transport.queue(callOKWithoutSDP(invite, "early-tag"))
				}
			}

			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if !waitForCallEvent(events, StateEarlyMedia, "", time.Second) {
				t.Fatalf("call state = %s, want early media event", call.State())
			}
			if !waitForCallEvent(events, StateConfirmed, "", time.Second) {
				t.Fatalf("call state = %s, want confirmed event", call.State())
			}
			if got := call.State(); got != StateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, StateConfirmed)
			}
			select {
			case cfg := <-opened:
				if cfg.RemotePort != 50000 || !cfg.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) {
					t.Fatalf("OpenMedia remote = %v:%d, want 192.0.2.10:50000", cfg.RemoteIP, cfg.RemotePort)
				}
			default:
				t.Fatal("OpenMedia was not called for authorized early media")
			}
		})
	}
}

func TestIncomingInvitePreparesMediaBeforeRinging(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "180 waits for prepared local media resource"},
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
			prepareStarted := make(chan struct{}, 1)
			releasePrepare := make(chan struct{})
			incoming := make(chan Incoming, 1)
			svc, err := New(Config{
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					prepareStarted <- struct{}{}
					select {
					case <-releasePrepare:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return &callMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}}, nil
				},
				OnIncoming: func(event Incoming) { incoming <- event },
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

			progressCh := make(chan sip.Message, 1)
			ringingCh := make(chan sip.Message, 1)
			transport.onWrite = func(msg sip.Message) {
				switch {
				case msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					progressCh <- msg
				case msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					ringingCh <- msg
				}
			}
			transport.queue(inviteWithSDP())
			var progress sip.Message
			select {
			case progress = <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress was not sent while media was unavailable")
			}
			if got := progress.Header("Require"); got != "" {
				t.Fatalf("183 Require = %q, want empty without 100rel", got)
			}
			if body, ok := sdpBody(progress); !ok || !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("183 SDP present = %v body=%q, want audio answer", ok, string(body))
			}
			select {
			case <-prepareStarted:
			case <-time.After(time.Second):
				t.Fatal("PrepareMedia was not called")
			}
			select {
			case ringing := <-ringingCh:
				t.Fatalf("180 Ringing was sent before media prepared: %s", ringing.StartLine)
			case <-time.After(80 * time.Millisecond):
			}
			close(releasePrepare)
			select {
			case <-ringingCh:
			case <-time.After(time.Second):
				t.Fatal("180 Ringing was not sent after media prepared")
			}
			select {
			case got := <-incoming:
				if got.Call == nil {
					t.Fatal("incoming call is nil")
				}
			case <-time.After(time.Second):
				t.Fatal("incoming callback was not called")
			}
		})
	}
}

func TestIncomingReliableInviteAnswerWaitsForPRACKBeforeRinging(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 answer is reliable and 180 waits for PRACK plus media resource"},
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
			prepareStarted := make(chan struct{}, 1)
			releasePrepare := make(chan struct{})
			incoming := make(chan Incoming, 1)
			events := make(chan Event, 8)
			media := &callMediaTransport{}
			svc, err := New(Config{
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					prepareStarted <- struct{}{}
					select {
					case <-releasePrepare:
					case <-ctx.Done():
						return nil, ctx.Err()
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

			progressCh := make(chan sip.Message, 1)
			ringingCh := make(chan sip.Message, 1)
			prackOKCh := make(chan sip.Message, 1)
			inviteOKCh := make(chan sip.Message, 1)
			transport.onWrite = func(msg sip.Message) {
				switch {
				case msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					progressCh <- msg
				case msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					ringingCh <- msg
				case msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "PRACK":
					prackOKCh <- msg
				case msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					inviteOKCh <- msg
				}
			}

			invite := inviteWithSDP()
			invite.Headers.Add("Supported", "100rel")
			invite.Headers.Add("Allow", sip.DefaultClientAllow)
			transport.queue(invite)

			var got Incoming
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			var progress sip.Message
			select {
			case progress = <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress timed out")
			}
			if got := progress.Header("Require"); got != "100rel" {
				t.Fatalf("183 Require = %q, want 100rel", got)
			}
			if got := progress.Header("RSeq"); got != "1" {
				t.Fatalf("183 RSeq = %q, want 1", got)
			}
			if got := progress.Header("P-Early-Media"); got != "" {
				t.Fatalf("183 P-Early-Media = %q, want empty for terminating UE", got)
			}
			if body, ok := sdpBody(progress); !ok || !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("183 SDP present = %v body=%q, want audio answer", ok, string(body))
			}
			select {
			case <-prepareStarted:
				t.Fatal("PrepareMedia was called before PRACK")
			case <-time.After(80 * time.Millisecond):
			}
			select {
			case ringing := <-ringingCh:
				t.Fatalf("180 Ringing was sent before PRACK: %s", ringing.StartLine)
			case <-time.After(80 * time.Millisecond):
			}

			answerErr := make(chan error, 1)
			go func() {
				answerErr <- got.Call.Answer(context.Background(), MediaOffer{})
			}()
			select {
			case err := <-answerErr:
				t.Fatalf("Answer() completed before PRACK: %v", err)
			case <-time.After(80 * time.Millisecond):
			}

			transport.queue(prackWithoutSDPForReliableProvisional(invite, progress))
			select {
			case <-prackOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for PRACK timed out")
			}
			select {
			case <-prepareStarted:
			case <-time.After(time.Second):
				t.Fatal("PrepareMedia was not called after PRACK")
			}
			select {
			case ringing := <-ringingCh:
				t.Fatalf("180 Ringing was sent before media prepared: %s", ringing.StartLine)
			case <-time.After(80 * time.Millisecond):
			}
			close(releasePrepare)
			var ringing sip.Message
			select {
			case ringing = <-ringingCh:
			case <-time.After(time.Second):
				t.Fatal("180 Ringing was not sent after PRACK and media preparation")
			}
			if got := ringing.Header("RSeq"); got != "2" {
				t.Fatalf("180 RSeq = %q, want 2", got)
			}

			if err := <-answerErr; err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			var inviteOK sip.Message
			select {
			case inviteOK = <-inviteOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for INVITE timed out")
			}
			if len(inviteOK.Body) != 0 {
				t.Fatalf("200 OK INVITE body len = %d, want no duplicate SDP answer", len(inviteOK.Body))
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("media remote = %v, want 192.0.2.10:50000", remote)
			}
			transport.queue(ackWithoutSDP(invite, inviteOK))
			if !waitForCallEvent(events, StateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK", got.Call.State())
			}
		})
	}
}

func TestIncomingReliableInviteAnswerUnblocksWhenCallEndsBeforePRACK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote cancel closes PRACK wait"},
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
			progressCh := make(chan sip.Message, 1)
			events := make(chan Event, 4)
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					progressCh <- msg
				}
			}
			svc, err := New(Config{
				ReliableProvisional: true,
				PrepareMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &callMediaTransport{}, nil
				},
				OnIncoming: func(event Incoming) { incoming <- event },
				OnEvent:    func(event Event) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			invite := inviteWithSDP()
			invite.Headers.Add("Supported", "100rel")
			invite.Headers.Add("Allow", sip.DefaultClientAllow)
			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: invite, Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}
			var got Incoming
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			select {
			case <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress timed out")
			}

			answerErr := make(chan error, 1)
			go func() {
				answerErr <- got.Call.Answer(context.Background(), MediaOffer{})
			}()
			select {
			case err := <-answerErr:
				t.Fatalf("Answer() completed before call ended: %v", err)
			case <-time.After(80 * time.Millisecond):
			}

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: cancelForInvite(invite), Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest(CANCEL) error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest(CANCEL) = false, want true")
			}
			select {
			case err := <-answerErr:
				if err == nil {
					t.Fatal("Answer() error = nil, want closed call error")
				}
				if strings.Contains(err.Error(), "context") {
					t.Fatalf("Answer() error = %v, want immediate closed call error", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Answer() did not return after call ended")
			}
			if got := got.Call.State(); got != StateEnded {
				t.Fatalf("call.State() = %s, want %s", got, StateEnded)
			}
			if !waitForCallEvent(events, StateEnded, "remote cancel", time.Second) {
				t.Fatal("remote cancel event was not observed")
			}
		})
	}
}

func TestDialDoesNotUseTerminatedEarlyDialogAnswer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "199 removes provisional SDP answer"},
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
			events := make(chan Event, 8)
			svc, err := New(Config{
				OnEvent: func(event Event) {
					events <- event
				},
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
					transport.queue(earlyDialogTerminated(invite, "early-tag"))
					transport.queue(callOKWithoutSDP(invite, "voicemail-tag"))
				}
			}

			_, err = svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err == nil || !strings.Contains(err.Error(), "missing answer sdp") {
				t.Fatalf("Dial() error = %v, want missing answer sdp", err)
			}
			if !waitForCallEvent(events, StateDialing, "early dialog terminated", time.Second) {
				t.Fatal("early dialog terminated event was not observed")
			}
		})
	}
}

func TestOutgoingRemoteBYEEndsCall(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "confirmed dialog bye"},
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
			events := make(chan Event, 8)
			svc, err := New(Config{
				OnEvent: func(event Event) {
					events <- event
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

			var ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" || ok200.StartLine != "" {
					return
				}
				ok200 = callOK(msg)
				transport.queue(ok200)
			}
			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			transport.queue(byeForConfirmedDialog(ok200))

			if !waitForCallEvent(events, StateEnded, "remote bye", time.Second) {
				t.Fatal("remote bye event was not observed")
			}
			if got := call.State(); got != StateEnded {
				t.Fatalf("call.State() = %q, want %q", got, StateEnded)
			}
		})
	}
}

func TestDialSendsRTCPReports(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "confirmed call sends compound rtcp receiver report"},
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

			rtcpCh := make(chan []byte, 2)
			media := &callMediaTransport{
				local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				rtcpCh: rtcpCh,
			}
			svc, err := New(Config{
				RTPInactivityTimeout:  time.Second,
				RTCPInactivityTimeout: time.Second,
				RTCPSendInterval:      20 * time.Millisecond,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
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
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			var packet []byte
			select {
			case packet = <-rtcpCh:
			case <-time.After(time.Second):
				t.Fatal("RTCP report was not sent")
			}
			if len(packet) < 12 {
				t.Fatalf("RTCP packet len = %d, want compound report", len(packet))
			}
			if got := packet[1]; got != rtcpRRPacketType {
				t.Fatalf("RTCP first packet type = %d, want %d", got, rtcpRRPacketType)
			}
			if got := packet[9]; got != rtcpSDESPacketType {
				t.Fatalf("RTCP second packet type = %d, want %d", got, rtcpSDESPacketType)
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
		})
	}
}

func TestDialDoesNotSendRTCPWhenAnswerDisablesRTCP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "answer b=RS:0 and b=RR:0 disables rtcp sender"},
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

			rtcpCh := make(chan []byte, 2)
			media := &callMediaTransport{
				local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				rtcpCh: rtcpCh,
			}
			svc, err := New(Config{
				RTPInactivityTimeout:  time.Second,
				RTCPInactivityTimeout: 40 * time.Millisecond,
				RTCPSendInterval:      20 * time.Millisecond,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
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
				switch msg.Method() {
				case "INVITE":
					resp := callOK(msg)
					resp.Body = bytes.Replace(resp.Body, []byte("m=audio 50000 RTP/AVP 104 101\r\n"), []byte("m=audio 50000 RTP/AVP 104 101\r\nb=RS:0\r\nb=RR:0\r\n"), 1)
					transport.queue(resp)
				case "BYE":
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if media := call.Media(); !media.RTCPDisabled {
				t.Fatalf("Call.Media().RTCPDisabled = false, want true")
			}

			select {
			case packet := <-rtcpCh:
				t.Fatalf("RTCP packet was sent despite disabled RTCP: %x", packet)
			case <-time.After(80 * time.Millisecond):
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
		})
	}
}

func TestDialDoesNotWriteRTCPReportsToRTPTransport(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "transport without rtcp writer does not receive rtcp on rtp path"},
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

			rtpWrites := make(chan []byte, 2)
			media := &callRTPOnlyMediaTransport{
				local:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				writeCh: rtpWrites,
			}
			svc, err := New(Config{
				RTPInactivityTimeout:  time.Second,
				RTCPInactivityTimeout: time.Second,
				RTCPSendInterval:      20 * time.Millisecond,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
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
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), Request{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if err := call.WriteRTCP(context.Background(), []byte("rtcp")); err == nil {
				t.Fatal("WriteRTCP() error = nil, want unsupported transport error")
			}

			select {
			case packet := <-rtpWrites:
				t.Fatalf("RTP WritePacket received RTCP fallback packet: %x", packet)
			case <-time.After(80 * time.Millisecond):
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
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

func trying(req sip.Message) sip.Message {
	return callStatus(req, 100, "Trying")
}

func cancelOK(req sip.Message) sip.Message {
	return callStatus(req, 200, "OK")
}

func okForRequest(req sip.Message) sip.Message {
	return callStatus(req, 200, "OK")
}

func inviteTerminated(req sip.Message) sip.Message {
	resp := callStatus(req, 487, "Request Terminated")
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Header("To"), "", "remote-tag"))
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

func earlyDialogTerminated(req sip.Message, tag string) sip.Message {
	resp := sip.NewResponse(199, "Early Dialog Terminated")
	resp.Headers = sip.ResponseHeaders(req, 199)
	resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(req.Header("To"), "", tag))
	return resp
}

func byeForConfirmedDialog(ok sip.Message) sip.Message {
	msg := sip.NewRequest("BYE", sip.AddressURI(ok.Header("Contact")))
	msg.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKbye")
	msg.Headers.Add("From", ok.Header("To"))
	msg.Headers.Add("To", ok.Header("From"))
	msg.Headers.Add("Call-ID", ok.Header("Call-ID"))
	msg.Headers.Add("CSeq", "2 BYE")
	return msg
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

func inviteWithSDP() sip.Message {
	msg := delayedInvite()
	msg.Headers.Set("Call-ID", "offer-call")
	msg.Headers.Add("Content-Type", "application/sdp")
	msg.Body = []byte("v=0\r\n" +
		"o=- 1 1 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 50000 RTP/AVP 104 101\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:101 telephone-event/8000\r\n" +
		"a=ptime:20\r\n")
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

func prackWithoutSDPForReliableProvisional(invite, provisional sip.Message) sip.Message {
	msg := prackForReliableProvisional(invite, provisional)
	msg.Headers.Del("Content-Type")
	msg.Body = nil
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

func nextCallEvent(t *testing.T, events <-chan Event, state State, cause string, timeout time.Duration) Event {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case event := <-events:
			if event.State == state && event.Cause == cause {
				return event
			}
		case <-timer.C:
			t.Fatalf("call event not observed: state=%s cause=%q", state, cause)
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
