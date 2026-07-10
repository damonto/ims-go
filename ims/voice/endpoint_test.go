package voice

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/pidf"
	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
	"github.com/damonto/uicc-go/usim"
	"io"
	"log/slog"

	"mime/multipart"
	"net"

	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type voiceStubCard struct{}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

type voiceStubTransport struct {
	local  net.Addr
	remote net.Addr

	mu      sync.Mutex
	writes  [][]byte
	readCh  chan []byte
	closed  chan struct{}
	onWrite func(sip.Message)
}

type voiceMediaTransport struct {
	local *net.UDPAddr

	mu       sync.Mutex
	remote   net.Addr
	onPacket func(MediaPacket)
	closed   bool
	rtcpCh   chan []byte
}

type voiceRTPOnlyMediaTransport struct {
	local *net.UDPAddr

	mu       sync.Mutex
	remote   net.Addr
	onPacket func(MediaPacket)
	closed   bool
	writeCh  chan []byte
}

func newVoiceStubTransport() *voiceStubTransport {
	return &voiceStubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		readCh: make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func secureRegistrationConfig(transport *voiceStubTransport, cfg registration.Config) registration.Config {
	cfg.DialSecureUDP = func(ctx context.Context, secure session.SecureUDPConfig) (session.Transport, error) {
		return transport, nil
	}
	cfg.DialSecureTCP = func(ctx context.Context, secure session.SecureTCPConfig) (session.Transport, error) {
		return transport, nil
	}
	return cfg
}

func (voiceStubCard) IMSI() string { return "001010123456789" }

func (voiceStubCard) MCC() string { return "001" }

func (voiceStubCard) MNC() string { return "001" }

func (voiceStubCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("call-test-ck"),
		IK:  []byte("call-test-ik"),
	}, nil
}

func (t *voiceStubTransport) LocalAddr() net.Addr { return t.local }

func (t *voiceStubTransport) RemoteAddr() net.Addr { return t.remote }

func (t *voiceStubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-t.closed:
		return nil, nil, errors.New("transport is closed")
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}

func (t *voiceStubTransport) WritePacket(ctx context.Context, data []byte) error {
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

func (t *voiceStubTransport) Close() error {
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	return nil
}

func (t *voiceStubTransport) queue(msg sip.Message) {
	t.readCh <- marshalSIPMessageForTest(msg)
}

func marshalSIPMessageForTest(msg sip.Message) []byte {
	data, err := msg.MarshalText()
	if err != nil {
		panic(err)
	}
	return data
}

func (t *voiceStubTransport) countMethod(method string) int {
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

func (t *voiceStubTransport) messagesByMethod(method string) []sip.Message {
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

func (t *voiceStubTransport) messagesByStatus(code int, cseqMethod string) []sip.Message {
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

func (t *voiceMediaTransport) LocalAddr() net.Addr { return t.local }

func (t *voiceMediaTransport) RemoteAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remote
}

func (t *voiceMediaTransport) ConfigureRemote(ctx context.Context, cfg MediaConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.remote = &net.UDPAddr{IP: append(net.IP(nil), cfg.RemoteIP...), Port: cfg.RemotePort}
	t.onPacket = cfg.OnPacket
	return nil
}

func (t *voiceMediaTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (t *voiceMediaTransport) WritePacket(ctx context.Context, data []byte) error { return nil }

func (t *voiceMediaTransport) WriteRTCP(ctx context.Context, data []byte) error {
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

func (t *voiceMediaTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
}

func (t *voiceMediaTransport) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *voiceMediaTransport) notify(packet MediaPacket) {
	t.mu.Lock()
	onPacket := t.onPacket
	t.mu.Unlock()
	if onPacket != nil {
		onPacket(packet)
	}
}

func (t *voiceRTPOnlyMediaTransport) LocalAddr() net.Addr { return t.local }

func (t *voiceRTPOnlyMediaTransport) RemoteAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remote
}

func (t *voiceRTPOnlyMediaTransport) ConfigureRemote(ctx context.Context, cfg MediaConfig) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.remote = &net.UDPAddr{IP: append(net.IP(nil), cfg.RemoteIP...), Port: cfg.RemotePort}
	t.onPacket = cfg.OnPacket
	return nil
}

func (t *voiceRTPOnlyMediaTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (t *voiceRTPOnlyMediaTransport) WritePacket(ctx context.Context, data []byte) error {
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

func (t *voiceRTPOnlyMediaTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return nil
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
		"m=audio 50000 RTP/AVP 104 110\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n" +
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
		"m=audio 50000 RTP/AVP 104 110\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n" +
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
		"m=audio 50000 RTP/AVP 104 110\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n" +
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
		"m=audio 50000 RTP/AVP 104 110\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n" +
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
		"m=audio 50000 RTP/AVP 104 110\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n" +
		"a=ptime:20\r\n")
	return msg
}

func waitForCallEvent(events <-chan CallEvent, state CallState, cause string, timeout time.Duration) bool {
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

func nextCallEvent(t *testing.T, events <-chan CallEvent, state CallState, cause string, timeout time.Duration) CallEvent {
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
func TestCallStateTransitions(t *testing.T) {
	tests := []struct {
		name string
		from CallState
		to   CallState
		want bool
	}{
		{name: "new call may enter dialing", to: CallStateDialing, want: true},
		{name: "dialing can ring", from: CallStateDialing, to: CallStateRinging, want: true},
		{name: "dialing can enter early media", from: CallStateDialing, to: CallStateEarlyMedia, want: true},
		{name: "ringing can answer", from: CallStateRinging, to: CallStateAnswering, want: true},
		{name: "ringing can be confirmed after reliable provisional", from: CallStateRinging, to: CallStateConfirmed, want: true},
		{name: "answering becomes active", from: CallStateAnswering, to: CallStateActive, want: true},
		{name: "confirmed can become active", from: CallStateConfirmed, to: CallStateActive, want: true},
		{name: "active can end", from: CallStateActive, to: CallStateEnding, want: true},
		{name: "any non terminal can fail", from: CallStateRinging, to: CallStateFailed, want: true},
		{name: "ended cannot become active", from: CallStateEnded, to: CallStateActive},
		{name: "failed cannot become ringing", from: CallStateFailed, to: CallStateRinging},
		{name: "ending cannot go active", from: CallStateEnding, to: CallStateActive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := callCanTransition(tt.from, tt.to); got != tt.want {
				t.Fatalf("callCanTransition(%q, %q) = %t, want %t", tt.from, tt.to, got, tt.want)
			}
		})
	}
}
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
	svc := &Endpoint{reg: reg}

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
				EmergencyURN: "urn:endpoint:sos.police",
			},
			wantPIDF:            true,
			wantCurrentLocation: true,
			wantRequestURI:      "urn:endpoint:sos.police",
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
func TestDialHandlesRetransmittedInvite2xx(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "repeated 200 OK sends another ACK and preserves DTMF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{
				TransactionTimers: session.TransactionTimers{T1: 10 * time.Millisecond, T2: 20 * time.Millisecond},
			}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:    "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:        "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:              "123456789012345",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
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
			call, err := svc.Dial(dialCtx, DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			media := call.Media()
			if media.DTMFPayloadType != 110 || media.DTMFClockRate != 16000 {
				t.Fatalf("Media() DTMF = %d/%d, want 110/16000", media.DTMFPayloadType, media.DTMFClockRate)
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			prepared := false
			svc, err := New(Config{Logger: testLogger(),
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
				if got := msg.Header("Supported"); strings.Contains(got, "100rel") {
					t.Fatalf("INVITE Supported = %q, want no 100rel option tag by default", got)
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
			if _, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"}); err != nil {
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{
				TransactionTimers: session.TransactionTimers{T1: 10 * time.Millisecond, T2: 20 * time.Millisecond},
			}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(), OnCallEvent: func(event CallEvent) { events <- event }}, sess, reg)
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
				_, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
				dialErr <- err
			}()

			event := nextCallEvent(t, events, CallStateDialing, "", time.Second)
			call := svc.lookupCall(event.CallID)
			if call == nil {
				t.Fatalf("lookupCall(%q) = nil", event.CallID)
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}

			if !waitForCallEvent(events, CallStateEnded, "cancelled", time.Second) {
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
			if got := cancels[0].Header("P-Access-Network-Info"); got != "" {
				t.Fatalf("CANCEL P-Access-Network-Info = %q, want empty", got)
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

func TestDialRetriesInviteAfterSessionIntervalTooSmall(t *testing.T) {
	tests := []struct {
		name       string
		cfg        Config
		wantFirst  string
		wantSecond string
	}{
		{
			name:       "422 with Min-SE",
			cfg:        Config{Logger: testLogger(), SessionTimer: true},
			wantFirst:  "3600",
			wantSecond: "4000",
		},
		{
			name:       "422 omits configured UAS refresher",
			cfg:        Config{Logger: testLogger(), SessionTimer: true, SessionRefresher: sessionRefresherUAS},
			wantFirst:  "3600",
			wantSecond: "4000",
		},
		{
			name:       "422 preserves configured UAC refresher",
			cfg:        Config{Logger: testLogger(), SessionTimer: true, SessionRefresher: sessionRefresherUAC},
			wantFirst:  "3600;refresher=uac",
			wantSecond: "4000;refresher=uac",
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
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(tt.cfg, sess, reg)
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
					if got := msg.Header("Session-Expires"); got != tt.wantFirst {
						t.Fatalf("retry Session-Expires = %q, want %q", got, tt.wantFirst)
					}
					if got := msg.Header("Min-SE"); got != "3600" {
						t.Fatalf("retry Min-SE = %q, want 3600", got)
					}
					resp := callStatus(msg, 422, "Session Interval Too Small")
					resp.Headers.Add("Min-SE", "4000")
					transport.queue(resp)
				case 3:
					if got := msg.Header("Session-Expires"); got != tt.wantSecond {
						t.Fatalf("second retry Session-Expires = %q, want %q", got, tt.wantSecond)
					}
					if got := msg.Header("Min-SE"); got != "4000" {
						t.Fatalf("second retry Min-SE = %q, want 4000", got)
					}
					transport.queue(callOK(msg))
				default:
					t.Fatalf("INVITE count = %d, want 3", invites)
				}
			}

			if _, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if invites != 3 {
				t.Fatalf("INVITE count = %d, want 3", invites)
			}
		})
	}
}

func TestDialRejectsInvalidMinSEOnSessionIntervalRetry(t *testing.T) {
	tests := []struct {
		name  string
		minSE string
	}{
		{name: "missing Min-SE"},
		{name: "below RFC minimum", minSE: "60"},
		{name: "not seconds", minSE: "invalid"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
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
					t.Fatalf("INVITE count = %d, want 1", invites)
				}
				resp := callStatus(msg, 422, "Session Interval Too Small")
				if tt.minSE != "" {
					resp.Headers.Add("Min-SE", tt.minSE)
				}
				transport.queue(resp)
			}

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil {
				t.Fatal("Dial() error = nil, want invalid Min-SE")
			}
			if !strings.Contains(err.Error(), "session timer retry: invalid Min-SE") {
				t.Fatalf("Dial() error = %v, want invalid Min-SE", err)
			}
			if invites != 1 {
				t.Fatalf("INVITE count = %d, want 1", invites)
			}
		})
	}
}

func TestDialRejectsTimerRequiredResponseWithoutSessionExpires(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "Require timer missing Session-Expires"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
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
				resp.Headers.Add("Require", "timer")
				transport.queue(resp)
			}

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil {
				t.Fatal("Dial() error = nil, want missing Session-Expires")
			}
			if !strings.Contains(err.Error(), "Require timer without Session-Expires") {
				t.Fatalf("Dial() error = %v, want missing Session-Expires", err)
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
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

			if _, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
				t.Fatalf("Dial() error = %v, want cancelled", err)
			}
			if invites != 1 {
				t.Fatalf("INVITE count = %d, want 1", invites)
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(),
				MOCallRequestTimeout: 50 * time.Millisecond,
				OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if call.State() != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", call.State(), CallStateConfirmed)
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), MOCallRequestTimeout: 40 * time.Millisecond}, sess, reg)
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

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(),
				RingbackTimeout: 50 * time.Millisecond,
				OnCallEvent:     func(event CallEvent) { events <- event },
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

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil || !strings.Contains(err.Error(), "cancelled") {
				t.Fatalf("Dial() error = %v, want cancelled", err)
			}
			if transport.countMethod("CANCEL") != 1 {
				t.Fatalf("CANCEL count = %d, want 1", transport.countMethod("CANCEL"))
			}
			if !waitForCallEvent(events, CallStateEnded, "cancelled", time.Second) {
				t.Fatal("cancelled event was not observed")
			}
		})
	}
}

func TestDialPreconditionSendsUPDATEAfterReliableAnswer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 requires precondition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{
				Logger:        testLogger(),
				Preconditions: true,
				OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
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
					if got := msg.Header("Supported"); !sip.TokenListContains(got, preconditionOption) {
						t.Fatalf("INVITE Supported = %q, want precondition", got)
					}
					if got := msg.Header("Supported"); !sip.TokenListContains(got, reliableProvisionalOption) {
						t.Fatalf("INVITE Supported = %q, want 100rel", got)
					}
					progress := reliableCallProgress(msg)
					progress.Headers.Add("Require", preconditionOption)
					progress.Body = append(progress.Body,
						[]byte("a=curr:qos local none\r\n"+
							"a=curr:qos remote none\r\n"+
							"a=des:qos mandatory local sendrecv\r\n"+
							"a=des:qos optional remote sendrecv\r\n")...)
					transport.queue(progress)
				case "PRACK":
					transport.queue(callStatus(msg, sipStatusOK, "OK"))
				case "UPDATE":
					if got := sip.RequestURI(msg); got != "sip:early@192.0.2.10:5060" {
						t.Fatalf("UPDATE Request-URI = %q, want early dialog target", got)
					}
					if got := sip.HeaderTag(msg.Header("To")); got != "early-tag" {
						t.Fatalf("UPDATE To tag = %q, want early-tag", got)
					}
					if got := msg.Header("Require"); got != preconditionOption {
						t.Fatalf("UPDATE Require = %q, want %q", got, preconditionOption)
					}
					body := string(msg.Body)
					for _, want := range []string{
						"m=audio 40000 RTP/AVP 104 110",
						"a=curr:qos local sendrecv",
						"a=des:qos mandatory local sendrecv",
						"a=des:qos optional remote sendrecv",
					} {
						if !strings.Contains(body, want+"\r\n") {
							t.Fatalf("UPDATE body missing %q:\n%s", want, body)
						}
					}
					if strings.Contains(body, "a=rtpmap:102") {
						t.Fatalf("UPDATE body included unselected codec:\n%s", body)
					}
					transport.queue(callStatus(msg, sipStatusOK, "OK"))
					transport.queue(callOK(invite))
				}
			}

			dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
			defer dialCancel()
			if _, err := svc.Dial(dialCtx, DialRequest{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if got := len(transport.messagesByMethod("PRACK")); got != 1 {
				t.Fatalf("PRACK count = %d, want 1", got)
			}
			if got := len(transport.messagesByMethod("UPDATE")); got != 1 {
				t.Fatalf("UPDATE count = %d, want 1", got)
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(),
				OnCallEvent: func(event CallEvent) {
					events <- event
				},
				OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
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

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil || !strings.Contains(err.Error(), "missing answer sdp") {
				t.Fatalf("Dial() error = %v, want missing answer sdp", err)
			}
			if !waitForCallEvent(events, CallStateDialing, "early dialog terminated", time.Second) {
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(),
				OnCallEvent: func(event CallEvent) {
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			transport.queue(byeForConfirmedDialog(ok200))

			if !waitForCallEvent(events, CallStateEnded, "remote bye", time.Second) {
				t.Fatal("remote bye event was not observed")
			}
			if got := call.State(); got != CallStateEnded {
				t.Fatalf("call.State() = %q, want %q", got, CallStateEnded)
			}
		})
	}
}

func TestHangupAcceptsBYETerminationResponses(t *testing.T) {
	tests := []struct {
		name       string
		byeStatus  int
		byeReason  string
		noResponse bool
	}{
		{name: "ok", byeStatus: 200, byeReason: "OK"},
		{name: "accepted", byeStatus: 202, byeReason: "Accepted"},
		{name: "missing dialog", byeStatus: 481, byeReason: "Call/Transaction Does Not Exist"},
		{name: "request timeout", byeStatus: 408, byeReason: "Request Timeout"},
		{name: "no response", noResponse: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
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
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					if !tt.noResponse {
						transport.queue(callStatus(msg, tt.byeStatus, tt.byeReason))
					}
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			hangupCtx := context.Background()
			hangupCancel := func() {}
			if tt.noResponse {
				hangupCtx, hangupCancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}
			defer hangupCancel()
			if err := call.Hangup(hangupCtx); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
			if got := call.State(); got != CallStateEnded {
				t.Fatalf("call.State() = %s, want %s", got, CallStateEnded)
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
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

			if _, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"}); err != nil {
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
		state CallState
	}{
		{name: "ending", state: CallStateEnding},
		{name: "ended", state: CallStateEnded},
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
func TestIncomingInviteRingingResponseIncludesContact(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "ringing response carries voice contact"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer func() {
				_ = sess.Close()
			}()
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:    "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:        "ims.mnc001.mcc001.3gppnetwork.org",
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

func TestIncomingInviteRejectsTooSmallSessionInterval(t *testing.T) {
	tests := []struct {
		name    string
		minSE   string
		wantMin string
		callID  string
		cfg     Config
	}{
		{
			name:    "below absolute minimum",
			wantMin: "90",
			callID:  "too-small-se-absolute",
			cfg:     Config{SessionTimer: true},
		},
		{
			name:    "below requested minimum",
			minSE:   "600",
			wantMin: "600",
			callID:  "too-small-se-requested",
			cfg:     Config{SessionTimer: true},
		},
		{
			name:    "below configured minimum",
			wantMin: "300",
			callID:  "too-small-se-configured",
			cfg:     Config{SessionTimer: true, MinSessionExpires: 300 * time.Second},
		},
		{
			name:    "configured minimum below absolute minimum",
			wantMin: "90",
			callID:  "too-small-se-configured-below-absolute",
			cfg:     Config{SessionTimer: true, MinSessionExpires: 30 * time.Second},
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
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
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
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			invite := delayedInvite()
			invite.Headers.Set("Call-ID", tt.callID)
			invite.Headers.Add("Supported", "timer")
			invite.Headers.Add("Session-Expires", "60;refresher=uac")
			if tt.minSE != "" {
				invite.Headers.Add("Min-SE", tt.minSE)
			}

			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: invite, Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}

			responses := transport.messagesByStatus(sipStatusSessionIntervalTooSmall, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("422 count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Min-SE"); got != tt.wantMin {
				t.Fatalf("422 Min-SE = %q, want %q", got, tt.wantMin)
			}
			if call := svc.lookupCall(tt.callID); call != nil {
				t.Fatalf("lookupCall() = %v, want no call stored after 422", call)
			}
		})
	}
}

func TestIncomingInviteRejectsRefresherWithoutTimerSupport(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "refresher without Supported timer is malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			invite := delayedInvite()
			invite.Headers.Set("Call-ID", "bad-session-refresher")
			invite.Headers.Del("Supported")
			invite.Headers.Add("Session-Expires", "180;refresher=uas")

			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: invite, Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}

			responses := transport.messagesByStatus(sipStatusBadRequest, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("400 INVITE count = %d, want 1", len(responses))
			}
			if call := svc.lookupCall("bad-session-refresher"); call != nil {
				t.Fatalf("lookupCall() = %v, want no call stored after 400", call)
			}
		})
	}
}

func TestIncomingInviteRejectsRequiredTimerWhenUnsupported(t *testing.T) {
	transport := newVoiceStubTransport()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	reg, err := registration.New(registration.Config{Logger: testLogger(),
		PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
	}, sess, voiceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		_ = svc.Close()
		_ = sess.Close()
	}()

	invite := delayedInvite()
	invite.Headers.Set("Call-ID", "required-timer-unsupported")
	invite.Headers.Add("Require", sessionTimerOption)

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: invite, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	responses := transport.messagesByStatus(sipStatusBadExtension, "INVITE")
	if len(responses) != 1 {
		t.Fatalf("420 count = %d, want 1", len(responses))
	}
	if got := responses[0].Header("Unsupported"); got != sessionTimerOption {
		t.Fatalf("Unsupported = %q, want %q", got, sessionTimerOption)
	}
	if got := transport.countMethod("INVITE"); got != 0 {
		t.Fatalf("outbound INVITE count = %d, want 0", got)
	}
	if call := svc.lookupCall("required-timer-unsupported"); call != nil {
		t.Fatalf("lookupCall() = %v, want no call stored after 420", call)
	}
}

func TestIncomingInviteRequiredReliableProvisional(t *testing.T) {
	tests := []struct {
		name            string
		reliableEnabled bool
		wantStatus      int
		wantRequire     string
		wantUnsupported string
		wantStoredCall  bool
	}{
		{
			name:            "unsupported required 100rel rejected",
			wantStatus:      sipStatusBadExtension,
			wantUnsupported: reliableProvisionalOption,
		},
		{
			name:            "required 100rel sends reliable provisional",
			reliableEnabled: true,
			wantStatus:      sipStatusSessionProgress,
			wantRequire:     reliableProvisionalOption,
			wantStoredCall:  true,
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
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), ReliableProvisional: tt.reliableEnabled}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			invite := delayedInvite()
			invite.Headers.Set("Call-ID", "required-100rel-"+tt.name)
			invite.Headers.Del("Supported")
			invite.Headers.Add("Require", reliableProvisionalOption)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: invite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(tt.wantStatus, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("%d count = %d, want 1", tt.wantStatus, len(responses))
			}
			if got := responses[0].Header("Require"); got != tt.wantRequire {
				t.Fatalf("Require = %q, want %q", got, tt.wantRequire)
			}
			if got := responses[0].Header("Unsupported"); got != tt.wantUnsupported {
				t.Fatalf("Unsupported = %q, want %q", got, tt.wantUnsupported)
			}
			if tt.wantRequire != "" && responses[0].Header("RSeq") == "" {
				t.Fatal("RSeq = empty, want reliable provisional sequence")
			}
			call := svc.lookupCall(invite.Header("Call-ID"))
			if (call != nil) != tt.wantStoredCall {
				t.Fatalf("lookupCall() = %v, stored = %t", call, tt.wantStoredCall)
			}
		})
	}
}

func TestIncomingInvitePreconditionResponseRequiresPrecondition(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 answer uses precondition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{
				Logger:        testLogger(),
				Preconditions: true,
				PrepareMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			invite := inviteWithSDP()
			invite.Headers.Set("Call-ID", "incoming-precondition")
			invite.Headers.Add("Supported", reliableProvisionalOption+","+preconditionOption)
			invite.Body = append(invite.Body,
				[]byte("a=curr:qos local none\r\n"+
					"a=curr:qos remote none\r\n"+
					"a=des:qos mandatory local sendrecv\r\n"+
					"a=des:qos optional remote sendrecv\r\n")...)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: invite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			progress := transport.messagesByStatus(sipStatusSessionProgress, "INVITE")
			if len(progress) != 1 {
				t.Fatalf("183 count = %d, want 1", len(progress))
			}
			if got := progress[0].Header("Require"); !sip.TokenListContains(got, reliableProvisionalOption) || !sip.TokenListContains(got, preconditionOption) {
				t.Fatalf("183 Require = %q, want 100rel and precondition", got)
			}
			body := string(progress[0].Body)
			if !strings.Contains(body, "a=conf:qos remote sendrecv\r\n") {
				t.Fatalf("183 SDP body missing resource confirmation request:\n%s", body)
			}
		})
	}
}

func TestIncomingInvitePreconditionFinalOKRequiresPrecondition(t *testing.T) {
	tests := []struct {
		name        string
		invite      func() sip.Message
		wantSDPLine string
	}{
		{
			name: "offer answer in final 200",
			invite: func() sip.Message {
				msg := inviteWithSDP()
				msg.Headers.Set("Call-ID", "incoming-precondition-final-answer")
				msg.Headers.Add("Supported", preconditionOption)
				msg.Body = append(msg.Body,
					[]byte("a=curr:qos local none\r\n"+
						"a=curr:qos remote none\r\n"+
						"a=des:qos mandatory local sendrecv\r\n"+
						"a=des:qos optional remote sendrecv\r\n")...)
				return msg
			},
			wantSDPLine: "a=curr:qos local none\r\n",
		},
		{
			name: "delayed offer in final 200",
			invite: func() sip.Message {
				msg := delayedInvite()
				msg.Headers.Set("Call-ID", "incoming-precondition-final-offer")
				msg.Headers.Add("Supported", preconditionOption)
				return msg
			},
			wantSDPLine: "a=des:qos mandatory local sendrecv\r\n",
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
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			svc, err := New(Config{
				Logger:        testLogger(),
				Preconditions: true,
				OnIncomingCall: func(event IncomingCall) {
					incoming <- event
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: tt.invite(), Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			got := <-incoming
			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			responses := transport.messagesByStatus(sipStatusOK, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("200 INVITE count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Require"); !sip.TokenListContains(got, preconditionOption) {
				t.Fatalf("200 INVITE Require = %q, want %q", got, preconditionOption)
			}
			body := string(responses[0].Body)
			if !strings.Contains(body, tt.wantSDPLine) {
				t.Fatalf("200 INVITE SDP body missing %q:\n%s", tt.wantSDPLine, body)
			}
		})
	}
}

func TestIncomingUPDATESessionRefresh(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote refresher updates dialog timer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				endpoint:  svc,
				id:        "update-refresh-call",
				sessionID: "update-refresh-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			update := sip.NewRequest("UPDATE", "sip:001010123456789@192.0.2.20:5062")
			update.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKrefresh")
			update.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
			update.Headers.Add("To", "<sip:001010123456789@example.com>;tag=local-tag")
			update.Headers.Add("Call-ID", "update-refresh-call")
			update.Headers.Add("CSeq", "2 UPDATE")
			update.Headers.Add("Contact", "<sip:caller-refresh@192.0.2.11:5070>")
			update.Headers.Add("Supported", "timer")
			update.Headers.Add("Session-Expires", "600;refresher=uac")
			update.Headers.Add("Min-SE", "600")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: update, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "UPDATE")
			if len(responses) != 1 {
				t.Fatalf("200 UPDATE count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Session-Expires"); got != "600;refresher=uac" {
				t.Fatalf("200 UPDATE Session-Expires = %q, want 600;refresher=uac", got)
			}
			if got := responses[0].Header("Require"); got != "timer" {
				t.Fatalf("200 UPDATE Require = %q, want timer", got)
			}
			call.mu.Lock()
			timer := call.sessionTimer
			targetURI := call.targetURI
			call.mu.Unlock()
			if !timer.active || timer.localRefresher || timer.minSE != 600 {
				t.Fatalf("session timer = %+v, want active remote refresher", timer)
			}
			if targetURI != "sip:caller-refresh@192.0.2.11:5070" {
				t.Fatalf("targetURI = %q, want UPDATE Contact remote target", targetURI)
			}
		})
	}
}

func TestIncomingUPDATESessionRefreshWithOfferAnswersSDP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "normal UPDATE refresh can carry offer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{
				Logger:       testLogger(),
				SessionTimer: true,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					if err := media.ConfigureRemote(ctx, cfg); err != nil {
						return nil, err
					}
					return media, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				endpoint:  svc,
				id:        "update-offer-call",
				sessionID: "update-offer-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			update := sip.NewRequest("UPDATE", "sip:001010123456789@192.0.2.20:5062")
			update.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKupdateoffer")
			update.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
			update.Headers.Add("To", "<sip:001010123456789@example.com>;tag=local-tag")
			update.Headers.Add("Call-ID", "update-offer-call")
			update.Headers.Add("CSeq", "2 UPDATE")
			update.Headers.Add("Supported", "timer")
			update.Headers.Add("Session-Expires", "600;refresher=uac")
			update.Headers.Add("Content-Type", "application/sdp")
			update.Body = inviteWithSDP().Body

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: update, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "UPDATE")
			if len(responses) != 1 {
				t.Fatalf("200 UPDATE count = %d, want 1", len(responses))
			}
			if _, ok := sdpBody(responses[0]); !ok {
				t.Fatalf("200 UPDATE SDP present = false, want true")
			}
			if got := responses[0].Header("Session-Expires"); got != "600;refresher=uac" {
				t.Fatalf("200 UPDATE Session-Expires = %q, want 600;refresher=uac", got)
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 {
				t.Fatalf("media remote port = %d, want offered port 50000", remote.Port)
			}
		})
	}
}

func TestIncomingUPDATEPreconditionAnswerRequiresPrecondition(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "UPDATE offer uses precondition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), Preconditions: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				endpoint:  svc,
				id:        "update-precondition-call",
				sessionID: "update-precondition-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			update := sip.NewRequest("UPDATE", "sip:001010123456789@192.0.2.20:5062")
			update.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKupdateprecondition")
			update.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
			update.Headers.Add("To", "<sip:001010123456789@example.com>;tag=local-tag")
			update.Headers.Add("Call-ID", "update-precondition-call")
			update.Headers.Add("CSeq", "2 UPDATE")
			update.Headers.Add("Supported", preconditionOption)
			update.Headers.Add("Content-Type", "application/sdp")
			update.Body = append(inviteWithSDP().Body,
				[]byte("a=curr:qos local none\r\n"+
					"a=curr:qos remote none\r\n"+
					"a=des:qos mandatory local sendrecv\r\n"+
					"a=des:qos optional remote sendrecv\r\n")...)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: update, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "UPDATE")
			if len(responses) != 1 {
				t.Fatalf("200 UPDATE count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Require"); got != preconditionOption {
				t.Fatalf("200 UPDATE Require = %q, want %q", got, preconditionOption)
			}
			body := string(responses[0].Body)
			if !strings.Contains(body, "a=conf:qos remote sendrecv\r\n") {
				t.Fatalf("200 UPDATE body missing resource confirmation request:\n%s", body)
			}
		})
	}
}

func TestIncomingReINVITESessionRefresh(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "existing dialog re-invite refreshes session"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				endpoint:  svc,
				id:        "reinvite-refresh-call",
				sessionID: "reinvite-refresh-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			reinvite := inviteWithSDP()
			reinvite.Headers.Set("Call-ID", "reinvite-refresh-call")
			reinvite.Headers.Set("From", "<sip:caller@example.com>;tag=remote-tag")
			reinvite.Headers.Set("To", "<sip:001010123456789@example.com>;tag=local-tag")
			reinvite.Headers.Set("CSeq", "2 INVITE")
			reinvite.Headers.Add("Supported", "timer")
			reinvite.Headers.Add("Session-Expires", "180;refresher=uac")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: reinvite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("200 INVITE count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Session-Expires"); got != "180;refresher=uac" {
				t.Fatalf("200 re-INVITE Session-Expires = %q, want 180;refresher=uac", got)
			}
			if _, ok := sdpBody(responses[0]); !ok {
				t.Fatalf("200 re-INVITE SDP present = false, want true")
			}
			call.mu.Lock()
			timer := call.sessionTimer
			call.mu.Unlock()
			if !timer.active || timer.localRefresher {
				t.Fatalf("session timer = %+v, want active remote refresher", timer)
			}
		})
	}
}

func TestIncomingReINVITEGlareWhileLocalINVITEPending(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "local re-invite in progress"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				endpoint:           svc,
				id:                 "local-pending-reinvite-call",
				sessionID:          "local-pending-reinvite-session",
				direction:          CallDirectionOutgoing,
				state:              CallStateActive,
				localURI:           "sip:001010123456789@example.com",
				localTag:           "local-tag",
				remoteURI:          "sip:callee@example.com",
				remoteTag:          "remote-tag",
				remoteTo:           "<sip:callee@example.com>;tag=remote-tag",
				targetURI:          "sip:callee@192.0.2.10:5060",
				inviteSeq:          1,
				localPort:          40000,
				localINVITEPending: true,
				rtcpSSRC:           randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			reinvite := inviteWithSDP()
			reinvite.Headers.Set("Call-ID", "local-pending-reinvite-call")
			reinvite.Headers.Set("From", "<sip:callee@example.com>;tag=remote-tag")
			reinvite.Headers.Set("To", "<sip:001010123456789@example.com>;tag=local-tag")
			reinvite.Headers.Set("CSeq", "2 INVITE")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: reinvite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusRequestPending, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("491 re-INVITE count = %d, want 1", len(responses))
			}
		})
	}
}

func TestIncomingRemoteHoldReINVITEUpdatesHoldState(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote recvonly marks remote hold"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 4)
			svc, err := New(Config{
				Logger:      testLogger(),
				OnCallEvent: func(event CallEvent) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				endpoint:  svc,
				id:        "remote-hold-call",
				sessionID: "remote-hold-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			reinvite := inviteWithSDP()
			reinvite.Headers.Set("Call-ID", "remote-hold-call")
			reinvite.Headers.Set("From", "<sip:caller@example.com>;tag=remote-tag")
			reinvite.Headers.Set("To", "<sip:001010123456789@example.com>;tag=local-tag")
			reinvite.Headers.Set("CSeq", "2 INVITE")
			reinvite.Body = append(reinvite.Body, []byte("a=recvonly\r\n")...)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: reinvite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("200 INVITE count = %d, want 1", len(responses))
			}
			if !strings.Contains(string(responses[0].Body), "a=sendonly\r\n") {
				t.Fatalf("remote hold answer missing sendonly:\n%s", string(responses[0].Body))
			}
			if got := call.HoldState(); got != CallHoldRemote {
				t.Fatalf("hold state = %s, want %s", got, CallHoldRemote)
			}
			event := nextCallEvent(t, events, CallStateActive, "remote session modification", time.Second)
			if event.Hold != CallHoldRemote {
				t.Fatalf("event hold = %s, want %s", event.Hold, CallHoldRemote)
			}
		})
	}
}

func TestSecondIncomingReINVITEGetsRetryAfterWhileFirstPending(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "second re-invite receives 500 retry-after"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			openStarted := make(chan struct{})
			releaseOpen := make(chan struct{})
			var openOnce sync.Once
			var releaseOnce sync.Once
			svc, err := New(Config{
				Logger:       testLogger(),
				SessionTimer: true,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					openOnce.Do(func() { close(openStarted) })
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-releaseOpen:
					}
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}}, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				releaseOnce.Do(func() { close(releaseOpen) })
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				endpoint:  svc,
				id:        "remote-pending-reinvite-call",
				sessionID: "remote-pending-reinvite-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			first := inviteWithSDP()
			first.Headers.Set("Call-ID", "remote-pending-reinvite-call")
			first.Headers.Set("From", "<sip:caller@example.com>;tag=remote-tag")
			first.Headers.Set("To", "<sip:001010123456789@example.com>;tag=local-tag")
			first.Headers.Set("CSeq", "2 INVITE")

			firstErr := make(chan error, 1)
			go func() {
				_, err := svc.HandleRequest(context.Background(), session.Request{Message: first, Transport: transport})
				firstErr <- err
			}()
			select {
			case <-openStarted:
			case <-time.After(time.Second):
				t.Fatal("OpenMedia was not called for first re-INVITE")
			}

			second := first
			second.Headers = first.Headers.Clone()
			second.Body = append([]byte(nil), first.Body...)
			second.Headers.Set("CSeq", "3 INVITE")
			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: second, Transport: transport})
			if err != nil {
				t.Fatalf("second HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("second HandleRequest() handled = false, want true")
			}

			responses := transport.messagesByStatus(sipStatusServerInternalError, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("500 re-INVITE count = %d, want 1", len(responses))
			}
			retryAfter, err := strconv.Atoi(responses[0].Header("Retry-After"))
			if err != nil || retryAfter < 0 || retryAfter > 10 {
				t.Fatalf("Retry-After = %q, want 0..10 seconds", responses[0].Header("Retry-After"))
			}

			releaseOnce.Do(func() { close(releaseOpen) })
			if err := <-firstErr; err != nil {
				t.Fatalf("first HandleRequest() error = %v", err)
			}
			if got := len(transport.messagesByStatus(sipStatusOK, "INVITE")); got != 1 {
				t.Fatalf("200 re-INVITE count = %d, want 1", got)
			}
		})
	}
}

func TestUnknownReINVITEDialogGets481(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "unknown dialog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			reinvite := sip.NewRequest("INVITE", "sip:001010123456789@192.0.2.20:5062")
			reinvite.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKmissingreinvite")
			reinvite.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
			reinvite.Headers.Add("To", "<sip:001010123456789@example.com>;tag=local-tag")
			reinvite.Headers.Add("Call-ID", "missing-reinvite-call")
			reinvite.Headers.Add("CSeq", "2 INVITE")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: reinvite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusCallTransactionDoesNotExist, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("481 re-INVITE count = %d, want 1", len(responses))
			}
		})
	}
}

func TestIncomingCancelEndsRingingCall(t *testing.T) {
	tests := []struct {
		name      string
		wantState CallState
		wantCause string
	}{
		{name: "cancel before answer", wantState: CallStateEnded, wantCause: "remote cancel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration New() error = %v", err)
			}
			events := make(chan CallEvent, 4)
			svc, err := New(Config{Logger: testLogger(),
				OnCallEvent: func(event CallEvent) {
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

func TestIncomingRingingTimeoutRejectsInvite(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "unanswered ringing call receives 486"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(),
				RingingTimeout: 50 * time.Millisecond,
				OnCallEvent:    func(event CallEvent) { events <- event },
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
			if !waitForCallEvent(events, CallStateEnded, "ringing timeout", time.Second) {
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
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
			var got IncomingCall
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
			progressRSeq, err := strconv.ParseInt(progress.Header("RSeq"), 10, 64)
			if err != nil || progressRSeq < 1 || progressRSeq > rseqInitialMax {
				t.Fatalf("183 RSeq = %q, want 1..%d", progress.Header("RSeq"), rseqInitialMax)
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
			ringingRSeq, err := strconv.ParseInt(ringing.Header("RSeq"), 10, 64)
			if err != nil || ringingRSeq != progressRSeq+1 {
				t.Fatalf("180 RSeq = %q, want %d", ringing.Header("RSeq"), progressRSeq+1)
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
			if !waitForCallEvent(events, CallStateActive, "", time.Second) {
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
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

func TestIncomingReliablePRACKOfferGetsAnswer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "PRACK offer is answered in 200 OK"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			prepared := make(chan MediaConfig, 1)
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					prepared <- cfg
					return nil, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
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

			invite := inviteWithSDP()
			invite.Headers.Add("Supported", "100rel")
			invite.Headers.Add("Allow", sip.DefaultClientAllow)
			transport.queue(invite)
			var call *Call
			select {
			case event := <-incoming:
				call = event.Call
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			var progress sip.Message
			if !waitForCallTest(func() bool {
				messages := transport.messagesByStatus(sipStatusSessionProgress, "INVITE")
				if len(messages) == 0 {
					return false
				}
				progress = messages[0]
				return true
			}) {
				t.Fatal("183 Session Progress was not sent")
			}

			prack := prackForReliableProvisional(invite, progress)
			prack.Body = []byte("v=0\r\n" +
				"o=- 3 1 IN IP4 192.0.2.10\r\n" +
				"s=-\r\n" +
				"c=IN IP4 192.0.2.10\r\n" +
				"t=0 0\r\n" +
				"m=audio 51002 RTP/AVP 104 110\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				"a=rtpmap:110 telephone-event/16000\r\n" +
				"a=ptime:20\r\n")
			transport.queue(prack)

			var ok sip.Message
			if !waitForCallTest(func() bool {
				messages := transport.messagesByStatus(sipStatusOK, "PRACK")
				if len(messages) == 0 {
					return false
				}
				ok = messages[0]
				return true
			}) {
				t.Fatal("200 OK for PRACK was not sent")
			}
			if got := ok.Header("Content-Type"); got != "application/sdp" {
				t.Fatalf("200 PRACK Content-Type = %q, want application/sdp", got)
			}
			if !strings.Contains(string(ok.Body), "m=audio ") {
				t.Fatalf("200 PRACK body = %q, want SDP answer", string(ok.Body))
			}
			select {
			case cfg := <-prepared:
				if cfg.Media.RemotePort != 51002 || !cfg.Media.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) {
					t.Fatalf("prepared media remote = %v:%d, want 192.0.2.10:51002", cfg.Media.RemoteIP, cfg.Media.RemotePort)
				}
			case <-time.After(time.Second):
				t.Fatal("PrepareMedia was not called after PRACK")
			}
			if media := call.Media(); media.RemotePort != 51002 || !media.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("call media remote = %v:%d, want 192.0.2.10:51002", media.RemoteIP, media.RemotePort)
			}
		})
	}
}

func TestIncomingDelayedOfferPRACKConfirmationSendsPreconditionUPDATE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "PRACK answer requests terminating resource confirmation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			updateCh := make(chan sip.Message, 1)
			svc, err := New(Config{
				Logger:        testLogger(),
				Preconditions: true,
				PrepareMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
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
				if msg.Method() == "UPDATE" {
					updateCh <- msg
					transport.queue(callStatus(msg, sipStatusOK, "OK"))
				}
			}

			invite := delayedInvite()
			invite.Headers.Add("Supported", reliableProvisionalOption+","+preconditionOption)
			invite.Headers.Add("Allow", sip.DefaultClientAllow)
			transport.queue(invite)
			select {
			case <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			var progress sip.Message
			if !waitForCallTest(func() bool {
				messages := transport.messagesByStatus(sipStatusSessionProgress, "INVITE")
				if len(messages) == 0 {
					return false
				}
				progress = messages[0]
				return true
			}) {
				t.Fatal("183 Session Progress was not sent")
			}
			if got := progress.Header("Require"); !sip.TokenListContains(got, reliableProvisionalOption) || !sip.TokenListContains(got, preconditionOption) {
				t.Fatalf("183 Require = %q, want 100rel and precondition", got)
			}

			prack := prackForReliableProvisional(invite, progress)
			prack.Headers.Add("Require", preconditionOption)
			prack.Body = append(prack.Body,
				[]byte("a=curr:qos local none\r\n"+
					"a=curr:qos remote none\r\n"+
					"a=des:qos mandatory local sendrecv\r\n"+
					"a=des:qos optional remote sendrecv\r\n"+
					"a=conf:qos remote sendrecv\r\n")...)
			transport.queue(prack)

			if !waitForCallTest(func() bool {
				return len(transport.messagesByStatus(sipStatusOK, "PRACK")) == 1
			}) {
				t.Fatalf("200 PRACK count = %d, want 1", len(transport.messagesByStatus(sipStatusOK, "PRACK")))
			}
			var update sip.Message
			select {
			case update = <-updateCh:
			case <-time.After(time.Second):
				t.Fatal("precondition UPDATE was not sent")
			}
			if got := update.Header("Require"); got != preconditionOption {
				t.Fatalf("UPDATE Require = %q, want %q", got, preconditionOption)
			}
			body := string(update.Body)
			for _, want := range []string{
				"a=curr:qos local sendrecv",
				"a=des:qos mandatory local sendrecv",
				"a=des:qos optional remote sendrecv",
			} {
				if !strings.Contains(body, want+"\r\n") {
					t.Fatalf("UPDATE body missing %q:\n%s", want, body)
				}
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			progressCh := make(chan sip.Message, 1)
			events := make(chan CallEvent, 4)
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					progressCh <- msg
				}
			}
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{}, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
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
			var got IncomingCall
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
			if got := got.Call.State(); got != CallStateEnded {
				t.Fatalf("call.State() = %s, want %s", got, CallStateEnded)
			}
			if !waitForCallEvent(events, CallStateEnded, "remote cancel", time.Second) {
				t.Fatal("remote cancel event was not observed")
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			prepareStarted := make(chan struct{}, 1)
			releasePrepare := make(chan struct{})
			incoming := make(chan IncomingCall, 1)
			svc, err := New(Config{Logger: testLogger(),
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					prepareStarted <- struct{}{}
					select {
					case <-releasePrepare:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}}, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			prepareStarted := make(chan struct{}, 1)
			releasePrepare := make(chan struct{})
			incoming := make(chan IncomingCall, 1)
			events := make(chan CallEvent, 8)
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
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
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
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

			var got IncomingCall
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
			progressRSeq, err := strconv.ParseInt(progress.Header("RSeq"), 10, 64)
			if err != nil || progressRSeq < 1 || progressRSeq > rseqInitialMax {
				t.Fatalf("183 RSeq = %q, want 1..%d", progress.Header("RSeq"), rseqInitialMax)
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
			ringingRSeq, err := strconv.ParseInt(ringing.Header("RSeq"), 10, 64)
			if err != nil || ringingRSeq != progressRSeq+1 {
				t.Fatalf("180 RSeq = %q, want %d", ringing.Header("RSeq"), progressRSeq+1)
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
			if !waitForCallEvent(events, CallStateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK", got.Call.State())
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			incoming := make(chan IncomingCall, 1)
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.RemotePort != 0 || len(cfg.RemoteIP) != 0 {
						t.Fatalf("PrepareMedia remote = %v:%d, want empty", cfg.RemoteIP, cfg.RemotePort)
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
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

			var got IncomingCall
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
			if !waitForCallEvent(events, CallStateActive, "", time.Second) {
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

func TestIncomingInviteAnswerOmitsGeolocationPIDF(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "200 OK carries SDP only under invite/register PIDF config"},
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

			incoming := make(chan IncomingCall, 1)
			svc, err := New(Config{Logger: testLogger(),
				GeolocationPIDFInvite: []int{GeolocationPIDFNonEmergencyWiFi},
				GeolocationCountry:    "US",
				OnIncomingCall:        func(event IncomingCall) { incoming <- event },
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

			var got IncomingCall
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
			if got := ok200.Header("Accept"); got != "application/sdp" {
				t.Fatalf("200 OK Accept = %q, want application/sdp", got)
			}
			if got := ok200.Header("Geolocation"); got != "" {
				t.Fatalf("200 OK Geolocation = %q, want empty", got)
			}
			if got := ok200.Header("Geolocation-Routing"); got != "" {
				t.Fatalf("200 OK Geolocation-Routing = %q, want empty", got)
			}
			body, ok := sdpBody(ok200)
			if !ok {
				t.Fatal("sdpBody() ok = false, want SDP part")
			}
			if !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("SDP body = %q, want audio media", string(body))
			}
			if got := ok200.Header("Content-Type"); got != "application/sdp" {
				t.Fatalf("200 OK Content-Type = %q, want application/sdp", got)
			}
			if strings.Contains(string(ok200.Body), "application/pidf+xml") {
				t.Fatalf("200 OK body contains PIDF, want SDP only:\n%s", string(ok200.Body))
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			incoming := make(chan IncomingCall, 1)
			events := make(chan CallEvent, 8)
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
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

			var got IncomingCall
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
			if !waitForCallEvent(events, CallStateActive, "", time.Second) {
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
func TestCallHoldAndResumeSendReINVITEs(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "local hold and resume modify dialog media"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
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
				if msg.Method() == "INVITE" {
					transport.queue(callOK(msg))
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if err := call.Hold(context.Background()); err != nil {
				t.Fatalf("Hold() error = %v", err)
			}
			if got := call.HoldState(); got != CallHoldLocal {
				t.Fatalf("hold state after Hold = %s, want %s", got, CallHoldLocal)
			}
			if err := call.Resume(context.Background()); err != nil {
				t.Fatalf("Resume() error = %v", err)
			}
			if got := call.HoldState(); got != CallHoldNone {
				t.Fatalf("hold state after Resume = %s, want %s", got, CallHoldNone)
			}

			invites := transport.messagesByMethod("INVITE")
			if len(invites) != 3 {
				t.Fatalf("INVITE count = %d, want initial plus hold plus resume", len(invites))
			}
			if !strings.Contains(string(invites[1].Body), "a=sendonly\r\n") {
				t.Fatalf("hold re-INVITE body missing sendonly:\n%s", string(invites[1].Body))
			}
			if !strings.Contains(string(invites[2].Body), "a=sendrecv\r\n") {
				t.Fatalf("resume re-INVITE body missing sendrecv:\n%s", string(invites[2].Body))
			}
			if got := transport.countMethod("ACK"); got != 3 {
				t.Fatalf("ACK count = %d, want initial plus hold plus resume", got)
			}
		})
	}
}

func TestCallHoldResponseWithoutSessionExpiresStopsTimer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "mid-dialog re-INVITE 2xx can turn off session timer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				SessionTimer: true,
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				resp := callOK(msg)
				if invites == 1 {
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "180;refresher=uac")
				}
				transport.queue(resp)
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.mu.Lock()
			activeBefore := call.sessionTimer.active
			call.mu.Unlock()
			if !activeBefore {
				t.Fatal("session timer active before hold = false, want true")
			}

			if err := call.Hold(context.Background()); err != nil {
				t.Fatalf("Hold() error = %v", err)
			}
			call.mu.Lock()
			timer := call.sessionTimer
			call.mu.Unlock()
			if timer.active {
				t.Fatalf("session timer active = true after hold 2xx without Session-Expires: %+v", timer)
			}
		})
	}
}

func TestCallHoldRetriesIncreasingMinSE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "hold re-INVITE retries with received Min-SE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				SessionTimer: true,
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				switch invites {
				case 1:
					resp := callOK(msg)
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "180;refresher=uac")
					transport.queue(resp)
				case 2:
					resp := callStatus(msg, sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
					resp.Headers.Add("Min-SE", "600")
					transport.queue(resp)
				case 3:
					if got := msg.Header("Min-SE"); got != "600" {
						t.Fatalf("hold retry Min-SE = %q, want 600", got)
					}
					if got := msg.Header("Session-Expires"); got != "600;refresher=uac" {
						t.Fatalf("hold retry Session-Expires = %q, want 600;refresher=uac", got)
					}
					resp := callOK(msg)
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "600;refresher=uac")
					transport.queue(resp)
				default:
					t.Fatalf("INVITE count = %d, want initial plus hold plus retry", invites)
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if err := call.Hold(context.Background()); err != nil {
				t.Fatalf("Hold() error = %v", err)
			}
			if invites != 3 {
				t.Fatalf("INVITE count = %d, want 3", invites)
			}
			if got := call.HoldState(); got != CallHoldLocal {
				t.Fatalf("hold state = %s, want %s", got, CallHoldLocal)
			}
			call.mu.Lock()
			timer := call.sessionTimer
			call.mu.Unlock()
			if !timer.active || !timer.localRefresher || timer.minSE != 600 || timer.interval != 600*time.Second {
				t.Fatalf("session timer = %+v, want active local refresher 600s/min-se 600", timer)
			}
		})
	}
}

func TestCallHoldRejectsPendingAndEmergency(t *testing.T) {
	tests := []struct {
		name      string
		call      func() *Call
		cfg       Config
		wantError string
	}{
		{
			name:      "local re-invite pending",
			call:      func() *Call { return &Call{state: CallStateActive, localINVITEPending: true} },
			wantError: "local re-INVITE is already pending",
		},
		{
			name:      "emergency default rejects hold",
			call:      func() *Call { return &Call{state: CallStateActive, emergency: true} },
			wantError: "emergency hold is disabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Endpoint{cfg: tt.cfg}
			call := tt.call()
			call.endpoint = svc
			err := call.Hold(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Hold() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestCallHoldResumeAlreadyAppliedAreIdempotent(t *testing.T) {
	tests := []struct {
		name string
		call func() *Call
		run  func(*Call) error
	}{
		{
			name: "hold already local held",
			call: func() *Call { return &Call{state: CallStateActive, hold: CallHoldLocal} },
			run:  func(call *Call) error { return call.Hold(context.Background()) },
		},
		{
			name: "resume already locally resumed",
			call: func() *Call { return &Call{state: CallStateActive} },
			run:  func(call *Call) error { return call.Resume(context.Background()) },
		},
		{
			name: "resume keeps remote hold",
			call: func() *Call { return &Call{state: CallStateActive, hold: CallHoldRemote} },
			run:  func(call *Call) error { return call.Resume(context.Background()) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := tt.call()
			call.endpoint = &Endpoint{}
			before := call.HoldState()
			if err := tt.run(call); err != nil {
				t.Fatalf("hold operation error = %v", err)
			}
			if got := call.HoldState(); got != before {
				t.Fatalf("hold state = %s, want %s", got, before)
			}
		})
	}
}

func TestCallHoldAllowsEmergencyOverride(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "carrier override allows emergency hold request"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			cfg, err := (Config{AllowHoldDuringEmergency: true}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			call := &Call{
				endpoint:  &Endpoint{cfg: cfg, sess: sess, reg: reg},
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:callee@example.com",
				remoteTo:  "<sip:callee@example.com>;tag=remote-tag",
				targetURI: "sip:callee@192.0.2.10:5060",
				localPort: 40000,
				emergency: true,
				localSDP:  inviteWithSDP().Body,
			}
			if _, _, _, _, _, clearPending, err := call.beginLocalHoldModification(callActionHold, true, mediaDirectionSendOnly); err != nil {
				t.Fatalf("beginLocalHoldModification() error = %v", err)
			} else {
				clearPending()
			}
		})
	}
}

func TestCallHoldPreconditionReINVITEMarksQoSMet(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "hold session modification reuses established qos"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{Preconditions: true}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			call := &Call{
				endpoint: &Endpoint{cfg: cfg},
				state:    CallStateActive,
				media:    NegotiatedMedia{Codec: CodecAMRWB},
				localSDP: []byte("v=0\r\n" +
					"o=- 1 1 IN IP4 10.0.0.1\r\n" +
					"s=-\r\n" +
					"c=IN IP4 10.0.0.1\r\n" +
					"t=0 0\r\n" +
					"m=audio 40000 RTP/AVP 104\r\n" +
					"a=rtpmap:104 AMR-WB/16000\r\n" +
					"a=sendrecv\r\n" +
					"a=curr:qos local none\r\n" +
					"a=curr:qos remote none\r\n" +
					"a=des:qos mandatory local sendrecv\r\n" +
					"a=des:qos optional remote sendrecv\r\n"),
			}
			body, err := call.localSDPWithDirection(mediaDirectionSendOnly)
			if err != nil {
				t.Fatalf("localSDPWithDirection() error = %v", err)
			}
			snap := dialogSnapshot{targetURI: "sip:remote@example.com", preconditions: true}
			msg := snap.buildMediaReINVITE(2, sessionTimerState{}, body)
			got := string(msg.Body)
			for _, want := range []string{
				"a=sendonly\r\n",
				"a=curr:qos local sendrecv\r\n",
				"a=curr:qos remote sendrecv\r\n",
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("hold re-INVITE body missing %q:\n%s", want, got)
				}
			}
			if got := msg.Header("Supported"); !sip.TokenListContains(got, preconditionOption) {
				t.Fatalf("hold re-INVITE Supported = %q, want precondition", got)
			}
		})
	}
}

func TestCallHoldNon2xxRestoresState(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "hold rejected by remote"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				if invites == 1 {
					transport.queue(callOK(msg))
					return
				}
				transport.queue(callStatus(msg, sipStatusNotAcceptableHere, "Not Acceptable Here"))
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			before := append([]byte(nil), call.localSDP...)
			err = call.Hold(context.Background())
			if err == nil {
				t.Fatal("Hold() error = nil, want remote rejection")
			}
			if got := call.HoldState(); got != CallHoldNone {
				t.Fatalf("hold state = %s, want %s", got, CallHoldNone)
			}
			if !bytes.Equal(call.localSDP, before) {
				t.Fatalf("localSDP changed after failed hold:\n%s", string(call.localSDP))
			}
		})
	}
}

func TestCallHoldContextCancelRestoresPendingState(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "cancelled hold does not leave local invite pending"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				if invites == 1 {
					transport.queue(callOK(msg))
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			before := append([]byte(nil), call.localSDP...)
			holdCtx, holdCancel := context.WithCancel(context.Background())
			holdCancel()
			err = call.Hold(holdCtx)
			if err == nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("Hold() error = %v, want context canceled", err)
			}
			if got := call.HoldState(); got != CallHoldNone {
				t.Fatalf("hold state = %s, want %s", got, CallHoldNone)
			}
			call.mu.Lock()
			pending := call.localINVITEPending
			localSDP := append([]byte(nil), call.localSDP...)
			call.mu.Unlock()
			if pending {
				t.Fatal("localINVITEPending = true, want false")
			}
			if !bytes.Equal(localSDP, before) {
				t.Fatalf("localSDP changed after cancelled hold:\n%s", string(localSDP))
			}
		})
	}
}

func TestCallHoldBlocksRTPButAllowsRTCP(t *testing.T) {
	tests := []struct {
		name      string
		hold      CallHoldState
		direction mediaDirection
		wantRTP   bool
	}{
		{name: "local hold", hold: CallHoldLocal, direction: mediaDirectionSendOnly},
		{name: "inactive media", hold: CallHoldRemote, direction: mediaDirectionInactive},
		{name: "remote hold sendonly answer allows rtp", hold: CallHoldRemote, direction: mediaDirectionSendOnly, wantRTP: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rtcpCh := make(chan []byte, 1)
			call := &Call{
				state: CallStateActive,
				hold:  tt.hold,
				media: NegotiatedMedia{Direction: tt.direction},
				transport: &voiceMediaTransport{
					local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
					rtcpCh: rtcpCh,
				},
			}
			err := call.WriteRTP(context.Background(), []byte("rtp"))
			if tt.wantRTP && err != nil {
				t.Fatalf("WriteRTP() error = %v, want nil", err)
			}
			if !tt.wantRTP && err == nil {
				t.Fatal("WriteRTP() error = nil, want hold rejection")
			}
			if err := call.WriteRTCP(context.Background(), []byte("rtcp")); err != nil {
				t.Fatalf("WriteRTCP() error = %v", err)
			}
			select {
			case got := <-rtcpCh:
				if string(got) != "rtcp" {
					t.Fatalf("RTCP packet = %q, want rtcp", string(got))
				}
			default:
				t.Fatal("RTCP packet was not written")
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			timeout := 80 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(timeout),
				RTCPInactivityTimeout: Duration(time.Second),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			time.Sleep(timeout / 2)
			media.notify(MediaPacket{})
			if waitForCallEvent(events, CallStateEnded, "rtp inactivity timeout", timeout*3/4) {
				t.Fatal("call ended before reset RTP inactivity timeout elapsed")
			}
			if !waitForCallEvent(events, CallStateEnded, "rtp inactivity timeout", 2*timeout) {
				t.Fatalf("call state = %s, want %s after RTP inactivity", call.State(), CallStateEnded)
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
			if got := byes[0].Header("Reason"); got != reasonMediaTimeout {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaTimeout)
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
				endpoint: &Endpoint{cfg: Config{
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
		name      string
		byeStatus int
		byeReason string
		wantError bool
	}{
		{name: "rtcp bye releases dialog", byeStatus: 200, byeReason: "OK"},
		{name: "rtcp bye accepts missing dialog response", byeStatus: 481, byeReason: "Call/Transaction Does Not Exist"},
		{name: "rtcp bye accepts request timeout response", byeStatus: 408, byeReason: "Request Timeout"},
		{name: "rtcp bye reports non-terminating response", byeStatus: 500, byeReason: "Server Internal Error", wantError: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			events := make(chan CallEvent, 16)
			errCh := make(chan error, 1)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(time.Second),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
				OnError:     func(err error) { errCh <- err },
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
					transport.queue(callStatus(msg, tt.byeStatus, tt.byeReason))
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			media.notify(MediaPacket{RTCP: true, RTCPBye: true})
			if !waitForCallEvent(events, CallStateEnded, "rtcp bye", time.Second) {
				t.Fatalf("call state = %s, want %s after RTCP BYE", call.State(), CallStateEnded)
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
			if tt.wantError {
				select {
				case err := <-errCh:
					if !strings.Contains(err.Error(), tt.byeReason) {
						t.Fatalf("OnError() = %v, want %q", err, tt.byeReason)
					}
				case <-time.After(time.Second):
					t.Fatal("OnError() was not called")
				}
			} else {
				select {
				case err := <-errCh:
					t.Fatalf("OnError() = %v, want none", err)
				default:
				}
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			rtcpCh := make(chan []byte, 2)
			media := &voiceMediaTransport{
				local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				rtcpCh: rtcpCh,
			}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(time.Second),
				RTCPSendInterval:      Duration(20 * time.Millisecond),
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			rtcpCh := make(chan []byte, 2)
			media := &voiceMediaTransport{
				local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				rtcpCh: rtcpCh,
			}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(40 * time.Millisecond),
				RTCPSendInterval:      Duration(20 * time.Millisecond),
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
					resp.Body = bytes.Replace(resp.Body, []byte("m=audio 50000 RTP/AVP 104 110\r\n"), []byte("m=audio 50000 RTP/AVP 104 110\r\nb=RS:0\r\nb=RR:0\r\n"), 1)
					transport.queue(resp)
				case "BYE":
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
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

func TestEarlyMediaHoldInactivityWatchDoesNotEndCall(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "early media hold ignores rtp and rtcp timeout release"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rtpTimeout := 40 * time.Millisecond
			rtcpTimeout := 160 * time.Millisecond
			cfg, err := (Config{
				Logger:                testLogger(),
				RTPInactivityTimeout:  Duration(rtpTimeout),
				RTCPInactivityTimeout: Duration(rtcpTimeout),
				RTCPSendInterval:      Duration(0),
				AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{
					AudioInactivityRTPOnConnected,
					AudioInactivityRTCPOnHold,
				},
			}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			events := make(chan CallEvent, 2)
			cfg.OnCallEvent = func(event CallEvent) { events <- event }
			svc := &Endpoint{
				cfg:       cfg,
				logger:    testLogger(),
				calls:     make(map[string]*Call),
				incomings: make(map[string]*Call),
			}
			call := &Call{
				endpoint: svc,
				id:       "hold-watch-call",
				state:    CallStateEarlyMedia,
				hold:     CallHoldLocal,
				transport: &voiceMediaTransport{
					local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				},
			}
			svc.calls[call.id] = call
			call.startMediaInactivityWatch()
			defer func() {
				call.finish(CallStateEnded, "test cleanup")
			}()

			if waitForCallEvent(events, CallStateEnded, "rtp inactivity timeout", 2*rtpTimeout) {
				t.Fatal("call ended on RTP inactivity while held")
			}
			if waitForCallEvent(events, CallStateEnded, "rtcp inactivity timeout", 2*rtcpTimeout) {
				t.Fatal("early media call ended on RTCP inactivity while held")
			}
			if got := call.State(); got != CallStateEarlyMedia {
				t.Fatalf("call.State() = %q, want %q", got, CallStateEarlyMedia)
			}
		})
	}
}

func TestHeldCallInactivityWatchUsesRTCPOnHoldPolicy(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "active hold keeps rtcp timeout release policy"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			rtpTimeout := 40 * time.Millisecond
			rtcpTimeout := 160 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(rtpTimeout),
				RTCPInactivityTimeout: Duration(rtcpTimeout),
				RTCPSendInterval:      Duration(0),
				AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{
					AudioInactivityRTPOnConnected,
					AudioInactivityRTCPOnHold,
				},
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.mu.Lock()
			call.hold = CallHoldLocal
			call.mu.Unlock()
			call.restartMediaInactivityWatch()

			if waitForCallEvent(events, CallStateEnded, "rtp inactivity timeout", 2*rtpTimeout) {
				t.Fatal("held call ended on RTP inactivity")
			}
			if !waitForCallEvent(events, CallStateEnded, "rtcp inactivity timeout", 2*rtcpTimeout) {
				t.Fatalf("call state = %s, want RTCP-on-hold timeout", call.State())
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaTimeout {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaTimeout)
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			rtpWrites := make(chan []byte, 2)
			media := &voiceRTPOnlyMediaTransport{
				local:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				writeCh: rtpWrites,
			}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(time.Second),
				RTCPSendInterval:      Duration(20 * time.Millisecond),
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
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

func TestDialEndsAfterRTCPInactivityWhenPolicyIncludesRTCP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "connected rtcp timeout ends call"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			rtcpTimeout := 40 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(rtcpTimeout),
				AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{
					AudioInactivityRTCPOnConnected,
				},
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			if !waitForCallEvent(events, CallStateEnded, "rtcp inactivity timeout", 3*rtcpTimeout) {
				t.Fatalf("call state = %s, want ended after RTCP inactivity", call.State())
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaTimeout {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaTimeout)
			}
		})
	}
}

func TestDialUsesEmergencyAudioInactivityPolicy(t *testing.T) {
	tests := []struct {
		name       string
		reasons    []AudioInactivityCallEndReason
		wantEnded  bool
		wantReason string
	}{
		{
			name:       "emergency rtcp reason ends emergency call",
			reasons:    []AudioInactivityCallEndReason{AudioInactivityE911RTCP},
			wantEnded:  true,
			wantReason: "rtcp inactivity timeout",
		},
		{
			name:    "normal connected rtcp reason does not end emergency call",
			reasons: []AudioInactivityCallEndReason{AudioInactivityRTCPOnConnected},
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
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			rtcpTimeout := 40 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:          Duration(time.Second),
				RTCPInactivityTimeout:         Duration(rtcpTimeout),
				AudioInactivityCallEndReasons: tt.reasons,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "911", Emergency: true})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			ended := waitForCallEvent(events, CallStateEnded, tt.wantReason, 3*rtcpTimeout)
			if ended != tt.wantEnded {
				t.Fatalf("ended after RTCP inactivity = %t, want %t", ended, tt.wantEnded)
			}
			if tt.wantEnded {
				return
			}
			if got := transport.countMethod("BYE"); got != 0 {
				t.Fatalf("BYE count before hangup = %d, want 0", got)
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(secureRegistrationConfig(transport, registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}), sess, voiceStubCard{})
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
					resp.Headers.Add("Security-Server", `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`)
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
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true,
				OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
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
			prackCount := 0
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					transport.queue(reliableCallProgress(msg))
				case "PRACK":
					prackCount++
					transport.queue(callStatus(msg, 200, "OK"))
					if prackCount == 1 {
						progress := sip.NewResponse(180, "Ringing")
						progress.Headers = sip.ResponseHeaders(invite, 180)
						progress.Headers = sip.UpsertHeader(progress.Headers, "To", sip.WithTag(invite.Header("To"), "", "early-tag"))
						progress.Headers.Add("Require", "100rel")
						progress.Headers.Add("RSeq", "8")
						transport.queue(progress)
						return
					}
					if prackCount == 2 {
						transport.queue(callOKWithoutSDP(invite, "early-tag"))
					}
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if call.State() != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", call.State(), CallStateConfirmed)
			}
			pracks := transport.messagesByMethod("PRACK")
			if len(pracks) != 2 {
				t.Fatalf("PRACK count = %d, want 2", len(pracks))
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
			if got := prack.Header("Supported"); !sip.TokenListContains(got, sessionTimerOption) {
				t.Fatalf("PRACK Supported = %q, want timer", got)
			}
			nextPRACK := pracks[1]
			if got := nextPRACK.Header("RAck"); got != "8 1 INVITE" {
				t.Fatalf("second PRACK RAck = %q, want %q", got, "8 1 INVITE")
			}
			if got := sip.RequestURI(nextPRACK); got != "sip:early@192.0.2.10:5060" {
				t.Fatalf("second PRACK Request-URI = %q, want early dialog target", got)
			}
			if got := nextPRACK.Header("Route"); got != "<sip:pcscf.example.com;lr>" {
				t.Fatalf("second PRACK Route = %q, want early dialog route set", got)
			}
			media := call.Media()
			if !media.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) || media.RemotePort != 50000 {
				t.Fatalf("call media = %+v, want early SDP answer media", media)
			}
		})
	}
}

func TestUnknownPRACKDialogGets481(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "unknown early dialog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			prack := sip.NewRequest("PRACK", "sip:001010123456789@192.0.2.20:5062")
			prack.Headers.Add("Via", "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKunknownprack")
			prack.Headers.Add("From", `<sip:caller@example.com>;tag=remote-tag`)
			prack.Headers.Add("To", `<sip:001010123456789@example.com>;tag=missing-local-tag`)
			prack.Headers.Add("Call-ID", "missing-call")
			prack.Headers.Add("CSeq", "2 PRACK")
			prack.Headers.Add("RAck", "1 1 INVITE")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: prack, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusCallTransactionDoesNotExist, "PRACK")
			if len(responses) != 1 {
				t.Fatalf("481 PRACK count = %d, want 1", len(responses))
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			opened := make(chan MediaConfig, 2)
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					opened <- cfg
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: cfg.LocalPort}}, nil
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
				_, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
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
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 16)
			opened := make(chan MediaConfig, 2)
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					opened <- cfg
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: cfg.LocalPort}}, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if !waitForCallEvent(events, CallStateEarlyMedia, "", time.Second) {
				t.Fatalf("call state = %s, want early media event", call.State())
			}
			if !waitForCallEvent(events, CallStateConfirmed, "", time.Second) {
				t.Fatalf("call state = %s, want confirmed event", call.State())
			}
			if got := call.State(); got != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, CallStateConfirmed)
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

func TestDialSendsACKBeforeOpeningFinalMedia(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "final 2xx is acknowledged before local media open"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			ackSeen := make(chan struct{}, 1)
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					select {
					case <-ackSeen:
					default:
						t.Fatal("OpenMedia was called before final INVITE ACK")
					}
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}}, nil
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
				case "ACK":
					select {
					case ackSeen <- struct{}{}:
					default:
					}
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if got := call.State(); got != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, CallStateConfirmed)
			}
			if got := transport.countMethod("ACK"); got != 1 {
				t.Fatalf("ACK count = %d, want 1", got)
			}
		})
	}
}

func TestDialRoutesInDialogRequestImmediatelyAfterACK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote bye after ack matches refreshed dialog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
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

			matchedRemoteBYE := make(chan struct{}, 1)
			var ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					ok200 = callOK(msg)
					transport.queue(ok200)
				case "ACK":
					if _, ok := sess.LookupDialogKey(byeForConfirmedDialog(ok200)); !ok {
						t.Error("remote BYE after ACK did not match refreshed dialog")
						return
					}
					matchedRemoteBYE <- struct{}{}
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			select {
			case <-matchedRemoteBYE:
			default:
				t.Fatal("remote BYE after ACK did not match dialog")
			}
			if got := call.State(); got != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, CallStateConfirmed)
			}
		})
	}
}

func TestDialKeepsEarlyMediaCallAfterRTCPBye(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "early media rtcp bye does not prevent final 2xx ack"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 16)
			opened := make(chan *voiceMediaTransport, 2)
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}, onPacket: cfg.OnPacket}
					opened <- media
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
			ackSeen := make(chan struct{}, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					progress := reliableCallProgress(msg)
					progress.Headers.Add("P-Early-Media", "sendrecv")
					transport.queue(progress)
				case "PRACK":
					transport.queue(callStatus(msg, 200, "OK"))
				case "ACK":
					select {
					case ackSeen <- struct{}{}:
					default:
					}
				}
			}

			errCh := make(chan error, 1)
			callCh := make(chan *Call, 1)
			go func() {
				call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
				if err != nil {
					errCh <- err
					return
				}
				callCh <- call
			}()

			earlyMedia := nextCallEvent(t, events, CallStateEarlyMedia, "", time.Second).Call
			var firstMedia *voiceMediaTransport
			select {
			case firstMedia = <-opened:
			case <-time.After(time.Second):
				t.Fatal("early media transport was not opened")
			}
			firstMedia.notify(MediaPacket{RTCP: true, RTCPBye: true})
			if !waitForCallTest(firstMedia.isClosed) {
				t.Fatal("early media transport was not closed after RTCP BYE")
			}
			if got := earlyMedia.State(); got != CallStateEarlyMedia {
				t.Fatalf("call.State() after early RTCP BYE = %q, want %q", got, CallStateEarlyMedia)
			}

			transport.queue(callOKWithoutSDP(invite, "early-tag"))
			var call *Call
			select {
			case err := <-errCh:
				t.Fatalf("Dial() error = %v", err)
			case call = <-callCh:
			case <-time.After(time.Second):
				t.Fatal("Dial() did not complete after final response")
			}
			select {
			case <-ackSeen:
			default:
				t.Fatal("final INVITE ACK was not sent")
			}
			if got := call.State(); got != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, CallStateConfirmed)
			}
			select {
			case <-opened:
			case <-time.After(time.Second):
				t.Fatal("final media transport was not reopened")
			}
		})
	}
}

func TestDialContinuesAfterRTCPInactivityWhenPolicyOmitsRTCP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "rtp activity keeps call alive without rtcp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			rtcpTimeout := 40 * time.Millisecond
			rtpTimeout := 180 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:          Duration(rtpTimeout),
				RTCPInactivityTimeout:         Duration(rtcpTimeout),
				AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{AudioInactivityRTPOnConnected},
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			time.Sleep(2 * rtcpTimeout)
			media.notify(MediaPacket{})
			if waitForCallEvent(events, CallStateEnded, "rtcp inactivity timeout", rtcpTimeout) {
				t.Fatal("call ended after RTCP inactivity despite RTP activity")
			}
			if got := transport.countMethod("BYE"); got != 0 {
				t.Fatalf("BYE count before hangup = %d, want 0", got)
			}

			time.Sleep(2 * rtcpTimeout)
			if call.State() == CallStateEnded {
				t.Fatalf("call state = %s, want active call before RTP timeout", call.State())
			}
			if got := transport.countMethod("BYE"); got != 0 {
				t.Fatalf("BYE count before hangup = %d, want 0", got)
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
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
			name: "configured interval is capped to IR92 initial invite value",
			cfg: Config{
				SessionTimer:      true,
				SessionExpires:    3600 * time.Second,
				MinSessionExpires: 600 * time.Second,
			},
			wantSupported:      sip.DefaultClientSupported + ",timer",
			wantSessionExpires: "1800",
			wantMinSE:          "600",
		},
		{
			name: "configured uac refresher included in initial invite",
			cfg: Config{
				SessionTimer:     true,
				SessionExpires:   3600 * time.Second,
				SessionRefresher: sessionRefresherUAC,
			},
			wantSupported:      sip.DefaultClientSupported + ",timer",
			wantSessionExpires: "1800;refresher=uac",
		},
		{
			name: "configured uas refresher is omitted in initial invite",
			cfg: Config{
				SessionTimer:     true,
				SessionExpires:   3600 * time.Second,
				SessionRefresher: sessionRefresherUAS,
			},
			wantSupported:      sip.DefaultClientSupported + ",timer",
			wantSessionExpires: "1800",
		},
		{
			name: "min se above IR92 initial invite value omits session expires",
			cfg: Config{
				SessionTimer:      true,
				SessionExpires:    3600 * time.Second,
				MinSessionExpires: 3600 * time.Second,
			},
			wantSupported:       sip.DefaultClientSupported + ",timer",
			wantMinSE:           "3600",
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

func TestConfigNormalizesSessionExpiresAgainstMinSE(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want time.Duration
	}{
		{
			name: "session expires raised to configured minimum",
			cfg:  Config{SessionExpires: 300 * time.Second, MinSessionExpires: 600 * time.Second},
			want: 600 * time.Second,
		},
		{
			name: "session expires keeps configured interval above minimum",
			cfg:  Config{SessionExpires: 900 * time.Second, MinSessionExpires: 600 * time.Second},
			want: 900 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got.SessionExpires != tt.want {
				t.Fatalf("SessionExpires = %s, want %s", got.SessionExpires, tt.want)
			}
		})
	}
}

func TestConfigNormalizesSessionRefresher(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		want    string
		wantErr bool
	}{
		{name: "default", want: sessionRefresherNone},
		{name: "none lower-case normalized", cfg: Config{SessionRefresher: " NONE "}, want: sessionRefresherNone},
		{name: "uac lower-case normalized", cfg: Config{SessionRefresher: " UAC "}, want: sessionRefresherUAC},
		{name: "uas lower-case normalized", cfg: Config{SessionRefresher: " UAS "}, want: sessionRefresherUAS},
		{name: "invalid rejected", cfg: Config{SessionRefresher: "proxy"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Normalized() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got.SessionRefresher != tt.want {
				t.Fatalf("SessionRefresher = %q, want %q", got.SessionRefresher, tt.want)
			}
		})
	}
}

func TestSessionTimerHeaderCodecs(t *testing.T) {
	t.Run("Session-Expires", func(t *testing.T) {
		tests := []struct {
			name     string
			value    string
			want     sessionExpiresHeader
			wantText string
			wantErr  bool
		}{
			{
				name:     "plain interval",
				value:    "1800",
				want:     sessionExpiresHeader{seconds: 1800},
				wantText: "1800",
			},
			{
				name:     "refresher and generic param",
				value:    `600;foo=bar;refresher="uac"`,
				want:     sessionExpiresHeader{seconds: 600, refresher: sessionRefresherUAC, params: []string{"foo=bar"}},
				wantText: "600;foo=bar;refresher=uac",
			},
			{name: "empty", wantErr: true},
			{name: "zero", value: "0", wantErr: true},
			{name: "invalid refresher", value: "1800;refresher=server", wantErr: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var got sessionExpiresHeader
				err := got.UnmarshalText([]byte(tt.value))
				if tt.wantErr {
					if err == nil {
						t.Fatal("UnmarshalText() error = nil, want error")
					}
					return
				}
				if err != nil {
					t.Fatalf("UnmarshalText() error = %v", err)
				}
				if got.seconds != tt.want.seconds || got.refresher != tt.want.refresher || !slices.Equal(got.params, tt.want.params) {
					t.Fatalf("UnmarshalText() = %+v, want %+v", got, tt.want)
				}
				text, err := got.MarshalText()
				if err != nil {
					t.Fatalf("MarshalText() error = %v", err)
				}
				if string(text) != tt.wantText {
					t.Fatalf("MarshalText() = %q, want %q", text, tt.wantText)
				}
			})
		}
	})

	t.Run("Min-SE", func(t *testing.T) {
		tests := []struct {
			name     string
			value    string
			want     minSEHeader
			wantText string
			wantErr  bool
		}{
			{
				name:     "absolute minimum",
				value:    "90",
				want:     minSEHeader{seconds: 90},
				wantText: "90",
			},
			{
				name:     "generic param preserved",
				value:    "600;foo=bar",
				want:     minSEHeader{seconds: 600, params: []string{"foo=bar"}},
				wantText: "600;foo=bar",
			},
			{name: "empty", wantErr: true},
			{name: "below absolute minimum", value: "89", wantErr: true},
			{name: "not decimal", value: "soon", wantErr: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var got minSEHeader
				err := got.UnmarshalText([]byte(tt.value))
				if tt.wantErr {
					if err == nil {
						t.Fatal("UnmarshalText() error = nil, want error")
					}
					return
				}
				if err != nil {
					t.Fatalf("UnmarshalText() error = %v", err)
				}
				if got.seconds != tt.want.seconds || !slices.Equal(got.params, tt.want.params) {
					t.Fatalf("UnmarshalText() = %+v, want %+v", got, tt.want)
				}
				text, err := got.MarshalText()
				if err != nil {
					t.Fatalf("MarshalText() error = %v", err)
				}
				if string(text) != tt.wantText {
					t.Fatalf("MarshalText() = %q, want %q", text, tt.wantText)
				}
			})
		}
	})
}

func TestAddInviteOKSessionTimerUsesIR92Default(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		min         string
		session     string
		want        string
		wantRequire string
		supported   bool
	}{
		{
			name:        "supported invite without session expires uses IR92 default",
			cfg:         Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			want:        "1800;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "configured uas refresher ignored when UE fills missing timer",
			cfg:         Config{SessionTimer: true, SessionExpires: 600 * time.Second, SessionRefresher: sessionRefresherUAS},
			want:        "1800;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "local min se does not change IR92 default",
			cfg:         Config{SessionTimer: true, MinSessionExpires: 3600 * time.Second},
			want:        "1800;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "min se above default",
			cfg:         Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			min:         "3600",
			want:        "3600;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "uac refresher copied from request requires timer",
			cfg:         Config{SessionTimer: true},
			session:     "120;refresher=uac",
			want:        "120;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "uas refresher copied from supported request requires timer",
			cfg:         Config{SessionTimer: true},
			session:     "120;refresher=uas",
			want:        "120;refresher=uas",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "missing request refresher filled with uac",
			cfg:         Config{SessionTimer: true, SessionRefresher: sessionRefresherUAS},
			session:     "120",
			want:        "120;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:    "proxy inserted session expires without uac timer support",
			cfg:     Config{SessionTimer: true},
			session: "300",
			want:    "300;refresher=uas",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invite := sip.NewRequest("INVITE", "sip:local@example.com")
			if tt.supported {
				invite.Headers.Add("Supported", "timer")
			}
			if tt.min != "" {
				invite.Headers.Add("Min-SE", tt.min)
			}
			if tt.session != "" {
				invite.Headers.Add("Session-Expires", tt.session)
			}
			resp := sip.NewResponse(200, "OK")

			addInviteOKSessionTimer(&resp, invite, tt.cfg)

			if got := resp.Header("Session-Expires"); got != tt.want {
				t.Fatalf("Session-Expires = %q, want %q", got, tt.want)
			}
			if got := resp.Header("Require"); got != tt.wantRequire {
				t.Fatalf("Require = %q, want %q", got, tt.wantRequire)
			}
		})
	}
}

func TestInvalidSessionTimerRefresher(t *testing.T) {
	tests := []struct {
		name      string
		supported bool
		session   string
		want      bool
	}{
		{name: "absent", supported: false},
		{name: "proxy inserted interval without refresher", session: "300"},
		{name: "unsupported uac refresher", session: "300;refresher=uac", want: true},
		{name: "unsupported uas refresher", session: "300;refresher=uas", want: true},
		{name: "supported uac refresher", supported: true, session: "300;refresher=uac"},
		{name: "malformed handled by header parser", session: "bad;refresher=uac"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewRequest("INVITE", "sip:local@example.com")
			if tt.supported {
				msg.Headers.Add("Supported", "timer")
			}
			if tt.session != "" {
				msg.Headers.Add("Session-Expires", tt.session)
			}

			if got := invalidSessionTimerRefresher(msg); got != tt.want {
				t.Fatalf("invalidSessionTimerRefresher() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestApplySessionTimerResponseKeepsUACRequestedTimerWithoutResponseHeader(t *testing.T) {
	tests := []struct {
		name               string
		cfg                Config
		currentMinSE       int
		wantInterval       time.Duration
		wantMinSE          int
		wantLocalRefresher bool
	}{
		{
			name:               "configured session expires",
			cfg:                Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			wantInterval:       600 * time.Second,
			wantMinSE:          durationSeconds(defaultMinSessionExpires),
			wantLocalRefresher: true,
		},
		{
			name:               "stored Min-SE raises fallback interval",
			cfg:                Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			currentMinSE:       900,
			wantInterval:       900 * time.Second,
			wantMinSE:          900,
			wantLocalRefresher: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{
				endpoint:      &Endpoint{cfg: tt.cfg},
				inviteRequest: sip.NewRequest("INVITE", "sip:remote@example.com"),
				sessionTimer: sessionTimerState{
					minSE: tt.currentMinSE,
				},
			}
			call.inviteRequest.Headers.Set("Session-Expires", strconv.Itoa(durationSeconds(tt.cfg.SessionExpires)))
			defer call.stopSessionTimer()

			if err := call.applySessionTimerUACResponse(sip.NewResponse(sipStatusOK, "OK"), true); err != nil {
				t.Fatalf("applySessionTimerUACResponse() error = %v", err)
			}
			call.mu.Lock()
			got := call.sessionTimer
			call.mu.Unlock()
			if !got.active {
				t.Fatal("session timer active = false, want true")
			}
			if got.interval != tt.wantInterval {
				t.Fatalf("session timer interval = %s, want %s", got.interval, tt.wantInterval)
			}
			if got.minSE != tt.wantMinSE {
				t.Fatalf("session timer minSE = %d, want %d", got.minSE, tt.wantMinSE)
			}
			if got.localRefresher != tt.wantLocalRefresher {
				t.Fatalf("session timer localRefresher = %t, want %t", got.localRefresher, tt.wantLocalRefresher)
			}
		})
	}
}

func TestApplySessionTimerResponseWithoutHeaderStopsSubsequentRefreshTimer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "subsequent UAC refresh can turn off timer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{
				endpoint: &Endpoint{cfg: Config{SessionTimer: true}},
				sessionTimer: sessionTimerState{
					active:         true,
					interval:       600 * time.Second,
					minSE:          durationSeconds(defaultMinSessionExpires),
					localRefresher: true,
				},
			}

			if err := call.applySessionTimerUACResponse(sip.NewResponse(sipStatusOK, "OK"), false); err != nil {
				t.Fatalf("applySessionTimerUACResponse() error = %v", err)
			}
			call.mu.Lock()
			got := call.sessionTimer
			call.mu.Unlock()
			if got.active {
				t.Fatalf("session timer active = true, want false after 2xx without Session-Expires")
			}
		})
	}
}

func TestDialSessionTimerRefreshesWithUPDATE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "local refresher sends UPDATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				SessionTimer: true,
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
					resp.Headers.Add("Allow", sip.DefaultClientAllow)
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "180;refresher=uac")
					transport.queue(resp)
				case "UPDATE":
					resp := okForRequest(msg)
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "180;refresher=uac")
					transport.queue(resp)
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.refreshSession()

			updates := transport.messagesByMethod("UPDATE")
			if len(updates) != 1 {
				t.Fatalf("UPDATE count = %d, want 1", len(updates))
			}
			if got := updates[0].Header("Session-Expires"); got != "180;refresher=uac" {
				t.Fatalf("UPDATE Session-Expires = %q, want 180;refresher=uac", got)
			}
			if got := updates[0].Header("Supported"); !sip.TokenListContains(got, "timer") {
				t.Fatalf("UPDATE Supported = %q, want timer", got)
			}
		})
	}
}

func TestDialSessionTimerRefreshRetriesIncreasingMinSE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "UPDATE refresh retries with largest Min-SE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				SessionTimer: true,
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

			updates := 0
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					resp := callOK(msg)
					resp.Headers.Add("Allow", sip.DefaultClientAllow)
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "180;refresher=uac")
					transport.queue(resp)
				case "UPDATE":
					updates++
					switch updates {
					case 1:
						resp := callStatus(msg, sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
						resp.Headers.Add("Min-SE", "600")
						transport.queue(resp)
					case 2:
						if got := msg.Header("Min-SE"); got != "600" {
							t.Fatalf("retry UPDATE Min-SE = %q, want 600", got)
						}
						if got := msg.Header("Session-Expires"); got != "600;refresher=uac" {
							t.Fatalf("retry UPDATE Session-Expires = %q, want 600;refresher=uac", got)
						}
						resp := callStatus(msg, sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
						resp.Headers.Add("Min-SE", "900")
						transport.queue(resp)
					case 3:
						if got := msg.Header("Min-SE"); got != "900" {
							t.Fatalf("second retry UPDATE Min-SE = %q, want 900", got)
						}
						if got := msg.Header("Session-Expires"); got != "900;refresher=uac" {
							t.Fatalf("second retry UPDATE Session-Expires = %q, want 900;refresher=uac", got)
						}
						resp := okForRequest(msg)
						resp.Headers.Add("Require", "timer")
						resp.Headers.Add("Session-Expires", "900;refresher=uac")
						transport.queue(resp)
					default:
						t.Fatalf("UPDATE count = %d, want 3", updates)
					}
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.refreshSession()

			if updates != 3 {
				t.Fatalf("UPDATE count = %d, want 3", updates)
			}
			call.mu.Lock()
			timer := call.sessionTimer
			call.mu.Unlock()
			if !timer.active || !timer.localRefresher || timer.minSE != 900 || timer.interval != 900*time.Second {
				t.Fatalf("session timer = %+v, want active local refresher 900s/min-se 900", timer)
			}
			if got := transport.countMethod("BYE"); got != 0 {
				t.Fatalf("BYE count = %d, want 0 after successful retry", got)
			}
		})
	}
}

func TestSessionTimerRefreshNon2xxTerminatesDialog(t *testing.T) {
	transport := newVoiceStubTransport()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	reg, err := registration.New(registration.Config{Logger: testLogger(),
		PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
		IMEI:            "123456789012345",
	}, sess, voiceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	media := &voiceMediaTransport{}
	svc, err := New(Config{Logger: testLogger(),
		SessionTimer: true,
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
			resp.Headers.Add("Allow", sip.DefaultClientAllow)
			resp.Headers.Add("Require", "timer")
			resp.Headers.Add("Session-Expires", "180;refresher=uac")
			transport.queue(resp)
		case "UPDATE":
			transport.queue(callStatus(msg, sipStatusServerInternalError, "Server Internal Error"))
		case "BYE":
			transport.queue(okForRequest(msg))
		}
	}

	call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	call.refreshSession()

	if !waitForCallTest(func() bool { return transport.countMethod("BYE") == 1 }) {
		t.Fatalf("BYE count = %d, want 1 after failed session refresh", transport.countMethod("BYE"))
	}
	if got := call.State(); got != CallStateEnded {
		t.Fatalf("call state = %s, want %s", got, CallStateEnded)
	}
}

func TestDialSessionTimerRefreshFallsBackToReINVITEWithoutRemoteUPDATE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote Allow does not advertise UPDATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				SessionTimer: true,
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				resp := callOK(msg)
				resp.Headers.Add("Require", "timer")
				resp.Headers.Add("Session-Expires", "180;refresher=uac")
				if invites == 1 {
					resp.Headers.Add("Allow", "ACK,BYE,CANCEL,INVITE,PRACK")
				} else {
					resp.Headers.Set("Contact", "<sip:remote-refresh@192.0.2.11:5060>")
					resp.Body = bytes.Replace(resp.Body, []byte("m=audio 50000 RTP/AVP 104 110\r\n"), []byte("m=audio 51000 RTP/AVP 104 110\r\n"), 1)
				}
				transport.queue(resp)
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.refreshSession()

			if got := transport.countMethod("UPDATE"); got != 0 {
				t.Fatalf("UPDATE count = %d, want 0", got)
			}
			refreshes := transport.messagesByMethod("INVITE")
			if len(refreshes) != 2 {
				t.Fatalf("INVITE count = %d, want initial plus refresh", len(refreshes))
			}
			refresh := refreshes[1]
			if got := refresh.Header("Session-Expires"); got != "180;refresher=uac" {
				t.Fatalf("re-INVITE Session-Expires = %q, want 180;refresher=uac", got)
			}
			if got := refresh.Header("Supported"); !sip.TokenListContains(got, "timer") {
				t.Fatalf("re-INVITE Supported = %q, want timer", got)
			}
			if got := refresh.Header("Content-Type"); got != "application/sdp" {
				t.Fatalf("re-INVITE Content-Type = %q, want application/sdp", got)
			}
			if got := transport.countMethod("ACK"); got != 2 {
				t.Fatalf("ACK count = %d, want initial ACK plus re-INVITE ACK", got)
			}
			call.mu.Lock()
			target := call.targetURI
			call.mu.Unlock()
			if target != "sip:remote-refresh@192.0.2.11:5060" {
				t.Fatalf("targetURI = %q, want refreshed Contact", target)
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 51000 {
				t.Fatalf("media remote port = %d, want refreshed SDP answer port 51000", remote.Port)
			}
		})
	}
}

func TestSessionRefreshReINVITEUsesLocalSDP(t *testing.T) {
	const remoteSDP = "v=0\r\no=- 10 10 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\n"
	const localSDP = "v=0\r\no=- 20 20 IN IP4 192.0.2.20\r\ns=-\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\nm=audio 40000 RTP/AVP 104\r\n"

	tests := []struct {
		name string
	}{
		{name: "incoming dialog refresh reuses local answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invite := sip.NewRequest("INVITE", "sip:local@example.com")
			invite.Headers.Set("Content-Type", "application/sdp")
			invite.Body = []byte(remoteSDP)
			snap := dialogSnapshot{
				id:            "call-id",
				localURI:      "sip:local@example.com",
				localTag:      "local-tag",
				remoteTo:      "<sip:remote@example.com>;tag=remote-tag",
				targetURI:     "sip:remote@192.0.2.10:5060",
				inviteSeq:     1,
				inviteRequest: invite,
				localSDP:      []byte(localSDP),
				transport:     "TCP",
				contactHost:   "192.0.2.20",
				messagePort:   5060,
				contact:       "<sip:local@192.0.2.20:5060>",
			}
			msg := snap.buildSessionRefreshRequest(2, sessionTimerState{
				active:         true,
				interval:       180 * time.Second,
				minSE:          durationSeconds(defaultMinSessionExpires),
				localRefresher: true,
			})

			if got := msg.Method(); got != "INVITE" {
				t.Fatalf("refresh method = %q, want INVITE", got)
			}
			if got := msg.Header("Content-Type"); got != "application/sdp" {
				t.Fatalf("Content-Type = %q, want application/sdp", got)
			}
			if string(msg.Body) != localSDP {
				t.Fatalf("refresh SDP = %q, want local SDP %q", string(msg.Body), localSDP)
			}
		})
	}
}
