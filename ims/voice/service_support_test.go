package voice

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
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
