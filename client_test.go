package imsclient

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/damonto/ims-client/ims"
	"github.com/damonto/ims-client/swu"
	"github.com/damonto/ims-client/usim"
)

type stubCard struct{}

func (stubCard) ICCID() string { return "8986000000000000000" }
func (stubCard) IMSI() string  { return "001010123456789" }
func (stubCard) MCC() string   { return "001" }
func (stubCard) MNC() string   { return "001" }
func (stubCard) SMSC() string  { return "+8613800000000" }
func (stubCard) AKA(_ context.Context, _, _ []byte) (usim.AKAResult, error) {
	return usim.AKAResult{RES: []byte("12345678")}, nil
}

const (
	testIMEI              = "356789012345678"
	fakeIMSSecurityServer = "ipsec-3gpp;alg=hmac-md5-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=10;spi-s=20"
)

func mustListenUDP(t *testing.T, name string) net.PacketConn {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket(%s): %v", name, err)
	}
	return conn
}

func newTestClient(t *testing.T, proxyAddr string) *Client {
	t.Helper()
	client, err := newClient(Config{
		IMEI:         testIMEI,
		PCSCFAddress: proxyAddr,
		IMS: ims.Config{
			RegisterExpires: time.Minute,
		},
	}, stubCard{})
	if err != nil {
		t.Fatalf("newClient() error = %v", err)
	}
	return client
}

func testNonce() string {
	return base64.StdEncoding.EncodeToString(append(bytesOf(0x01, 16), bytesOf(0x02, 16)...))
}

func newIMSResponse(req ims.Message, code int, reason string) ims.Message {
	res := ims.NewResponse(code, reason)
	res.Headers = responseHeaders(req)
	return res
}

func newUnauthorizedRegisterResponse(req ims.Message, nonce string) ims.Message {
	res := newIMSResponse(req, 401, "Unauthorized")
	res.AddHeader("WWW-Authenticate", fmt.Sprintf(`Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="%s",algorithm=AKAv1-MD5`, nonce))
	res.AddHeader("Security-Server", fakeIMSSecurityServer)
	return res
}

func TestClientConnectAndSendSMS(t *testing.T) {
	server := mustListenUDP(t, "server")
	defer server.Close()

	messageSeen := make(chan struct{}, 1)
	go runFakeIMS(t, server, messageSeen)

	client := newTestClient(t, server.LocalAddr().String())
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := client.SMS().Send(ctx, "+8613700000000", "hello"); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case <-messageSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("MESSAGE request not observed")
	}

	events := client.Events()
	got := collectStates(events.State, 3, 2*time.Second)
	want := []RegistrationState{StateConnecting, StateAuthenticating, StateRegistered}
	for i, state := range want {
		if i >= len(got) || got[i] != state {
			t.Fatalf("state[%d] = %q, want %q (all=%v)", i, firstOrEmpty(got, i), state, got)
		}
	}
}

func TestClientSendSMSLateRPErrorEmitsEvent(t *testing.T) {
	server := mustListenUDP(t, "server")
	defer server.Close()

	reportSeen := make(chan struct{}, 1)
	go runFakeIMSSubmitReportError(t, server, reportSeen)

	client := newTestClient(t, server.LocalAddr().String())
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if err := client.SMS().Send(ctx, "+8613700000000", "hello"); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	select {
	case <-reportSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("RP-ERROR request not observed")
	}

	select {
	case err := <-client.Events().Errors:
		var rpErr *ims.RPError
		if !errors.As(err, &rpErr) {
			t.Fatalf("Events().Errors err = %v, want RPError", err)
		}
		if rpErr.Cause != 96 {
			t.Fatalf("RPError.Cause = %d, want 96", rpErr.Cause)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting for async SMS error event")
	}
}

func runFakeIMS(t *testing.T, server net.PacketConn, messageSeen chan<- struct{}) {
	t.Helper()
	nonce := testNonce()
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			return
		}
		msg, err := ims.ParseMessage(buf[:n])
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch msg.Method() {
		case "REGISTER":
			res := newUnauthorizedRegisterResponse(msg, nonce)
			authorization := msg.Header("Authorization")
			if authorization != "" && !strings.Contains(authorization, `nonce=""`) && !strings.Contains(authorization, `response=""`) {
				res = newIMSResponse(msg, 200, "OK")
			}
			_, _ = server.WriteTo(res.Bytes(), addr)
		case "SUBSCRIBE":
			_, _ = server.WriteTo(newIMSResponse(msg, 200, "OK").Bytes(), addr)
		case "MESSAGE":
			_, _ = server.WriteTo(newIMSResponse(msg, 200, "OK").Bytes(), addr)
			if len(msg.Body) >= 2 {
				rpAck := ims.NewRequest("MESSAGE", msg.Header("From"))
				rpAck.AddHeader("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-rp-ack")
				rpAck.AddHeader("From", "<sip:smsc@example.com>;tag=1")
				rpAck.AddHeader("To", msg.Header("From"))
				rpAck.AddHeader("Call-ID", "sms-rp-ack")
				rpAck.AddHeader("CSeq", "1 MESSAGE")
				rpAck.AddHeader("In-Reply-To", msg.Header("Call-ID"))
				rpAck.AddHeader("P-Asserted-Identity", fmt.Sprintf("<tel:%s>", stubCard{}.SMSC()))
				rpAck.Body = []byte{0x03, msg.Body[1]}
				_, _ = server.WriteTo(rpAck.Bytes(), addr)
			}
			select {
			case messageSeen <- struct{}{}:
			default:
			}
			return
		}
	}
}

func runFakeIMSSubmitReportError(t *testing.T, server net.PacketConn, reportSeen chan<- struct{}) {
	t.Helper()
	nonce := testNonce()
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			return
		}
		msg, err := ims.ParseMessage(buf[:n])
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch msg.Method() {
		case "REGISTER":
			res := newUnauthorizedRegisterResponse(msg, nonce)
			authorization := msg.Header("Authorization")
			if authorization != "" && !strings.Contains(authorization, `nonce=""`) && !strings.Contains(authorization, `response=""`) {
				res = newIMSResponse(msg, 200, "OK")
			}
			_, _ = server.WriteTo(res.Bytes(), addr)
		case "SUBSCRIBE":
			_, _ = server.WriteTo(newIMSResponse(msg, 200, "OK").Bytes(), addr)
		case "MESSAGE":
			_, _ = server.WriteTo(newIMSResponse(msg, 202, "Accepted").Bytes(), addr)
			if len(msg.Body) < 2 {
				continue
			}
			go func(req ims.Message, remote net.Addr) {
				time.Sleep(10 * time.Millisecond)
				rpErr := ims.NewRequest("MESSAGE", req.Header("From"))
				rpErr.AddHeader("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-rp-error")
				rpErr.AddHeader("From", "<sip:smsc@example.com>;tag=1")
				rpErr.AddHeader("To", req.Header("From"))
				rpErr.AddHeader("Call-ID", "sms-rp-error")
				rpErr.AddHeader("CSeq", "1 MESSAGE")
				rpErr.AddHeader("In-Reply-To", req.Header("Call-ID"))
				rpErr.AddHeader("P-Asserted-Identity", fmt.Sprintf("<tel:%s>", stubCard{}.SMSC()))
				rpErr.Body = []byte{0x05, req.Body[1], 0x01, 96}
				_, _ = server.WriteTo(rpErr.Bytes(), remote)
				select {
				case reportSeen <- struct{}{}:
				default:
				}
			}(msg, addr)
		}
	}
}

func responseHeaders(req ims.Message) []ims.Header {
	return []ims.Header{
		{Name: "Via", Value: req.Header("Via")},
		{Name: "From", Value: req.Header("From")},
		{Name: "To", Value: req.Header("To")},
		{Name: "Call-ID", Value: req.Header("Call-ID")},
		{Name: "CSeq", Value: req.Header("CSeq")},
	}
}

func collectStates(ch <-chan RegistrationState, count int, timeout time.Duration) []RegistrationState {
	states := make([]RegistrationState, 0, count)
	deadline := time.After(timeout)
	for len(states) < count {
		select {
		case state := <-ch:
			states = append(states, state)
		case <-deadline:
			return states
		}
	}
	return states
}

func firstOrEmpty(states []RegistrationState, idx int) RegistrationState {
	if idx >= len(states) {
		return ""
	}
	return states[idx]
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range count {
		out[i] = value
	}
	return out
}

func TestNewClientNilDriver(t *testing.T) {
	_, err := NewClient(context.Background(), Config{}, nil)
	if err == nil {
		t.Fatal("NewClient() error = nil, want non-nil")
	}
}

func TestResolveIMSProxyAddr(t *testing.T) {
	tests := []struct {
		name     string
		explicit string
		cfg      swu.Config
		tunnel   swu.TunnelInfo
		want     string
	}{
		{name: "explicit wins", explicit: "pcscf.example.com:5060", cfg: swu.Config{SIPPort: 5070}, tunnel: swu.TunnelInfo{PCSCFIP: []byte{10, 0, 0, 1}}, want: "pcscf.example.com:5060"},
		{name: "derive ipv4", cfg: swu.Config{SIPPort: 5070}, tunnel: swu.TunnelInfo{PCSCFIP: []byte{10, 0, 0, 1}}, want: "10.0.0.1:5070"},
		{name: "default sip port", tunnel: swu.TunnelInfo{PCSCFIP: []byte{10, 0, 0, 2}}, want: "10.0.0.2:5060"},
		{name: "empty", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveIMSProxyAddr(tt.explicit, tt.cfg, tt.tunnel); got != tt.want {
				t.Fatalf("resolveIMSProxyAddr() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHandleUSSDEvent(t *testing.T) {
	client, err := newClient(Config{}, stubCard{})
	if err != nil {
		t.Fatalf("newClient() error = %v", err)
	}
	session := &ims.USSDSession{}
	client.handleUSSD(session, ims.USSDMessage{Text: "Enter PIN", Language: "en", Request: true})
	select {
	case event := <-client.Events().USSD:
		if event.Session != session {
			t.Fatal("event.Session != session")
		}
		if event.Message.Text != "Enter PIN" || !event.Message.Request {
			t.Fatalf("event.Message = %+v", event.Message)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for USSD event")
	}
}

func TestClientConnectFailureDoesNotPoisonReconnect(t *testing.T) {
	server := mustListenUDP(t, "server")
	defer server.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runFakeIMSFailFirstRegister(t, server)
	}()

	client := newTestClient(t, server.LocalAddr().String())
	defer client.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Connect(ctx); err == nil {
		t.Fatal("first Connect() error = nil, want failure")
	}
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("second Connect() error = %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("server.Close() error = %v", err)
	}
	<-done
}

func runFakeIMSFailFirstRegister(t *testing.T, server net.PacketConn) {
	t.Helper()
	nonce := testNonce()
	authorizedRegisters := 0
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := server.ReadFrom(buf)
		if err != nil {
			return
		}
		msg, err := ims.ParseMessage(buf[:n])
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch msg.Method() {
		case "REGISTER":
			res := newUnauthorizedRegisterResponse(msg, nonce)
			authorization := msg.Header("Authorization")
			if authorization != "" && !strings.Contains(authorization, `nonce=""`) && !strings.Contains(authorization, `response=""`) {
				authorizedRegisters++
				if authorizedRegisters == 1 {
					res = newIMSResponse(msg, 500, "Server Error")
				} else {
					res = newIMSResponse(msg, 200, "OK")
				}
			}
			_, _ = server.WriteTo(res.Bytes(), addr)
		case "SUBSCRIBE":
			_, _ = server.WriteTo(newIMSResponse(msg, 200, "OK").Bytes(), addr)
		}
	}
}
