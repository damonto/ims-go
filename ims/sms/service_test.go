package sms

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"github.com/damonto/ims-client/usim"
)

type serviceStubTransport struct {
	local   net.Addr
	remote  net.Addr
	readCh  chan []byte
	writes  [][]byte
	onWrite func([]byte)
}

type serviceStubCard struct{}
type serviceCentreStubCard struct {
	serviceStubCard
	centre usim.ServiceCentre
}

func (t *serviceStubTransport) LocalAddr() net.Addr  { return t.local }
func (t *serviceStubTransport) RemoteAddr() net.Addr { return t.remote }
func (t *serviceStubTransport) WritePacket(ctx context.Context, data []byte) error {
	t.writes = append(t.writes, append([]byte(nil), data...))
	if t.onWrite != nil {
		t.onWrite(data)
	}
	return nil
}
func (t *serviceStubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}
func (t *serviceStubTransport) Close() error          { return nil }
func (t *serviceStubTransport) queue(msg sip.Message) { t.readCh <- msg.Bytes() }

func (serviceStubCard) IMSI() string { return "001010123456789" }
func (serviceStubCard) MCC() string  { return "001" }
func (serviceStubCard) MNC() string  { return "001" }
func (serviceStubCard) SMSC() string { return "+15550000000" }
func (serviceStubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		IK:  []byte("client-test-ik"),
	}, nil
}

func (c serviceCentreStubCard) SMSC() string {
	return c.centre.Address
}

func (c serviceCentreStubCard) ServiceCentre() usim.ServiceCentre {
	return c.centre
}

func TestSendBuildsMESSAGEFromRegistrationState(t *testing.T) {
	const wantSecurityVerify = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222"

	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseSMSMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		if got := req.HeadersByName("Route"); len(got) != 1 || got[0] != "<sip:pcscf.example.com;lr>" {
			t.Fatalf("Route = %v", got)
		}
		if got := req.Header("P-Preferred-Identity"); got != "<tel:+15551234567>" {
			t.Fatalf("P-Preferred-Identity = %q", got)
		}
		if got := req.Header("User-Agent"); got == "" {
			t.Fatal("User-Agent = empty")
		}
		if got := req.Header("P-Access-Network-Info"); got == "" {
			t.Fatal("P-Access-Network-Info = empty")
		}
		if got := req.Header("Security-Verify"); got != wantSecurityVerify {
			t.Fatalf("Security-Verify = %q, want %q", got, wantSecurityVerify)
		}
		if got := req.Header("Require"); got != "sec-agree" {
			t.Fatalf("Require = %q, want sec-agree", got)
		}
		if got := req.Header("Proxy-Require"); got != "sec-agree" {
			t.Fatalf("Proxy-Require = %q, want sec-agree", got)
		}
		transport.queue(newSMSResponse(req, 202, "Accepted"))
	}

	got, err := svc.Send(context.Background(), "777", "BAL")
	if err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("len(Send()) = %d, want 1", len(got))
	}
	if got[0].CallID == "" {
		t.Fatal("Send()[0].CallID = empty")
	}
}

func TestSendUsesServiceCentrePSIForSIPTargetAndAddressForRP(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	card := serviceCentreStubCard{centre: usim.ServiceCentre{
		Address: "+15550000000",
		PSI:     "sip:smsc@example.com",
	}}
	svc, err := New(Config{}, sess, reg, card)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseSMSMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		if got := sip.RequestURI(req); got != "sip:smsc@example.com" {
			t.Fatalf("Request-URI = %q, want sip:smsc@example.com", got)
		}
		var rp rpMessage
		if err := rp.UnmarshalBinary(req.Body); err != nil {
			t.Fatalf("RP unmarshal error = %v", err)
		}
		if rp.Destination != "+15550000000" {
			t.Fatalf("RP Destination = %q, want +15550000000", rp.Destination)
		}
		transport.queue(newSMSResponse(req, 202, "Accepted"))
	}

	if _, err := svc.Send(context.Background(), "777", "BAL"); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestSendPrefersDefaultPublicIdentityWhenNoTelURI(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredServiceWithAssociatedURIs(t, transport, "<sip:alice@example.com>", "<sip:alias@example.com>")
	svc, err := New(Config{}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseSMSMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		if got := req.Header("P-Preferred-Identity"); got != "<sip:alice@example.com>" {
			t.Fatalf("P-Preferred-Identity = %q, want <sip:alice@example.com>", got)
		}
		if got := req.Header("From"); !strings.Contains(got, "<sip:alice@example.com>;") {
			t.Fatalf("From = %q, want default public identity", got)
		}
		transport.queue(newSMSResponse(req, 202, "Accepted"))
	}

	if _, err := svc.Send(context.Background(), "777", "BAL"); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
}

func TestHandleMalformedInboundSMSReturns200(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	inboundTransport := newServiceTransport()
	req := session.Request{Message: newInboundSMSRequest("call-1", "1 MESSAGE", []byte{0x03}), Transport: inboundTransport}
	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	if len(inboundTransport.writes) != 1 {
		t.Fatalf("len(writes) = %d, want 1", len(inboundTransport.writes))
	}
	resp := mustParseSMSMessage(t, inboundTransport.writes[0])
	if got := resp.StatusCode(); got != 200 {
		t.Fatalf("StatusCode() = %d, want 200", got)
	}
}

func TestHandleInboundSMSCallsOnIncoming(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	gotCh := make(chan Incoming, 1)
	svc, err := New(Config{OnIncoming: func(in Incoming) { gotCh <- in }}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	ackSMSReports(t, transport)

	inboundTransport := newServiceTransport()
	tpdu, err := buildSMSDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildSMSDeliver() error = %v", err)
	}
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x01,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	req := session.Request{Message: newInboundSMSRequest("call-1", "1 MESSAGE", rpdu), Transport: inboundTransport}
	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	select {
	case got := <-gotCh:
		if got.Text != "hello" || got.From != "+15551234567" || got.ServiceCenter != "+15550000000" {
			t.Fatalf("Incoming = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for incoming sms callback")
	}
}

func TestHandleInboundSMSDelaysRPACKUntilCallbackReturns(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	callbackStarted := make(chan struct{})
	callbackRelease := make(chan struct{})
	reportCh := make(chan sip.Message, 1)
	svc, err := New(Config{
		OnIncoming: func(in Incoming) {
			close(callbackStarted)
			<-callbackRelease
		},
	}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseSMSMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		reportCh <- req
		transport.queue(newSMSResponse(req, 202, "Accepted"))
	}

	tpdu, err := buildSMSDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildSMSDeliver() error = %v", err)
	}
	rpdu, err := (rpMessage{
		Type:       rpDataNetworkToMS,
		Reference:  0x01,
		Originator: "+15550000000",
		TPDU:       tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	inboundTransport := newServiceTransport()
	done := make(chan error, 1)
	go func() {
		_, err := svc.HandleRequest(context.Background(), session.Request{
			Message:   newInboundSMSRequest("call-1", "1 MESSAGE", rpdu),
			Transport: inboundTransport,
		})
		done <- err
	}()

	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("waiting for callback start")
	}

	select {
	case req := <-reportCh:
		t.Fatalf("delivery report sent before callback returned: %s", req.StartLine)
	case <-time.After(20 * time.Millisecond):
	}

	close(callbackRelease)

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleRequest() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for HandleRequest()")
	}

	select {
	case req := <-reportCh:
		if req.Header("In-Reply-To") != "call-1" {
			t.Fatalf("In-Reply-To = %q, want call-1", req.Header("In-Reply-To"))
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for delivery report")
	}
}

func TestSendReportsSubmitReportTimeoutWithoutRetry(t *testing.T) {
	oldTimeout := currentSMSSubmitReportTimeout()
	setSMSSubmitReportTimeout(20 * time.Millisecond)
	defer setSMSSubmitReportTimeout(oldTimeout)

	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	errCh := make(chan error, 1)
	svc, err := New(Config{OnError: func(err error) { errCh <- err }}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		if err := svc.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}()

	requests := make(chan []byte, 4)
	transport.onWrite = func(data []byte) {
		req, err := sip.ParseMessage(data)
		if err != nil {
			panic(err)
		}
		if req.Method() != "MESSAGE" {
			return
		}
		requests <- append([]byte(nil), data...)
		transport.queue(newSMSResponse(req, 202, "Accepted"))
	}

	if _, err := svc.Send(context.Background(), "777", "BAL"); err != nil {
		t.Fatalf("Send() error = %v", err)
	}

	first := mustParseSMSMessage(t, <-requests)
	var firstRP rpMessage
	if err := firstRP.UnmarshalBinary(first.Body); err != nil {
		t.Fatalf("first RP unmarshal error = %v", err)
	}

	select {
	case data := <-requests:
		t.Fatalf("unexpected retried MESSAGE: %s", mustParseSMSMessage(t, data).StartLine)
	case err := <-errCh:
		if !strings.Contains(err.Error(), "submit report not received") {
			t.Fatalf("OnError = %v, want submit report timeout", err)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("waiting for submit report timeout")
	}
}

func TestHandleInboundReservedRPDirectionReturnsRPError97(t *testing.T) {
	transport := newServiceTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{}, sess, reg, serviceStubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	reports := make(chan sip.Message, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseSMSMessage(t, data)
		if req.Method() != "MESSAGE" {
			return
		}
		reports <- req
		transport.queue(newSMSResponse(req, 202, "Accepted"))
	}

	tpdu, err := buildSMSDeliver("+15551234567", "hello")
	if err != nil {
		t.Fatalf("buildSMSDeliver() error = %v", err)
	}
	rpdu, err := (rpMessage{
		Type:      rpDataMSToNetwork,
		Reference: 0x22,
		TPDU:      tpdu,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	inboundTransport := newServiceTransport()
	req := session.Request{Message: newInboundSMSRequest("call-1", "1 MESSAGE", rpdu), Transport: inboundTransport}
	handled, err := svc.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}

	select {
	case report := <-reports:
		var got rpMessage
		if err := got.UnmarshalBinary(report.Body); err != nil {
			t.Fatalf("report RP unmarshal error = %v", err)
		}
		if got.Type != rpErrorMSToNetwork || got.Reference != 0x22 || got.Cause != rpCauseMessageTypeNotImplemented {
			t.Fatalf("report RP = %+v, want RP-ERROR ref 0x22 cause 97", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for RP-ERROR report")
	}
}

func newServiceTransport() *serviceStubTransport {
	return &serviceStubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		readCh: make(chan []byte, 16),
	}
}

func ackSMSReports(t *testing.T, transport *serviceStubTransport) {
	t.Helper()
	transport.onWrite = func(data []byte) {
		req := mustParseSMSMessage(t, data)
		if req.Method() == "MESSAGE" {
			transport.queue(newSMSResponse(req, 202, "Accepted"))
		}
	}
}

func registeredService(t *testing.T, transport *serviceStubTransport) (*session.Session, *registration.Service) {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(registration.Config{AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aa"}, sess, serviceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseSMSMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if len(transport.writes) == 1 {
				transport.queue(newSMSResponse(req, 401, "Unauthorized",
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222`},
				))
				return
			}
			transport.queue(newSMSResponse(req, 200, "OK",
				sip.Header{Name: "P-Associated-URI", Value: "<tel:+15551234567>"},
				sip.Header{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"},
			))
		}
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func registeredServiceWithAssociatedURIs(t *testing.T, transport *serviceStubTransport, associatedURIs ...string) (*session.Session, *registration.Service) {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(registration.Config{AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aa"}, sess, serviceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseSMSMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if len(transport.writes) == 1 {
				transport.queue(newSMSResponse(req, 401, "Unauthorized",
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222`},
				))
				return
			}
			headers := []sip.Header{{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"}}
			if len(associatedURIs) > 0 {
				headers = append(headers, sip.Header{Name: "P-Associated-URI", Value: strings.Join(associatedURIs, ",")})
			}
			transport.queue(newSMSResponse(req, 200, "OK", headers...))
		}
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func newInboundSMSRequest(callID, cseq string, body []byte) sip.Message {
	msg := sip.NewRequest("MESSAGE", "sip:test@example.com")
	msg.Headers = sip.Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1"},
		{Name: "From", Value: "<tel:+15551234567>;tag=remote"},
		{Name: "To", Value: "<sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>"},
		{Name: "Call-ID", Value: callID},
		{Name: "CSeq", Value: cseq},
		{Name: "Content-Type", Value: "application/vnd.3gpp.sms"},
	}
	msg.Body = body
	return msg
}

func newSMSResponse(req sip.Message, code int, reason string, extra ...sip.Header) sip.Message {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req, code)
	resp.Headers = append(resp.Headers, extra...)
	return resp
}

func mustParseSMSMessage(t *testing.T, data []byte) sip.Message {
	t.Helper()
	msg, err := sip.ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	return msg
}
