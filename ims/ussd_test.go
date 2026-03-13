package ims

import (
	"context"
	"errors"
	"fmt"
	"mime"
	"net/textproto"
	"strings"
	"testing"
	"time"
)

func newUSSDDialogRequest(method, target, branch, from, to, callID, cseq string) Message {
	msg := NewRequest(method, target)
	msg.AddHeader("Via", branch)
	msg.AddHeader("From", from)
	msg.AddHeader("To", to)
	msg.AddHeader("Call-ID", callID)
	msg.AddHeader("CSeq", cseq)
	return msg
}

func newUSSDOKResponse(req Message, body []byte, extra ...Header) Message {
	resp := newTestResponse(req, 200, "OK")
	if len(extra) > 0 {
		resp.Headers = append(resp.Headers, extra...)
	}
	resp.Body = body
	return resp
}

func TestUSSDXMLRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  USSDMessage
		want USSDMessage
	}{
		{name: "plain", msg: USSDMessage{Text: "*100#", Language: "en"}, want: USSDMessage{Text: "*100#", Language: "en"}},
		{name: "request", msg: USSDMessage{Text: "Enter PIN", Language: "en", Request: true}, want: USSDMessage{Text: "Enter PIN", Language: "en", Request: true}},
		{name: "notify", msg: USSDMessage{Text: "Done", Language: "en", Notify: true}, want: USSDMessage{Text: "Done", Language: "en", Notify: true}},
		{name: "error", msg: USSDMessage{Language: "en", ErrorCode: 2}, want: USSDMessage{Language: "en", ErrorCode: 2}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := (ussdXMLBody{Message: tt.msg}).MarshalText()
			if err != nil {
				t.Fatalf("ussdXMLBody.MarshalText() error = %v", err)
			}
			got, err := decodeUSSDXML(body)
			if err != nil {
				t.Fatalf("decodeUSSDXML() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("decodeUSSDXML() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseUSSDXMLNormalizesUnknownErrorCode(t *testing.T) {
	body := []byte(xmlHeader + `<ussd-data><language>en</language><error-code>99</error-code></ussd-data>`)
	got, err := decodeUSSDXML(body)
	if err != nil {
		t.Fatalf("decodeUSSDXML() error = %v", err)
	}
	if got.ErrorCode != 1 {
		t.Fatalf("decodeUSSDXML() error_code = %d, want 1", got.ErrorCode)
	}
}

func TestMultipartUSSDPayload(t *testing.T) {
	payload, err := (ussdXMLBody{Message: USSDMessage{Text: "Balance", Language: "en"}}).MarshalText()
	if err != nil {
		t.Fatalf("ussdXMLBody.MarshalText() error = %v", err)
	}
	boundary := "outer"
	body, err := (multipartBody{Boundary: boundary, Parts: []multipartBodyPart{
		{Header: textHeader("Content-Type", "application/sdp"), Body: []byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n")},
		{Header: textHeader("Content-Type", ussdContentType), Body: payload},
	}}).MarshalBinary()
	if err != nil {
		t.Fatalf("multipartBody.MarshalBinary() error = %v", err)
	}
	msg := Message{Headers: []Header{{Name: "Content-Type", Value: "multipart/mixed; boundary=outer"}}, Body: body}
	got, err := decodeUSSDPayload(msg)
	if err != nil {
		t.Fatalf("decodeUSSDPayload() error = %v", err)
	}
	if got.Text != "Balance" || got.Language != "en" {
		t.Fatalf("decodeUSSDPayload() = %+v", got)
	}
}

func TestStartUSSDSessionFlow(t *testing.T) {
	transport := newClientTCPTransport()
	client := newTestUSSDClient(t, Config{}, transport)
	client.serviceRoutes = []string{"<sip:pcscf.example.com;lr>", "<sip:scscf.example.com;lr>"}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	transport.onWrite = func(data []byte) {
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(request) error = %v", err)
			return
		}
		if !req.IsRequest() {
			return
		}
		switch req.Method() {
		case "INVITE":
			if got := req.HeadersByName("Route"); len(got) != 2 || got[0] != client.serviceRoutes[0] || got[1] != client.serviceRoutes[1] {
				t.Errorf("INVITE routes = %v", got)
			}
			trying := newTestResponse(req, 100, "Trying")
			go client.dispatchResponse(trying)
			ok := newUSSDOKResponse(req, []byte(client.ussdSDP()),
				Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
				Header{Name: "Record-Route", Value: "<sip:pcscf.example.com;lr>"},
				Header{Name: "Record-Route", Value: "<sip:scscf.example.com;lr>"},
				Header{Name: "Recv-Info", Value: ussdInfoPackage},
				Header{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
				Header{Name: "Content-Type", Value: "application/sdp"},
			)
			go client.dispatchResponse(ok)
		case "ACK":
		case "INFO":
			ok := newTestResponse(req, 200, "OK")
			go client.dispatchResponse(ok)
		case "BYE":
			ok := newTestResponse(req, 200, "OK")
			go client.dispatchResponse(ok)
		default:
			t.Errorf("unexpected method %q", req.Method())
		}
	}

	session, err := client.StartUSSD(ctx, "*100#")
	if err != nil {
		t.Fatalf("StartUSSD() error = %v", err)
	}
	if got := session.routeSet; len(got) != 2 || got[0] != "<sip:scscf.example.com;lr>" || got[1] != "<sip:pcscf.example.com;lr>" {
		t.Fatalf("session.routeSet = %v", got)
	}
	if err := session.Reply(ctx, "1"); err != nil {
		t.Fatalf("Reply() error = %v", err)
	}

	last := mustParseMessage(t, "last", transport.writes[len(transport.writes)-1])
	if last.Method() != "INFO" {
		t.Fatalf("last.Method() = %q, want INFO", last.Method())
	}
	if got := last.HeadersByName("Route"); len(got) != 2 || got[0] != "<sip:scscf.example.com;lr>" || got[1] != "<sip:pcscf.example.com;lr>" {
		t.Fatalf("INFO routes = %v", got)
	}
}

func TestStartUSSDCancelSendsCancel(t *testing.T) {
	transport := newClientUDPTransport()
	client := newTestClient(t, Config{}, transport)

	ctx, cancel := context.WithCancel(context.Background())
	transport.onWrite = func(data []byte) {
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(request) error = %v", err)
			return
		}
		if req.Method() == "INVITE" {
			go func() {
				time.Sleep(20 * time.Millisecond)
				cancel()
			}()
		}
	}

	if _, err := client.StartUSSD(ctx, "*100#"); !errors.Is(err, context.Canceled) {
		t.Fatalf("StartUSSD() error = %v, want context.Canceled", err)
	}
	var sawCancel bool
	for _, data := range transport.writes {
		msg := mustParseMessage(t, "write", data)
		if msg.Method() == "CANCEL" {
			sawCancel = true
			break
		}
	}
	if !sawCancel {
		t.Fatal("CANCEL request not observed")
	}
}

func TestNetworkInitiatedUSSDRequest(t *testing.T) {
	transport := newClientTCPTransport()
	var callbackSession *USSDSession
	var callbackMsg USSDMessage
	callbackCh := make(chan struct{}, 1)
	client := newTestUSSDClient(t, Config{OnUSSD: func(session *USSDSession, msg USSDMessage) {
		callbackSession = session
		callbackMsg = msg
		callbackCh <- struct{}{}
	}}, transport)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	transport.onWrite = func(data []byte) {
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(request) error = %v", err)
			return
		}
		if req.Method() != "INFO" && req.Method() != "BYE" {
			return
		}
		ok := newTestResponse(req, 200, "OK")
		go client.dispatchResponse(ok)
	}

	invite := buildNetworkUSSDInvite(t, client, "Enter PIN", true)
	if err := client.handleRequest(ctx, transport, invite); err != nil {
		t.Fatalf("handleRequest(INVITE) error = %v", err)
	}
	select {
	case <-callbackCh:
	case <-ctx.Done():
		t.Fatal("waiting for USSD callback")
	}
	if callbackSession == nil {
		t.Fatal("USSD callback session = nil")
	}
	if !callbackMsg.Request || callbackMsg.Text != "Enter PIN" {
		t.Fatalf("USSD callback message = %+v", callbackMsg)
	}
	ok := mustParseMessage(t, "200 OK", transport.writes[0])
	if ok.StatusCode() != 200 {
		t.Fatalf("ok.StatusCode() = %d, want 200", ok.StatusCode())
	}
	if ok.Header("Recv-Info") != ussdInfoPackage {
		t.Fatalf("Recv-Info = %q", ok.Header("Recv-Info"))
	}
	if !strings.Contains(strings.ToLower(ok.Header("Accept")), ussdContentType) {
		t.Fatalf("Accept = %q", ok.Header("Accept"))
	}

	replyCtx, cancelReply := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancelReply()
	if err := callbackSession.Reply(replyCtx, "1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Reply(before ACK) error = %v, want deadline exceeded", err)
	}

	ack := newUSSDDialogRequest("ACK", callbackSession.targetURI, "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-ack", invite.Header("From"), ok.Header("To"), invite.Header("Call-ID"), "1 ACK")
	if err := client.handleRequest(ctx, transport, ack); err != nil {
		t.Fatalf("handleRequest(ACK) error = %v", err)
	}

	if err := callbackSession.Reply(ctx, "1"); err != nil {
		t.Fatalf("Reply(after ACK) error = %v", err)
	}
	info := mustParseMessage(t, "INFO", transport.writes[len(transport.writes)-1])
	if info.Method() != "INFO" {
		t.Fatalf("info.Method() = %q, want INFO", info.Method())
	}
	payload, err := decodeUSSDPayload(info)
	if err != nil {
		t.Fatalf("decodeUSSDPayload(INFO) error = %v", err)
	}
	if !payload.Request || payload.Text != "1" {
		t.Fatalf("INFO payload = %+v", payload)
	}

	select {
	case msg := <-callbackSession.Events():
		if msg.Text != "Enter PIN" || !msg.Request {
			t.Fatalf("session event = %+v", msg)
		}
	case <-ctx.Done():
		t.Fatal("waiting for initial USSD event")
	}

	byeBody, err := (ussdXMLBody{Message: USSDMessage{Text: "Done", Language: "en", Request: true}}).MarshalText()
	if err != nil {
		t.Fatalf("ussdXMLBody.MarshalText(BYE) error = %v", err)
	}
	bye := newUSSDDialogRequest("BYE", callbackSession.targetURI, "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-bye", invite.Header("From"), ok.Header("To"), invite.Header("Call-ID"), "2 BYE")
	bye.AddHeader("Content-Type", ussdContentType)
	bye.Body = byeBody
	if err := client.handleRequest(ctx, transport, bye); err != nil {
		t.Fatalf("handleRequest(BYE) error = %v", err)
	}
	select {
	case msg := <-callbackSession.Events():
		if msg.Text != "Done" || !msg.Final {
			t.Fatalf("final session event = %+v", msg)
		}
	case <-ctx.Done():
		t.Fatal("waiting for final USSD event")
	}
}

func TestCloseContextWaitsForOnUSSDCallback(t *testing.T) {
	transport := newClientTCPTransport()
	callbackStarted := make(chan struct{})
	callbackRelease := make(chan struct{})
	client := newTestUSSDClient(t, Config{OnUSSD: func(session *USSDSession, msg USSDMessage) {
		close(callbackStarted)
		<-callbackRelease
	}}, transport)

	transport.onWrite = func(data []byte) {
		req, err := ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage(request) error = %v", err)
			return
		}
		if req.Method() != "BYE" {
			return
		}
		transport.reads = append(transport.reads, newTestResponse(req, 200, "OK").Bytes())
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	invite := buildNetworkUSSDInvite(t, client, "Enter PIN", true)
	if err := client.handleRequest(ctx, transport, invite); err != nil {
		t.Fatalf("handleRequest(INVITE) error = %v", err)
	}

	select {
	case <-callbackStarted:
	case <-ctx.Done():
		t.Fatal("waiting for OnUSSD callback start")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- client.CloseContext(ctx)
	}()

	select {
	case err := <-closeDone:
		t.Fatalf("CloseContext() returned before callback release: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(callbackRelease)

	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("CloseContext() error = %v", err)
		}
	case <-ctx.Done():
		t.Fatal("waiting for CloseContext to finish")
	}
}

func TestNetworkInitiatedUSSDByeAlwaysReturns200(t *testing.T) {
	transport := newClientTCPTransport()
	client := newTestUSSDClient(t, Config{}, transport)
	session := &USSDSession{
		client:           client,
		callID:           "bye-call",
		sessionID:        "bye-session",
		localTag:         "local",
		remoteTag:        "remote",
		remoteTo:         fmt.Sprintf("<%s>;tag=remote", testPublicIdentity),
		targetURI:        "sip:ussias@example.com",
		networkInitiated: true,
		ackCh:            make(chan struct{}),
		events:           make(chan USSDMessage, 1),
		remoteCSeqs:      map[string]struct{}{},
	}
	client.storeUSSDSession(session)

	bye := newUSSDDialogRequest("BYE", session.targetURI, "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-bye", "<sip:remote@example.com>;tag=remote", fmt.Sprintf("<%s>;tag=%s", testPublicIdentity, session.localTag), session.callID, "2 BYE")
	bye.AddHeader("Content-Type", "text/plain")
	bye.Body = []byte("bad payload")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.handleRequest(ctx, transport, bye); err != nil {
		t.Fatalf("handleRequest(BYE) error = %v", err)
	}
	resp := mustParseMessage(t, "BYE response", transport.writes[0])
	if resp.StatusCode() != 200 {
		t.Fatalf("resp.StatusCode() = %d, want 200", resp.StatusCode())
	}
	if !session.isClosed() {
		t.Fatal("session.isClosed() = false, want true")
	}
}

func TestUnknownUSSDDialogGets481(t *testing.T) {
	transport := newClientUDPTransport()
	client := newTestClient(t, Config{}, transport)
	body, err := (ussdXMLBody{Message: USSDMessage{Text: "1", Language: "en"}}).MarshalText()
	if err != nil {
		t.Fatalf("ussdXMLBody.MarshalText() error = %v", err)
	}
	info := newUSSDDialogRequest("INFO", "sip:remote@example.com", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-info", "<sip:remote@example.com>;tag=remote-1", fmt.Sprintf("<%s>;tag=local-1", testPublicIdentity), "missing-dialog", "1 INFO")
	info.AddHeader("Info-Package", ussdInfoPackage)
	info.AddHeader("Content-Disposition", "info-package")
	info.AddHeader("Content-Type", ussdContentType)
	info.Body = body
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.handleRequest(ctx, transport, info); err != nil {
		t.Fatalf("handleRequest(INFO) error = %v", err)
	}
	resp := mustParseMessage(t, "response", transport.writes[0])
	if resp.StatusCode() != 481 {
		t.Fatalf("resp.StatusCode() = %d, want 481", resp.StatusCode())
	}
}

func TestRegisterContactValueAdvertisesNetworkUSSD(t *testing.T) {
	client := newTestClient(t, Config{}, newClientUDPTransport())
	if got := client.registerContactValue(5062); !strings.Contains(got, "+g.3gpp.nw-init-ussi") {
		t.Fatalf("registerContactValue() = %q", got)
	}
}

func TestParseUSSDPayloadRejectsUnsupportedType(t *testing.T) {
	msg := Message{Headers: []Header{{Name: "Content-Type", Value: "text/plain"}}, Body: []byte("nope")}
	if _, err := decodeUSSDPayload(msg); err == nil {
		t.Fatal("decodeUSSDPayload() error = nil, want non-nil")
	}
}

func TestUSSDTargetURI(t *testing.T) {
	client := newTestClient(t, Config{}, newClientUDPTransport())
	got := client.ussdTargetURI("*100#")
	if want := "sip:*100%23;phone-context=ims.mnc001.mcc001.3gppnetwork.org@ims.mnc001.mcc001.3gppnetwork.org;user=dialstring"; got != want {
		t.Fatalf("ussdTargetURI() = %q, want %q", got, want)
	}
	if mediaType, _, err := mime.ParseMediaType("multipart/mixed; boundary=outer"); err != nil || mediaType != "multipart/mixed" {
		t.Fatalf("ParseMediaType() = %q, %v", mediaType, err)
	}
}

func buildNetworkUSSDInvite(t *testing.T, client *Client, text string, request bool) Message {
	t.Helper()
	payload, err := (ussdXMLBody{Message: USSDMessage{Text: text, Language: "en", Request: request, Notify: !request}}).MarshalText()
	if err != nil {
		t.Fatalf("ussdXMLBody.MarshalText() error = %v", err)
	}
	boundary := "outer"
	body, err := (multipartBody{Boundary: boundary, Parts: []multipartBodyPart{
		{Header: textHeader("Content-Type", "application/sdp"), Body: []byte(client.ussdSDP())},
		{Header: textHeader("Content-Type", ussdContentType), Body: payload},
	}}).MarshalBinary()
	if err != nil {
		t.Fatalf("multipartBody.MarshalBinary() error = %v", err)
	}
	invite := NewRequest("INVITE", client.cfg.PublicIdentity)
	invite.AddHeader("Via", "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-invite")
	invite.AddHeader("Max-Forwards", "70")
	invite.AddHeader("Route", "<sip:pcscf.example.com;lr>")
	invite.AddHeader("Route", "<sip:scscf.example.com;lr>")
	invite.AddHeader("From", "<sip:ussias@example.com>;tag=remote-1")
	invite.AddHeader("To", "<sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>")
	invite.AddHeader("Call-ID", "network-ussd-1")
	invite.AddHeader("Session-ID", "abcdef0123456789")
	invite.AddHeader("CSeq", "1 INVITE")
	invite.AddHeader("Contact", "<sip:ussias@example.com;lr>")
	invite.AddHeader("Accept", "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed")
	invite.AddHeader("Recv-Info", ussdInfoPackage)
	invite.AddHeader("Content-Type", "multipart/mixed; boundary=outer")
	invite.Body = body
	return invite
}

func textHeader(name, value string) textproto.MIMEHeader {
	return textproto.MIMEHeader{name: {value}}
}

const xmlHeader = `<?xml version="1.0" encoding="UTF-8"?>`

func TestMOUSSDRequestMarkersAndAccessNetworkInfo(t *testing.T) {
	tests := []struct {
		name       string
		accessInfo string
		wantPANI   string
	}{
		{name: "default omitted"},
		{name: "configured value", accessInfo: "IEEE-802.11;i-wlan-node-id=001122334455", wantPANI: "IEEE-802.11;i-wlan-node-id=001122334455"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newClientTCPTransport()
			client := newTestUSSDClient(t, Config{AccessNetworkInfo: tt.accessInfo}, transport)
			client.serviceRoutes = []string{"<sip:pcscf.example.com;lr>"}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			transport.onWrite = func(data []byte) {
				req, err := ParseMessage(data)
				if err != nil {
					t.Errorf("ParseMessage(request) error = %v", err)
					return
				}
				if !req.IsRequest() {
					return
				}
				switch req.Method() {
				case "INVITE":
					if got := req.Header("P-Access-Network-Info"); got != tt.wantPANI {
						t.Errorf("INVITE P-Access-Network-Info = %q, want %q", got, tt.wantPANI)
					}
					payload, err := decodeUSSDPayload(req)
					if err != nil {
						t.Errorf("decodeUSSDPayload(INVITE) error = %v", err)
						return
					}
					if !payload.Request || payload.Text != "*100#" {
						t.Errorf("INVITE payload = %+v", payload)
					}
					ok := newUSSDOKResponse(req, []byte(client.ussdSDP()),
						Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
						Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
						Header{Name: "Record-Route", Value: "<sip:pcscf.example.com;lr>"},
						Header{Name: "Recv-Info", Value: ussdInfoPackage},
						Header{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
						Header{Name: "Content-Type", Value: "application/sdp"},
					)
					go client.dispatchResponse(ok)
				case "ACK":
				case "INFO":
					if got := req.Header("P-Access-Network-Info"); got != tt.wantPANI {
						t.Errorf("INFO P-Access-Network-Info = %q, want %q", got, tt.wantPANI)
					}
					payload, err := decodeUSSDPayload(req)
					if err != nil {
						t.Errorf("decodeUSSDPayload(INFO) error = %v", err)
						return
					}
					if !payload.Request || payload.Text != "1" {
						t.Errorf("INFO payload = %+v", payload)
					}
					ok := newTestResponse(req, 200, "OK")
					go client.dispatchResponse(ok)
				default:
					t.Errorf("unexpected method %q", req.Method())
				}
			}

			session, err := client.StartUSSD(ctx, "*100#")
			if err != nil {
				t.Fatalf("StartUSSD() error = %v", err)
			}
			if err := session.Reply(ctx, "1"); err != nil {
				t.Fatalf("Reply() error = %v", err)
			}
		})
	}
}

func TestUSSDBodyMarshalTextRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  USSDMessage
	}{
		{name: "request", msg: USSDMessage{Text: "*100#", Language: "en", Request: true}},
		{name: "notify", msg: USSDMessage{Text: "Done", Language: "en", Notify: true}},
		{name: "error", msg: USSDMessage{Language: "en", ErrorCode: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			textBody, err := (ussdXMLBody{Message: tt.msg}).MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			var body ussdXMLBody
			if err := body.UnmarshalText(textBody); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if body.Message != tt.msg {
				t.Fatalf("round trip = %+v, want %+v", body.Message, tt.msg)
			}
		})
	}
}

func TestMultipartBodyMarshalBinaryRoundTrip(t *testing.T) {
	payload, err := (ussdXMLBody{Message: USSDMessage{Text: "Balance", Language: "en", Request: true}}).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	body := multipartBody{
		Boundary: "outer",
		Parts: []multipartBodyPart{
			{Header: textHeader("Content-Type", "application/sdp"), Body: []byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n")},
			{Header: textHeader("Content-Type", ussdContentType), Body: payload},
		},
	}
	data, err := body.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	var parsed multipartBody
	parsed.Boundary = "outer"
	if err := parsed.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if len(parsed.Parts) != 2 {
		t.Fatalf("len(Parts) = %d, want 2", len(parsed.Parts))
	}
	msg, ok, err := parsed.ussdPayload()
	if err != nil {
		t.Fatalf("ussdPayload() error = %v", err)
	}
	if !ok {
		t.Fatal("ussdPayload() ok = false, want true")
	}
	if msg.Text != "Balance" || msg.Language != "en" || !msg.Request {
		t.Fatalf("ussdPayload() = %+v", msg)
	}
}
