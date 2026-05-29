package ussd

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"strings"
	"testing"
	"time"

	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"github.com/damonto/vowifi-go/usim"
)

type stubTransport struct {
	local   net.Addr
	remote  net.Addr
	readCh  chan []byte
	writes  [][]byte
	onWrite func([]byte)
}

type stubCard struct{}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func (t *stubTransport) LocalAddr() net.Addr  { return t.local }
func (t *stubTransport) RemoteAddr() net.Addr { return t.remote }
func (t *stubTransport) WritePacket(ctx context.Context, data []byte) error {
	t.writes = append(t.writes, append([]byte(nil), data...))
	if t.onWrite != nil {
		t.onWrite(data)
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
func (t *stubTransport) Close() error          { return nil }
func (t *stubTransport) queue(msg sip.Message) { t.readCh <- msg.Bytes() }

func (stubCard) IMSI() string { return "001010123456789" }
func (stubCard) MCC() string  { return "001" }
func (stubCard) MNC() string  { return "001" }
func (stubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{RES: []byte("password"), IK: []byte("client-test-ik")}, nil
}

func TestUSSDXMLRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want Message
	}{
		{name: "plain", msg: Message{Text: "*100#", Language: "en"}, want: Message{Text: "*100#", Language: "en"}},
		{name: "request", msg: Message{Text: "Enter PIN", Language: "en", Request: true}, want: Message{Text: "Enter PIN", Language: "en", Request: true}},
		{name: "notify", msg: Message{Text: "Done", Language: "en", Notify: true}, want: Message{Text: "Done", Language: "en", Notify: true}},
		{name: "error", msg: Message{Language: "en", ErrorCode: 2}, want: Message{Language: "en", ErrorCode: 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := (xmlBody{Message: tt.msg}).MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			got, err := decodeXML(body)
			if err != nil {
				t.Fatalf("decodeXML() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("decodeXML() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestUSSDXMLValidation(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{
			name: "valid",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>*100#</ussd-string></ussd-data>`,
		},
		{
			name: "unknown element ignored",
			body: xml.Header + `<ussd-data><language>en</language><vendor-extension>ignored</vendor-extension><ussd-string>*100#</ussd-string></ussd-data>`,
		},
		{
			name: "namespaced unknown element ignored",
			body: xml.Header + `<ussd-data xmlns:x="urn:vendor"><language>en</language><x:language>ignored</x:language><ussd-string>*100#</ussd-string></ussd-data>`,
		},
		{
			name:    "duplicate language",
			body:    xml.Header + `<ussd-data><language>en</language><language>fr</language><ussd-string>*100#</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "language has region subtag",
			body:    xml.Header + `<ussd-data><language>en-US</language><ussd-string>*100#</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "language is numeric",
			body:    xml.Header + `<ussd-data><language>123</language><ussd-string>*100#</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "wrong root",
			body:    xml.Header + `<ussd><language>en</language><ussd-string>*100#</ussd-string></ussd>`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeXML([]byte(tt.body))
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("decodeXML() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestMarshalUSSDXMLRejectsInvalidLanguage(t *testing.T) {
	tests := []struct {
		name    string
		msg     Message
		wantErr bool
	}{
		{name: "valid", msg: Message{Text: "*100#", Language: "en"}},
		{name: "region subtag", msg: Message{Text: "*100#", Language: "en-US"}, wantErr: true},
		{name: "numeric", msg: Message{Text: "*100#", Language: "123"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := (xmlBody{Message: tt.msg}).MarshalText()
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("MarshalText() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestMultipartBodyRoundTrip(t *testing.T) {
	payload, err := (xmlBody{Message: Message{Text: "Balance", Language: "en"}}).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	body, err := (multipartBody{
		Boundary: "outer",
		Parts: []multipartBodyPart{
			{Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, Body: []byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n")},
			{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: payload},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	msg := sip.Message{Headers: sip.Headers{{Name: "Content-Type", Value: "multipart/mixed; boundary=outer"}}, Body: body}
	got, err := decodePayload(msg)
	if err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}
	if got.Text != "Balance" || got.Language != "en" {
		t.Fatalf("decodePayload() = %+v", got)
	}
}

func TestValidateSDPBodyRequiresOneZeroPortMedia(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "one zero port media", body: "v=0\r\nm=audio 0 RTP/AVP 97\r\n"},
		{name: "no media", body: "v=0\r\ns=-\r\n", wantErr: true},
		{name: "nonzero port", body: "v=0\r\nm=audio 49170 RTP/AVP 97\r\n", wantErr: true},
		{name: "two media", body: "v=0\r\nm=audio 0 RTP/AVP 97\r\nm=video 0 RTP/AVP 98\r\n", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSDPBody([]byte(tt.body))
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("validateSDPBody() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestValidateInboundUSSDInfoRequiresSingleUSSDXMLBody(t *testing.T) {
	payload, err := (xmlBody{Message: Message{Text: "Balance", Language: "en"}}).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	multipartPayload, err := (multipartBody{
		Boundary: "info",
		Parts: []multipartBodyPart{
			{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: payload},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	tests := []struct {
		name              string
		headerContentType string
		body              []byte
		wantErr           bool
	}{
		{name: "single ussd xml", headerContentType: xmlContentType, body: payload},
		{name: "multipart rejected", headerContentType: "multipart/mixed; boundary=info", body: multipartPayload, wantErr: true},
		{name: "missing content type", body: payload, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewRequest("INFO", "sip:ussias@example.com")
			msg.Headers.Add("Info-Package", infoPackage)
			msg.Headers.Add("Content-Disposition", "Info-Package")
			if tt.headerContentType != "" {
				msg.Headers.Add("Content-Type", tt.headerContentType)
			}
			msg.Body = tt.body
			_, err := validateInboundInfo(msg, false)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("validateInboundInfo() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestHandleByeRejectsMultipartUSSDPayload(t *testing.T) {
	payload, err := (xmlBody{Message: Message{Text: "Done", Language: "en"}}).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	multipartPayload, err := (multipartBody{
		Boundary: "bye",
		Parts: []multipartBodyPart{
			{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: payload},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	tests := []struct {
		name              string
		headerContentType string
		body              []byte
		wantStatus        int
		wantClosed        bool
	}{
		{name: "single ussd xml", headerContentType: xmlContentType, body: payload, wantStatus: 200, wantClosed: true},
		{name: "multipart rejected", headerContentType: "multipart/mixed; boundary=bye", body: multipartPayload, wantStatus: 415},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			us := &Session{
				service:     svc,
				callID:      "bye-call",
				localTag:    "local",
				remoteTag:   "remote",
				remoteTo:    "<sip:network@example.com>;tag=remote",
				targetURI:   "sip:network@example.com",
				events:      make(chan Message, 1),
				remoteCSeqs: make(map[string]struct{}),
			}
			bye := newDialogRequest("BYE", "sip:user@example.com", "<sip:network@example.com>;tag=remote", "<sip:user@example.com>;tag=local", "bye-call", "2 BYE")
			bye.Headers.Add("Content-Type", tt.headerContentType)
			bye.Body = tt.body
			if err := us.handleBye(context.Background(), session.Request{Message: bye, Transport: transport}); err != nil {
				t.Fatalf("handleBye() error = %v", err)
			}
			resp := mustParseUSSDMessage(t, transport.writes[len(transport.writes)-1])
			if got := resp.StatusCode(); got != tt.wantStatus {
				t.Fatalf("StatusCode() = %d, want %d", got, tt.wantStatus)
			}
			if got := us.isClosed(); got != tt.wantClosed {
				t.Fatalf("isClosed() = %t, want %t", got, tt.wantClosed)
			}
		})
	}
}

func TestContactValueFormatsIPHosts(t *testing.T) {
	tests := []struct {
		name  string
		state registration.State
		want  string
	}{
		{
			name: "ipv4",
			state: registration.State{
				ContactHost: "127.0.0.1",
				MessagePort: 5062,
			},
			want: "<sip:127.0.0.1:5062>;",
		},
		{
			name: "ipv6",
			state: registration.State{
				ContactHost: "2001:db8::20",
				MessagePort: 5062,
			},
			want: "<sip:[2001:db8::20]:5062>;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contactValue(tt.state); !strings.HasPrefix(got, tt.want) {
				t.Fatalf("contactValue() = %q, want prefix %q", got, tt.want)
			}
		})
	}
}

func TestStartUSSDSessionFlow(t *testing.T) {
	const wantSecurityVerify = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222"

	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "INVITE":
			if got := req.Header("Security-Verify"); got != wantSecurityVerify {
				t.Fatalf("INVITE Security-Verify = %q, want %q", got, wantSecurityVerify)
			}
			if got := req.Header("Require"); got != "sec-agree" {
				t.Fatalf("INVITE Require = %q, want sec-agree", got)
			}
			if got := req.Header("Proxy-Require"); got != "sec-agree" {
				t.Fatalf("INVITE Proxy-Require = %q, want sec-agree", got)
			}
			transport.queue(newUSSDResponse(req, 200, "OK",
				[]byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n"),
				sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				sip.Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
				sip.Header{Name: "Record-Route", Value: "<sip:pcscf.example.com;lr>"},
				sip.Header{Name: "Recv-Info", Value: infoPackage},
				sip.Header{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
				sip.Header{Name: "Content-Type", Value: "application/sdp"},
			))
		case "INFO", "BYE":
			if got := req.Header("Security-Verify"); got != wantSecurityVerify {
				t.Fatalf("%s Security-Verify = %q, want %q", req.Method(), got, wantSecurityVerify)
			}
			if got := req.Header("Require"); got != "sec-agree" {
				t.Fatalf("%s Require = %q, want sec-agree", req.Method(), got)
			}
			if got := req.Header("Proxy-Require"); got != "sec-agree" {
				t.Fatalf("%s Proxy-Require = %q, want sec-agree", req.Method(), got)
			}
			transport.queue(newUSSDResponse(req, 200, "OK", nil))
		}
	}

	session, err := svc.Start(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := session.Reply(context.Background(), "1"); err != nil {
		t.Fatalf("Reply() error = %v", err)
	}
	last := mustParseUSSDMessage(t, transport.writes[len(transport.writes)-1])
	if last.Method() != "INFO" {
		t.Fatalf("last.Method() = %q, want INFO", last.Method())
	}
	payload, err := decodePayload(last)
	if err != nil {
		t.Fatalf("decodePayload() error = %v", err)
	}
	if payload.Request {
		t.Fatalf("payload.Request = %t, want false", payload.Request)
	}
}

func TestValidateInviteOKDoesNotRequireAccept(t *testing.T) {
	tests := []struct {
		name    string
		headers sip.Headers
		wantErr bool
	}{
		{
			name: "recv info and sdp without accept",
			headers: sip.Headers{
				{Name: "Recv-Info", Value: infoPackage},
				{Name: "Content-Type", Value: "application/sdp"},
			},
		},
		{
			name: "missing recv info",
			headers: sip.Headers{
				{Name: "Content-Type", Value: "application/sdp"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewResponse(200, "OK")
			msg.Headers = tt.headers
			msg.Body = []byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n")

			err := validateInviteOK(msg)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("validateInviteOK() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestUSSDRegistersDialogsInSessionRegistry(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "INVITE":
			transport.queue(newUSSDResponse(req, 200, "OK",
				[]byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n"),
				sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				sip.Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
				sip.Header{Name: "Record-Route", Value: "<sip:pcscf.example.com;lr>"},
				sip.Header{Name: "Recv-Info", Value: infoPackage},
				sip.Header{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
				sip.Header{Name: "Content-Type", Value: "application/sdp"},
			))
		case "INFO", "BYE":
			transport.queue(newUSSDResponse(req, 200, "OK", nil))
		}
	}

	us, err := svc.Start(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	msg := newDialogRequest("INFO", us.targetURI, us.remoteTo, "<sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>;tag="+us.localTag, us.callID, "2 INFO")
	msg.Headers.Add("Info-Package", infoPackage)
	msg.Headers.Add("Content-Disposition", "info-package")
	msg.Headers.Add("Content-Type", xmlContentType)
	msg.Body = []byte(xml.Header + `<ussd-data><language>en</language><ussd-string>Next</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`)

	key, ok := sess.LookupDialogKey(msg)
	if !ok {
		t.Fatal("LookupDialogKey() ok = false, want true")
	}
	if key != us.sessionKey() {
		t.Fatalf("LookupDialogKey() = %q, want %q", key, us.sessionKey())
	}
}

func TestBuildACKAppliesStrictRouteSet(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ussdSession := &Session{
		service:   svc,
		targetURI: "sip:ussias@example.com",
		routeSet: []string{
			"<sip:edge.example.com>",
			"<sip:pcscf.example.com;lr>",
		},
		localURI:  "sip:user@example.com",
		localTag:  "local-1",
		remoteTo:  "<sip:network@example.com>;tag=remote-1",
		callID:    "call-1",
		inviteSeq: 1,
	}

	ack := ussdSession.buildACK()
	if got := sip.RequestURI(ack); got != "sip:edge.example.com" {
		t.Fatalf("RequestURI() = %q, want sip:edge.example.com", got)
	}
	if got := ack.HeadersByName("Route"); len(got) != 2 || got[0] != "<sip:pcscf.example.com;lr>" || got[1] != "<sip:ussias@example.com>" {
		t.Fatalf("Route = %v", got)
	}
}

func TestUSSDTargetURIUsesConfiguredPhoneContext(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger(), PhoneContextDomain: "wifi.example"}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if got := svc.ussdTargetURI("*100#"); got != "sip:*100%23;phone-context=wifi.example@ims.mnc001.mcc001.3gppnetwork.org;user=dialstring" {
		t.Fatalf("ussdTargetURI() = %q", got)
	}
}

func TestLookupIncomingInviteSessionMatchesServerTransaction(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	orig := buildNetworkUSSDInvite(t)
	orig.Headers = sip.UpsertHeader(orig.Headers, "Call-ID", "shared-call")
	orig.Headers = sip.UpsertHeader(orig.Headers, "From", "<sip:network@example.com>;tag=remote-1")
	orig.Headers = sip.UpsertHeader(orig.Headers, "CSeq", "1 INVITE")
	orig.Headers = sip.UpsertHeader(orig.Headers, "Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1")

	us := svc.newIncomingSession(orig, Message{Text: "Enter PIN", Language: "en", Request: true})
	us.inviteOK = svc.buildIncomingInviteOK(orig, us.localURI, us.localTag)
	if err := svc.storeSession(us); err != nil {
		t.Fatalf("storeSession() error = %v", err)
	}

	tests := []struct {
		name       string
		via        string
		requestURI string
		wantMatch  bool
	}{
		{
			name:       "same branch and sent-by",
			via:        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1",
			requestURI: sip.RequestURI(orig),
			wantMatch:  true,
		},
		{
			name:       "different branch",
			via:        "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-2",
			requestURI: sip.RequestURI(orig),
			wantMatch:  false,
		},
		{
			name:       "different sent-by",
			via:        "SIP/2.0/UDP 127.0.0.2:5060;branch=z9hG4bK-1",
			requestURI: sip.RequestURI(orig),
			wantMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invite := buildNetworkUSSDInvite(t)
			invite.StartLine = "INVITE " + tt.requestURI + " SIP/2.0"
			invite.Headers = sip.UpsertHeader(invite.Headers, "Call-ID", orig.Header("Call-ID"))
			invite.Headers = sip.UpsertHeader(invite.Headers, "From", orig.Header("From"))
			invite.Headers = sip.UpsertHeader(invite.Headers, "CSeq", orig.Header("CSeq"))
			invite.Headers = sip.UpsertHeader(invite.Headers, "Via", tt.via)

			got := svc.lookupIncomingInviteSession(invite)
			if tt.wantMatch && got != us {
				t.Fatalf("lookupIncomingInviteSession() = %p, want stored session %p", got, us)
			}
			if !tt.wantMatch && got != nil {
				t.Fatalf("lookupIncomingInviteSession() = %p, want nil", got)
			}
		})
	}
}

func TestLookupIncomingInviteSessionMatchesLegacyServerTransaction(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	orig := buildNetworkUSSDInvite(t)
	orig.StartLine = "INVITE sip:*100%23;phone-context=ims.example@ims.example;user=dialstring SIP/2.0"
	orig.Headers = sip.UpsertHeader(orig.Headers, "Call-ID", "legacy-call")
	orig.Headers = sip.UpsertHeader(orig.Headers, "From", "<sip:network@example.com>;tag=legacy-remote")
	orig.Headers = sip.UpsertHeader(orig.Headers, "CSeq", "7 INVITE")
	orig.Headers = sip.UpsertHeader(orig.Headers, "Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=legacy-1")

	us := svc.newIncomingSession(orig, Message{Text: "Enter PIN", Language: "en", Request: true})
	us.inviteOK = svc.buildIncomingInviteOK(orig, us.localURI, us.localTag)
	if err := svc.storeSession(us); err != nil {
		t.Fatalf("storeSession() error = %v", err)
	}

	tests := []struct {
		name       string
		via        string
		requestURI string
		wantMatch  bool
	}{
		{
			name:       "same legacy request",
			via:        "SIP/2.0/UDP 127.0.0.1:5060;branch=legacy-1",
			requestURI: sip.RequestURI(orig),
			wantMatch:  true,
		},
		{
			name:       "different request uri",
			via:        "SIP/2.0/UDP 127.0.0.1:5060;branch=legacy-1",
			requestURI: "sip:*101%23;phone-context=ims.example@ims.example;user=dialstring",
			wantMatch:  false,
		},
		{
			name:       "different top via",
			via:        "SIP/2.0/UDP 127.0.0.2:5060;branch=legacy-1",
			requestURI: sip.RequestURI(orig),
			wantMatch:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invite := buildNetworkUSSDInvite(t)
			invite.StartLine = "INVITE " + tt.requestURI + " SIP/2.0"
			invite.Headers = sip.UpsertHeader(invite.Headers, "Call-ID", orig.Header("Call-ID"))
			invite.Headers = sip.UpsertHeader(invite.Headers, "From", orig.Header("From"))
			invite.Headers = sip.UpsertHeader(invite.Headers, "CSeq", orig.Header("CSeq"))
			invite.Headers = sip.UpsertHeader(invite.Headers, "Via", tt.via)

			got := svc.lookupIncomingInviteSession(invite)
			if tt.wantMatch && got != us {
				t.Fatalf("lookupIncomingInviteSession() = %p, want stored session %p", got, us)
			}
			if !tt.wantMatch && got != nil {
				t.Fatalf("lookupIncomingInviteSession() = %p, want nil", got)
			}
		})
	}
}

func TestStartUSSDSessionUsesDefaultIdentityAndInitialBody(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredServiceWithAssociatedURIs(t, transport, "<sip:alice@example.com>", "<tel:+15551234567>")
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "INVITE":
			if got := req.Header("P-Preferred-Identity"); got != "<sip:alice@example.com>" {
				t.Fatalf("P-Preferred-Identity = %q, want <sip:alice@example.com>", got)
			}
			if got := req.Header("From"); !strings.Contains(got, "<sip:alice@example.com>;") {
				t.Fatalf("From = %q, want default public identity", got)
			}
			payload, hasSDP, err := decodeInvitePayload(req)
			if err != nil {
				t.Fatalf("decodeInvitePayload() error = %v", err)
			}
			if !hasSDP {
				t.Fatal("decodeInvitePayload() missing SDP")
			}
			if payload.Text != "*100#" || payload.Language != defaultLang {
				t.Fatalf("payload = %+v", payload)
			}
			if payload.Request {
				t.Fatalf("payload.Request = true, want false")
			}
			transport.queue(newUSSDResponse(req, 200, "OK",
				[]byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n"),
				sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				sip.Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
				sip.Header{Name: "Record-Route", Value: "<sip:pcscf.example.com;lr>"},
				sip.Header{Name: "Recv-Info", Value: infoPackage},
				sip.Header{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
				sip.Header{Name: "Content-Type", Value: "application/sdp"},
			))
		case "INFO", "BYE":
			transport.queue(newUSSDResponse(req, 200, "OK", nil))
		}
	}

	if _, err := svc.Start(context.Background(), "*100#"); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
}

func TestStartUSSDSessionINFOGate(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "INVITE":
			transport.queue(newUSSDResponse(req, 200, "OK",
				[]byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n"),
				sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				sip.Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
				sip.Header{Name: "Record-Route", Value: "<sip:pcscf.example.com;lr>"},
				sip.Header{Name: "Recv-Info", Value: infoPackage},
				sip.Header{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
				sip.Header{Name: "Content-Type", Value: "application/sdp"},
			))
		case "INFO", "BYE":
			transport.queue(newUSSDResponse(req, 200, "OK", nil))
		}
	}

	us, err := svc.Start(context.Background(), "*100#")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := us.Reply(context.Background(), "1"); err != nil {
		t.Fatalf("Reply() error = %v", err)
	}
	if err := us.Reply(context.Background(), "2"); err == nil {
		t.Fatal("Reply(with pending INFO) error = nil, want non-nil")
	}

	info := newDialogRequest("INFO", us.targetURI, us.remoteTo, "<sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>;tag="+us.localTag, us.callID, "2 INFO")
	info.Headers.Add("Info-Package", infoPackage)
	info.Headers.Add("Content-Disposition", "info-package")
	info.Headers.Add("Content-Type", xmlContentType)
	info.Body = []byte(xml.Header + `<ussd-data><language>en</language><ussd-string>Next</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`)
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: info, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(INFO) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(INFO) handled = false, want true")
	}
	if err := us.Reply(context.Background(), "3"); err != nil {
		t.Fatalf("Reply(after remote INFO) error = %v", err)
	}
}

func TestNetworkInitiatedUSSDInviteAndACKGate(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	callbackCh := make(chan Message, 1)
	svc, err := New(Config{Logger: testLogger(), OnIncoming: func(session *Session, msg Message) { callbackCh <- msg }}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		if req.Method() == "INFO" || req.Method() == "BYE" {
			transport.queue(newUSSDResponse(req, 200, "OK", nil))
		}
	}

	invite := buildNetworkUSSDInvite(t)
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: invite, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(INVITE) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(INVITE) handled = false, want true")
	}
	select {
	case got := <-callbackCh:
		if !got.Request || got.Text != "Enter PIN" {
			t.Fatalf("callback message = %+v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for callback")
	}

	us := svc.lookupSessionByCallID(invite.Header("Call-ID"))
	if us == nil {
		t.Fatal("lookupSessionByCallID() = nil")
	}

	replyCtx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := us.Reply(replyCtx, "1"); err == nil {
		t.Fatal("Reply(before ACK) error = nil, want non-nil")
	}

	ack := newDialogRequest("ACK", us.targetURI, invite.Header("From"), sip.WithTag(invite.Header("To"), "", us.localTag), invite.Header("Call-ID"), "1 ACK")
	handled, err = svc.HandleRequest(context.Background(), session.Request{Message: ack, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(ACK) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(ACK) handled = false, want true")
	}
	if err := us.Reply(context.Background(), "1"); err != nil {
		t.Fatalf("Reply(after ACK) error = %v", err)
	}
}

func TestNetworkInitiatedUSSDWaitsForCallbackBefore200OK(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	callbackStarted := make(chan struct{})
	callbackRelease := make(chan struct{})
	writeCh := make(chan sip.Message, 1)
	svc, err := New(Config{Logger: testLogger(),
		OnIncoming: func(session *Session, msg Message) {
			close(callbackStarted)
			<-callbackRelease
		},
	}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		writeCh <- mustParseUSSDMessage(t, data)
	}

	done := make(chan struct{})
	var handled bool
	var handleErr error
	go func() {
		defer close(done)
		handled, handleErr = svc.HandleRequest(context.Background(), session.Request{Message: buildNetworkUSSDInvite(t), Transport: transport})
	}()

	select {
	case <-callbackStarted:
	case <-time.After(time.Second):
		t.Fatal("waiting for callback start")
	}

	select {
	case msg := <-writeCh:
		if got := msg.StatusCode(); got != 100 {
			t.Fatalf("StatusCode() = %d, want 100", got)
		}
	case <-time.After(20 * time.Millisecond):
		t.Fatal("waiting for 100 Trying")
	}

	close(callbackRelease)

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("waiting for HandleRequest()")
	}
	if handleErr != nil {
		t.Fatalf("HandleRequest(INVITE) error = %v", handleErr)
	}
	if !handled {
		t.Fatal("HandleRequest(INVITE) handled = false, want true")
	}

	select {
	case msg := <-writeCh:
		if got := msg.StatusCode(); got != 200 {
			t.Fatalf("StatusCode() = %d, want 200", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for 200 OK")
	}
}

func TestNetworkInitiatedUSSDReplyFromCallbackQueuesUntilACK(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	callbackReturned := make(chan struct{})
	writeCh := make(chan sip.Message, 5)
	svc, err := New(Config{Logger: testLogger(),
		OnIncoming: func(session *Session, msg Message) {
			replyCtx, cancel := context.WithCancel(context.Background())
			if err := session.Reply(replyCtx, "1"); err != nil {
				t.Errorf("Reply() in callback error = %v", err)
				cancel()
				return
			}
			cancel()
			close(callbackReturned)
		},
	}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		msg := mustParseUSSDMessage(t, data)
		writeCh <- msg
		if msg.Method() == "INFO" || msg.Method() == "BYE" {
			transport.queue(newUSSDResponse(msg, 200, "OK", nil))
		}
	}

	invite := buildNetworkUSSDInvite(t)
	invite.Headers = sip.UpsertHeader(invite.Headers, "To", "<sip:alias@example.com>")

	done := make(chan error, 1)
	go func() {
		handled, err := svc.HandleRequest(context.Background(), session.Request{Message: invite, Transport: transport})
		if err != nil {
			done <- err
			return
		}
		if !handled {
			done <- errors.New("HandleRequest(INVITE) handled = false")
			return
		}
		done <- nil
	}()

	select {
	case <-callbackReturned:
	case <-time.After(time.Second):
		t.Fatal("waiting for callback to return")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("HandleRequest(INVITE) error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for HandleRequest(INVITE)")
	}

	var inviteOK sip.Message
	select {
	case trying := <-writeCh:
		if got := trying.StatusCode(); got != 100 {
			t.Fatalf("StatusCode() = %d, want 100", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for 100 Trying")
	}

	select {
	case inviteOK = <-writeCh:
		if got := inviteOK.StatusCode(); got != 200 {
			t.Fatalf("StatusCode() = %d, want 200", got)
		}
		if got := inviteOK.Header("To"); got != "<sip:alias@example.com>;tag="+svc.lookupSessionByCallID(invite.Header("Call-ID")).localTag {
			t.Fatalf("To = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for 200 OK")
	}

	select {
	case msg := <-writeCh:
		t.Fatalf("wrote %s before ACK", msg.StartLine)
	case <-time.After(20 * time.Millisecond):
	}

	us := svc.lookupSessionByCallID(invite.Header("Call-ID"))
	if us == nil {
		t.Fatal("lookupSessionByCallID() = nil")
	}

	ack := newDialogRequest("ACK", us.targetURI, invite.Header("From"), sip.WithTag(invite.Header("To"), "", us.localTag), invite.Header("Call-ID"), "1 ACK")
	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: ack, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(ACK) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(ACK) handled = false, want true")
	}

	select {
	case info := <-writeCh:
		if info.Method() != "INFO" {
			t.Fatalf("info.Method() = %q, want INFO", info.Method())
		}
		if got := info.Header("From"); got != "<sip:alias@example.com>;tag="+us.localTag {
			t.Fatalf("From = %q, want <sip:alias@example.com>;tag=%s", got, us.localTag)
		}
		payload, err := decodePayload(info)
		if err != nil {
			t.Fatalf("decodePayload() error = %v", err)
		}
		if payload.Text != "1" || !payload.Request {
			t.Fatalf("payload = %+v", payload)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for queued INFO")
	}
}

func TestUnknownDialogGets481(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	info := newDialogRequest("INFO", "sip:uss@example.com", "<sip:a@example.com>;tag=a", "<sip:b@example.com>;tag=b", "missing-call", "1 INFO")
	info.Headers.Add("Info-Package", infoPackage)
	info.Headers.Add("Content-Disposition", "info-package")
	info.Headers.Add("Content-Type", xmlContentType)
	info.Body = []byte(xml.Header + `<ussd-data><language>en</language><ussd-string>1</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`)

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: info, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	resp := mustParseUSSDMessage(t, transport.writes[len(transport.writes)-1])
	if got := resp.StatusCode(); got != 481 {
		t.Fatalf("StatusCode() = %d, want 481", got)
	}
}

func newTransport() *stubTransport {
	return &stubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		readCh: make(chan []byte, 16),
	}
}

func registeredService(t *testing.T, transport *stubTransport) (*session.Session, *registration.Service) {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(registration.Config{Logger: testLogger(), AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aa"}, sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if len(transport.writes) == 1 {
				transport.queue(newUSSDResponse(req, 401, "Unauthorized", nil,
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222`},
				))
				return
			}
			transport.queue(newUSSDResponse(req, 200, "OK", nil, sip.Header{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"}))
		}
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func registeredServiceWithAssociatedURIs(t *testing.T, transport *stubTransport, associatedURIs ...string) (*session.Session, *registration.Service) {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(registration.Config{Logger: testLogger(), AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aa"}, sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if len(transport.writes) == 1 {
				transport.queue(newUSSDResponse(req, 401, "Unauthorized", nil,
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=111;spi-s=222`},
				))
				return
			}
			headers := []sip.Header{{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"}}
			if len(associatedURIs) > 0 {
				headers = append(headers, sip.Header{Name: "P-Associated-URI", Value: strings.Join(associatedURIs, ",")})
			}
			transport.queue(newUSSDResponse(req, 200, "OK", nil, headers...))
		}
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func buildNetworkUSSDInvite(t *testing.T) sip.Message {
	t.Helper()
	payload, err := (xmlBody{Message: Message{Text: "Enter PIN", Language: "en", Request: true}}).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	body, err := (multipartBody{
		Boundary: "invite",
		Parts: []multipartBodyPart{
			{Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, Body: []byte("v=0\r\nm=audio 0 RTP/AVP 97\r\n")},
			{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: payload},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	msg := sip.NewRequest("INVITE", "sip:*100%23;phone-context=ims.example@ims.example;user=dialstring")
	msg.Headers = sip.Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1"},
		{Name: "From", Value: "<sip:network@example.com>;tag=remote"},
		{Name: "To", Value: "<sip:user@example.com>"},
		{Name: "Call-ID", Value: "call-1"},
		{Name: "Session-ID", Value: "session-1"},
		{Name: "CSeq", Value: "1 INVITE"},
		{Name: "Recv-Info", Value: infoPackage},
		{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
		{Name: "Content-Type", Value: "multipart/mixed; boundary=invite"},
	}
	msg.Body = body
	return msg
}

func newDialogRequest(method, target, from, to, callID, cseq string) sip.Message {
	msg := sip.NewRequest(method, target)
	msg.Headers = sip.Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-2"},
		{Name: "From", Value: from},
		{Name: "To", Value: to},
		{Name: "Call-ID", Value: callID},
		{Name: "CSeq", Value: cseq},
	}
	return msg
}

func newUSSDResponse(req sip.Message, code int, reason string, body []byte, extra ...sip.Header) sip.Message {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req, code)
	resp.Headers = append(resp.Headers, extra...)
	resp.Body = body
	return resp
}

func mustParseUSSDMessage(t *testing.T, data []byte) sip.Message {
	t.Helper()
	msg, err := sip.ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	return msg
}
