package ussd

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/textproto"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
	usim "github.com/damonto/wwan-go/sim"
)

type stubTransport struct {
	local   net.Addr
	remote  net.Addr
	readCh  chan []byte
	mu      sync.Mutex
	writes  [][]byte
	onWrite func([]byte)
}

type stubCard struct{}

const testSDP = "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 97\r\n"

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func closeEndpointAfterTest(t *testing.T, endpoint *Endpoint) {
	t.Helper()
	t.Cleanup(func() {
		if err := endpoint.Close(); err != nil {
			t.Errorf("Endpoint.Close() error = %v", err)
		}
	})
}

func closeServiceAfterTest(t *testing.T, endpoint *Endpoint, registrar *registration.Registrar, stack *session.Stack) {
	t.Helper()
	t.Cleanup(func() {
		if err := endpoint.Close(); err != nil {
			t.Errorf("Endpoint.Close() error = %v", err)
		}
		if err := registrar.Close(); err != nil {
			t.Errorf("Registrar.Close() error = %v", err)
		}
		if err := stack.Close(); err != nil {
			t.Errorf("Stack.Close() error = %v", err)
		}
	})
}

func (t *stubTransport) LocalAddr() net.Addr  { return t.local }
func (t *stubTransport) RemoteAddr() net.Addr { return t.remote }
func (t *stubTransport) WritePacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	t.writes = append(t.writes, append([]byte(nil), data...))
	onWrite := t.onWrite
	t.mu.Unlock()
	if onWrite != nil {
		onWrite(data)
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
func (t *stubTransport) Close() error { return nil }
func (t *stubTransport) queue(msg sip.Message) {
	t.readCh <- marshalSIPMessageForTest(msg)
}

func marshalSIPMessageForTest(msg sip.Message) []byte {
	data, err := msg.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return data
}

func (t *stubTransport) writeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}

func (t *stubTransport) lastWrite() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.writes) == 0 {
		return nil
	}
	return append([]byte(nil), t.writes[len(t.writes)-1]...)
}

func (t *stubTransport) writesSnapshot() [][]byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	writes := make([][]byte, len(t.writes))
	for i, write := range t.writes {
		writes[i] = append([]byte(nil), write...)
	}
	return writes
}

func (stubCard) IMSI() string { return "001010123456789" }
func (stubCard) MCC() string  { return "001" }
func (stubCard) MNC() string  { return "001" }
func (stubCard) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}, nil
}

func TestUSSDXMLRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
		want Message
	}{
		{name: "plain", msg: Message{Text: "*100#", Language: "en"}, want: Message{Text: "*100#", Language: "en"}},
		{name: "regional language", msg: Message{Text: "*100#", Language: "en-US"}, want: Message{Text: "*100#", Language: "en-US"}},
		{name: "empty string", msg: Message{Language: "en"}, want: Message{Language: "en"}},
		{name: "string preserves spaces", msg: Message{Text: " Enter PIN: ", Language: "en"}, want: Message{Text: " Enter PIN: ", Language: "en"}},
		{name: "request", msg: Message{Text: "Enter PIN", Language: "en", Request: true}, want: Message{Text: "Enter PIN", Language: "en", Request: true}},
		{name: "notify", msg: Message{Text: "Done", Language: "en", Notify: true}, want: Message{Text: "Done", Language: "en", Notify: true}},
		{name: "error", msg: Message{Language: "en", ErrorCode: ErrorCodeLanguageUnsupported}, want: Message{Language: "en", ErrorCode: ErrorCodeLanguageUnsupported}},
		{name: "busy error", msg: Message{Language: "en", ErrorCode: ErrorCodeUSSDBusy}, want: Message{Language: "en", ErrorCode: ErrorCodeUSSDBusy}},
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
		want    Message
		wantErr bool
	}{
		{
			name: "valid",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>*100#</ussd-string></ussd-data>`,
			want: Message{Language: "en", Text: "*100#"},
		},
		{
			name: "unknown element ignored",
			body: xml.Header + `<ussd-data><language>en</language><vendor-extension>ignored</vendor-extension><ussd-string>*100#</ussd-string></ussd-data>`,
			want: Message{Language: "en", Text: "*100#"},
		},
		{
			name: "namespaced unknown element ignored",
			body: xml.Header + `<ussd-data xmlns:x="urn:vendor"><language>en</language><x:language>ignored</x:language><ussd-string>*100#</ussd-string></ussd-data>`,
			want: Message{Language: "en", Text: "*100#"},
		},
		{
			name:    "undefined language rejected",
			body:    xml.Header + `<ussd-data><language>undefined</language><ussd-string>*100#</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name: "top-level request marker ignored",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>*100#</ussd-string><UnstructuredSS-Request/></ussd-data>`,
			want: Message{Language: "en", Text: "*100#"},
		},
		{
			name: "top-level notify marker ignored",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>*100#</ussd-string><UnstructuredSS-Notify/></ussd-data>`,
			want: Message{Language: "en", Text: "*100#"},
		},
		{
			name: "request marker in anyExt accepted",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>*100#</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`,
			want: Message{Language: "en", Text: "*100#", Request: true},
		},
		{
			name: "notify marker in anyExt accepted",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>*100#</ussd-string><anyExt><UnstructuredSS-Notify/></anyExt></ussd-data>`,
			want: Message{Language: "en", Text: "*100#", Notify: true},
		},
		{
			name:    "bare ampersand in string",
			body:    xml.Header + `<ussd-data><language>en</language><ussd-string>AT&T</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name: "escaped ampersand preserved",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>AT&amp;T</ussd-string></ussd-data>`,
			want: Message{Language: "en", Text: "AT&T"},
		},
		{
			name: "zero error code means success",
			body: xml.Header + `<ussd-data><error-code>0</error-code></ussd-data>`,
			want: Message{},
		},
		{
			name: "out of range error code treated as unspecified",
			body: xml.Header + `<ussd-data><error-code>9</error-code></ussd-data>`,
			want: Message{ErrorCode: ErrorCodeUnspecified},
		},
		{
			name: "USSD busy error code preserved",
			body: xml.Header + `<ussd-data><error-code>4</error-code></ussd-data>`,
			want: Message{ErrorCode: ErrorCodeUSSDBusy},
		},
		{
			name: "zero error code with result text means success",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>Done</ussd-string><error-code>0</error-code></ussd-data>`,
			want: Message{Language: "en", Text: "Done"},
		},
		{
			name: "unknown error code with result text remains an error",
			body: xml.Header + `<ussd-data><language>en</language><ussd-string>Rejected</ussd-string><error-code>9</error-code></ussd-data>`,
			want: Message{Language: "en", Text: "Rejected", ErrorCode: ErrorCodeUnspecified},
		},
		{
			name:    "duplicate language",
			body:    xml.Header + `<ussd-data><language>en</language><language>fr</language><ussd-string>*100#</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name: "carrier field order",
			body: xml.Header + `<ussd-data><ussd-string>*100#</ussd-string><language>en</language></ussd-data>`,
			want: Message{Language: "en", Text: "*100#"},
		},
		{
			name: "error precedes language and result",
			body: xml.Header + `<ussd-data><error-code>3</error-code><language>en</language><ussd-string>Rejected</ussd-string></ussd-data>`,
			want: Message{Language: "en", Text: "Rejected", ErrorCode: ErrorCodeUnexpectedDataValue},
		},
		{
			name: "extension precedes language and string",
			body: xml.Header + `<ussd-data><anyExt><UnstructuredSS-Request/></anyExt><language>en</language><ussd-string>Enter PIN</ussd-string></ussd-data>`,
			want: Message{Language: "en", Text: "Enter PIN", Request: true},
		},
		{
			name:    "duplicate string across language",
			body:    xml.Header + `<ussd-data><ussd-string>1</ussd-string><language>en</language><ussd-string>2</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "duplicate error across string",
			body:    xml.Header + `<ussd-data><error-code>0</error-code><ussd-string>Done</ussd-string><error-code>1</error-code></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "duplicate request marker",
			body:    xml.Header + `<ussd-data><anyExt><UnstructuredSS-Request/><UnstructuredSS-Request/></anyExt></ussd-data>`,
			wantErr: true,
		},
		{
			name: "language has region subtag",
			body: xml.Header + `<ussd-data><language>en-US</language><ussd-string>*100#</ussd-string></ussd-data>`,
			want: Message{Language: "en-US", Text: "*100#"},
		},
		{
			name: "language has script and region subtags",
			body: xml.Header + `<ussd-data><language>zh-Hant-TW</language><ussd-string>*100#</ussd-string></ussd-data>`,
			want: Message{Language: "zh-Hant-TW", Text: "*100#"},
		},
		{
			name:    "language has empty subtag",
			body:    xml.Header + `<ussd-data><language>en--US</language><ussd-string>*100#</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "language uses underscore separator",
			body:    xml.Header + `<ussd-data><language>en_US</language><ussd-string>*100#</ussd-string></ussd-data>`,
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
		{
			name:    "namespaced root",
			body:    xml.Header + `<ussd-data xmlns="urn:vendor"><language>en</language><ussd-string>*100#</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "namespaced anyExt marker",
			body:    xml.Header + `<ussd-data xmlns="urn:vendor"><language>en</language><ussd-string>*100#</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeXML([]byte(tt.body))
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("decodeXML() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil && got != tt.want {
				t.Fatalf("decodeXML() = %+v, want %+v", got, tt.want)
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
		{name: "undefined", msg: Message{Text: "*100#", Language: "undefined"}, wantErr: true},
		{name: "region subtag", msg: Message{Text: "*100#", Language: "en-US"}},
		{name: "empty subtag", msg: Message{Text: "*100#", Language: "en--US"}, wantErr: true},
		{name: "underscore separator", msg: Message{Text: "*100#", Language: "en_US"}, wantErr: true},
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
			{Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, Body: []byte("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 97\r\n")},
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
		{name: "one zero port media", body: testSDP},
		{name: "no media", body: "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\n", wantErr: true},
		{name: "missing origin", body: "v=0\r\ns=-\r\nt=0 0\r\nm=audio 0 RTP/AVP 97\r\n", wantErr: true},
		{name: "nonzero port", body: "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\nm=audio 49170 RTP/AVP 97\r\n", wantErr: true},
		{name: "two media", body: "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nt=0 0\r\nm=audio 0 RTP/AVP 97\r\nm=video 0 RTP/AVP 98\r\n", wantErr: true},
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

func TestAcceptsMediaParsesMIMETypes(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{
			name:  "required media types",
			value: `application/vnd.3gpp.ussd+xml; q=1.0, application/sdp, multipart/mixed`,
			want:  true,
		},
		{
			name:  "missing multipart",
			value: `application/vnd.3gpp.ussd+xml, application/sdp`,
			want:  false,
		},
		{
			name:  "substring false positive",
			value: `application/not-vnd.3gpp.ussd+xml, application/sdp, multipart/mixed-extra`,
			want:  false,
		},
		{
			name:  "zero quality XML",
			value: `application/vnd.3gpp.ussd+xml;q=0, application/sdp, multipart/mixed`,
			want:  false,
		},
		{
			name:  "positive quality",
			value: `application/vnd.3gpp.ussd+xml;q=0.5, application/sdp;q=1, multipart/mixed`,
			want:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := acceptsMedia(tt.value); got != tt.want {
				t.Fatalf("acceptsMedia() = %t, want %t", got, tt.want)
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
		name                     string
		headerContentDisposition string
		headerContentType        string
		body                     []byte
		wantErr                  bool
	}{
		{name: "single ussd xml", headerContentDisposition: "Info-Package", headerContentType: xmlContentType, body: payload},
		{name: "missing content disposition rejected", headerContentType: xmlContentType, body: payload, wantErr: true},
		{name: "wrong content disposition rejected", headerContentDisposition: "render", headerContentType: xmlContentType, body: payload, wantErr: true},
		{name: "multipart rejected", headerContentDisposition: "Info-Package", headerContentType: "multipart/mixed; boundary=info", body: multipartPayload, wantErr: true},
		{name: "missing content type", headerContentDisposition: "Info-Package", body: payload, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewRequest("INFO", "sip:ussias@example.com")
			msg.Headers.Add("Info-Package", infoPackage)
			if tt.headerContentDisposition != "" {
				msg.Headers.Add("Content-Disposition", tt.headerContentDisposition)
			}
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

func TestValidateNetworkInitiatedInboundInfoMarkerRules(t *testing.T) {
	tests := []struct {
		name    string
		msg     Message
		rawBody string
		wantErr bool
	}{
		{
			name:    "plain string without marker rejected",
			msg:     Message{Text: "Enter PIN", Language: "en"},
			wantErr: true,
		},
		{
			name: "request string accepted",
			msg:  Message{Text: "Enter PIN", Language: "en", Request: true},
		},
		{
			name:    "request without string rejected",
			rawBody: `<ussd-data><language>en</language><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "request without language rejected",
			msg:     Message{Text: "Enter PIN", Request: true},
			wantErr: true,
		},
		{
			name:    "request and notify rejected",
			msg:     Message{Text: "Enter PIN", Language: "en", Request: true, Notify: true},
			wantErr: true,
		},
		{
			name:    "notify string rejected in request dialog",
			msg:     Message{Text: "Done", Language: "en", Notify: true},
			wantErr: true,
		},
		{
			name: "error only accepted",
			msg:  Message{Language: "en", ErrorCode: ErrorCodeUnexpectedDataValue},
		},
		{
			name:    "zero error with request accepted",
			rawBody: `<ussd-data><error-code>0</error-code><language>en-US</language><ussd-string>Enter PIN</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`,
		},
		{
			name:    "zero error does not bypass request marker",
			rawBody: `<ussd-data><error-code>0</error-code><language>en-US</language><ussd-string>Enter PIN</ussd-string></ussd-data>`,
			wantErr: true,
		},
		{
			name:    "zero error does not bypass language",
			rawBody: `<ussd-data><error-code>0</error-code><ussd-string>Enter PIN</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := []byte(xml.Header + tt.rawBody)
			if tt.rawBody == "" {
				var err error
				payload, err = (xmlBody{Message: tt.msg}).MarshalText()
				if err != nil {
					t.Fatalf("MarshalText() error = %v", err)
				}
			}
			msg := sip.NewRequest("INFO", "sip:ussias@example.com")
			msg.Headers.Add("Info-Package", infoPackage)
			msg.Headers.Add("Content-Disposition", infoPackageDisposition)
			msg.Headers.Add("Content-Type", xmlContentType)
			msg.Body = payload

			_, err := validateInboundInfo(msg, true)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("validateInboundInfo() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeInvitePayloadRejectsDuplicateBodyParts(t *testing.T) {
	payload, err := (xmlBody{Message: Message{Text: "Enter PIN", Language: "en", Request: true}}).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	sdp := []byte(testSDP)
	tests := []struct {
		name  string
		parts []multipartBodyPart
	}{
		{
			name: "duplicate ussd xml",
			parts: []multipartBodyPart{
				{Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, Body: sdp},
				{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: payload},
				{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: payload},
			},
		},
		{
			name: "duplicate sdp",
			parts: []multipartBodyPart{
				{Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, Body: sdp},
				{Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, Body: sdp},
				{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: payload},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := (multipartBody{Boundary: "invite", Parts: tt.parts}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			msg := sip.NewRequest("INVITE", "sip:user@example.com")
			msg.Headers.Add("Content-Type", "multipart/mixed; boundary=invite")
			msg.Body = body
			if _, _, _, err := decodeInvitePayload(msg); err == nil {
				t.Fatal("decodeInvitePayload() error = nil, want error")
			}
		})
	}
}

func TestDecodeInvitePayloadUnsupportedBodyPartHandling(t *testing.T) {
	payload, err := (xmlBody{Message: Message{Text: "Enter PIN", Language: "en", Request: true}}).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	sdp := []byte(testSDP)
	tests := []struct {
		name    string
		header  textproto.MIMEHeader
		wantErr bool
	}{
		{
			name: "optional unsupported part ignored",
			header: textproto.MIMEHeader{
				"Content-Type":        {"text/plain"},
				"Content-Disposition": {"render;handling=optional"},
			},
		},
		{
			name: "optional malformed content type ignored",
			header: textproto.MIMEHeader{
				"Content-Type":        {"%%%"},
				"Content-Disposition": {"render;handling=optional"},
			},
		},
		{
			name: "missing disposition is required",
			header: textproto.MIMEHeader{
				"Content-Type": {"text/plain"},
			},
			wantErr: true,
		},
		{
			name: "explicit required unsupported part rejected",
			header: textproto.MIMEHeader{
				"Content-Type":        {"text/plain"},
				"Content-Disposition": {"render;handling=required"},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := (multipartBody{
				Boundary: "invite",
				Parts: []multipartBodyPart{
					{Header: textproto.MIMEHeader{"Content-Type": {sdpContentType}}, Body: sdp},
					{Header: tt.header, Body: []byte("ignored")},
					{Header: textproto.MIMEHeader{"Content-Type": {xmlContentType}}, Body: payload},
				},
			}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			msg := sip.NewRequest("INVITE", "sip:user@example.com")
			msg.Headers.Add("Content-Type", "multipart/mixed; boundary=invite")
			msg.Body = body
			got, _, _, err := decodeInvitePayload(msg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("decodeInvitePayload() error = nil, want unsupported body part error")
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeInvitePayload() error = %v", err)
			}
			if got.Text != "Enter PIN" || !got.Request {
				t.Fatalf("decodeInvitePayload() = %+v, want request payload", got)
			}
		})
	}
}

func TestHandleInfoMapsPackageAndMediaErrors(t *testing.T) {
	payload, err := (xmlBody{Message: Message{Text: "Balance", Language: "en"}}).MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	tests := []struct {
		name               string
		infoPackage        string
		contentDisposition string
		contentType        string
		wantStatus         int
	}{
		{
			name:               "missing info package",
			contentDisposition: "info-package",
			contentType:        xmlContentType,
			wantStatus:         sipStatusBadInfoPackage,
		},
		{
			name:               "wrong info package",
			infoPackage:        "g.example.other",
			contentDisposition: "info-package",
			contentType:        xmlContentType,
			wantStatus:         sipStatusBadInfoPackage,
		},
		{
			name:               "wrong content disposition",
			infoPackage:        infoPackage,
			contentDisposition: "render",
			contentType:        xmlContentType,
			wantStatus:         sipStatusUnsupportedMediaType,
		},
		{
			name:               "wrong content type",
			infoPackage:        infoPackage,
			contentDisposition: "info-package",
			contentType:        "text/plain",
			wantStatus:         sipStatusUnsupportedMediaType,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			us := &Session{
				endpoint:    svc,
				callID:      "info-call",
				localTag:    "local",
				remoteTag:   "remote",
				remoteTo:    "<sip:network@example.com>;tag=remote",
				targetURI:   "sip:network@example.com",
				events:      make(chan Message, 1),
				remoteCSeqs: make(map[string]struct{}),
			}
			info := newDialogRequest("INFO", "sip:user@example.com", "<sip:network@example.com>;tag=remote", "<sip:user@example.com>;tag=local", "info-call", "2 INFO")
			if tt.infoPackage != "" {
				info.Headers.Add("Info-Package", tt.infoPackage)
			}
			if tt.contentDisposition != "" {
				info.Headers.Add("Content-Disposition", tt.contentDisposition)
			}
			if tt.contentType != "" {
				info.Headers.Add("Content-Type", tt.contentType)
			}
			info.Body = payload
			if err := us.handleInfo(t.Context(), session.Request{Message: info, Transport: transport}); err != nil {
				t.Fatalf("handleInfo() error = %v", err)
			}
			resp := mustParseUSSDMessage(t, transport.lastWrite())
			if got := resp.StatusCode(); got != tt.wantStatus {
				t.Fatalf("StatusCode() = %d, want %d", got, tt.wantStatus)
			}
			if tt.wantStatus == sipStatusUnsupportedMediaType {
				if got := resp.Header("Accept"); got != acceptHeader {
					t.Fatalf("Accept = %q, want %q", got, acceptHeader)
				}
			}
		})
	}
}

func TestHandleByeUSSDPayload(t *testing.T) {
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
		wantMessage       bool
		want              Message
	}{
		{
			name: "single ussd xml", headerContentType: xmlContentType, body: payload,
			wantStatus: 200, wantClosed: true, wantMessage: true,
			want: Message{Language: "en", Text: "Done", Final: true},
		},
		{
			name: "carrier result with zero error and regional language", headerContentType: xmlContentType,
			body:       []byte("<ussd-data>\r\n<error-code>0</error-code>\r\n<language>en-US</language>\r\n<ussd-string>Request accepted</ussd-string>\r\n</ussd-data>\r\n"),
			wantStatus: 200, wantClosed: true, wantMessage: true,
			want: Message{Language: "en-US", Text: "Request accepted", Final: true},
		},
		{
			name: "zero error without language ignored", headerContentType: xmlContentType,
			body:       []byte(`<ussd-data><error-code>0</error-code><ussd-string>Done</ussd-string></ussd-data>`),
			wantStatus: 200, wantClosed: true,
		},
		{
			name: "duplicate error ignored", headerContentType: xmlContentType,
			body:       []byte(`<ussd-data><error-code>0</error-code><language>en</language><ussd-string>Done</ussd-string><error-code>1</error-code></ussd-data>`),
			wantStatus: 200, wantClosed: true,
		},
		{name: "multipart body ignored", headerContentType: "multipart/mixed; boundary=bye", body: multipartPayload, wantStatus: 200, wantClosed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			closeServiceAfterTest(t, svc, reg, sess)
			us := &Session{
				endpoint:    svc,
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
			if err := us.handleBye(t.Context(), session.Request{Message: bye, Transport: transport}); err != nil {
				t.Fatalf("handleBye() error = %v", err)
			}
			resp := mustParseUSSDMessage(t, transport.lastWrite())
			if got := resp.StatusCode(); got != tt.wantStatus {
				t.Fatalf("StatusCode() = %d, want %d", got, tt.wantStatus)
			}
			if tt.wantStatus == sipStatusUnsupportedMediaType {
				if got := resp.Header("Accept"); got != acceptHeader {
					t.Fatalf("Accept = %q, want %q", got, acceptHeader)
				}
			}
			if got := us.isClosed(); got != tt.wantClosed {
				t.Fatalf("isClosed() = %t, want %t", got, tt.wantClosed)
			}
			if got, ok := <-us.Events(); ok != tt.wantMessage || got != tt.want {
				t.Fatalf("Events() = %+v, %t; want %+v, %t", got, ok, tt.want, tt.wantMessage)
			}
		})
	}
}

func TestContactValuesUseRegisteredURI(t *testing.T) {
	tests := []struct {
		name                      string
		state                     registration.State
		networkInitiatedSupported bool
		wantRequestURI            string
		wantNetworkInitTag        bool
	}{
		{
			name: "ipv4",
			state: registration.State{
				ContactURI: "sip:opaque@127.0.0.1:5062;transport=tcp",
			},
			wantRequestURI: "sip:opaque@127.0.0.1:5062;transport=tcp",
		},
		{
			name: "outbound ipv6",
			state: registration.State{
				ContactURI: "sip:opaque@[2001:db8::20]:5062;transport=tcp",
				Flow:       registration.Flow{Outbound: true},
			},
			wantRequestURI: "sip:opaque@[2001:db8::20]:5062;transport=tcp;ob",
		},
		{
			name:                      "network initiated advertised only when configured",
			networkInitiatedSupported: true,
			state: registration.State{
				ContactURI: "sip:opaque@127.0.0.1:5062",
			},
			wantRequestURI:     "sip:opaque@127.0.0.1:5062",
			wantNetworkInitTag: true,
		},
		{
			name: "imei does not add sip instance outside REGISTER",
			state: registration.State{
				ContactURI: "sip:opaque@127.0.0.1:5062",
				IMEI:       "123456789012345",
			},
			wantRequestURI: "sip:opaque@127.0.0.1:5062",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := contactValue(tt.state, tt.networkInitiatedSupported)
			if got := sip.AddressURI(response); got != tt.state.ContactURI {
				t.Fatalf("contactValue() URI = %q, want %q", got, tt.state.ContactURI)
			}
			request := requestContactValue(tt.state, tt.networkInitiatedSupported)
			if got := sip.AddressURI(request); got != tt.wantRequestURI {
				t.Fatalf("requestContactValue() URI = %q, want %q", got, tt.wantRequestURI)
			}
			if strings.Contains(response, nwInitUSSI) != tt.wantNetworkInitTag || strings.Contains(request, nwInitUSSI) != tt.wantNetworkInitTag {
				t.Fatalf("Contact values = %q / %q, want network init tag %t", response, request, tt.wantNetworkInitTag)
			}
			if strings.Contains(response, "+sip.instance") || strings.Contains(request, "+sip.instance") {
				t.Fatalf("Contact values = %q / %q, want no +sip.instance", response, request)
			}
		})
	}
}

func TestUSSDCancelKeepsInviteSupportedOptions(t *testing.T) {
	tests := []struct {
		name      string
		supported []string
	}{
		{name: "outbound", supported: []string{"199,path,sec-agree,outbound"}},
		{name: "repeated headers", supported: []string{"199,path", "outbound"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invite := sip.NewRequest("INVITE", "sip:ussd@example.com")
			invite.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bK-test")
			invite.Headers.Add("From", "<sip:user@example.com>;tag=local")
			invite.Headers.Add("To", "<sip:ussd@example.com>")
			invite.Headers.Add("Call-ID", "call-1")
			invite.Headers.Add("CSeq", "1 INVITE")
			for _, value := range tt.supported {
				invite.Headers.Add("Supported", value)
			}
			cancel := buildCancel(invite)
			if got := cancel.HeadersByName("Supported"); !slices.Equal(got, tt.supported) {
				t.Fatalf("CANCEL Supported = %q, want %q", got, tt.supported)
			}
		})
	}
}

func TestHandleDialogRequestRejectsCSeqMethodMismatch(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	us := &Session{
		endpoint:    svc,
		callID:      "cseq-call",
		localTag:    "local",
		remoteTag:   "remote",
		remoteTo:    "<sip:network@example.com>;tag=remote",
		targetURI:   "sip:network@example.com",
		events:      make(chan Message, 1),
		remoteCSeqs: make(map[string]struct{}),
	}
	info := newDialogRequest("INFO", "sip:user@example.com", "<sip:network@example.com>;tag=remote", "<sip:user@example.com>;tag=local", "cseq-call", "2 BYE")
	info.Headers.Add("Info-Package", infoPackage)
	info.Headers.Add("Content-Disposition", "info-package")
	info.Headers.Add("Content-Type", xmlContentType)
	info.Body = []byte(xml.Header + `<ussd-data><language>en</language><ussd-string>Next</ussd-string></ussd-data>`)

	if err := us.handleRequest(t.Context(), session.Request{Message: info, Transport: transport}); err != nil {
		t.Fatalf("handleRequest() error = %v", err)
	}
	resp := mustParseUSSDMessage(t, transport.lastWrite())
	if got := resp.StatusCode(); got != sipStatusBadRequest {
		t.Fatalf("StatusCode() = %d, want %d", got, sipStatusBadRequest)
	}
}

func TestUSSDExchange481ClosesSession(t *testing.T) {
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
				[]byte(testSDP),
				sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				sip.Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
				sip.Header{Name: "Recv-Info", Value: infoPackage},
				sip.Header{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
				sip.Header{Name: "Content-Type", Value: "application/sdp"},
			))
		case "INFO":
			transport.queue(newUSSDResponse(req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist", nil))
		}
	}

	us, err := svc.Start(t.Context(), "*100#")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := us.Reply(t.Context(), "1"); err == nil {
		t.Fatal("Reply() error = nil, want 481")
	}
	if !us.isClosed() {
		t.Fatal("USSD session is open, want closed")
	}
	if svc.hasActiveSession() {
		t.Fatal("hasActiveSession() = true, want false")
	}
}

func TestUSSDInviteSDP(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		network string
	}{
		{name: "IPv4", host: "192.0.2.1", network: "IP4"},
		{name: "IPv6", host: "2001:db8::1", network: "IP6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			transport.local = &net.TCPAddr{IP: net.ParseIP(tt.host), Port: 5062}
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			closeServiceAfterTest(t, svc, reg, sess)

			_, invite, err := svc.newStart("#225#")
			if err != nil {
				t.Fatalf("newStart() error = %v", err)
			}
			body, err := messageSDPBody(invite)
			if err != nil {
				t.Fatalf("messageSDPBody() error = %v", err)
			}
			if err := validateSDPBody(body); err != nil {
				t.Fatalf("validateSDPBody() error = %v", err)
			}

			// USSD disables media with port zero, while rtpmap still declares
			// the clock rates required by RFC 8866.
			lines := strings.Split(string(body), "\r\n")
			for _, want := range []string{
				"c=IN " + tt.network + " " + tt.host,
				"m=audio 0 RTP/AVP 97 96",
				"a=rtpmap:97 AMR/8000",
				"a=rtpmap:96 telephone-event/8000",
			} {
				if !slices.Contains(lines, want) {
					t.Errorf("INVITE SDP missing %q:\n%s", want, body)
				}
			}
		})
	}
}

func TestStartUSSDSessionFlow(t *testing.T) {
	const wantSecurityVerify = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222"

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
				[]byte(testSDP),
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

	session, err := svc.Start(t.Context(), "*100#")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := session.Reply(t.Context(), "1"); err != nil {
		t.Fatalf("Reply() error = %v", err)
	}
	last := mustParseUSSDMessage(t, transport.lastWrite())
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

func TestStartUSSDACKsInvalidInviteOK(t *testing.T) {
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
				[]byte(testSDP),
				sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				sip.Header{Name: "Contact", Value: "<sip:ussias@example.com>"},
				sip.Header{Name: "Accept", Value: acceptHeader},
				sip.Header{Name: "Content-Type", Value: sdpContentType},
			))
		case "BYE":
			transport.queue(newUSSDResponse(req, 200, "OK", nil))
		}
	}

	if _, err := svc.Start(t.Context(), "*100#"); err == nil {
		t.Fatal("Start() error = nil, want invalid 200 OK error")
	}
	var acked, ended bool
	for _, data := range transport.writesSnapshot() {
		msg := mustParseUSSDMessage(t, data)
		switch msg.Method() {
		case "ACK":
			acked = true
		case "BYE":
			ended = true
		}
	}
	if !acked || !ended {
		t.Fatalf("invalid 200 OK cleanup: ACK=%t BYE=%t, want both true", acked, ended)
	}
}

func TestRetransmittedInviteOKIsACKed(t *testing.T) {
	tests := []struct {
		name      string
		remoteTag string
		wantBYE   bool
	}{
		{name: "same dialog retransmission", remoteTag: "remote"},
		{name: "forked dialog", remoteTag: "fork", wantBYE: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			closeServiceAfterTest(t, svc, reg, sess)

			ack := newDialogRequest("ACK", "sip:ussias@example.com", "<sip:user@example.com>;tag=local", "<sip:ussias@example.com>;tag=remote", "call-retransmit", "1 ACK")
			us := &Session{
				endpoint:     svc,
				callID:       "call-retransmit",
				sessionID:    "session-retransmit",
				localURI:     "sip:user@example.com",
				localTag:     "local",
				remoteTag:    "remote",
				remoteTo:     "<sip:ussias@example.com>;tag=remote",
				targetURI:    "sip:ussias@example.com",
				inviteSeq:    1,
				localCSeq:    1,
				inviteACK:    ack,
				events:       make(chan Message, 1),
				remoteCSeqs:  make(map[string]struct{}),
				responseKind: dialogKindRequest,
			}
			if err := svc.storeSession(us); err != nil {
				t.Fatalf("storeSession() error = %v", err)
			}
			byeCh := make(chan struct{}, 1)
			transport.onWrite = func(data []byte) {
				msg := mustParseUSSDMessage(t, data)
				if msg.Method() != "BYE" {
					return
				}
				transport.queue(newUSSDResponse(msg, 200, "OK", nil))
				byeCh <- struct{}{}
			}

			writesBefore := transport.writeCount()
			resp := sip.NewResponse(200, "OK")
			resp.Headers = sip.Headers{
				{Name: "Call-ID", Value: us.callID},
				{Name: "CSeq", Value: "1 INVITE"},
				{Name: "To", Value: "<sip:ussias@example.com>;tag=" + tt.remoteTag},
				{Name: "Contact", Value: "<sip:" + tt.remoteTag + "@example.com>"},
			}
			handled, err := svc.HandleResponse(t.Context(), resp)
			if err != nil {
				t.Fatalf("HandleResponse() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleResponse() handled = false, want true")
			}
			if tt.wantBYE {
				select {
				case <-byeCh:
				case <-time.After(time.Second):
					t.Fatal("waiting for forked dialog BYE")
				}
			}
			wantWrites := writesBefore + 1
			if tt.wantBYE {
				wantWrites++
			}
			if got := transport.writeCount(); got != wantWrites {
				t.Fatalf("write count = %d, want %d", got, wantWrites)
			}
		})
	}
}

func TestEndClosesSessionOnNon2xxResponse(t *testing.T) {
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
				[]byte(testSDP),
				sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				sip.Header{Name: "Contact", Value: "<sip:ussias@example.com>"},
				sip.Header{Name: "Recv-Info", Value: infoPackage},
				sip.Header{Name: "Accept", Value: acceptHeader},
				sip.Header{Name: "Content-Type", Value: sdpContentType},
			))
		case "BYE":
			transport.queue(newUSSDResponse(req, 500, "Server Internal Error", nil))
		}
	}

	us, err := svc.Start(t.Context(), "*100#")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := us.End(t.Context(), ""); err == nil {
		t.Fatal("End() error = nil, want non-2xx response error")
	}
	if !us.isClosed() {
		t.Fatal("session closed = false after sending BYE")
	}
}

func TestStartUSSDRejectsNonIMSDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain Domain
	}{
		{name: "cs preferred", domain: DomainCS},
		{name: "disabled", domain: DomainDisabled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger(), Domain: tt.domain}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			writesBefore := transport.writeCount()

			_, err = svc.Start(t.Context(), "*100#")
			if err == nil || !errors.Is(err, ErrIMSDomainNotAllowed) {
				t.Fatalf("Start() error = %v, want ErrIMSDomainNotAllowed", err)
			}
			if got := transport.writeCount(); got != writesBefore {
				t.Fatalf("transport writes after Start = %d, want %d", got, writesBefore)
			}
		})
	}
}

func TestCloseClosesUSSDLocallyWithoutBYE(t *testing.T) {
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
				[]byte(testSDP),
				sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
				sip.Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
				sip.Header{Name: "Recv-Info", Value: infoPackage},
				sip.Header{Name: "Accept", Value: xmlContentType + ", application/sdp, multipart/mixed"},
				sip.Header{Name: "Content-Type", Value: "application/sdp"},
			))
		case "BYE":
			t.Fatalf("unexpected BYE during service close: %s", req.StartLine)
		}
	}

	session, err := svc.Start(t.Context(), "*100#")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	writesAfterStart := transport.writeCount()
	if err := svc.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	if got := transport.writeCount(); got != writesAfterStart {
		t.Fatalf("write count after Close() = %d, want %d", got, writesAfterStart)
	}
	if !session.isClosed() {
		t.Fatal("USSD session closed = false, want true")
	}
	select {
	case _, ok := <-session.Events():
		if ok {
			t.Fatal("USSD events channel still open")
		}
	default:
		t.Fatal("USSD events channel not closed")
	}
}

func TestUSSDRejectsParallelTransactions(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, svc *Endpoint, transport *stubTransport)
	}{
		{
			name: "local start while active",
			run: func(t *testing.T, svc *Endpoint, transport *stubTransport) {
				writesBefore := transport.writeCount()
				_, err := svc.Start(t.Context(), "*101#")
				if !errors.Is(err, errSessionActive) {
					t.Fatalf("Start() error = %v, want errSessionActive", err)
				}
				if got := transport.writeCount(); got != writesBefore {
					t.Fatalf("write count = %d, want %d", got, writesBefore)
				}
			},
		},
		{
			name: "network invite while active",
			run: func(t *testing.T, svc *Endpoint, transport *stubTransport) {
				transport.onWrite = nil
				invite := buildNetworkUSSDInvite(t)
				handled, err := svc.HandleRequest(t.Context(), session.Request{Message: invite, Transport: transport})
				if err != nil {
					t.Fatalf("HandleRequest() error = %v", err)
				}
				if !handled {
					t.Fatal("HandleRequest() handled = false, want true")
				}
				resp := mustParseUSSDMessage(t, transport.lastWrite())
				if got := resp.StatusCode(); got != sipStatusBusyHere {
					t.Fatalf("parallel INVITE status = %d, want %d", got, sipStatusBusyHere)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			transport.onWrite = func(data []byte) {
				req := mustParseUSSDMessage(t, data)
				switch req.Method() {
				case "INVITE":
					transport.queue(newUSSDResponse(req, 200, "OK",
						[]byte(testSDP),
						sip.Header{Name: "To", Value: req.Header("To") + ";tag=remote-1"},
						sip.Header{Name: "Contact", Value: "<sip:ussias@example.com;lr>"},
						sip.Header{Name: "Recv-Info", Value: infoPackage},
						sip.Header{Name: "Accept", Value: "application/vnd.3gpp.ussd+xml, application/sdp, multipart/mixed"},
						sip.Header{Name: "Content-Type", Value: "application/sdp"},
					))
				case "BYE":
					transport.queue(newUSSDResponse(req, 200, "OK", nil))
				}
			}
			if _, err := svc.Start(t.Context(), "*100#"); err != nil {
				t.Fatalf("Start() error = %v", err)
			}
			tt.run(t, svc, transport)
		})
	}
}

func TestHandleIncomingInviteMapsUnsupportedMediaTo415(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *sip.Message)
	}{
		{
			name: "unsupported invite content type",
			mutate: func(t *testing.T, msg *sip.Message) {
				msg.Headers.Set("Content-Type", "application/vnd.3gpp.ussd+xml")
			},
		},
		{
			name: "unsupported required multipart part",
			mutate: func(t *testing.T, msg *sip.Message) {
				t.Helper()
				body, err := (multipartBody{
					Boundary: "invite",
					Parts: []multipartBodyPart{
						{Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, Body: []byte(testSDP)},
						{Header: textproto.MIMEHeader{"Content-Type": {"text/plain"}}, Body: []byte("ignored")},
					},
				}).MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				msg.Body = body
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			invite := buildNetworkUSSDInvite(t)
			tt.mutate(t, &invite)

			handled, err := svc.HandleRequest(t.Context(), session.Request{Message: invite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			resp := mustParseUSSDMessage(t, transport.lastWrite())
			if got := resp.StatusCode(); got != sipStatusUnsupportedMediaType {
				t.Fatalf("StatusCode() = %d, want %d", got, sipStatusUnsupportedMediaType)
			}
			if got := resp.Header("Accept"); got != acceptHeader {
				t.Fatalf("Accept = %q, want %q", got, acceptHeader)
			}
		})
	}
}

func TestHandleIncomingInviteDisabledReturns404(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	handled, err := svc.HandleRequest(t.Context(), session.Request{Message: buildNetworkUSSDInvite(t), Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	resp := mustParseUSSDMessage(t, transport.lastWrite())
	if got := resp.StatusCode(); got != sipStatusNotFound {
		t.Fatalf("StatusCode() = %d, want %d", got, sipStatusNotFound)
	}
	if got := svc.lookupSessionByCallID("call-1"); got != nil {
		t.Fatalf("lookupSessionByCallID() = %p, want nil", got)
	}
}

func TestValidateInviteOKRequiresAccept(t *testing.T) {
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
			wantErr: true,
		},
		{
			name: "recv info accept and sdp",
			headers: sip.Headers{
				{Name: "Recv-Info", Value: infoPackage},
				{Name: "Accept", Value: acceptHeader},
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
			msg.Headers.Add("To", "<sip:ussias@example.com>;tag=remote")
			msg.Headers.Add("Contact", "<sip:ussias@example.com>")
			msg.Body = []byte(testSDP)

			err := validateInviteOK(msg)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("validateInviteOK() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestInviteDialogContactValidation(t *testing.T) {
	tests := []struct {
		name     string
		contacts []string
		wantErr  bool
	}{
		{name: "sip", contacts: []string{"<sip:ussias@example.com>"}},
		{name: "sips", contacts: []string{"<sips:ussias@example.com>"}},
		{name: "missing", wantErr: true},
		{name: "non SIP URI", contacts: []string{"<mailto:ussias@example.com>"}, wantErr: true},
		{name: "multiple fields", contacts: []string{"<sip:first@example.com>", "<sip:second@example.com>"}, wantErr: true},
		{name: "comma separated", contacts: []string{"<sip:first@example.com>, <sip:second@example.com>"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewResponse(200, "OK")
			for _, contact := range tt.contacts {
				msg.Headers.Add("Contact", contact)
			}
			_, err := dialogContactURI(msg)
			if (err != nil) != tt.wantErr {
				t.Fatalf("dialogContactURI() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestIncomingInviteOKCopiesRecordRoute(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	closeEndpointAfterTest(t, svc)

	invite := buildNetworkUSSDInvite(t)
	want := []string{"<sip:first.example.com;lr>", "<sip:second.example.com;lr>"}
	for _, value := range want {
		invite.Headers.Add("Record-Route", value)
	}
	ok := svc.buildIncomingInviteOK(invite, "sip:user@example.com", "local", []byte(testSDP))
	got := ok.HeadersByName("Record-Route")
	if !slices.Equal(got, want) {
		t.Fatalf("Record-Route = %v, want %v", got, want)
	}
}

func TestCancelOnlyClosesPendingIncomingInvite(t *testing.T) {
	tests := []struct {
		name      string
		finalSent bool
		wantClose bool
	}{
		{name: "pending INVITE", wantClose: true},
		{name: "final response sent", finalSent: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			closeEndpointAfterTest(t, svc)

			invite := buildNetworkUSSDInvite(t)
			us := svc.newIncomingSession(invite, Message{Text: "prompt", Language: "en", Request: true})
			if tt.finalSent {
				us.markInviteFinalResponseSent()
			}
			if err := svc.storeSession(us); err != nil {
				t.Fatalf("storeSession() error = %v", err)
			}
			cancel := invite
			cancel.StartLine = "CANCEL " + sip.RequestURI(invite) + " SIP/2.0"
			cancel.Headers = sip.UpsertHeader(cancel.Headers, "CSeq", "1 CANCEL")
			handled, err := svc.HandleRequest(t.Context(), session.Request{Message: cancel})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			if got := us.isClosed(); got != tt.wantClose {
				t.Fatalf("session closed = %t, want %t", got, tt.wantClose)
			}
		})
	}
}

func TestSDPAnswerMatchesOfferMedia(t *testing.T) {
	tests := []struct {
		name      string
		offer     string
		wantMedia string
		wantErr   bool
	}{
		{
			name:      "video offer",
			offer:     "v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=7 9\r\nm=video 0 RTP/AVP 99\r\n",
			wantMedia: "m=video 0 RTP/AVP 99",
		},
		{
			name:    "missing timing",
			offer:   "v=0\r\nm=audio 0 RTP/AVP 97\r\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTransport()
			sess, reg := registeredService(t, transport)
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			answer, err := svc.sdpAnswer([]byte(tt.offer))
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("sdpAnswer() error = %v, wantErr %t", err, tt.wantErr)
			}
			if err == nil && !strings.Contains(string(answer), tt.wantMedia+"\r\n") {
				t.Fatalf("sdpAnswer() = %q, want media %q", answer, tt.wantMedia)
			}
			if err == nil && !strings.Contains(string(answer), "t=7 9\r\n") {
				t.Fatalf("sdpAnswer() = %q, want offered timing", answer)
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
				[]byte(testSDP),
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

	us, err := svc.Start(t.Context(), "*100#")
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
	const wantSecurityVerify = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222"

	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	session := &Session{
		endpoint:  svc,
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

	ack := session.buildACK()
	if got := sip.RequestURI(ack); got != "sip:edge.example.com" {
		t.Fatalf("RequestURI() = %q, want sip:edge.example.com", got)
	}
	if got := ack.HeadersByName("Route"); len(got) != 2 || got[0] != "<sip:pcscf.example.com;lr>" || got[1] != "<sip:ussias@example.com>" {
		t.Fatalf("Route = %v", got)
	}
	if got := ack.Header("Security-Verify"); got != wantSecurityVerify {
		t.Fatalf("Security-Verify = %q, want %q", got, wantSecurityVerify)
	}
	if got := ack.Header("Require"); got != "" {
		t.Fatalf("Require = %q, want empty for ACK", got)
	}
	if got := ack.Header("Proxy-Require"); got != "" {
		t.Fatalf("Proxy-Require = %q, want empty for ACK", got)
	}
}

func TestUSSDTargetURIUsesConfiguredPhoneContext(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	svc, err := New(Config{Logger: testLogger(), PhoneContextDomain: "wifi.example"}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if got := svc.targetURI("*100#"); got != "sip:*100%23;phone-context=wifi.example@ims.mnc001.mcc001.3gppnetwork.org;user=dialstring" {
		t.Fatalf("targetURI() = %q", got)
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
	us.inviteOK = svc.buildIncomingInviteOK(orig, us.localURI, us.localTag, []byte(svc.sdp()))
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
	us.inviteOK = svc.buildIncomingInviteOK(orig, us.localURI, us.localTag, []byte(svc.sdp()))
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
			payload, _, _, err := decodeInvitePayload(req)
			if err != nil {
				t.Fatalf("decodeInvitePayload() error = %v", err)
			}
			if payload.Text != "*100#" || payload.Language != defaultLang {
				t.Fatalf("payload = %+v", payload)
			}
			if payload.Request {
				t.Fatalf("payload.Request = true, want false")
			}
			transport.queue(newUSSDResponse(req, 200, "OK",
				[]byte(testSDP),
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

	if _, err := svc.Start(t.Context(), "*100#"); err != nil {
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
				[]byte(testSDP),
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

	us, err := svc.Start(t.Context(), "*100#")
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if err := us.Reply(t.Context(), "1"); err != nil {
		t.Fatalf("Reply() error = %v", err)
	}
	if err := us.Reply(t.Context(), "2"); err == nil {
		t.Fatal("Reply(with pending INFO) error = nil, want non-nil")
	}

	info := newDialogRequest("INFO", us.targetURI, us.remoteTo, "<sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>;tag="+us.localTag, us.callID, "2 INFO")
	info.Headers.Add("Info-Package", infoPackage)
	info.Headers.Add("Content-Disposition", "info-package")
	info.Headers.Add("Content-Type", xmlContentType)
	info.Body = []byte(xml.Header + `<ussd-data><language>en</language><ussd-string>Next</ussd-string><anyExt><UnstructuredSS-Request/></anyExt></ussd-data>`)
	handled, err := svc.HandleRequest(t.Context(), session.Request{Message: info, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(INFO) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(INFO) handled = false, want true")
	}
	if err := us.Reply(t.Context(), "3"); err != nil {
		t.Fatalf("Reply(after remote INFO) error = %v", err)
	}
}

func TestUSSDSessionInfoExchangeStateTransitions(t *testing.T) {
	tests := []struct {
		name         string
		start        sessionState
		wantBeginErr bool
		wantBegin    sessionState
		wantRelease  sessionState
	}{
		{name: "active starts info", start: sessionStateActive, wantBegin: sessionStateInfoInFlight, wantRelease: sessionStateActive},
		{name: "waiting ack keeps ack gate", start: sessionStateWaitingACK, wantBegin: sessionStateWaitingACKInfoInFlight, wantRelease: sessionStateWaitingACK},
		{name: "info in flight rejects second info", start: sessionStateInfoInFlight, wantBeginErr: true, wantBegin: sessionStateInfoInFlight, wantRelease: sessionStateActive},
		{name: "closed rejects info", start: sessionStateClosed, wantBeginErr: true, wantBegin: sessionStateClosed, wantRelease: sessionStateClosed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			us := &Session{state: tt.start}
			err := us.beginInfoExchange(sessionActionReplyUSSD)
			if gotErr := err != nil; gotErr != tt.wantBeginErr {
				t.Fatalf("beginInfoExchange() error = %v, wantErr %t", err, tt.wantBeginErr)
			}
			if us.state != tt.wantBegin {
				t.Fatalf("state after begin = %v, want %v", us.state, tt.wantBegin)
			}
			us.releaseInfoExchange()
			if us.state != tt.wantRelease {
				t.Fatalf("state after release = %v, want %v", us.state, tt.wantRelease)
			}
		})
	}
}

func TestUSSDSessionACKStateTransitions(t *testing.T) {
	tests := []struct {
		name  string
		start sessionState
		want  sessionState
	}{
		{name: "waiting ack becomes active", start: sessionStateWaitingACK, want: sessionStateActive},
		{name: "waiting ack with info keeps info gate", start: sessionStateWaitingACKInfoInFlight, want: sessionStateInfoInFlight},
		{name: "active stays active", start: sessionStateActive, want: sessionStateActive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			us := &Session{
				state:  tt.start,
				ackCh:  make(chan struct{}),
				events: make(chan Message, 1),
			}
			us.markACK()
			if us.state != tt.want {
				t.Fatalf("state after ACK = %v, want %v", us.state, tt.want)
			}
		})
	}
}

func TestNetworkInitiatedUSSDInviteAndACKGate(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	callbackCh := make(chan Message, 1)
	svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true, OnIncoming: func(session *Session, msg Message) { callbackCh <- msg }}, sess, reg)
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
	handled, err := svc.HandleRequest(t.Context(), session.Request{Message: invite, Transport: transport})
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

	replyCtx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := us.Reply(replyCtx, "1"); err == nil {
		t.Fatal("Reply(before ACK) error = nil, want non-nil")
	}

	ack := newDialogRequest("ACK", us.targetURI, invite.Header("From"), sip.WithTag(invite.Header("To"), "", us.localTag), invite.Header("Call-ID"), "1 ACK")
	handled, err = svc.HandleRequest(t.Context(), session.Request{Message: ack, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(ACK) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(ACK) handled = false, want true")
	}
	if err := us.Reply(t.Context(), "1"); err != nil {
		t.Fatalf("Reply(after ACK) error = %v", err)
	}
}

func TestNetworkInitiatedUSSDInviteOKRetransmitsUntilACK(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredServiceWithSessionConfig(t, transport, session.Config{
		TransactionTimers: session.TransactionTimers{
			T1: 10 * time.Millisecond,
			T2: 20 * time.Millisecond,
		},
	})
	svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	transport.onWrite = nil

	invite := buildNetworkUSSDInvite(t)
	handled, err := svc.HandleRequest(t.Context(), session.Request{Message: invite, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest(INVITE) error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest(INVITE) handled = false, want true")
	}

	deadline := time.After(time.Second)
	for countUSSDResponses(transport, sipStatusOK, "INVITE") < 2 {
		select {
		case <-deadline:
			t.Fatalf("200 OK INVITE count = %d, want retransmission", countUSSDResponses(transport, sipStatusOK, "INVITE"))
		case <-time.After(time.Millisecond):
		}
	}

	us := svc.lookupSessionByCallID(invite.Header("Call-ID"))
	if us == nil {
		t.Fatal("lookupSessionByCallID() = nil")
	}
	ack := newDialogRequest("ACK", us.targetURI, invite.Header("From"), sip.WithTag(invite.Header("To"), "", us.localTag), invite.Header("Call-ID"), "1 ACK")
	if _, err := svc.HandleRequest(t.Context(), session.Request{Message: ack, Transport: transport}); err != nil {
		t.Fatalf("HandleRequest(ACK) error = %v", err)
	}
	afterACK := countUSSDResponses(transport, sipStatusOK, "INVITE")
	time.Sleep(50 * time.Millisecond)
	if got := countUSSDResponses(transport, sipStatusOK, "INVITE"); got != afterACK {
		t.Fatalf("200 OK INVITE count after ACK = %d, want stopped at %d", got, afterACK)
	}
}

func TestNetworkInitiatedUSSDWaitsForCallbackBefore200OK(t *testing.T) {
	transport := newTransport()
	sess, reg := registeredService(t, transport)
	callbackStarted := make(chan struct{})
	callbackRelease := make(chan struct{})
	writeCh := make(chan sip.Message, 1)
	svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true,
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
		handled, handleErr = svc.HandleRequest(t.Context(), session.Request{Message: buildNetworkUSSDInvite(t), Transport: transport})
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
	svc, err := New(Config{Logger: testLogger(), NetworkInitiatedSupported: true,
		OnIncoming: func(session *Session, msg Message) {
			replyCtx, cancel := context.WithCancel(t.Context())
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
		handled, err := svc.HandleRequest(t.Context(), session.Request{Message: invite, Transport: transport})
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
	handled, err := svc.HandleRequest(t.Context(), session.Request{Message: ack, Transport: transport})
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

	handled, err := svc.HandleRequest(t.Context(), session.Request{Message: info, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	resp := mustParseUSSDMessage(t, transport.lastWrite())
	if got := resp.StatusCode(); got != 481 {
		t.Fatalf("StatusCode() = %d, want 481", got)
	}
}

func newTransport() *stubTransport {
	return &stubTransport{
		local:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
		remote: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		readCh: make(chan []byte, 16),
	}
}

func countUSSDResponses(transport *stubTransport, status int, cseqMethod string) int {
	count := 0
	for _, data := range transport.writesSnapshot() {
		msg, err := sip.ParseMessage(data)
		if err != nil {
			continue
		}
		if msg.StatusCode() == status && strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), cseqMethod) {
			count++
		}
	}
	return count
}

func registeredService(t *testing.T, transport *stubTransport) (*session.Stack, *registration.Registrar) {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if transport.writeCount() == 1 {
				transport.queue(newUSSDResponse(req, 401, "Unauthorized", nil,
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222`},
				))
				return
			}
			transport.queue(newUSSDResponse(req, 200, "OK", nil, sip.Header{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"}))
		}
	}
	if err := reg.Register(t.Context()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func registeredServiceWithSessionConfig(t *testing.T, transport *stubTransport, cfg session.Config) (*session.Stack, *registration.Registrar) {
	t.Helper()
	sess, err := session.Open(cfg, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if transport.writeCount() == 1 {
				transport.queue(newUSSDResponse(req, 401, "Unauthorized", nil,
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222`},
				))
				return
			}
			transport.queue(newUSSDResponse(req, 200, "OK", nil, sip.Header{Name: "Service-Route", Value: "<sip:pcscf.example.com;lr>"}))
		}
	}
	if err := reg.Register(t.Context()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func registeredServiceWithAssociatedURIs(t *testing.T, transport *stubTransport, associatedURIs ...string) (*session.Stack, *registration.Registrar) {
	t.Helper()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	transport.onWrite = func(data []byte) {
		req := mustParseUSSDMessage(t, data)
		switch req.Method() {
		case "REGISTER":
			if transport.writeCount() == 1 {
				transport.queue(newUSSDResponse(req, 401, "Unauthorized", nil,
					sip.Header{Name: "WWW-Authenticate", Value: `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`},
					sip.Header{Name: "Security-Server", Value: `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=0000001111;spi-s=0000002222`},
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
	if err := reg.Register(t.Context()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func testRegistrationConfig(transport *stubTransport) registration.Config {
	return registration.Config{
		Logger:                    testLogger(),
		AccessNetworkInfo:         "IEEE-802.11;i-wlan-node-id=aa",
		IPSecIntegrityAlgorithms:  []string{"hmac-sha-1-96"},
		IPSecEncryptionAlgorithms: []string{"null", "aes-cbc"},
		IPSecModes:                []string{"trans", "UDP-enc-tun"},
		DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			return transport, nil
		},
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return transport, nil
		},
	}
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
			{Header: textproto.MIMEHeader{"Content-Type": {"application/sdp"}}, Body: []byte("v=0\r\no=- 1 1 IN IP4 192.0.2.1\r\ns=-\r\nc=IN IP4 192.0.2.1\r\nt=0 0\r\nm=audio 0 RTP/AVP 97\r\n")},
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
		{Name: "Contact", Value: "<sip:network@example.com>"},
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
	for _, header := range extra {
		if strings.EqualFold(header.Name, "To") {
			resp.Headers = sip.UpsertHeader(resp.Headers, header.Name, header.Value)
			continue
		}
		resp.Headers.Add(header.Name, header.Value)
	}
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
