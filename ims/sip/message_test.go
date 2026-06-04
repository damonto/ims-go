package sip

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantStart string
		wantCode  int
	}{
		{
			name:      "request",
			data:      "MESSAGE sip:+123@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n\r\n",
			wantStart: "MESSAGE sip:+123@example.com SIP/2.0",
			wantCode:  0,
		},
		{
			name:      "response",
			data:      "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n\r\n",
			wantStart: "SIP/2.0 200 OK",
			wantCode:  200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseMessage([]byte(tt.data))
			if err != nil {
				t.Fatalf("ParseMessage() error = %v", err)
			}
			if msg.StartLine != tt.wantStart {
				t.Fatalf("StartLine = %q, want %q", msg.StartLine, tt.wantStart)
			}
			if got := msg.StatusCode(); got != tt.wantCode {
				t.Fatalf("StatusCode() = %d, want %d", got, tt.wantCode)
			}
		})
	}
}

func TestParseMessageIgnoresLeadingCRLF(t *testing.T) {
	data := []byte("\r\n\r\nMESSAGE sip:+123@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nhello")

	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	if msg.StartLine != "MESSAGE sip:+123@example.com SIP/2.0" {
		t.Fatalf("StartLine = %q, want MESSAGE", msg.StartLine)
	}
	if string(msg.Body) != "hello" {
		t.Fatalf("Body = %q, want hello", string(msg.Body))
	}
}

func TestReadFromIgnoresLeadingCRLF(t *testing.T) {
	var msg Message

	n, err := msg.ReadFrom(strings.NewReader("\r\nSIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\nnext"))
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if msg.StartLine != "SIP/2.0 200 OK" {
		t.Fatalf("StartLine = %q, want response", msg.StartLine)
	}
	if n != int64(len("\r\nSIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")) {
		t.Fatalf("ReadFrom() n = %d, want counted SIP message only", n)
	}
}

func TestResponseError(t *testing.T) {
	tests := []struct {
		name       string
		message    Message
		wantReason string
		wantText   string
		wantError  string
	}{
		{
			name: "warning text",
			message: Message{
				StartLine: "SIP/2.0 403 Forbidden",
				Headers: Headers{
					{Name: "Warning", Value: `399 anonymous.invalid "Credit limit reached"`},
				},
			},
			wantReason: "Forbidden",
			wantText:   "Credit limit reached",
			wantError:  "403 Forbidden: Credit limit reached",
		},
		{
			name: "multiple warning headers",
			message: Message{
				StartLine: "SIP/2.0 488 Not Acceptable Here",
				Headers: Headers{
					{Name: "Warning", Value: `301 ims.example "Incompatible network address type", 399 ims.example "Codec rejected"`},
				},
			},
			wantReason: "Not Acceptable Here",
			wantText:   "Incompatible network address type; Codec rejected",
			wantError:  "488 Not Acceptable Here: Incompatible network address type; Codec rejected",
		},
		{
			name: "status only",
			message: Message{
				StartLine: "SIP/2.0 500",
			},
			wantError: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := NewResponseError(tt.message)
			if got := tt.message.ReasonPhrase(); got != tt.wantReason {
				t.Fatalf("ReasonPhrase() = %q, want %q", got, tt.wantReason)
			}
			if got := err.WarningText(); got != tt.wantText {
				t.Fatalf("WarningText() = %q, want %q", got, tt.wantText)
			}
			if got := err.Error(); got != tt.wantError {
				t.Fatalf("Error() = %q, want %q", got, tt.wantError)
			}
			wrapped := errors.Join(err)
			var responseErr *ResponseError
			if !errors.As(wrapped, &responseErr) {
				t.Fatal("errors.As() = false, want true")
			}
			if responseErr.StatusCode != tt.message.StatusCode() {
				t.Fatalf("ResponseError.StatusCode = %d, want %d", responseErr.StatusCode, tt.message.StatusCode())
			}
		})
	}
}

func TestWarningValueText(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    WarningValue
		wantOut string
		wantErr bool
	}{
		{
			name:    "valid",
			value:   `399 anonymous.invalid "Credit limit reached"`,
			want:    WarningValue{Code: 399, Agent: "anonymous.invalid", Text: "Credit limit reached"},
			wantOut: `399 anonymous.invalid "Credit limit reached"`,
		},
		{
			name:    "escaped text",
			value:   `301 ims.example "Codec \"AMR\" rejected"`,
			want:    WarningValue{Code: 301, Agent: "ims.example", Text: `Codec "AMR" rejected`},
			wantOut: `301 ims.example "Codec \"AMR\" rejected"`,
		},
		{
			name:    "short code",
			value:   `99 ims.example "bad"`,
			wantErr: true,
		},
		{
			name:    "unquoted text",
			value:   `399 ims.example bad`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got WarningValue
			err := got.UnmarshalText([]byte(tt.value))
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalText() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("UnmarshalText() = %#v, want %#v", got, tt.want)
			}
			out, err := got.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if string(out) != tt.wantOut {
				t.Fatalf("MarshalText() = %q, want %q", out, tt.wantOut)
			}
		})
	}
}

func TestParseMessageFoldedHeader(t *testing.T) {
	data := []byte("SIP/2.0 401 Unauthorized\r\nWWW-Authenticate: Digest realm=\"ims.example\",\r\n nonce=\"abc\",\r\n algorithm=AKAv1-MD5\r\nContent-Length: 0\r\n\r\n")

	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}

	want := `Digest realm="ims.example", nonce="abc", algorithm=AKAv1-MD5`
	if got := msg.Header("WWW-Authenticate"); got != want {
		t.Fatalf("Header() = %q, want %q", got, want)
	}
}

func TestParseMessageCompactHeaders(t *testing.T) {
	data := []byte("INVITE sip:user@example.com SIP/2.0\r\n" +
		"i: call-1@example.com\r\n" +
		"v: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1\r\n" +
		"f: <sip:alice@example.com>;tag=a\r\n" +
		"t: <sip:bob@example.com>\r\n" +
		"m: <sip:alice@192.0.2.10>\r\n" +
		"c: application/sdp\r\n" +
		"k: 100rel\r\n" +
		"l: 5\r\n" +
		"\r\nhello")

	msg, err := ParseMessage(data)
	if err != nil {
		t.Fatalf("ParseMessage() error = %v", err)
	}
	tests := []struct {
		name string
		want string
	}{
		{name: "Call-ID", want: "call-1@example.com"},
		{name: "Via", want: "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-1"},
		{name: "From", want: "<sip:alice@example.com>;tag=a"},
		{name: "To", want: "<sip:bob@example.com>"},
		{name: "Contact", want: "<sip:alice@192.0.2.10>"},
		{name: "Content-Type", want: "application/sdp"},
		{name: "Supported", want: "100rel"},
		{name: "Content-Length", want: "5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := msg.Header(tt.name); got != tt.want {
				t.Fatalf("Header(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
	if string(msg.Body) != "hello" {
		t.Fatalf("Body = %q, want hello", string(msg.Body))
	}
}

func TestParseMessageUsesContentLengthForBody(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		wantBody string
		wantErr  bool
	}{
		{
			name:     "truncates trailing bytes after counted body",
			data:     "MESSAGE sip:+123@example.com SIP/2.0\r\nContent-Length: 5\r\n\r\nhelloSIP/2.0 200 OK\r\n\r\n",
			wantBody: "hello",
		},
		{
			name:     "compact content length",
			data:     "MESSAGE sip:+123@example.com SIP/2.0\r\nl: 5\r\n\r\nhelloextra",
			wantBody: "hello",
		},
		{
			name:    "body shorter than content length",
			data:    "MESSAGE sip:+123@example.com SIP/2.0\r\nContent-Length: 6\r\n\r\nhello",
			wantErr: true,
		},
		{
			name:    "invalid content length",
			data:    "MESSAGE sip:+123@example.com SIP/2.0\r\nContent-Length: bad\r\n\r\nhello",
			wantErr: true,
		},
		{
			name:    "empty content length",
			data:    "MESSAGE sip:+123@example.com SIP/2.0\r\nContent-Length: \r\n\r\nhello",
			wantErr: true,
		},
		{
			name:    "duplicate content length",
			data:    "MESSAGE sip:+123@example.com SIP/2.0\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseMessage([]byte(tt.data))
			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseMessage() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseMessage() error = %v", err)
			}
			if got := string(msg.Body); got != tt.wantBody {
				t.Fatalf("Body = %q, want %q", got, tt.wantBody)
			}
		})
	}
}

func TestMessageMarshalTextRecognizesCompactContentLength(t *testing.T) {
	msg := Message{
		StartLine: "MESSAGE sip:+123@example.com SIP/2.0",
		Headers: Headers{
			{Name: "l", Value: "5"},
		},
		Body: []byte("hello"),
	}

	got := mustMarshalText(t, msg)
	if strings.Count(got, "Content-Length:") != 0 {
		t.Fatalf("MarshalText() emitted long Content-Length despite compact l: %q", got)
	}
	if strings.Count(got, "\r\nl: 5\r\n") != 1 {
		t.Fatalf("MarshalText() = %q, want one compact l header", got)
	}
}

func TestSplitHeaderList(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  []string
	}{
		{
			name:  "empty",
			value: "",
		},
		{
			name:  "simple",
			value: "<sip:a@example.com>, <sip:b@example.com>",
			want:  []string{"<sip:a@example.com>", "<sip:b@example.com>"},
		},
		{
			name:  "comma inside quoted display name",
			value: `"Doe, Jane" <sip:jane@example.com>, <sip:bob@example.com>`,
			want:  []string{`"Doe, Jane" <sip:jane@example.com>`, "<sip:bob@example.com>"},
		},
		{
			name:  "comma inside angle brackets",
			value: `<sip:a@example.com;note=one,two>, <sip:b@example.com>`,
			want:  []string{"<sip:a@example.com;note=one,two>", "<sip:b@example.com>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SplitHeaderList(tt.value); !slices.Equal(got, tt.want) {
				t.Fatalf("SplitHeaderList() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestAddressURIAndParams(t *testing.T) {
	tests := []struct {
		name       string
		value      string
		wantURI    string
		wantParams string
	}{
		{
			name:       "empty",
			value:      "",
			wantURI:    "",
			wantParams: "",
		},
		{
			name:       "name addr with params",
			value:      `<sip:alice@example.com>;expires=120`,
			wantURI:    "sip:alice@example.com",
			wantParams: ";expires=120",
		},
		{
			name:       "strips uri params inside brackets",
			value:      `<sip:alice@example.com;transport=tcp>;expires=120`,
			wantURI:    "sip:alice@example.com",
			wantParams: ";expires=120",
		},
		{
			name:       "addr spec with params",
			value:      `sip:alice@example.com;expires=120`,
			wantURI:    "sip:alice@example.com",
			wantParams: ";expires=120",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotURI, gotParams := AddressURIAndParams(tt.value)
			if gotURI != tt.wantURI || gotParams != tt.wantParams {
				t.Fatalf("AddressURIAndParams() = %q, %q; want %q, %q", gotURI, gotParams, tt.wantURI, tt.wantParams)
			}
		})
	}
}

func TestHeaderParam(t *testing.T) {
	tests := []struct {
		name   string
		params string
		want   string
	}{
		{
			name:   "empty",
			params: "",
		},
		{
			name:   "matching param",
			params: `;expires=120;q=0.5`,
			want:   "120",
		},
		{
			name:   "case insensitive quoted param",
			params: `;Expires="120"`,
			want:   "120",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HeaderParam(tt.params, "expires"); got != tt.want {
				t.Fatalf("HeaderParam() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseMessageErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{
			name: "missing separator",
			data: "MESSAGE sip:+123@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n",
		},
		{
			name: "folded first header",
			data: "SIP/2.0 200 OK\r\n continued\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name: "invalid header",
			data: "SIP/2.0 200 OK\r\nVia SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name: "lf line endings",
			data: "SIP/2.0 200 OK\nVia: SIP/2.0/UDP 127.0.0.1:5060\nContent-Length: 0\n\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseMessage([]byte(tt.data)); err == nil {
				t.Fatal("ParseMessage() error = nil, want non-nil")
			}
		})
	}
}

func TestHeadersRoundTrip(t *testing.T) {
	want := Headers{
		{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"},
		{Name: "Route", Value: "<sip:pcscf.example.com;lr>"},
	}

	text, err := want.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}

	var got Headers
	if err := got.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("len(got) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMessageMarshalTextRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{
			name: "request",
			msg: Message{
				StartLine: "MESSAGE sip:+123@example.com SIP/2.0",
				Headers:   Headers{{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"}},
				Body:      []byte("hello"),
			},
		},
		{
			name: "response",
			msg: Message{
				StartLine: "SIP/2.0 200 OK",
				Headers: Headers{
					{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"},
					{Name: "Content-Length", Value: "0"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			text, err := tt.msg.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			var parsed Message
			if err := parsed.UnmarshalText(text); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got, want := mustMarshalText(t, parsed), mustMarshalText(t, tt.msg); got != want {
				t.Fatalf("round trip = %q, want %q", got, want)
			}
		})
	}
}

func TestMessageWriteToReadFrom(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{
			name: "adds content length",
			msg: Message{
				StartLine: "MESSAGE sip:+123@example.com SIP/2.0",
				Headers:   Headers{{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"}},
				Body:      []byte("hello"),
			},
		},
		{
			name: "preserves existing content length",
			msg: Message{
				StartLine: "SIP/2.0 200 OK",
				Headers: Headers{
					{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"},
					{Name: "Content-Length", Value: "5"},
				},
				Body: []byte("hello"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			written, err := tt.msg.WriteTo(&buf)
			if err != nil {
				t.Fatalf("WriteTo() error = %v", err)
			}
			if written != int64(len(buf.Bytes())) {
				t.Fatalf("WriteTo() bytes = %d, want %d", written, len(buf.Bytes()))
			}
			if got, want := buf.String(), mustMarshalText(t, tt.msg); got != want {
				t.Fatalf("WriteTo() output = %q, want %q", got, want)
			}

			var parsed Message
			read, err := parsed.ReadFrom(strings.NewReader(buf.String()))
			if err != nil {
				t.Fatalf("ReadFrom() error = %v", err)
			}
			if read != int64(len(buf.String())) {
				t.Fatalf("ReadFrom() bytes = %d, want %d", read, len(buf.String()))
			}
			if got := mustMarshalText(t, parsed); got != buf.String() {
				t.Fatalf("ReadFrom() parsed = %q, want %q", got, buf.String())
			}
		})
	}
}

func mustMarshalText(t *testing.T, msg Message) string {
	t.Helper()
	text, err := msg.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	return string(text)
}

func TestMessageReadFromWithoutContentLengthUsesRemainingBytes(t *testing.T) {
	raw := "MESSAGE sip:+123@example.com SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\nhello"

	var msg Message
	read, err := msg.ReadFrom(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if read != int64(len(raw)) {
		t.Fatalf("ReadFrom() bytes = %d, want %d", read, len(raw))
	}
	if got := string(msg.Body); got != "hello" {
		t.Fatalf("Body = %q, want %q", got, "hello")
	}
}

func TestMessageReadFromCountsLFLineEndings(t *testing.T) {
	raw := "MESSAGE sip:+123@example.com SIP/2.0\nVia: SIP/2.0/TCP 127.0.0.1:5060\nContent-Length: 5\n\nhello"

	var msg Message
	read, err := msg.ReadFrom(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ReadFrom() error = %v", err)
	}
	if read != int64(len(raw)) {
		t.Fatalf("ReadFrom() bytes = %d, want %d", read, len(raw))
	}
	if got := string(msg.Body); got != "hello" {
		t.Fatalf("Body = %q, want %q", got, "hello")
	}
}

func TestResponseHelpers(t *testing.T) {
	req := NewRequest("MESSAGE", "sip:+123@example.com")
	req.Headers = Headers{
		{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1"},
		{Name: "Via", Value: "SIP/2.0/UDP proxy.example.com:5060;branch=z9hG4bK-2"},
		{Name: "From", Value: "<sip:alice@example.com>;tag=local"},
		{Name: "To", Value: "<sip:bob@example.com>"},
		{Name: "Call-ID", Value: "call-1"},
		{Name: "CSeq", Value: "2 MESSAGE"},
	}

	respHeaders := ResponseHeaders(req, 200)
	if got := respHeaders.Get("To"); !strings.Contains(got, ";tag=") {
		t.Fatalf("ResponseHeaders().To = %q, want tag", got)
	}
	if got := respHeaders.Values("Via"); len(got) != 2 || got[0] != req.Headers[0].Value || got[1] != req.Headers[1].Value {
		t.Fatalf("ResponseHeaders().Via = %v, want both request Via headers", got)
	}
	if got := ResponseTag(req); got == "" {
		t.Fatal("ResponseTag() = empty, want non-empty")
	}
}

func TestHelpers(t *testing.T) {
	msg := NewRequest("INFO", "sip:service@example.com")
	msg.Headers = Headers{
		{Name: "To", Value: "<sip:alice@example.com>;tag=remote"},
		{Name: "CSeq", Value: "42 INFO"},
	}

	if got := RequestURI(msg); got != "sip:service@example.com" {
		t.Fatalf("RequestURI() = %q", got)
	}
	if got := AddressURI("<sip:alice@example.com>;tag=remote"); got != "sip:alice@example.com" {
		t.Fatalf("AddressURI() = %q", got)
	}
	if got := HeaderTag(msg.Header("To")); got != "remote" {
		t.Fatalf("HeaderTag() = %q", got)
	}
	if got := WithTag("<sip:bob@example.com>", "", "abc"); got != "<sip:bob@example.com>;tag=abc" {
		t.Fatalf("WithTag() = %q", got)
	}
	if got := CSeqNumber(msg.Header("CSeq")); got != 42 {
		t.Fatalf("CSeqNumber() = %d", got)
	}
	if !TokenListContains("path, sec-agree", "sec-agree") {
		t.Fatal("TokenListContains() = false, want true")
	}
}

func TestPendingKeyUsesTopViaBranchAndMethod(t *testing.T) {
	messageReq := NewRequest("MESSAGE", "sip:bob@example.com")
	messageReq.Headers = Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1"},
		{Name: "Call-ID", Value: "call-1"},
		{Name: "CSeq", Value: "7 MESSAGE"},
	}
	cancelReq := NewRequest("CANCEL", "sip:bob@example.com")
	cancelReq.Headers = Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1"},
		{Name: "Call-ID", Value: "call-1"},
		{Name: "CSeq", Value: "7 CANCEL"},
	}

	messageKey := PendingKey(messageReq)
	cancelKey := PendingKey(cancelReq)
	if messageKey != "z9hG4bK-1|MESSAGE" {
		t.Fatalf("PendingKey(MESSAGE) = %q, want z9hG4bK-1|MESSAGE", messageKey)
	}
	if cancelKey != "z9hG4bK-1|CANCEL" {
		t.Fatalf("PendingKey(CANCEL) = %q, want z9hG4bK-1|CANCEL", cancelKey)
	}
	if messageKey == cancelKey {
		t.Fatalf("PendingKey() keys are equal: %q", messageKey)
	}
}

func TestTopViaHasRPortDistinguishesBareParameter(t *testing.T) {
	tests := []struct {
		name string
		via  string
		want string
		has  bool
	}{
		{
			name: "bare rport",
			via:  "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1;rport",
			has:  true,
		},
		{
			name: "valued rport",
			via:  "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1;rport=5070",
			want: "5070",
			has:  true,
		},
		{
			name: "missing rport",
			via:  "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1",
			has:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TopViaRPort(tt.via); got != tt.want {
				t.Fatalf("TopViaRPort() = %q, want %q", got, tt.want)
			}
			if got := TopViaHasRPort(tt.via); got != tt.has {
				t.Fatalf("TopViaHasRPort() = %t, want %t", got, tt.has)
			}
		})
	}
}
