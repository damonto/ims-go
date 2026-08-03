package sip

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
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

func TestReadMessageIgnoresLeadingCRLF(t *testing.T) {
	var msg Message

	n, err := msg.ReadMessage(strings.NewReader("\r\nSIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\nnext"))
	if err != nil {
		t.Fatalf("ReadMessage() error = %v", err)
	}
	if msg.StartLine != "SIP/2.0 200 OK" {
		t.Fatalf("StartLine = %q, want response", msg.StartLine)
	}
	if n != int64(len("\r\nSIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")) {
		t.Fatalf("ReadMessage() n = %d, want counted SIP message only", n)
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
		{
			name:    "unescaped inner quote",
			value:   `399 ims.example "bad "quote""`,
			wantErr: true,
		},
		{
			name:    "dangling escape",
			value:   "399 ims.example \"bad\\\"",
			wantErr: true,
		},
		{
			name:    "newline in text",
			value:   "399 ims.example \"bad\ntext\"",
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

func TestWarningValueMarshalTextRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name    string
		warning WarningValue
	}{
		{name: "agent with whitespace", warning: WarningValue{Code: 399, Agent: "bad agent", Text: "text"}},
		{name: "agent with quote", warning: WarningValue{Code: 399, Agent: `bad"agent`, Text: "text"}},
		{name: "newline in text", warning: WarningValue{Code: 399, Agent: "ims.example", Text: "bad\ntext"}},
		{name: "control in text", warning: WarningValue{Code: 399, Agent: "ims.example", Text: "bad\x00text"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.warning.MarshalText(); err == nil {
				t.Fatal("MarshalText() error = nil, want non-nil")
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

func TestParseMessagePartialPreservesHeadersOnBodyError(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"truncated body", "MESSAGE sip:bob@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 5\r\n\r\nhi"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, err := ParseMessagePartial([]byte(tt.data))
			if err == nil {
				t.Fatal("ParseMessagePartial() error = nil, want body framing error")
			}
			if msg.Method() != "MESSAGE" || msg.Header("Via") == "" {
				t.Fatalf("ParseMessagePartial() = %#v, want preserved start-line and headers", msg)
			}
			if len(msg.Body) != 0 {
				t.Fatalf("ParseMessagePartial() body length = %d, want 0", len(msg.Body))
			}
		})
	}
}

func TestMessageMarshalBinaryRecognizesCompactContentLength(t *testing.T) {
	msg := Message{
		StartLine: "MESSAGE sip:+123@example.com SIP/2.0",
		Headers: Headers{
			{Name: "l", Value: "5"},
		},
		Body: []byte("hello"),
	}

	got := mustMarshalBinary(t, msg)
	if strings.Count(got, "Content-Length:") != 0 {
		t.Fatalf("MarshalBinary() emitted long Content-Length despite compact l: %q", got)
	}
	if strings.Count(got, "\r\nl: 5\r\n") != 1 {
		t.Fatalf("MarshalBinary() = %q, want one compact l header", got)
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
		{
			name:  "escaped quote and comma",
			value: `"Doe\", Jane" <sip:jane@example.com>, <sip:bob@example.com>`,
			want:  []string{`"Doe\", Jane" <sip:jane@example.com>`, "<sip:bob@example.com>"},
		},
		{
			name:  "comma inside comment",
			value: `<sip:jane@example.com> (Doe, Jane), <sip:bob@example.com>`,
			want:  []string{"<sip:jane@example.com> (Doe, Jane)", "<sip:bob@example.com>"},
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
			name:       "preserves uri params inside brackets",
			value:      `<sip:alice@example.com;transport=tcp>;expires=120`,
			wantURI:    "sip:alice@example.com;transport=tcp",
			wantParams: ";expires=120",
		},
		{
			name:       "addr spec with params",
			value:      `sip:alice@example.com;expires=120`,
			wantURI:    "sip:alice@example.com",
			wantParams: ";expires=120",
		},
		{
			name:       "angle bracket in quoted display name",
			value:      `"Alice <Ops>" <sip:alice@example.com;transport=tcp>;tag=remote`,
			wantURI:    "sip:alice@example.com;transport=tcp",
			wantParams: ";tag=remote",
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
		key    string
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
		{
			name:   "quoted semicolon",
			params: `;purpose="one;two";expires=120`,
			key:    "purpose",
			want:   "one;two",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := tt.key
			if key == "" {
				key = "expires"
			}
			if got := HeaderParam(tt.params, key); got != tt.want {
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
		{
			name: "invalid request version",
			data: "MESSAGE sip:bob@example.com SIP/3.0\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name: "invalid response code",
			data: "SIP/2.0 20 OK\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name: "invalid header name",
			data: "SIP/2.0 200 OK\r\nBad@Name: value\r\nContent-Length: 0\r\n\r\n",
		},
		{
			name: "mixed header line endings",
			data: "SIP/2.0 200 OK\r\nVia: first\nVia: second\r\nContent-Length: 0\r\n\r\n",
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

func TestMessageValidate(t *testing.T) {
	valid := NewRequest("MESSAGE", "sip:bob@example.com")
	valid.Headers = Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK1"},
		{Name: "From", Value: "<sip:alice@example.com>;tag=local"},
		{Name: "To", Value: "<sip:bob@example.com>"},
		{Name: "Call-ID", Value: "call-1"},
		{Name: "CSeq", Value: "1 MESSAGE"},
		{Name: "Max-Forwards", Value: "70"},
	}

	tests := []struct {
		name   string
		mutate func(*Message)
		wantOK bool
	}{
		{name: "valid", mutate: func(*Message) {}, wantOK: true},
		{name: "missing via", mutate: func(msg *Message) { msg.Headers.Del("Via") }},
		{name: "missing from tag is accepted for rfc2543 compatibility", mutate: func(msg *Message) { msg.Headers.Set("From", "<sip:alice@example.com>") }, wantOK: true},
		{name: "bad max forwards", mutate: func(msg *Message) { msg.Headers.Set("Max-Forwards", "many") }},
		{name: "mismatched cseq method", mutate: func(msg *Message) { msg.Headers.Set("CSeq", "1 INVITE") }},
		{name: "duplicate call id", mutate: func(msg *Message) { msg.Headers.Add("Call-ID", "call-2") }},
		{name: "invalid cseq method", mutate: func(msg *Message) { msg.Headers.Set("CSeq", "1 BAD/METHOD") }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := valid
			msg.Headers = valid.Headers.Clone()
			tt.mutate(&msg)
			err := msg.Validate()
			if tt.wantOK && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
			if !tt.wantOK && err == nil {
				t.Fatal("Validate() error = nil, want non-nil")
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

func TestHeadersWriteToRejectsInjection(t *testing.T) {
	tests := []struct {
		name   string
		header Header
	}{
		{name: "invalid name", header: Header{Name: "Bad Name", Value: "value"}},
		{name: "carriage return in value", header: Header{Name: "Subject", Value: "safe\rInjected: yes"}},
		{name: "line feed in value", header: Header{Name: "Subject", Value: "safe\nInjected: yes"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			if _, err := (Headers{tt.header}).WriteTo(&buf); err == nil {
				t.Fatal("WriteTo() error = nil, want non-nil")
			}
			if buf.Len() != 0 {
				t.Fatalf("WriteTo() wrote %d bytes before validation", buf.Len())
			}
		})
	}
}

func TestMessageWriteToRejectsInvalidStartLine(t *testing.T) {
	tests := []struct {
		name      string
		startLine string
	}{
		{name: "bad version", startLine: "MESSAGE sip:bob@example.com SIP/3.0"},
		{name: "injected line", startLine: "MESSAGE sip:bob@example.com SIP/2.0\r\nInjected: yes"},
		{name: "bad response code", startLine: "SIP/2.0 20 OK"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			msg := Message{StartLine: tt.startLine}
			if _, err := msg.WriteTo(&buf); err == nil {
				t.Fatal("WriteTo() error = nil, want non-nil")
			}
			if buf.Len() != 0 {
				t.Fatalf("WriteTo() wrote %d bytes before validation", buf.Len())
			}
		})
	}
}

func TestMessageMarshalBinaryRoundTrip(t *testing.T) {
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
		{
			name: "binary body",
			msg: Message{
				StartLine: "SIP/2.0 200 OK",
				Headers:   Headers{{Name: "Content-Type", Value: "application/octet-stream"}},
				Body:      []byte{0xff, 0x00, 0xfe},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.msg.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var parsed Message
			if err := parsed.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got, want := mustMarshalBinary(t, parsed), mustMarshalBinary(t, tt.msg); got != want {
				t.Fatalf("round trip = %q, want %q", got, want)
			}
		})
	}
}

func TestMessageAppendBinaryPreservesPrefix(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{
			name: "binary body",
			msg: Message{
				StartLine: "SIP/2.0 200 OK",
				Body:      []byte{0xff, 0x00, 0xfe},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prefix := make([]byte, 2, 256)
			copy(prefix, []byte{0xaa, 0xbb})
			got, err := tt.msg.AppendBinary(prefix)
			if err != nil {
				t.Fatalf("AppendBinary() error = %v", err)
			}
			want, err := tt.msg.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got[:2], []byte{0xaa, 0xbb}) || !bytes.Equal(got[2:], want) {
				t.Fatalf("AppendBinary() = %x, want prefix plus %x", got, want)
			}
			if !bytes.Equal(prefix, []byte{0xaa, 0xbb}) {
				t.Fatalf("prefix = %x, want unchanged", prefix)
			}
		})
	}
}

func TestMessageWriteToReadMessage(t *testing.T) {
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
			if got, want := buf.String(), mustMarshalBinary(t, tt.msg); got != want {
				t.Fatalf("WriteTo() output = %q, want %q", got, want)
			}

			var parsed Message
			read, err := parsed.ReadMessage(strings.NewReader(buf.String()))
			if err != nil {
				t.Fatalf("ReadMessage() error = %v", err)
			}
			if read != int64(len(buf.String())) {
				t.Fatalf("ReadMessage() bytes = %d, want %d", read, len(buf.String()))
			}
			if got := mustMarshalBinary(t, parsed); got != buf.String() {
				t.Fatalf("ReadMessage() parsed = %q, want %q", got, buf.String())
			}
		})
	}
}

func mustMarshalBinary(t *testing.T, msg Message) string {
	t.Helper()
	data, err := msg.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	return string(data)
}

func TestMessageReadMessageRejectsMissingContentLength(t *testing.T) {
	raw := "MESSAGE sip:+123@example.com SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\nhello"

	var msg Message
	read, err := msg.ReadMessage(strings.NewReader(raw))
	if err == nil {
		t.Fatal("ReadMessage() error = nil, want missing Content-Length error")
	}
	if read >= int64(len(raw)) {
		t.Fatalf("ReadMessage() bytes = %d, want fewer than %d", read, len(raw))
	}
}

func TestMessageReadMessageRejectsLFLineEndings(t *testing.T) {
	raw := "MESSAGE sip:+123@example.com SIP/2.0\nVia: SIP/2.0/TCP 127.0.0.1:5060\nContent-Length: 5\n\nhello"

	var msg Message
	read, err := msg.ReadMessage(strings.NewReader(raw))
	if err == nil {
		t.Fatal("ReadMessage() error = nil, want invalid line ending error")
	}
	if read == 0 {
		t.Fatal("ReadMessage() bytes = 0, want consumed bytes")
	}
}

func TestMessageReadMessagePreservesNextMessage(t *testing.T) {
	first := "SIP/2.0 100 Trying\r\nContent-Length: 0\r\n\r\n"
	second := "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"
	tests := []struct {
		name string
		new  func(string) io.Reader
	}{
		{name: "plain reader", new: func(value string) io.Reader { return strings.NewReader(value) }},
		{name: "buffered reader", new: func(value string) io.Reader { return bufio.NewReader(strings.NewReader(value)) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := tt.new(first + second)
			var firstMsg, secondMsg Message
			if _, err := firstMsg.ReadMessage(r); err != nil {
				t.Fatalf("first ReadMessage() error = %v", err)
			}
			if _, err := secondMsg.ReadMessage(r); err != nil {
				t.Fatalf("second ReadMessage() error = %v", err)
			}
			if firstMsg.StatusCode() != 100 || secondMsg.StatusCode() != 200 {
				t.Fatalf("status codes = %d, %d; want 100, 200", firstMsg.StatusCode(), secondMsg.StatusCode())
			}
		})
	}
}

func TestMessageMarshalBinaryCorrectsContentLength(t *testing.T) {
	tests := []struct {
		name    string
		headers Headers
		want    string
	}{
		{name: "stale long form", headers: Headers{{Name: "Content-Length", Value: "0"}}, want: "Content-Length: 5"},
		{name: "stale compact form", headers: Headers{{Name: "l", Value: "99"}}, want: "l: 5"},
		{name: "duplicate forms", headers: Headers{{Name: "Content-Length", Value: "0"}, {Name: "l", Value: "99"}}, want: "Content-Length: 5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewRequest("MESSAGE", "sip:bob@example.com")
			msg.Headers = tt.headers
			msg.Body = []byte("hello")
			got := mustMarshalBinary(t, msg)
			if !strings.Contains(got, "\r\n"+tt.want+"\r\n") {
				t.Fatalf("MarshalBinary() = %q, want %q", got, tt.want)
			}
			count := strings.Count(strings.ToLower(got), "\r\ncontent-length:") + strings.Count(strings.ToLower(got), "\r\nl:")
			if count != 1 {
				t.Fatalf("MarshalBinary() Content-Length count = %d, want 1", count)
			}
		})
	}
}

func TestSetResponseViaPeer(t *testing.T) {
	tests := []struct {
		name string
		peer net.Addr
		via  string
		want string
	}{
		{
			name: "udp nat fills received and rport",
			peer: &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 45000},
			via:  "SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bK1;rport",
			want: "SIP/2.0/UDP 192.168.1.5:5060;branch=z9hG4bK1;rport=45000;received=203.0.113.10",
		},
		{
			name: "udp public address only fills rport",
			peer: &net.UDPAddr{IP: net.ParseIP("203.0.113.10"), Port: 45000},
			via:  "SIP/2.0/UDP 203.0.113.10:5060;branch=z9hG4bK1;rport",
			want: "SIP/2.0/UDP 203.0.113.10:5060;branch=z9hG4bK1;rport=45000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := NewResponse(200, "OK")
			resp.Headers.Add("Via", tt.via)
			SetResponseViaPeer(&resp, tt.peer)
			if got := resp.Header("Via"); got != tt.want {
				t.Fatalf("Via = %q, want %q", got, tt.want)
			}
		})
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
	if got := WithTag("<sip:bob@example.com;tag=uri>", "", "header"); got != "<sip:bob@example.com;tag=uri>;tag=header" {
		t.Fatalf("WithTag() URI tag = %q", got)
	}
	if got := HeaderTag("<sip:bob@example.com;tag=uri>;tag=header"); got != "header" {
		t.Fatalf("HeaderTag() = %q, want header", got)
	}
	if got := CSeqNumber(msg.Header("CSeq")); got != 42 {
		t.Fatalf("CSeqNumber() = %d", got)
	}
	if !TokenListContains("path, sec-agree", "sec-agree") {
		t.Fatal("TokenListContains() = false, want true")
	}
	msg.Headers.Add("Supported", "path")
	msg.Headers.Add("Supported", "100rel,timer")
	if !msg.HeaderHasToken("Supported", "timer") {
		t.Fatal("HeaderHasToken() = false, want token from second field")
	}
	msg.Headers.Add("Record-Route", `<sip:p1.example.com;lr>, "Proxy, Two" <sip:p2.example.com;lr>`)
	msg.Headers.Add("Record-Route", `<sip:p3.example.com;lr>`)
	wantRoutes := []string{
		"<sip:p1.example.com;lr>",
		`"Proxy, Two" <sip:p2.example.com;lr>`,
		"<sip:p3.example.com;lr>",
	}
	if got := msg.HeaderList("Record-Route"); !slices.Equal(got, wantRoutes) {
		t.Fatalf("HeaderList() = %#v, want %#v", got, wantRoutes)
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

func TestTopViaHasKeepDistinguishesBareParameter(t *testing.T) {
	tests := []struct {
		name string
		via  string
		want string
		has  bool
	}{
		{
			name: "bare keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep",
			has:  true,
		},
		{
			name: "valued keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep=30",
			want: "30",
			has:  true,
		},
		{
			name: "quoted keep",
			via:  `SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep="45"`,
			want: "45",
			has:  true,
		},
		{
			name: "quoted extension before keep",
			via:  `SIP/2.0/TCP 127.0.0.1:5060;extension="one;two";keep=45`,
			want: "45",
			has:  true,
		},
		{
			name: "missing keep",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1",
			has:  false,
		},
		{
			name: "top via only",
			via:  "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bK-1;keep=30, SIP/2.0/TCP proxy.example.com:5060;keep=60",
			want: "30",
			has:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TopViaKeep(tt.via); got != tt.want {
				t.Fatalf("TopViaKeep() = %q, want %q", got, tt.want)
			}
			if got := TopViaHasKeep(tt.via); got != tt.has {
				t.Fatalf("TopViaHasKeep() = %t, want %t", got, tt.has)
			}
		})
	}
}
