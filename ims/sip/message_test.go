package sip

import (
	"bytes"
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
			if got, want := string(parsed.Bytes()), string(tt.msg.Bytes()); got != want {
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
			if got := buf.String(); got != string(tt.msg.Bytes()) {
				t.Fatalf("WriteTo() output = %q, want %q", got, string(tt.msg.Bytes()))
			}

			var parsed Message
			read, err := parsed.ReadFrom(strings.NewReader(buf.String()))
			if err != nil {
				t.Fatalf("ReadFrom() error = %v", err)
			}
			if read != int64(len(buf.String())) {
				t.Fatalf("ReadFrom() bytes = %d, want %d", read, len(buf.String()))
			}
			if got := string(parsed.Bytes()); got != buf.String() {
				t.Fatalf("ReadFrom() parsed = %q, want %q", got, buf.String())
			}
		})
	}
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
		{Name: "From", Value: "<sip:alice@example.com>;tag=local"},
		{Name: "To", Value: "<sip:bob@example.com>"},
		{Name: "Call-ID", Value: "call-1"},
		{Name: "CSeq", Value: "2 MESSAGE"},
	}

	respHeaders := ResponseHeaders(req, 200)
	if got := respHeaders.Get("To"); !strings.Contains(got, ";tag=") {
		t.Fatalf("ResponseHeaders().To = %q, want tag", got)
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
