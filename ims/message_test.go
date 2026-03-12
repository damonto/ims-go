package ims

import (
	"bytes"
	"testing"
)

func TestParseMessage(t *testing.T) {
	tests := []struct {
		name      string
		data      string
		wantStart string
		wantCode  int
	}{
		{"request", "MESSAGE sip:+123@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n\r\n", "MESSAGE sip:+123@example.com SIP/2.0", 0},
		{"response", "SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n\r\n", "SIP/2.0 200 OK", 200},
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
			if code := msg.StatusCode(); code != tt.wantCode {
				t.Fatalf("StatusCode() = %d, want %d", code, tt.wantCode)
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
		t.Fatalf("ParseMessage() WWW-Authenticate = %q, want %q", got, want)
	}
}

func TestParseMessageErrors(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "missing separator", data: "MESSAGE sip:+123@example.com SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n"},
		{name: "folded first header", data: "SIP/2.0 200 OK\r\n continued\r\nContent-Length: 0\r\n\r\n"},
		{name: "invalid header", data: "SIP/2.0 200 OK\r\nVia SIP/2.0/UDP 127.0.0.1:5060\r\nContent-Length: 0\r\n\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ParseMessage([]byte(tt.data)); err == nil {
				t.Fatal("ParseMessage() error = nil, want non-nil")
			}
		})
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
				Headers:   []Header{{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"}},
				Body:      []byte("hello"),
			},
		},
		{
			name: "response",
			msg: Message{
				StartLine: "SIP/2.0 200 OK",
				Headers:   []Header{{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"}, {Name: "Content-Length", Value: "0"}},
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

func TestMessageWriteTo(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{
			name: "adds content length",
			msg: Message{
				StartLine: "MESSAGE sip:+123@example.com SIP/2.0",
				Headers:   []Header{{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"}},
				Body:      []byte("hello"),
			},
		},
		{
			name: "preserves existing content length",
			msg: Message{
				StartLine: "SIP/2.0 200 OK",
				Headers:   []Header{{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5060"}, {Name: "Content-Length", Value: "5"}},
				Body:      []byte("hello"),
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
		})
	}
}
