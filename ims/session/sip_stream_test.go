package session

import (
	"strings"
	"testing"
)

func TestStageSIPMessages(t *testing.T) {
	msg1 := []byte("SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nbody")
	msg2 := []byte("OPTIONS sip:ims.example SIP/2.0\r\nl: 0\r\n\r\n")
	tests := []struct {
		name      string
		stream    []byte
		wantMsgs  [][]byte
		wantRest  string
		wantErr   bool
		wantErrIn string
	}{
		{
			name:     "two complete messages with trailing partial",
			stream:   append(append(append([]byte("\r\n"), msg1...), msg2...), []byte("INVITE")...),
			wantMsgs: [][]byte{msg1, msg2},
			wantRest: "INVITE",
		},
		{
			name:     "partial body waits for more bytes",
			stream:   []byte("SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nbo"),
			wantRest: "SIP/2.0 200 OK\r\nContent-Length: 4\r\n\r\nbo",
		},
		{
			name:      "missing content length fails",
			stream:    []byte("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP host\r\n\r\n"),
			wantErr:   true,
			wantErrIn: "missing Content-Length",
		},
		{
			name:      "negative content length fails",
			stream:    []byte("SIP/2.0 200 OK\r\nContent-Length: -1\r\n\r\n"),
			wantErr:   true,
			wantErrIn: "invalid negative Content-Length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotMsgs, gotRest, err := StageSIPMessages(tt.stream)
			if tt.wantErr {
				if err == nil {
					t.Fatal("StageSIPMessages() error = nil, want non-nil")
				}
				if !strings.Contains(err.Error(), tt.wantErrIn) {
					t.Fatalf("StageSIPMessages() error = %v, want containing %q", err, tt.wantErrIn)
				}
				return
			}
			if err != nil {
				t.Fatalf("StageSIPMessages() error = %v", err)
			}
			if len(gotMsgs) != len(tt.wantMsgs) {
				t.Fatalf("messages len = %d, want %d", len(gotMsgs), len(tt.wantMsgs))
			}
			for i, want := range tt.wantMsgs {
				if string(gotMsgs[i]) != string(want) {
					t.Fatalf("message[%d] = %q, want %q", i, string(gotMsgs[i]), string(want))
				}
			}
			if string(gotRest) != tt.wantRest {
				t.Fatalf("rest = %q, want %q", string(gotRest), tt.wantRest)
			}
		})
	}
}

func TestNextSIPMessage(t *testing.T) {
	tests := []struct {
		name    string
		stream  string
		wantMsg string
		wantOK  bool
		wantErr bool
	}{
		{
			name:    "complete",
			stream:  "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello",
			wantMsg: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello",
			wantOK:  true,
		},
		{
			name:    "leading crlf ignored",
			stream:  "\r\n\r\nMESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello",
			wantMsg: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello",
			wantOK:  true,
		},
		{
			name:   "incomplete body",
			stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhel",
		},
		{
			name:    "missing length",
			stream:  "MESSAGE sip:test SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "invalid length",
			stream:  "MESSAGE sip:test SIP/2.0\r\nContent-Length: nope\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "negative length",
			stream:  "MESSAGE sip:test SIP/2.0\r\nContent-Length: -1\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "compact length",
			stream:  "MESSAGE sip:test SIP/2.0\r\nl: 5\r\n\r\nhello",
			wantMsg: "MESSAGE sip:test SIP/2.0\r\nl: 5\r\n\r\nhello",
			wantOK:  true,
		},
		{
			name:    "header too large",
			stream:  "MESSAGE sip:test SIP/2.0\r\n" + strings.Repeat("X-Test: x\r\n", maxSIPHeaderBytes/10+1),
			wantErr: true,
		},
		{
			name:    "incomplete oversized header",
			stream:  strings.Repeat("A", maxSIPHeaderBytes+1),
			wantErr: true,
		},
		{
			name:    "message too large",
			stream:  "MESSAGE sip:test SIP/2.0\r\nContent-Length: 1048577\r\n\r\n",
			wantErr: true,
		},
		{
			name:    "message length overflows total",
			stream:  "MESSAGE sip:test SIP/2.0\r\nContent-Length: 9223372036854775807\r\n\r\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, _, ok, err := NextSIPMessage([]byte(tt.stream))
			if tt.wantErr {
				if err == nil {
					t.Fatal("NextSIPMessage() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("NextSIPMessage() error = %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %t, want %t", ok, tt.wantOK)
			}
			if tt.wantOK && string(msg) != tt.wantMsg {
				t.Fatalf("msg = %q, want %q", string(msg), tt.wantMsg)
			}
		})
	}
}
