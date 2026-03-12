package swu

import "testing"

func TestNextSIPMessage(t *testing.T) {
	tests := []struct {
		name    string
		stream  string
		wantOK  bool
		wantErr bool
		wantLen int
	}{
		{
			name:    "header only",
			stream:  "OPTIONS sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n",
			wantOK:  true,
			wantLen: len("OPTIONS sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"),
		},
		{
			name:    "body",
			stream:  "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello",
			wantOK:  true,
			wantLen: len("MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello"),
		},
		{
			name:    "negative content length",
			stream:  "MESSAGE sip:test SIP/2.0\r\nContent-Length: -1\r\n\r\n",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, _, ok, err := nextSIPMessage([]byte(tt.stream))
			if tt.wantErr {
				if err == nil {
					t.Fatal("error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("nextSIPMessage() error = %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %t, want %t", ok, tt.wantOK)
			}
			if len(msg) != tt.wantLen {
				t.Fatalf("len(msg) = %d, want %d", len(msg), tt.wantLen)
			}
		})
	}
}
