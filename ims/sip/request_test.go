package sip

import (
	"net"
	"testing"
)

func TestClientRequestPolicyApply(t *testing.T) {
	tests := []struct {
		name string
		in   ClientRequestPolicy
		want map[string]string
	}{
		{
			name: "with security and routes",
			in: ClientRequestPolicy{
				Routes:            []string{"<sip:pcscf.example.com;lr>"},
				UserAgent:         "IMSClient/1.0",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				Security: SecurityAgreement{
					Verify:   "ipsec-3gpp;alg=hmac-sha-1-96",
					Required: true,
				},
			},
			want: map[string]string{
				"Allow":                 DefaultClientAllow,
				"Max-Forwards":          "70",
				"Supported":             DefaultClientSupported,
				"User-Agent":            "IMSClient/1.0",
				"P-Access-Network-Info": "IEEE-802.11;i-wlan-node-id=aabbcc",
				"Route":                 "<sip:pcscf.example.com;lr>",
				"Security-Verify":       "ipsec-3gpp;alg=hmac-sha-1-96",
				"Require":               "sec-agree",
				"Proxy-Require":         "sec-agree",
			},
		},
		{
			name: "without optional headers",
			in:   ClientRequestPolicy{},
			want: map[string]string{
				"Allow":        DefaultClientAllow,
				"Max-Forwards": "70",
				"Supported":    DefaultClientSupported,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewRequest("MESSAGE", "sip:user@example.com")
			tt.in.Apply(&msg)
			for name, want := range tt.want {
				if got := msg.Header(name); got != want {
					t.Fatalf("Header(%q) = %q, want %q", name, got, want)
				}
			}
		})
	}
}

func TestDialogIDMatches(t *testing.T) {
	tests := []struct {
		name string
		id   DialogID
		msg  Message
		want bool
	}{
		{
			name: "full match",
			id:   DialogID{CallID: "call-1", LocalTag: "local", RemoteTag: "remote"},
			msg: Message{
				Headers: Headers{
					{Name: "Call-ID", Value: "call-1"},
					{Name: "To", Value: "<sip:b@example.com>;tag=local"},
					{Name: "From", Value: "<sip:a@example.com>;tag=remote"},
				},
			},
			want: true,
		},
		{
			name: "missing remote tag still matches",
			id:   DialogID{CallID: "call-1", LocalTag: "local", RemoteTag: "remote"},
			msg: Message{
				Headers: Headers{
					{Name: "Call-ID", Value: "call-1"},
					{Name: "To", Value: "<sip:b@example.com>;tag=local"},
					{Name: "From", Value: "<sip:a@example.com>"},
				},
			},
			want: true,
		},
		{
			name: "wrong local tag",
			id:   DialogID{CallID: "call-1", LocalTag: "local", RemoteTag: "remote"},
			msg: Message{
				Headers: Headers{
					{Name: "Call-ID", Value: "call-1"},
					{Name: "To", Value: "<sip:b@example.com>;tag=other"},
					{Name: "From", Value: "<sip:a@example.com>;tag=remote"},
				},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.Matches(tt.msg); got != tt.want {
				t.Fatalf("Matches() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestTransportTokenAndVia(t *testing.T) {
	tests := []struct {
		name string
		addr net.Addr
		want string
	}{
		{name: "tcp", addr: &net.TCPAddr{}, want: "TCP"},
		{name: "udp", addr: &net.UDPAddr{}, want: "UDP"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TransportToken(tt.addr); got != tt.want {
				t.Fatalf("TransportToken() = %q, want %q", got, tt.want)
			}
		})
	}

	if got, want := BuildVia("TCP", "127.0.0.1", 5060, "abc123"), "SIP/2.0/TCP 127.0.0.1:5060;branch=z9hG4bKabc123"; got != want {
		t.Fatalf("BuildVia() = %q, want %q", got, want)
	}
	if got, want := BuildViaWithOptions("UDP", "127.0.0.1", 5060, "abc123", ViaOptions{Keep: true}), "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKabc123;rport;keep"; got != want {
		t.Fatalf("BuildViaWithOptions() = %q, want %q", got, want)
	}
}

func TestApplyRouteSet(t *testing.T) {
	tests := []struct {
		name           string
		routes         []string
		wantRequestURI string
		wantRoutes     []string
	}{
		{
			name:           "loose route keeps remote target",
			routes:         []string{"<sip:pcscf.example.com;lr>"},
			wantRequestURI: "sip:user@example.com",
			wantRoutes:     []string{"<sip:pcscf.example.com;lr>"},
		},
		{
			name:           "strict route rewrites request uri",
			routes:         []string{"<sip:edge.example.com>", "<sip:pcscf.example.com;lr>"},
			wantRequestURI: "sip:edge.example.com",
			wantRoutes:     []string{"<sip:pcscf.example.com;lr>", "<sip:user@example.com>"},
		},
		{
			name:           "empty routes leaves request untouched",
			wantRequestURI: "sip:user@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := NewRequest("MESSAGE", "sip:user@example.com")
			ApplyRouteSet(&msg, tt.routes)
			if got := RequestURI(msg); got != tt.wantRequestURI {
				t.Fatalf("RequestURI() = %q, want %q", got, tt.wantRequestURI)
			}
			if got := msg.HeadersByName("Route"); len(got) != len(tt.wantRoutes) {
				t.Fatalf("HeadersByName(Route) = %v, want %v", got, tt.wantRoutes)
			} else {
				for i := range got {
					if got[i] != tt.wantRoutes[i] {
						t.Fatalf("HeadersByName(Route) = %v, want %v", got, tt.wantRoutes)
					}
				}
			}
		})
	}
}
