package registration

import (
	"maps"
	"testing"
)

func TestComparableSIPURIUnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    comparableSIPURI
		wantErr bool
	}{
		{
			name: "normalized SIP URI",
			text: " SIP:%41lice@example.test:5060;TRANSPORT=TCP?Subject=hello%20world ",
			want: comparableSIPURI{
				scheme:     "sip",
				userinfo:   "Alice",
				hostPort:   "example.test:5060",
				parameters: map[string]string{"transport": "tcp"},
				headers:    map[string]string{"subject": "hello%20world"},
			},
		},
		{
			name: "SIPS with IPv6",
			text: "sips:token@[2001:db8::10]:5061",
			want: comparableSIPURI{scheme: "sips", userinfo: "token", hostPort: "[2001:db8::10]:5061"},
		},
		{
			name: "host without user",
			text: "sip:example.test",
			want: comparableSIPURI{scheme: "sip", hostPort: "example.test"},
		},
		{name: "empty", wantErr: true},
		{name: "missing scheme", text: "alice@example.test", wantErr: true},
		{name: "unsupported scheme", text: "tel:+15551234567", wantErr: true},
		{name: "empty user", text: "sip:@example.test", wantErr: true},
		{name: "empty host", text: "sip:alice@", wantErr: true},
		{name: "whitespace in host", text: "sip:alice@example .test", wantErr: true},
		{name: "duplicate parameter", text: "sip:alice@example.test;transport=tcp;TRANSPORT=udp", wantErr: true},
		{name: "empty parameter name", text: "sip:alice@example.test;=tcp", wantErr: true},
		{name: "duplicate header", text: "sip:alice@example.test?subject=one&Subject=two", wantErr: true},
		{name: "empty header name", text: "sip:alice@example.test?=one", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := comparableSIPURI{
				scheme:     "sip",
				userinfo:   "original",
				hostPort:   "original.example.test",
				parameters: map[string]string{"transport": "udp"},
			}
			got := original
			err := got.UnmarshalText([]byte(tt.text))
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalText() error = %v, want error %t", err, tt.wantErr)
			}
			want := tt.want
			if tt.wantErr {
				want = original
			}
			if got.scheme != want.scheme || got.userinfo != want.userinfo || got.hostPort != want.hostPort ||
				!maps.Equal(got.parameters, want.parameters) || !maps.Equal(got.headers, want.headers) {
				t.Fatalf("UnmarshalText() = %+v, want %+v", got, want)
			}
		})
	}
}
