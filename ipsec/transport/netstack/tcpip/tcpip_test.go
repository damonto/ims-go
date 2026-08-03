package tcpip

import (
	"bytes"
	"testing"
)

func TestLinkAddressTextRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		text string
		want string
	}{
		{name: "colon separated", text: "02:00:5e:10:00:00", want: "02:00:5e:10:00:00"},
		{name: "hyphen separated", text: "02-00-5E-10-00-01", want: "02:00:5e:10:00:01"},
		{name: "dot separated", text: "0200.5e10.0002", want: "02:00:5e:10:00:02"},
		{name: "compact", text: "02005e100003", want: "02:00:5e:10:00:03"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var address LinkAddress
			if err := address.UnmarshalText([]byte(tt.text)); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}

			marshaled, err := address.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if got := string(marshaled); got != tt.want {
				t.Fatalf("MarshalText() = %q, want %q", got, tt.want)
			}

			prefix := []byte("mac=")
			appended, err := address.AppendText(bytes.Clone(prefix))
			if err != nil {
				t.Fatalf("AppendText() error = %v", err)
			}
			if !bytes.Equal(appended[:len(prefix)], prefix) {
				t.Fatalf("AppendText() prefix = %q, want %q", appended[:len(prefix)], prefix)
			}
			if got := string(appended[len(prefix):]); got != tt.want {
				t.Fatalf("AppendText() text = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLinkAddressTextRejectsInvalidValue(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		address LinkAddress
	}{
		{name: "too short", text: "02:00:5e:10:00", address: LinkAddress("original")},
		{name: "invalid hexadecimal", text: "02:00:5e:10:00:gg", address: LinkAddress("original")},
		{name: "EUI-64", text: "02:00:5e:10:00:00:00:01", address: LinkAddress("original")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address := tt.address
			if err := address.UnmarshalText([]byte(tt.text)); err == nil {
				t.Fatal("UnmarshalText() error = nil, want non-nil")
			}
			if address != tt.address {
				t.Fatalf("address after rejected text = %q, want %q", address, tt.address)
			}
		})
	}
}

func TestLinkAddressMarshalTextRejectsNonIEEE802Length(t *testing.T) {
	tests := []struct {
		name    string
		address LinkAddress
	}{
		{name: "empty", address: ""},
		{name: "eight bytes", address: LinkAddress("12345678")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.address.MarshalText(); err == nil {
				t.Fatal("MarshalText() error = nil, want non-nil")
			}
		})
	}
}
