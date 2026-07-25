//go:build linux

package ims

import (
	"testing"

	"github.com/damonto/wwan-go/mbim"
)

func TestMBIMClientIPType(t *testing.T) {
	tests := []struct {
		name    string
		pdnType string
		want    mbim.ContextIPType
		wantErr bool
	}{
		{name: "IPv4", pdnType: "ipv4", want: mbim.ContextIPTypeIPv4},
		{name: "IPv6", pdnType: "ipv6", want: mbim.ContextIPTypeIPv6},
		{name: "dual stack", pdnType: "ipv4v6", want: mbim.ContextIPTypeIPv4v6},
		{name: "unsupported", pdnType: "ipv5", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mbimIPType(tt.pdnType)
			if tt.wantErr {
				if err == nil {
					t.Fatal("mbimIPType() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("mbimIPType() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("mbimIPType() = %d, want %d", got, tt.want)
			}
		})
	}
}
