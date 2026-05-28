package handshake

import (
	"context"
	"net"
	"testing"

	"github.com/damonto/vowifi-go/usim"
)

type stubCard struct{}

func (stubCard) IMSI() string { return "001010123456789" }
func (stubCard) MCC() string  { return "001" }
func (stubCard) MNC() string  { return "001" }
func (stubCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

func TestConnectInputValidate(t *testing.T) {
	tests := []struct {
		name    string
		input   ConnectInput
		wantErr bool
	}{
		{name: "valid", input: ConnectInput{IMEI: "356789012345678", Card: stubCard{}, OuterRemote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}},
		{name: "missing card", input: ConnectInput{IMEI: "356789012345678", OuterRemote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}, wantErr: true},
		{name: "missing imei", input: ConnectInput{OuterRemote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}, wantErr: true},
		{name: "missing remote", input: ConnectInput{IMEI: "356789012345678"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.input.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("Validate() error = nil, want error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}
