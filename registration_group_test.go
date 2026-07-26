package ims

import (
	"context"
	"strings"
	"testing"

	"github.com/damonto/ims-go/lte"
	usim "github.com/damonto/wwan-go/sim"
)

func TestIMSConfigMultipleRegistrationValidation(t *testing.T) {
	group := NewRegistrationGroup()
	tests := []struct {
		name    string
		cfg     IMSConfig
		wantErr string
	}{
		{
			name:    "settings require group",
			cfg:     IMSConfig{RegistrationID: 1, RegistrationPreference: 1000, IMEI: testIMEI},
			wantErr: "registration group is required",
		},
		{
			name:    "group requires registration id",
			cfg:     IMSConfig{RegistrationGroup: group, RegistrationPreference: 1000, IMEI: testIMEI},
			wantErr: "registration id must be greater than zero",
		},
		{
			name:    "group requires valid preference",
			cfg:     IMSConfig{RegistrationGroup: group, RegistrationID: 1, RegistrationPreference: 1001, IMEI: testIMEI},
			wantErr: "registration preference must be between 1 and 1000",
		},
		{
			name:    "group requires stable instance id",
			cfg:     IMSConfig{RegistrationGroup: group, RegistrationID: 1, RegistrationPreference: 1000},
			wantErr: "imei is required",
		},
		{
			name: "valid multiple registration",
			cfg: IMSConfig{
				RegistrationGroup:      group,
				RegistrationID:         1,
				RegistrationPreference: 1000,
				IMEI:                   testIMEI,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := withTestIMSIPSecAlgorithms(tt.cfg).Normalized()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Normalized() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Normalized() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigDefaultsMultipleRegistrationByAccess(t *testing.T) {
	group := NewRegistrationGroup()
	tests := []struct {
		name           string
		access         AccessConfig
		wantID         uint32
		wantPreference int
	}{
		{
			name:           "VoWiFi is preferred",
			access:         VoWiFi(VoWiFiConfig{}),
			wantID:         defaultVoWiFiRegistrationID,
			wantPreference: defaultVoWiFiRegistrationPreference,
		},
		{
			name:           "VoLTE is fallback",
			access:         VoLTE(lte.Config{AccessNetworkInfo: testVoLTEPANI}),
			wantID:         defaultVoLTERegistrationID,
			wantPreference: defaultVoLTERegistrationPreference,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := withTestIPSecAlgorithms(Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   tt.access,
				IMS:      IMSConfig{RegistrationGroup: group},
			})
			got, err := cfg.normalizedIMS()
			if err != nil {
				t.Fatalf("normalizedIMS() error = %v", err)
			}
			if got.RegistrationID != tt.wantID {
				t.Fatalf("RegistrationID = %d, want %d", got.RegistrationID, tt.wantID)
			}
			if got.RegistrationPreference != tt.wantPreference {
				t.Fatalf("RegistrationPreference = %d, want %d", got.RegistrationPreference, tt.wantPreference)
			}
		})
	}
}

func TestIMSConfigCoordinatedAKA(t *testing.T) {
	tests := []struct {
		name string
		cfg  IMSConfig
	}{
		{
			name: "without registration group",
		},
		{
			name: "with registration group",
			cfg:  IMSConfig{RegistrationGroup: NewRegistrationGroup()},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls int
			authenticate := func(context.Context, []byte, []byte) (usim.AKAResult, error) {
				calls++
				return usim.AKAResult{RES: []byte("response")}, nil
			}
			got, err := tt.cfg.coordinatedAKA(authenticate)(context.Background(), make([]byte, 16), make([]byte, 16))
			if err != nil {
				t.Fatalf("coordinatedAKA() error = %v", err)
			}
			if calls != 1 {
				t.Fatalf("authenticate calls = %d, want 1", calls)
			}
			if string(got.RES) != "response" {
				t.Fatalf("RES = %q, want response", got.RES)
			}
		})
	}
}
