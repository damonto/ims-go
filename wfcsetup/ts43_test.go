package wfcsetup

import (
	"testing"
	"time"

	"github.com/damonto/ts43-go/ts43"
)

func TestTS43WebsheetClientName(t *testing.T) {
	status := ts43.WFCStatus{
		ServiceFlowURL: "https://example.test/e911",
	}
	tests := []struct {
		name       string
		clientName string
		want       string
	}{
		{name: "profile client name is passed through", clientName: "VoWiFiWebServiceFlow", want: "VoWiFiWebServiceFlow"},
		{name: "missing profile client name stays empty", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ts43Websheet(status, WebsheetKindEmergencyAddress, ts43.WFCConfig{WebsheetClientName: tt.clientName})
			if err != nil {
				t.Fatalf("ts43Websheet() error = %v", err)
			}
			if got.ClientName != tt.want {
				t.Fatalf("ClientName = %q, want %q", got.ClientName, tt.want)
			}
		})
	}
}

func TestTS43CachedToken(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name      string
		token     ts43.AuthToken
		wantValue string
		wantKept  bool
	}{
		{
			name:      "token without expiry is returned",
			token:     ts43.AuthToken{Value: "cached", Cookies: []string{"sid=old"}},
			wantValue: "cached",
			wantKept:  true,
		},
		{
			name:      "future token is returned",
			token:     ts43.AuthToken{Value: "fresh", ExpiresAt: now.Add(time.Minute), Cookies: []string{"sid=fresh"}},
			wantValue: "fresh",
			wantKept:  true,
		},
		{
			name:  "expired token is deleted",
			token: ts43.AuthToken{Value: "expired", ExpiresAt: now.Add(-time.Second), Cookies: []string{"sid=expired"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "imsi\x00server"
			ts43Tokens.mu.Lock()
			ts43Tokens.values = map[string]ts43.AuthToken{key: tt.token}
			ts43Tokens.mu.Unlock()
			t.Cleanup(func() {
				ts43Tokens.mu.Lock()
				ts43Tokens.values = make(map[string]ts43.AuthToken)
				ts43Tokens.mu.Unlock()
			})

			got := ts43CachedToken(key)
			if got.Value != tt.wantValue {
				t.Fatalf("AuthToken.Value = %q, want %q", got.Value, tt.wantValue)
			}
			if len(got.Cookies) > 0 {
				got.Cookies[0] = "mutated"
			}

			ts43Tokens.mu.Lock()
			stored, kept := ts43Tokens.values[key]
			ts43Tokens.mu.Unlock()
			if kept != tt.wantKept {
				t.Fatalf("cache kept = %t, want %t", kept, tt.wantKept)
			}
			if kept && len(stored.Cookies) > 0 && stored.Cookies[0] == "mutated" {
				t.Fatal("cached cookies were not copied")
			}
		})
	}
}
