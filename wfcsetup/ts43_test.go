package wfcsetup

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	ts43 "github.com/damonto/ts43-go"
)

type ts43HTTPTransport struct {
	called bool
}

func (t *ts43HTTPTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.called = true
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body: io.NopCloser(strings.NewReader(
			`{"APPLICATION":{"AppID":"ap2004","EntitlementStatus":"1","TC_Status":"2","AddrStatus":"2","ProvStatus":"2","ServiceFlow_URL":"https://carrier.example/e911"}}`,
		)),
		Request: req,
	}, nil
}

func TestTS43FlowHTTPClient(t *testing.T) {
	tests := []struct {
		name         string
		purpose      Purpose
		customClient bool
		wantAction   Action
	}{
		{name: "activation with default client", purpose: PurposeActivation, wantAction: ActionAllowActivation},
		{name: "activation with custom client", purpose: PurposeActivation, customClient: true, wantAction: ActionAllowActivation},
		{name: "emergency address with default client", purpose: PurposeEmergencyAddressUpdate, wantAction: ActionOpenWebsheet},
		{name: "emergency address with custom client", purpose: PurposeEmergencyAddressUpdate, customClient: true, wantAction: ActionOpenWebsheet},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defaultTransport := &ts43HTTPTransport{}
			originalTransport := http.DefaultTransport
			http.DefaultTransport = defaultTransport
			t.Cleanup(func() { http.DefaultTransport = originalTransport })

			transport := defaultTransport
			var client *http.Client
			if tt.customClient {
				transport = &ts43HTTPTransport{}
				client = &http.Client{Transport: transport}
			}
			flow := ts43Flow{
				req: Request{
					Card:       testCard{mcc: "310", mnc: "260", mncLength: 3},
					Device:     Device{IMEI: "111111111111111", Vendor: "Google", Model: "Pixel 8 Pro", SoftwareVersion: "15"},
					Purpose:    tt.purpose,
					HTTPClient: client,
				},
				wfc: ts43.WFCConfig{Server: "https://carrier.example/entitlement", ShowVoWiFiWebview: true},
			}

			result, err := flow.Check(t.Context())
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if !transport.called {
				t.Fatal("selected HTTP client was not used")
			}
			if tt.customClient && defaultTransport.called {
				t.Fatal("default transport was used instead of the custom HTTP client")
			}
			if result.Action != tt.wantAction || !result.Entitled {
				t.Fatalf("result = %+v, want entitled with action %v", result, tt.wantAction)
			}
			if tt.wantAction == ActionOpenWebsheet {
				if result.Websheet == nil || result.Websheet.URL != "https://carrier.example/e911" {
					t.Fatalf("Websheet = %+v, want emergency address URL", result.Websheet)
				}
			}
		})
	}
}

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
