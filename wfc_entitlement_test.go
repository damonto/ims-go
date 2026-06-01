package vowifi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	ts43http "github.com/damonto/ts43-go/http"
	"github.com/damonto/ts43-go/sim"
	"github.com/damonto/ts43-go/ts43"
	"github.com/damonto/vowifi-go/usim"
)

func TestCheckWFCEntitlement(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		wantAction WFCEntitlementAction
		wantErr    error
		check      func(t *testing.T, err error)
	}{
		{
			name:       "entitled",
			body:       `<wap-provisioningdoc><characteristic type="APPLICATION"><parm name="AppID" value="ap2004"/><parm name="EntitlementStatus" value="1"/><parm name="TC_Status" value="2"/><parm name="AddrStatus" value="2"/><parm name="ProvStatus" value="2"/></characteristic></wap-provisioningdoc>`,
			wantAction: WFCEntitlementActionAllowActivation,
		},
		{
			name:       "needs user web flow",
			body:       `<wap-provisioningdoc><characteristic type="APPLICATION"><parm name="AppID" value="ap2004"/><parm name="EntitlementStatus" value="0"/><parm name="TC_Status" value="0"/><parm name="AddrStatus" value="0"/><parm name="ProvStatus" value="0"/><parm name="ServiceFlow_URL" value="https://example.test/e911"/><parm name="ServiceFlow_UserData" value="token=abc"/></characteristic></wap-provisioningdoc>`,
			wantAction: WFCEntitlementActionOpenWebsheet,
			wantErr:    ErrWFCEntitlementUserActionRequired,
			check: func(t *testing.T, err error) {
				t.Helper()
				var entitlementErr *WFCEntitlementError
				if !errors.As(err, &entitlementErr) {
					t.Fatalf("error = %T, want *WFCEntitlementError", err)
				}
				if entitlementErr.Result.Websheet == nil {
					t.Fatal("Websheet is nil")
				}
				if entitlementErr.Result.Websheet.URL != "https://example.test/e911" {
					t.Fatalf("Websheet.URL = %q", entitlementErr.Result.Websheet.URL)
				}
				if entitlementErr.Result.Websheet.Kind != WFCWebsheetKindTermsAndConditions {
					t.Fatalf("Websheet.Kind = %q, want %q", entitlementErr.Result.Websheet.Kind, WFCWebsheetKindTermsAndConditions)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if got := req.URL.Query().Get("app"); got != "ap2004" {
					t.Fatalf("app = %q, want ap2004", got)
				}
				if got := req.URL.Query().Get("terminal_id"); got != "111122223333444" {
					t.Fatalf("terminal_id = %q, want configured terminal ID", got)
				}
				if got := req.URL.Query().Get("terminal_vendor"); got != "Goog" {
					t.Fatalf("terminal_vendor = %q, want truncated vendor", got)
				}
				if got := req.URL.Query().Get("terminal_model"); got != "Pixel" {
					t.Fatalf("terminal_model = %q, want Pixel", got)
				}
				if got := req.URL.Query().Get("terminal_sw_version"); got != "16" {
					t.Fatalf("terminal_sw_version = %q, want 16", got)
				}
				if got := req.Header.Get("User-Agent"); !strings.Contains(got, "client-IMS-Entitlement") {
					t.Fatalf("User-Agent = %q, want WFC entitlement marker", got)
				}
				w.Header().Set("Content-Type", "text/vnd.wap.connectivity-xml")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			cfg := Config{
				Logger: slog.Default(),
				Terminal: TerminalInfo{
					ID:              "111122223333444",
					Vendor:          "Google",
					Model:           "Pixel",
					SoftwareVersion: "16",
				},
			}
			client := newClient(cfg)
			result, err := client.checkTS43WFCEntitlement(context.Background(), &cfg, plmnWFCCard{mcc: "208", mnc: "01"}, WFCEntitlementActivation, ts43.WFCConfig{
				Server: server.URL,
				App:    ts43.AppVoWiFi,
			})
			if err == nil {
				err = wfcEntitlementResultError(result)
			}
			if result.Action != tt.wantAction {
				t.Fatalf("Action = %v, want %v", result.Action, tt.wantAction)
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("checkWFCEntitlement() error = %v, want %v", err, tt.wantErr)
				}
				if tt.check != nil {
					tt.check(t, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkWFCEntitlement() error = %v", err)
			}
		})
	}
}

func TestCheckWFCEntitlementSkipsMissingConfig(t *testing.T) {
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Logger:   slog.Default(),
	}
	client := newClient(cfg)
	err := client.checkWFCEntitlement(context.Background(), &cfg, plmnWFCCard{mcc: "999", mnc: "99"})
	if err != nil {
		t.Fatalf("checkWFCEntitlement() error = %v", err)
	}
}

func TestCheckWFCEntitlementRequestValidation(t *testing.T) {
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Logger:   slog.Default(),
	}
	client := newClient(cfg)
	tests := []struct {
		name string
		req  WFCEntitlementRequest
	}{
		{
			name: "missing config",
			req: WFCEntitlementRequest{
				Card:    plmnWFCCard{mcc: "999", mnc: "99"},
				Purpose: WFCEntitlementActivation,
			},
		},
		{
			name: "missing card",
			req: WFCEntitlementRequest{
				Config:  &cfg,
				Purpose: WFCEntitlementActivation,
			},
		},
		{
			name: "invalid purpose",
			req: WFCEntitlementRequest{
				Config:  &cfg,
				Card:    plmnWFCCard{mcc: "999", mnc: "99"},
				Purpose: WFCEntitlementPurpose(99),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := client.CheckWFCEntitlement(context.Background(), tt.req); err == nil {
				t.Fatal("CheckWFCEntitlement() error is nil")
			}
		})
	}
}

func TestCheckTS43WFCEntitlementHonorsSkipActivation(t *testing.T) {
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Logger:   slog.Default(),
	}
	client := newClient(cfg)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.Header().Set("Content-Type", "text/vnd.wap.connectivity-xml")
		_, _ = w.Write([]byte(`<wap-provisioningdoc><characteristic type="APPLICATION"><parm name="AppID" value="ap2004"/><parm name="EntitlementStatus" value="1"/><parm name="TC_Status" value="2"/><parm name="AddrStatus" value="2"/><parm name="ProvStatus" value="2"/><parm name="ServiceFlow_URL" value="https://example.test/e911"/><parm name="ServiceFlow_UserData" value="token=abc"/></characteristic></wap-provisioningdoc>`))
	}))
	defer server.Close()

	tests := []struct {
		name       string
		purpose    WFCEntitlementPurpose
		wantAction WFCEntitlementAction
		wantCalls  int
		wantSheet  bool
	}{
		{name: "activation skips server", purpose: WFCEntitlementActivation, wantAction: WFCEntitlementActionAllowActivation},
		{name: "emergency address update checks server", purpose: WFCEntitlementEmergencyAddressUpdate, wantAction: WFCEntitlementActionOpenWebsheet, wantCalls: 1, wantSheet: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls = 0
			result, err := client.checkDiscoveredWFCEntitlement(context.Background(), &cfg, plmnWFCCard{mcc: "310", mnc: "240", mncLength: 3}, tt.purpose, ts43.WFCConfig{
				CarrierName:    "T-Mobile US",
				Server:         server.URL,
				App:            ts43.AppVoWiFi,
				SkipActivation: true,
			})
			if err != nil {
				t.Fatalf("checkDiscoveredWFCEntitlement() error = %v", err)
			}
			if calls != tt.wantCalls {
				t.Fatalf("server calls = %d, want %d", calls, tt.wantCalls)
			}
			if result.Action != tt.wantAction {
				t.Fatalf("Action = %v, want %v", result.Action, tt.wantAction)
			}
			if result.Websheet != nil != tt.wantSheet {
				t.Fatalf("Websheet nil = %t, want sheet %t", result.Websheet == nil, tt.wantSheet)
			}
		})
	}
}

func TestCheckWFCE911UpdateMissingConfigDenied(t *testing.T) {
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Logger:   slog.Default(),
	}
	client := newClient(cfg)
	result, err := client.CheckWFCE911Update(context.Background(), WFCEntitlementRequest{
		Config: &cfg,
		Card:   plmnWFCCard{mcc: "999", mnc: "99"},
	})
	if err != nil {
		t.Fatalf("CheckWFCE911Update() error = %v", err)
	}
	if result.Action != WFCEntitlementActionDenied {
		t.Fatalf("Action = %v, want %v", result.Action, WFCEntitlementActionDenied)
	}
	if result.Entitled {
		t.Fatal("Entitled is true")
	}
}

func TestCheckTS43WFCEntitlementEmergencyAddressUpdateDeniesServerDataMissing(t *testing.T) {
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Logger:   slog.Default(),
	}
	client := newClient(cfg)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/vnd.wap.connectivity-xml")
		_, _ = w.Write([]byte(`<wap-provisioningdoc><characteristic type="APPLICATION"><parm name="AppID" value="ap2004"/><parm name="EntitlementStatus" value="0"/><parm name="TC_Status" value="0"/><parm name="AddrStatus" value="0"/><parm name="ProvStatus" value="0"/><parm name="ServiceFlow_URL" value="https://example.test/e911"/><parm name="ServiceFlow_UserData" value="token=abc"/></characteristic></wap-provisioningdoc>`))
	}))
	defer server.Close()

	result, err := client.checkTS43WFCEntitlement(context.Background(), &cfg, plmnWFCCard{mcc: "208", mnc: "01"}, WFCEntitlementEmergencyAddressUpdate, ts43.WFCConfig{
		Server: server.URL,
		App:    ts43.AppVoWiFi,
	})
	if err != nil {
		t.Fatalf("checkTS43WFCEntitlement() error = %v", err)
	}
	if result.Action != WFCEntitlementActionDenied {
		t.Fatalf("Action = %v, want %v", result.Action, WFCEntitlementActionDenied)
	}
	if result.Websheet != nil {
		t.Fatalf("Websheet = %+v, want nil", result.Websheet)
	}
}

func TestCheckTS43WFCEntitlementEmergencyAddressRecheck(t *testing.T) {
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Logger:   slog.Default(),
	}
	client := newClient(cfg)
	tests := []struct {
		name       string
		body       string
		wantAction WFCEntitlementAction
		wantSheet  bool
	}{
		{
			name:       "accepted after websheet",
			body:       `<wap-provisioningdoc><characteristic type="APPLICATION"><parm name="AppID" value="ap2004"/><parm name="EntitlementStatus" value="1"/><parm name="TC_Status" value="2"/><parm name="AddrStatus" value="2"/><parm name="ProvStatus" value="2"/><parm name="ServiceFlow_URL" value="https://example.test/e911"/></characteristic></wap-provisioningdoc>`,
			wantAction: WFCEntitlementActionNone,
		},
		{
			name:       "carrier disabled after websheet",
			body:       `<wap-provisioningdoc><characteristic type="APPLICATION"><parm name="AppID" value="ap2004"/><parm name="EntitlementStatus" value="0"/><parm name="TC_Status" value="0"/><parm name="AddrStatus" value="0"/><parm name="ProvStatus" value="0"/><parm name="ServiceFlow_URL" value="https://example.test/e911"/><parm name="ServiceFlow_UserData" value="token=abc"/></characteristic></wap-provisioningdoc>`,
			wantAction: WFCEntitlementActionDisableWFC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/vnd.wap.connectivity-xml")
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()

			result, err := client.checkTS43WFCEntitlement(context.Background(), &cfg, plmnWFCCard{mcc: "208", mnc: "01"}, WFCEntitlementEmergencyAddressRecheck, ts43.WFCConfig{
				Server: server.URL,
				App:    ts43.AppVoWiFi,
			})
			if err != nil {
				t.Fatalf("checkTS43WFCEntitlement() error = %v", err)
			}
			if result.Action != tt.wantAction {
				t.Fatalf("Action = %v, want %v", result.Action, tt.wantAction)
			}
			if result.Websheet != nil != tt.wantSheet {
				t.Fatalf("Websheet nil = %t, want sheet %t", result.Websheet == nil, tt.wantSheet)
			}
		})
	}
}

func TestTS43RetryAfterError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantOK  bool
		wantMin time.Duration
		wantMax time.Duration
	}{
		{
			name: "service unavailable with retry-after seconds",
			err: &ts43http.HTTPError{
				StatusCode: http.StatusServiceUnavailable,
				Header: http.Header{
					"Retry-After": {"30"},
				},
			},
			wantOK:  true,
			wantMin: 30 * time.Second,
			wantMax: 30 * time.Second,
		},
		{
			name: "other status",
			err:  &ts43http.HTTPError{StatusCode: http.StatusBadRequest},
		},
		{
			name: "plain error",
			err:  errors.New("boom"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ts43RetryAfter(tt.err)
			if ok != tt.wantOK {
				t.Fatalf("ts43RetryAfter() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got < tt.wantMin || got > tt.wantMax {
				t.Fatalf("RetryAfter = %s, want between %s and %s", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestRetryAfterDurationAt(t *testing.T) {
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		header http.Header
		want   time.Duration
	}{
		{
			name: "seconds",
			header: http.Header{
				"Retry-After": {"30"},
			},
			want: 30 * time.Second,
		},
		{
			name: "http date",
			header: http.Header{
				"Retry-After": {now.Add(2 * time.Minute).Format(http.TimeFormat)},
			},
			want: 2 * time.Minute,
		},
		{
			name: "past date",
			header: http.Header{
				"Retry-After": {now.Add(-time.Second).Format(http.TimeFormat)},
			},
		},
		{
			name: "invalid",
			header: http.Header{
				"Retry-After": {"soon"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := retryAfterDurationAt(tt.header, now); got != tt.want {
				t.Fatalf("retryAfterDurationAt() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestNSDSWFCProfileForCard(t *testing.T) {
	tests := []struct {
		name        string
		card        plmnWFCCard
		wantCarrier string
		wantOK      bool
	}{
		{
			name:        "att",
			card:        plmnWFCCard{mcc: "310", mnc: "030"},
			wantCarrier: "AT&T",
			wantOK:      true,
		},
		{
			name:        "firstnet",
			card:        plmnWFCCard{mcc: "313", mnc: "100"},
			wantCarrier: "FirstNet/AT&T",
			wantOK:      true,
		},
		{
			name:        "gci xaa",
			card:        plmnWFCCard{mcc: "311", mnc: "370"},
			wantCarrier: "GCI",
			wantOK:      true,
		},
		{
			name:   "unknown",
			card:   plmnWFCCard{mcc: "208", mnc: "01"},
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := nsdsWFCProfileForCard(tt.card)
			if ok != tt.wantOK {
				t.Fatalf("nsdsWFCProfileForCard() ok = %v, want %v", ok, tt.wantOK)
			}
			if got.Carrier != tt.wantCarrier {
				t.Fatalf("nsdsWFCProfileForCard() carrier = %q, want %q", got.Carrier, tt.wantCarrier)
			}
		})
	}
}

func TestCheckNSDSWFCEntitlement(t *testing.T) {
	tests := []struct {
		name       string
		purpose    WFCEntitlementPurpose
		status     nsdsResponse
		wantAction WFCEntitlementAction
		wantErr    error
		check      func(*testing.T, WFCEntitlementResult, error)
	}{
		{
			name:       "entitlement accepted for activation",
			purpose:    WFCEntitlementActivation,
			wantAction: WFCEntitlementActionAllowActivation,
			status: nsdsResponse{
				MessageID:      nsdsMessageIDManageLocationAndTC,
				ResponseCode:   1000,
				LocationStatus: boolPtr(true),
				TCStatus:       boolPtr(true),
				AddressID:      "aid-1",
				AIDExpiration:  nsdsAIDExpiration{Time: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
				ServerURL:      "https://example.test/e911",
				ServerData:     "token=accepted",
			},
			check: func(t *testing.T, result WFCEntitlementResult, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("checkNSDSWFCEntitlement() error = %v", err)
				}
				if result.E911 != nil {
					t.Fatalf("E911 = %+v, want nil", result.E911)
				}
			},
		},
		{
			name:       "emergency address update opens websheet",
			purpose:    WFCEntitlementEmergencyAddressUpdate,
			wantAction: WFCEntitlementActionOpenWebsheet,
			status: nsdsResponse{
				MessageID:      nsdsMessageIDManageLocationAndTC,
				ResponseCode:   1000,
				LocationStatus: boolPtr(true),
				TCStatus:       boolPtr(true),
				ServerURL:      "https://example.test/e911",
				ServerData:     "token=accepted",
			},
			check: func(t *testing.T, result WFCEntitlementResult, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("checkNSDSWFCEntitlement() error = %v", err)
				}
				if result.Websheet == nil {
					t.Fatal("Websheet is nil")
				}
				if result.Websheet.Kind != WFCWebsheetKindEmergencyAddress {
					t.Fatalf("Websheet.Kind = %q, want %q", result.Websheet.Kind, WFCWebsheetKindEmergencyAddress)
				}
			},
		},
		{
			name:       "emergency address recheck accepted",
			purpose:    WFCEntitlementEmergencyAddressRecheck,
			wantAction: WFCEntitlementActionNone,
			status: nsdsResponse{
				MessageID:      nsdsMessageIDManageLocationAndTC,
				ResponseCode:   1000,
				LocationStatus: boolPtr(true),
				TCStatus:       boolPtr(true),
				ServerURL:      "https://example.test/e911",
				ServerData:     "token=accepted",
			},
		},
		{
			name:       "emergency address recheck carrier disabled",
			purpose:    WFCEntitlementEmergencyAddressRecheck,
			wantAction: WFCEntitlementActionDisableWFC,
			status: nsdsResponse{
				MessageID:      nsdsMessageIDManageLocationAndTC,
				ResponseCode:   1000,
				LocationStatus: boolPtr(false),
				TCStatus:       boolPtr(false),
				ServerURL:      "https://example.test/e911",
				ServerData:     "token=abc",
			},
		},
		{
			name:       "needs e911 websheet",
			purpose:    WFCEntitlementEmergencyAddressUpdate,
			wantAction: WFCEntitlementActionOpenWebsheet,
			status: nsdsResponse{
				MessageID:      nsdsMessageIDManageLocationAndTC,
				ResponseCode:   1000,
				LocationStatus: boolPtr(false),
				TCStatus:       boolPtr(false),
				ServerURL:      "https://example.test/e911",
				ServerData:     "token=abc",
			},
			check: func(t *testing.T, result WFCEntitlementResult, err error) {
				t.Helper()
				if err != nil {
					t.Fatalf("checkNSDSWFCEntitlement() error = %v", err)
				}
				if result.Websheet == nil {
					t.Fatal("Websheet is nil")
				}
				if result.Websheet.URL != "https://example.test/e911" {
					t.Fatalf("Websheet.URL = %q", result.Websheet.URL)
				}
				if result.Websheet.Data != "token=abc" {
					t.Fatalf("Websheet.Data = %q", result.Websheet.Data)
				}
				if result.Websheet.ClientName != "WiFiCallingWebViewController" {
					t.Fatalf("Websheet.ClientName = %q", result.Websheet.ClientName)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := newNSDSWFCTestServer(t, tt.status)
			defer server.Close()

			cfg := Config{
				Logger: slog.Default(),
				Terminal: TerminalInfo{
					ID:              testIMEI,
					Model:           "Pixel",
					SoftwareVersion: "13",
				},
				IMS: IMSConfig{
					HomeDomain: "ims.mnc030.mcc310.3gppnetwork.org",
				},
			}
			client := newClient(cfg)
			profile := nsdsWFCProfile{
				Carrier:    "AT&T",
				ServerURL:  server.URL,
				Title:      "Wi-Fi Calling",
				ClientName: "WiFiCallingWebViewController",
			}
			result, err := client.checkNSDSWFCEntitlement(context.Background(), WFCEntitlementRequest{
				Config:  &cfg,
				Card:    nsdsTestCard{},
				Purpose: tt.purpose,
			}, profile)
			if err == nil && tt.purpose == WFCEntitlementActivation {
				err = wfcEntitlementResultError(result)
			}
			if result.Action != tt.wantAction {
				t.Fatalf("Action = %v, want %v", result.Action, tt.wantAction)
			}
			if cfg.IMS.PublicIdentity != "" {
				t.Fatalf("PublicIdentity = %q, want empty", cfg.IMS.PublicIdentity)
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("checkNSDSWFCEntitlement() error = %v, want %v", err, tt.wantErr)
				}
				if tt.check != nil {
					tt.check(t, result, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkNSDSWFCEntitlement() error = %v", err)
			}
			if tt.check != nil {
				tt.check(t, result, err)
			}
		})
	}
}

func TestCheckNSDSWFCEntitlementSkipsFreshE911AID(t *testing.T) {
	cfg := Config{
		Logger: slog.Default(),
		Terminal: TerminalInfo{
			ID:              testIMEI,
			Model:           "Pixel",
			SoftwareVersion: "13",
		},
	}
	client := newClient(cfg)
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	current := &WFCE911Info{
		AddressID:     "aid-1",
		AIDExpiration: now.Add(72 * time.Hour),
		ServerURL:     "https://example.test/e911",
		ServerData:    "token=accepted",
	}
	result, err := client.checkNSDSWFCEntitlement(context.Background(), WFCEntitlementRequest{
		Config:      &cfg,
		Card:        nsdsTestCard{},
		Purpose:     WFCEntitlementEmergencyAddressRecheck,
		CurrentE911: current,
		Now:         now,
	}, nsdsWFCProfile{
		Carrier:   "AT&T",
		ServerURL: "http://127.0.0.1:1",
	})
	if err != nil {
		t.Fatalf("checkNSDSWFCEntitlement() error = %v", err)
	}
	if result.Action != WFCEntitlementActionNone {
		t.Fatalf("Action = %v, want %v", result.Action, WFCEntitlementActionNone)
	}
	if !result.Entitled {
		t.Fatal("Entitled is false")
	}
	if result.E911 != current {
		t.Fatalf("E911 = %p, want %p", result.E911, current)
	}
}

func TestCheckNSDSWFCEntitlementAuthErrorFallback(t *testing.T) {
	tests := []struct {
		name         string
		purpose      WFCEntitlementPurpose
		responseCode int
		wantAllow    bool
	}{
		{name: "activation invalid request", purpose: WFCEntitlementActivation, responseCode: nsdsResponseInvalidRequest, wantAllow: true},
		{name: "activation aka auth failed", purpose: WFCEntitlementActivation, responseCode: nsdsResponseAKAAuthFailed},
		{name: "e911 update invalid request", purpose: WFCEntitlementEmergencyAddressUpdate, responseCode: nsdsResponseInvalidRequest},
		{name: "e911 recheck invalid request", purpose: WFCEntitlementEmergencyAddressRecheck, responseCode: nsdsResponseInvalidRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challengeText := nsdsAKAChallengeText(t)
			var calls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests := readNSDSRequests(t, req)
				calls++
				switch calls {
				case 1:
					checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication})
					writeNSDSResponses(t, w, []nsdsResponse{{
						MessageID:    nsdsMessageID3GPPAuthentication,
						Method:       nsdsMethod3GPPAuthentication,
						ResponseCode: nsdsResponseAKAChallenge,
						AKAChallenge: challengeText,
						AKAToken:     "aka-token",
					}})
				case 2:
					wantMethods := []string{nsdsMethod3GPPAuthentication, nsdsMethodServiceEntitlement}
					if tt.purpose != WFCEntitlementActivation {
						wantMethods = append(wantMethods, nsdsMethodGetMSISDN)
					}
					checkNSDSMethods(t, requests, wantMethods)
					if requests[0].AKAChallengeRsp == "" {
						t.Fatal("aka-challenge-rsp is empty")
					}
					if requests[0].AKAToken != "" {
						t.Fatalf("aka-token = %q, want empty", requests[0].AKAToken)
					}
					writeNSDSResponses(t, w, []nsdsResponse{{
						MessageID:    nsdsMessageID3GPPAuthentication,
						Method:       nsdsMethod3GPPAuthentication,
						ResponseCode: tt.responseCode,
					}})
				default:
					t.Fatalf("unexpected request %d", calls)
				}
			}))
			defer server.Close()

			cfg := Config{
				Logger: slog.Default(),
				Terminal: TerminalInfo{
					ID:              testIMEI,
					Model:           "Pixel",
					SoftwareVersion: "13",
				},
			}
			client := newClient(cfg)
			result, err := client.checkNSDSWFCEntitlement(context.Background(), WFCEntitlementRequest{
				Config:  &cfg,
				Card:    nsdsTestCard{},
				Purpose: tt.purpose,
			}, nsdsWFCProfile{
				Carrier:   "AT&T",
				ServerURL: server.URL,
			})
			if tt.wantAllow {
				if err != nil {
					t.Fatalf("checkNSDSWFCEntitlement() error = %v", err)
				}
				if result.Action != WFCEntitlementActionAllowActivation {
					t.Fatalf("Action = %v, want %v", result.Action, WFCEntitlementActionAllowActivation)
				}
				if !result.Entitled {
					t.Fatal("Entitled is false")
				}
				return
			}
			if err == nil {
				t.Fatal("checkNSDSWFCEntitlement() error is nil")
			}
			var codeErr nsdsResponseCodeError
			if !errors.As(err, &codeErr) {
				t.Fatalf("error = %T, want nsdsResponseCodeError", err)
			}
			if codeErr.Got != tt.responseCode {
				t.Fatalf("response code = %d, want %d", codeErr.Got, tt.responseCode)
			}
		})
	}
}

func TestCheckNSDSWFCE911UpdateUsesBatchedChallengeResponse(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "server rejects standalone challenge response"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challengeText := nsdsAKAChallengeText(t)
			var calls int
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				requests := readNSDSRequests(t, req)
				calls++
				switch calls {
				case 1:
					checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication})
					writeNSDSResponses(t, w, []nsdsResponse{{
						MessageID:    nsdsMessageID3GPPAuthentication,
						Method:       nsdsMethod3GPPAuthentication,
						ResponseCode: nsdsResponseAKAChallenge,
						AKAChallenge: challengeText,
						AKAToken:     "aka-token",
					}})
				case 2:
					if len(requests) == 1 && requests[0].Method == nsdsMethod3GPPAuthentication {
						writeNSDSResponses(t, w, []nsdsResponse{{
							MessageID:    nsdsMessageID3GPPAuthentication,
							Method:       nsdsMethod3GPPAuthentication,
							ResponseCode: nsdsResponseInvalidRequest,
						}})
						return
					}
					checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication, nsdsMethodServiceEntitlement, nsdsMethodGetMSISDN})
					if requests[0].AKAChallengeRsp == "" {
						t.Fatal("aka-challenge-rsp is empty")
					}
					if requests[0].AKAToken != "" {
						t.Fatalf("aka-token = %q, want empty", requests[0].AKAToken)
					}
					writeNSDSResponses(t, w, []nsdsResponse{
						{MessageID: nsdsMessageID3GPPAuthentication, Method: nsdsMethod3GPPAuthentication, ResponseCode: nsdsResponseSuccessful, AKAToken: "aka-token"},
						{
							MessageID:    nsdsMessageIDServiceEntitlement,
							Method:       nsdsMethodServiceEntitlement,
							ResponseCode: nsdsResponseSuccessful,
							ServiceEntitlementList: []serviceEntitlement{{
								ServiceName:       nsdsServiceVowifi,
								EntitlementStatus: nsdsResponseSuccessful,
							}},
						},
						{
							MessageID:          nsdsMessageIDGetMSISDN,
							Method:             nsdsMethodGetMSISDN,
							ResponseCode:       nsdsResponseSuccessful,
							ServiceFingerprint: "fingerprint-1",
						},
					})
				case 3:
					checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication, nsdsMethodManageLocationAndTC})
					if requests[0].AKAChallengeRsp != "" {
						t.Fatalf("aka-challenge-rsp = %q, want empty", requests[0].AKAChallengeRsp)
					}
					if requests[0].AKAToken != "aka-token" {
						t.Fatalf("aka-token = %q, want aka-token", requests[0].AKAToken)
					}
					if requests[1].ServiceFingerprint != "fingerprint-1" {
						t.Fatalf("service-fingerprint = %q, want fingerprint-1", requests[1].ServiceFingerprint)
					}
					writeNSDSResponses(t, w, []nsdsResponse{
						{MessageID: nsdsMessageID3GPPAuthentication, Method: nsdsMethod3GPPAuthentication, ResponseCode: nsdsResponseSuccessful},
						{
							MessageID:      nsdsMessageIDManageLocationAndTC,
							Method:         nsdsMethodManageLocationAndTC,
							ResponseCode:   nsdsResponseSuccessful,
							LocationStatus: boolPtr(true),
							TCStatus:       boolPtr(true),
							ServerURL:      "https://example.test/e911",
							ServerData:     "token=accepted",
						},
					})
				default:
					t.Fatalf("unexpected request %d", calls)
				}
			}))
			defer server.Close()

			cfg := Config{
				Logger: slog.Default(),
				Terminal: TerminalInfo{
					ID:              testIMEI,
					Model:           "Pixel",
					SoftwareVersion: "13",
				},
			}
			client := newClient(cfg)
			result, err := client.checkNSDSWFCEntitlement(context.Background(), WFCEntitlementRequest{
				Config:  &cfg,
				Card:    nsdsTestCard{},
				Purpose: WFCEntitlementEmergencyAddressUpdate,
			}, nsdsWFCProfile{
				Carrier:    "AT&T",
				ServerURL:  server.URL,
				Title:      "Wi-Fi Calling",
				ClientName: "WiFiCallingWebViewController",
			})
			if err != nil {
				t.Fatalf("checkNSDSWFCEntitlement() error = %v", err)
			}
			if result.Action != WFCEntitlementActionOpenWebsheet {
				t.Fatalf("Action = %v, want %v", result.Action, WFCEntitlementActionOpenWebsheet)
			}
			if result.Websheet == nil {
				t.Fatal("Websheet is nil")
			}
			if calls != 3 {
				t.Fatalf("server calls = %d, want 3", calls)
			}
		})
	}
}

func TestNSDSWFCPublicMSISDN(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "ten digit us", in: "5551234567", want: "+15551234567"},
		{name: "eleven digit us", in: "15551234567", want: "+15551234567"},
		{name: "already e164", in: "+15551234567", want: "+15551234567"},
		{name: "unknown format", in: "441234567890", want: "441234567890"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nsdsWFCPublicMSISDN(tt.in); got != tt.want {
				t.Fatalf("nsdsWFCPublicMSISDN() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNSDSWFCIMSIEAPPadsTwoDigitMNC(t *testing.T) {
	tests := []struct {
		name string
		card Card
		want string
	}{
		{
			name: "two digit mnc",
			card: nsdsTwoDigitMNCTestCard{},
			want: "020420123456789@nai.epc.mnc020.mcc204.3gppnetwork.org",
		},
		{
			name: "padded two digit mnc",
			card: nsdsPaddedTwoDigitMNCTestCard{},
			want: "020420123456789@nai.epc.mnc020.mcc204.3gppnetwork.org",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nsdsWFCIMSIEAP(tt.card)
			if err != nil {
				t.Fatalf("nsdsWFCIMSIEAP() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("nsdsWFCIMSIEAP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNSDSWFCDeviceID(t *testing.T) {
	tests := []struct {
		name string
		imei string
		want string
	}{
		{
			name: "imei urn",
			imei: "869710031623444",
			want: "dXJuOmdzbWE6aW1laTo4Njk3MTAwMy0xNjIzNDQtMA==",
		},
		{
			name: "already formatted fallback",
			imei: "urn:uuid:abc",
			want: "dXJuOnV1aWQ6YWJj",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nsdsWFCDeviceID(tt.imei); got != tt.want {
				t.Fatalf("nsdsWFCDeviceID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNSDSVowifiEntitled(t *testing.T) {
	tests := []struct {
		name   string
		status int
		onDmd  *bool
		want   bool
	}{
		{name: "success", status: nsdsResponseSuccessful, want: true},
		{name: "on demand provisioning", status: nsdsResponseServiceNotEntitled, onDmd: boolPtr(true), want: true},
		{name: "not entitled without on demand", status: nsdsResponseServiceNotEntitled, onDmd: boolPtr(false)},
		{name: "server suspended is not success", status: nsdsResponseServerSuspended},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nsdsVowifiEntitled(nsdsResponse{
				ServiceEntitlementList: []serviceEntitlement{{
					ServiceName:       nsdsServiceVowifi,
					EntitlementStatus: tt.status,
					OnDemandProv:      tt.onDmd,
				}},
			})
			if got != tt.want {
				t.Fatalf("nsdsVowifiEntitled() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestNSDSResponseCodeName(t *testing.T) {
	tests := []struct {
		name string
		code int
		want string
	}{
		{name: "success", code: nsdsResponseSuccessful, want: "REQUEST_SUCCESSFUL"},
		{name: "challenge", code: nsdsResponseAKAChallenge, want: "REQUEST_AKA_CHALLENGE"},
		{name: "invalid request", code: nsdsResponseInvalidRequest, want: "ERROR_INVALID_REQUEST"},
		{name: "service not entitled", code: nsdsResponseServiceNotEntitled, want: "ERROR_SERVICE_NOT_ENTITLED"},
		{name: "server suspended", code: nsdsResponseServerSuspended, want: "ERROR_SERVER_SUSPENDED"},
		{name: "unknown", code: 12345, want: "ERROR_UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nsdsResponseCodeName(tt.code); got != tt.want {
				t.Fatalf("nsdsResponseCodeName(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestNSDSDefinedResponseCodeName(t *testing.T) {
	tests := []struct {
		name string
		code int
		want string
	}{
		{name: "unknown", code: nsdsDefinedUnknown, want: "UNKNOWN"},
		{name: "request auth failure", code: nsdsDefinedRequest3GPPAuthGenFailure, want: "REQUEST_3GPP_AUTH_GEN_FAILURE"},
		{name: "aka auth failed", code: nsdsDefinedAKAAuthFailed, want: "AKA_AUTH_FAILED"},
		{name: "manage service provision failure", code: nsdsDefinedManageServiceProvisionFailed, want: "MANAGE_SERVICE_PROVISION_GEN_FAILURE"},
		{name: "location update cancel", code: nsdsDefinedLocationTCUpdateCancel, want: "LOCATIONANDTC_UPDATE_CANCEL_CODE"},
		{name: "unknown code", code: 12345, want: "ERROR_UNKNOWN"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nsdsDefinedResponseCodeName(tt.code); got != tt.want {
				t.Fatalf("nsdsDefinedResponseCodeName(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

func TestNSDSRequireResponseCodeIncludesName(t *testing.T) {
	err := nsdsRequireResponseCode(nsdsResponse{
		MessageID:    nsdsMessageID3GPPAuthentication,
		ResponseCode: nsdsResponseInvalidRequest,
	}, nsdsResponseSuccessful, nsdsMethod3GPPAuthentication)
	if err == nil {
		t.Fatal("nsdsRequireResponseCode() error is nil")
	}
	if got := err.Error(); !strings.Contains(got, "ERROR_INVALID_REQUEST") || !strings.Contains(got, "REQUEST_SUCCESSFUL") {
		t.Fatalf("error = %q, want response code names", got)
	}
}

func TestWFCE911InfoValidAt(t *testing.T) {
	now := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		info WFCE911Info
		want bool
	}{
		{name: "missing expiration"},
		{name: "less than safety window", info: WFCE911Info{AIDExpiration: now.Add(47 * time.Hour)}},
		{name: "at safety window", info: WFCE911Info{AIDExpiration: now.Add(48 * time.Hour)}, want: true},
		{name: "beyond safety window", info: WFCE911Info{AIDExpiration: now.Add(72 * time.Hour)}, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.ValidAt(now); got != tt.want {
				t.Fatalf("ValidAt() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestNSDSAIDExpirationText(t *testing.T) {
	want := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name string
		text string
		want time.Time
	}{
		{name: "rfc3339", text: "2030-01-01T00:00:00Z", want: want},
		{name: "millisecond zone offset", text: "2030-01-01T00:00:00.000Z+0000", want: want},
		{name: "zone offset", text: "2030-01-01T00:00:00Z+0000", want: want},
		{name: "blank"},
		{name: "invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got nsdsAIDExpiration
			if err := got.UnmarshalText([]byte(tt.text)); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if !got.Time.Equal(tt.want) {
				t.Fatalf("Time = %s, want %s", got.Time, tt.want)
			}
			text, err := got.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if tt.want.IsZero() && len(text) != 0 {
				t.Fatalf("MarshalText() = %q, want empty", text)
			}
			if !tt.want.IsZero() && string(text) != tt.want.Format(time.RFC3339Nano) {
				t.Fatalf("MarshalText() = %q, want %q", text, tt.want.Format(time.RFC3339Nano))
			}
		})
	}
}

type nsdsTestCard struct{}

func (nsdsTestCard) ICCID() string { return "" }
func (nsdsTestCard) IMSI() string  { return "310030123456789" }
func (nsdsTestCard) MCC() string   { return "310" }
func (nsdsTestCard) MNC() string   { return "030" }
func (nsdsTestCard) SMSC() string  { return "" }
func (nsdsTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: bytes.Repeat([]byte{0x01}, 8),
		CK:  bytes.Repeat([]byte{0x02}, 16),
		IK:  bytes.Repeat([]byte{0x03}, 16),
	}, nil
}

func newNSDSWFCTestServer(t *testing.T, locationTC nsdsResponse) *httptest.Server {
	t.Helper()
	challengeText := nsdsAKAChallengeText(t)
	var calls int

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", req.Method)
		}
		if got := req.Header.Get("Content-Encoding"); got != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", got)
		}
		if got := req.Header.Get("Accept-Encoding"); got != "gzip" {
			t.Fatalf("Accept-Encoding = %q, want gzip", got)
		}

		requests := readNSDSRequests(t, req)
		calls++
		switch calls {
		case 1:
			checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication})
			writeNSDSResponses(t, w, []nsdsResponse{{
				MessageID:    nsdsMessageID3GPPAuthentication,
				Method:       nsdsMethod3GPPAuthentication,
				ResponseCode: nsdsResponseAKAChallenge,
				AKAChallenge: challengeText,
				AKAToken:     "aka-token",
			}})
		case 2:
			wantMethods := []string{nsdsMethod3GPPAuthentication, nsdsMethodServiceEntitlement}
			if len(requests) == 3 {
				wantMethods = append(wantMethods, nsdsMethodGetMSISDN)
			}
			checkNSDSMethods(t, requests, wantMethods)
			if requests[0].AKAChallengeRsp == "" {
				t.Fatal("aka-challenge-rsp is empty")
			}
			if requests[0].AKAToken != "" {
				t.Fatalf("aka-token = %q, want empty", requests[0].AKAToken)
			}
			responses := []nsdsResponse{
				{MessageID: nsdsMessageID3GPPAuthentication, Method: nsdsMethod3GPPAuthentication, ResponseCode: nsdsResponseSuccessful, AKAToken: "aka-token"},
				{
					MessageID:    nsdsMessageIDServiceEntitlement,
					Method:       nsdsMethodServiceEntitlement,
					ResponseCode: nsdsResponseSuccessful,
					ServiceEntitlementList: []serviceEntitlement{{
						ServiceName:       nsdsServiceVowifi,
						EntitlementStatus: nsdsResponseSuccessful,
					}},
				},
			}
			if len(requests) == 3 {
				responses = append(responses, nsdsResponse{
					MessageID:          nsdsMessageIDGetMSISDN,
					Method:             nsdsMethodGetMSISDN,
					ResponseCode:       nsdsResponseSuccessful,
					ServiceFingerprint: "fingerprint-1",
				})
			}
			writeNSDSResponses(t, w, responses)
		case 3:
			checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication, nsdsMethodManageLocationAndTC})
			if requests[0].AKAChallengeRsp != "" {
				t.Fatalf("aka-challenge-rsp = %q, want empty", requests[0].AKAChallengeRsp)
			}
			if requests[0].AKAToken != "aka-token" {
				t.Fatalf("aka-token = %q, want aka-token", requests[0].AKAToken)
			}
			if requests[1].ServiceFingerprint != "fingerprint-1" {
				t.Fatalf("service-fingerprint = %q, want fingerprint-1", requests[1].ServiceFingerprint)
			}
			writeNSDSResponses(t, w, []nsdsResponse{
				{MessageID: nsdsMessageID3GPPAuthentication, Method: nsdsMethod3GPPAuthentication, ResponseCode: nsdsResponseSuccessful},
				locationTC,
			})
		default:
			t.Fatalf("unexpected request %d", calls)
		}
	}))
}

func readNSDSRequests(t *testing.T, req *http.Request) []nsdsRequest {
	t.Helper()
	reader, err := gzip.NewReader(req.Body)
	if err != nil {
		t.Fatalf("gzip.NewReader() error = %v", err)
	}
	defer reader.Close()

	var requests []nsdsRequest
	if err := json.NewDecoder(reader).Decode(&requests); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	return requests
}

func checkNSDSMethods(t *testing.T, requests []nsdsRequest, want []string) {
	t.Helper()
	got := make([]string, len(requests))
	for i, req := range requests {
		got[i] = req.Method
	}
	if !slices.Equal(got, want) {
		t.Fatalf("methods = %v, want %v", got, want)
	}
}

type nsdsTwoDigitMNCTestCard struct{ nsdsTestCard }

func (nsdsTwoDigitMNCTestCard) IMSI() string { return "20420123456789" }
func (nsdsTwoDigitMNCTestCard) MCC() string  { return "204" }
func (nsdsTwoDigitMNCTestCard) MNC() string  { return "20" }

type nsdsPaddedTwoDigitMNCTestCard struct{ nsdsTestCard }

func (nsdsPaddedTwoDigitMNCTestCard) IMSI() string   { return "20420123456789" }
func (nsdsPaddedTwoDigitMNCTestCard) MCC() string    { return "204" }
func (nsdsPaddedTwoDigitMNCTestCard) MNC() string    { return "020" }
func (nsdsPaddedTwoDigitMNCTestCard) MNCLength() int { return 2 }

func writeNSDSResponses(t *testing.T, w http.ResponseWriter, responses []nsdsResponse) {
	t.Helper()
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "application/json")
	writer := gzip.NewWriter(w)
	if err := json.NewEncoder(writer).Encode(responses); err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func nsdsAKAChallengeText(t *testing.T) string {
	t.Helper()
	challenge := sim.AKAChallenge{
		Identifier: 1,
		Rand:       bytes.Repeat([]byte{0x11}, 16),
		Autn:       bytes.Repeat([]byte{0x22}, 16),
	}
	text, err := challenge.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	return string(text)
}
