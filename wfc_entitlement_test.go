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
		name    string
		body    string
		wantErr error
		check   func(t *testing.T, err error)
	}{
		{
			name: "entitled",
			body: `<wap-provisioningdoc><characteristic type="APPLICATION"><parm name="AppID" value="ap2004"/><parm name="EntitlementStatus" value="1"/><parm name="TC_Status" value="2"/><parm name="AddrStatus" value="2"/><parm name="ProvStatus" value="2"/></characteristic></wap-provisioningdoc>`,
		},
		{
			name:    "needs user web flow",
			body:    `<wap-provisioningdoc><characteristic type="APPLICATION"><parm name="AppID" value="ap2004"/><parm name="EntitlementStatus" value="0"/><parm name="TC_Status" value="0"/><parm name="AddrStatus" value="0"/><parm name="ProvStatus" value="0"/><parm name="ServiceFlow_URL" value="https://example.test/e911"/><parm name="ServiceFlow_UserData" value="token=abc"/></characteristic></wap-provisioningdoc>`,
			wantErr: ErrWFCEntitlementUserActionRequired,
			check: func(t *testing.T, err error) {
				t.Helper()
				var entitlementErr *WFCEntitlementError
				if !errors.As(err, &entitlementErr) {
					t.Fatalf("error = %T, want *WFCEntitlementError", err)
				}
				if entitlementErr.Status.ServiceFlowURL != "https://example.test/e911" {
					t.Fatalf("ServiceFlowURL = %q", entitlementErr.Status.ServiceFlowURL)
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
			err := client.checkTS43WFCEntitlement(context.Background(), &cfg, plmnWFCCard{mcc: "208", mnc: "01"}, ts43.WFCConfig{
				Server: server.URL,
				App:    ts43.AppVoWiFi,
			})
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

func TestCheckTS43WFCEntitlementHonorsSkipActivation(t *testing.T) {
	cfg := Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Logger:   slog.Default(),
	}
	client := newClient(cfg)
	err := client.checkWFCEntitlement(context.Background(), &cfg, plmnWFCCard{
		mcc:       "310",
		mnc:       "240",
		mncLength: 3,
	})
	if err != nil {
		t.Fatalf("checkWFCEntitlement() error = %v", err)
	}
}

func TestTS43RetryAfterError(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		wantOK  bool
		wantErr error
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
			wantErr: ErrWFCEntitlementPending,
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
			got, ok := ts43RetryAfterError(ts43.WFCConfig{}, tt.err)
			if ok != tt.wantOK {
				t.Fatalf("ts43RetryAfterError() ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if !errors.Is(got, tt.wantErr) {
				t.Fatalf("ts43RetryAfterError() error = %v, want %v", got, tt.wantErr)
			}
			if got.RetryAfter < tt.wantMin || got.RetryAfter > tt.wantMax {
				t.Fatalf("RetryAfter = %s, want between %s and %s", got.RetryAfter, tt.wantMin, tt.wantMax)
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
		name    string
		status  nsdsResponse
		wantErr error
		check   func(*testing.T, error)
	}{
		{
			name: "location and tc accepted",
			status: nsdsResponse{
				MessageID:      2,
				ResponseCode:   1000,
				LocationStatus: boolPtr(true),
				TCStatus:       boolPtr(true),
			},
		},
		{
			name: "needs e911 websheet",
			status: nsdsResponse{
				MessageID:      2,
				ResponseCode:   1000,
				LocationStatus: boolPtr(false),
				TCStatus:       boolPtr(false),
				ServerURL:      "https://example.test/e911",
				ServerData:     "token=abc",
			},
			wantErr: ErrWFCEntitlementUserActionRequired,
			check: func(t *testing.T, err error) {
				t.Helper()
				var entitlementErr *NSDSWFCEntitlementError
				if !errors.As(err, &entitlementErr) {
					t.Fatalf("error = %T, want *NSDSWFCEntitlementError", err)
				}
				if entitlementErr.Websheet.URL != "https://example.test/e911" {
					t.Fatalf("Websheet.URL = %q", entitlementErr.Websheet.URL)
				}
				if entitlementErr.Websheet.Data != "token=abc" {
					t.Fatalf("Websheet.Data = %q", entitlementErr.Websheet.Data)
				}
				if entitlementErr.Websheet.ClientName != "WiFiCallingWebViewController" {
					t.Fatalf("Websheet.ClientName = %q", entitlementErr.Websheet.ClientName)
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
			err := client.checkNSDSWFCEntitlement(context.Background(), &cfg, nsdsTestCard{}, profile)
			if cfg.IMS.PublicIdentity != "sip:+15551234567@ims.mnc030.mcc310.3gppnetwork.org" {
				t.Fatalf("PublicIdentity = %q, want sip:+15551234567@ims.mnc030.mcc310.3gppnetwork.org", cfg.IMS.PublicIdentity)
			}
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("checkNSDSWFCEntitlement() error = %v, want %v", err, tt.wantErr)
				}
				if tt.check != nil {
					tt.check(t, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("checkNSDSWFCEntitlement() error = %v", err)
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
			checkNSDSMethods(t, requests, []string{"3gppAuthentication"})
			writeNSDSResponses(t, w, []nsdsResponse{{
				MessageID:    1,
				Method:       "3gppAuthentication",
				ResponseCode: 1003,
				AKAChallenge: challengeText,
			}})
		case 2:
			checkNSDSMethods(t, requests, []string{"3gppAuthentication"})
			if requests[0].AKAChallengeRsp == "" {
				t.Fatal("aka-challenge-rsp is empty")
			}
			writeNSDSResponses(t, w, []nsdsResponse{
				{MessageID: 1, Method: "3gppAuthentication", ResponseCode: 1000, AKAToken: "aka-token"},
			})
		case 3:
			checkNSDSMethods(t, requests, []string{"3gppAuthentication", "serviceEntitlementStatus", "getMSISDN"})
			if requests[0].AKAToken != "aka-token" {
				t.Fatalf("aka-token = %q, want aka-token", requests[0].AKAToken)
			}
			writeNSDSResponses(t, w, []nsdsResponse{
				{MessageID: 1, Method: "3gppAuthentication", ResponseCode: 1000, AKAToken: "aka-token"},
				{
					MessageID:    2,
					Method:       "serviceEntitlementStatus",
					ResponseCode: 1000,
					ServiceEntitlementList: []serviceEntitlement{{
						ServiceName:       "vowifi",
						EntitlementStatus: 1000,
					}},
				},
				{MessageID: 3, Method: "getMSISDN", ResponseCode: 1000, MSISDN: "15551234567", ServiceFingerprint: "fingerprint"},
			})
		case 4:
			checkNSDSMethods(t, requests, []string{"3gppAuthentication", "manageLocationAndTC"})
			if requests[0].AKAToken != "aka-token" {
				t.Fatalf("aka-token = %q, want aka-token", requests[0].AKAToken)
			}
			if requests[1].ServiceFingerprint != "fingerprint" {
				t.Fatalf("service-fingerprint = %q, want fingerprint", requests[1].ServiceFingerprint)
			}
			writeNSDSResponses(t, w, []nsdsResponse{
				{MessageID: 1, Method: "3gppAuthentication", ResponseCode: 1000},
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

func boolPtr(value bool) *bool {
	return &value
}
