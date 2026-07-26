package wfcsetup

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/damonto/ims-go/eapaka"
	usim "github.com/damonto/wwan-go/sim"
)

const testAKAChallenge = "AQIAfBcBAAABBQAAXOZSkCjxysgE43GWqHJvgQIFAABrikWGrekAALNU4TxmCDPoCwUAAJT0nqXeAYlqzT0UGXINENWBBQAA7z3fhImkg+vcCKWIZBdvuYIJAAAPRUFp7KWFo+Thr78Qj9hEkB2zA0i6KakODsufBC+BJQ=="
const testTelusAKAChallengeResponse = "AgIAKBcBAAADAwBAx58CpZ/Jo48LBQAAkfZGP8zKZP5Pr0jlb913NA=="
const testO2AKAChallengeResponse = "AgIAKBcBAAADAwBAx58CpZ/Jo48LBQAA4F7rN+J4dlTRddqJyg9UYw=="

func TestDecodeEAPAKAChallengeRejectsAKAPrime(t *testing.T) {
	wire, err := (eapaka.AKAMessage{
		Code:       1,
		Identifier: 2,
		EAPType:    50,
		Subtype:    1,
		Attributes: []eapaka.AKAAttribute{
			{Type: 1, Value: append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x11}, 16)...)},
			{Type: 2, Value: append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x22}, 16)...)},
			{Type: 23, Value: []byte{0x00, 0x04, 'W', 'L', 'A', 'N'}},
			{Type: 24, Value: []byte{0x00, 0x01}},
			{Type: 11, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	challenge := base64.StdEncoding.EncodeToString(wire)
	tests := []struct {
		name string
		kind akaChallengeKind
	}{
		{name: "complete eap challenge", kind: akaChallengeKindEAPAKA},
		{name: "nsds challenge", kind: akaChallengeKindNSDS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := decodeEAPAKAChallenge(challenge, tt.kind); err == nil || !strings.Contains(err.Error(), "unsupported") {
				t.Fatalf("decodeEAPAKAChallenge() error = %v, want unsupported AKA prime", err)
			}
		})
	}
}

func testAKAResult(t *testing.T) usim.AKAResult {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString("2wjHnwKln8mjjxDzMKJvLBzMHtm0X9SNBsUWEAbEiAdD7xeqqZ7nsXzukRkIhd6SDZ4bj7s=")
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	if len(data) < 1 || data[0] != 0xdb {
		t.Fatalf("AKA response = % X, want success security context", data)
	}
	res, off := testAKAChunk(t, data, 1, "RES")
	ck, off := testAKAChunk(t, data, off, "CK")
	ik, _ := testAKAChunk(t, data, off, "IK")
	return usim.AKAResult{
		RES: res,
		CK:  ck,
		IK:  ik,
	}
}

func testAKAChunk(t *testing.T, data []byte, off int, name string) ([]byte, int) {
	t.Helper()
	if off >= len(data) {
		t.Fatalf("%s length is missing", name)
	}
	n := int(data[off])
	off++
	if n > len(data)-off {
		t.Fatalf("%s length %d exceeds remaining data %d", name, n, len(data)-off)
	}
	return append([]byte(nil), data[off:off+n]...), off + n
}

func TestTelusCheckRunsEWGFlow(t *testing.T) {
	card := testCard{mcc: "302", mnc: "220", mncLength: 3, gid1: "5455", aka: testAKAResult(t)}
	var postBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/androidgw/entitlements/"+card.IMSI() && req.URL.RawQuery == "":
			_, _ = io.WriteString(w, `{"eapChallengeResponse":"`+testAKAChallenge+`"}`)
		case req.Method == http.MethodPost && req.URL.Path == "/androidgw/eap-aka/dialog":
			data, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatalf("ReadAll() error = %v", err)
			}
			postBody = string(data)
			w.Header().Set("Location", "/callback?access_token=access-token")
			w.WriteHeader(http.StatusFound)
		case req.Method == http.MethodGet && req.URL.Path == "/androidgw/entitlements/"+card.IMSI() && req.URL.Query().Get("access_token") == "access-token":
			_, _ = io.WriteString(w, `[{"type":"volte","status":"enabled"},{"type":"vowifi","status":"enabled"}]`)
		case req.Method == http.MethodGet && req.URL.Path == "/androidgw/servicePolicies/"+card.IMSI() && req.URL.Query().Get("access_token") == "access-token":
			_, _ = io.WriteString(w, `{"managementUrl":{"url":"https://telus.example/manage","access_token":"web-token"},"servicePolicies":["no-usr-def-n911-addr"]}`)
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.String())
		}
	}))
	defer server.Close()

	got, err := Check(context.Background(), Request{
		Card:            card,
		AuthenticateAKA: card.AKA,
		Purpose:         PurposeActivation,
		HTTPClient:      testSetupHTTPClient(t, server.URL),
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if !strings.Contains(postBody, `"eapChallengeResponse":"`+testTelusAKAChallengeResponse+`"`) {
		t.Fatalf("POST body = %s, want challenge response", postBody)
	}
	if got.Scheme != SchemeTelus || got.Action != ActionOpenWebsheet || !got.Entitled {
		t.Fatalf("Result = %+v, want telus websheet", got)
	}
	if got.Token == nil || got.Token.Value != "access-token" {
		t.Fatalf("Token = %+v, want access-token", got.Token)
	}
	if got.Websheet == nil || got.Websheet.Kind != WebsheetKindEmergencyAddress {
		t.Fatalf("Websheet = %+v, want emergency address", got.Websheet)
	}
	wantURL := "https://telus.example/manage?page=no-usr-def-n911-addr&access_token=web-token"
	if got.Websheet.URL != wantURL {
		t.Fatalf("Websheet.URL = %q, want %q", got.Websheet.URL, wantURL)
	}
}

func TestTelusCheckMapsEWGOutcomes(t *testing.T) {
	card := testCard{mcc: "302", mnc: "220", mncLength: 3, gid1: "5455", aka: testAKAResult(t)}
	tests := []struct {
		name          string
		entitlements  string
		policies      string
		wantAction    Action
		wantEntitled  bool
		wantPending   bool
		wantWebKind   WebsheetKind
		wantWebURL    string
		wantPolicyHit bool
	}{
		{
			name:         "enabled and complete allows activation",
			entitlements: `[{"type":"vowifi","status":"enabled"}]`,
			policies:     `{"managementUrl":{"url":"https://telus.example/manage","access_token":"web-token"},"servicePolicies":["e911-addr-not-reqd","tnc-usr-acpt-not-reqd"]}`,
			wantAction:   ActionAllowActivation,
			wantEntitled: true,
		},
		{
			name:         "pending asks caller to wait",
			entitlements: `[{"type":"vowifi","status":"pending"}]`,
			wantAction:   ActionWait,
			wantPending:  true,
		},
		{
			name:         "disabled denies activation",
			entitlements: `[{"type":"vowifi","status":"disabled"}]`,
			wantAction:   ActionDenied,
		},
		{
			name:          "terms policy opens terms websheet",
			entitlements:  `[{"type":"vowifi","status":"enabled"}]`,
			policies:      `{"managementUrl":{"url":"https://telus.example/manage","access_token":"web-token"},"servicePolicies":["no-tnc-usr-acpt"]}`,
			wantAction:    ActionOpenWebsheet,
			wantEntitled:  true,
			wantWebKind:   WebsheetKindTermsAndConditions,
			wantWebURL:    "https://telus.example/manage?page=no-tnc-usr-acpt&access_token=web-token",
			wantPolicyHit: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var policyHit bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				switch {
				case req.Method == http.MethodGet && req.URL.Path == "/androidgw/entitlements/"+card.IMSI() && req.URL.RawQuery == "":
					_, _ = io.WriteString(w, `{"eapChallengeResponse":"`+testAKAChallenge+`"}`)
				case req.Method == http.MethodPost && req.URL.Path == "/androidgw/eap-aka/dialog":
					w.Header().Set("Location", "/callback?access_token=access-token")
					w.WriteHeader(http.StatusFound)
				case req.Method == http.MethodGet && req.URL.Path == "/androidgw/entitlements/"+card.IMSI():
					if req.URL.Query().Get("access_token") != "access-token" {
						t.Fatalf("access_token = %q, want access-token", req.URL.Query().Get("access_token"))
					}
					_, _ = io.WriteString(w, tt.entitlements)
				case req.Method == http.MethodGet && req.URL.Path == "/androidgw/servicePolicies/"+card.IMSI():
					policyHit = true
					_, _ = io.WriteString(w, tt.policies)
				default:
					t.Fatalf("unexpected request: %s %s", req.Method, req.URL.String())
				}
			}))
			defer server.Close()

			got, err := Check(context.Background(), Request{
				Card:            card,
				AuthenticateAKA: card.AKA,
				Purpose:         PurposeActivation,
				HTTPClient:      testSetupHTTPClient(t, server.URL),
			})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if got.Action != tt.wantAction || got.Entitled != tt.wantEntitled || got.Pending != tt.wantPending {
				t.Fatalf("Result = %+v, want action=%v entitled=%t pending=%t", got, tt.wantAction, tt.wantEntitled, tt.wantPending)
			}
			if policyHit != tt.wantPolicyHit && tt.wantAction != ActionAllowActivation {
				t.Fatalf("policyHit = %t, want %t", policyHit, tt.wantPolicyHit)
			}
			if tt.wantWebURL == "" {
				return
			}
			if got.Websheet == nil {
				t.Fatal("Websheet is nil")
			}
			if got.Websheet.Kind != tt.wantWebKind || got.Websheet.URL != tt.wantWebURL {
				t.Fatalf("Websheet = %+v, want kind=%q url=%q", got.Websheet, tt.wantWebKind, tt.wantWebURL)
			}
		})
	}
}

func TestTelusCheckRetriesTransientEWGFailure(t *testing.T) {
	card := testCard{mcc: "302", mnc: "220", mncLength: 3, gid1: "5455", aka: testAKAResult(t)}
	var entitlementHits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == http.MethodGet && req.URL.Path == "/androidgw/entitlements/"+card.IMSI() && req.URL.RawQuery == "":
			_, _ = io.WriteString(w, `{"eapChallengeResponse":"`+testAKAChallenge+`"}`)
		case req.Method == http.MethodPost && req.URL.Path == "/androidgw/eap-aka/dialog":
			w.Header().Set("Location", "/callback?access_token=access-token")
			w.WriteHeader(http.StatusFound)
		case req.Method == http.MethodGet && req.URL.Path == "/androidgw/entitlements/"+card.IMSI():
			entitlementHits++
			if entitlementHits == 1 {
				http.Error(w, "try again", http.StatusServiceUnavailable)
				return
			}
			_, _ = io.WriteString(w, `[{"type":"vowifi","status":"enabled"}]`)
		case req.Method == http.MethodGet && req.URL.Path == "/androidgw/servicePolicies/"+card.IMSI():
			_, _ = io.WriteString(w, `{"managementUrl":{"url":"https://telus.example/manage","access_token":"web-token"},"servicePolicies":["e911-addr-not-reqd"]}`)
		default:
			t.Fatalf("unexpected request: %s %s", req.Method, req.URL.String())
		}
	}))
	defer server.Close()

	got, err := Check(context.Background(), Request{
		Card:            card,
		AuthenticateAKA: card.AKA,
		Purpose:         PurposeActivation,
		HTTPClient:      testSetupHTTPClient(t, server.URL),
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if entitlementHits != 2 {
		t.Fatalf("entitlementHits = %d, want 2", entitlementHits)
	}
	if got.Action != ActionAllowActivation || !got.Entitled {
		t.Fatalf("Result = %+v, want allow activation", got)
	}
}

func TestTelusCarrierMatching(t *testing.T) {
	tests := []struct {
		name        string
		card        testCard
		wantMatch   bool
		wantCarrier string
	}{
		{
			name:        "telus 302220",
			card:        testCard{mcc: "302", mnc: "220", mncLength: 3, gid1: "5455"},
			wantMatch:   true,
			wantCarrier: "TELUS",
		},
		{
			name:        "koodo 302220",
			card:        testCard{mcc: "302", mnc: "220", mncLength: 3, gid1: "4B4F"},
			wantMatch:   true,
			wantCarrier: "Koodo",
		},
		{
			name:        "public mobile 302220",
			card:        testCard{mcc: "302", mnc: "220", mncLength: 3, gid1: "4D4F"},
			wantMatch:   true,
			wantCarrier: "Public Mobile",
		},
		{
			name:      "cloudcore does not match telus group",
			card:      testCard{mcc: "302", mnc: "221", mncLength: 3, gid1: "4C4F"},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Request{Card: tt.card}
			if got := isTelusCarrier(req); got != tt.wantMatch {
				t.Fatalf("isTelusCarrier() = %t, want %t", got, tt.wantMatch)
			}
			if !tt.wantMatch {
				return
			}
			if got := telusCarrierName(req); got != tt.wantCarrier {
				t.Fatalf("telusCarrierName() = %q, want %q", got, tt.wantCarrier)
			}
		})
	}
}

func TestO2UKCheckRunsGenericDevicesFlow(t *testing.T) {
	card := testCard{mcc: "234", mnc: "10", mncLength: 2, aka: testAKAResult(t)}
	o2UKForgetToken(card)
	var requests [][]map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", req.Method)
		}
		if req.Header.Get("Content-Encoding") != "gzip" {
			t.Fatalf("Content-Encoding = %q, want gzip", req.Header.Get("Content-Encoding"))
		}
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			t.Fatalf("gzip.NewReader() error = %v", err)
		}
		data, err := io.ReadAll(gz)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		var body []map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		requests = append(requests, body)
		if len(requests) == 1 {
			_, _ = io.WriteString(w, `[{"message-id":1,"response-code":1000,"aka-challenge":"`+testAKAChallenge+`"}]`)
			return
		}
		_, _ = io.WriteString(w, `[
			{"message-id":1,"response-code":1000,"aka-token":"aka-token"},
			{"message-id":2,"response-code":1000,"poll-interval":60,"service-entitlement":[
				{"service-name":"VoLTE","entitlement-status":1000},
				{"service-name":"VoWiFi","entitlement-status":1000}
			]},
			{"message-id":3,"response-code":1000}
		]`)
	}))
	defer server.Close()

	got, err := Check(context.Background(), Request{
		Card:            card,
		AuthenticateAKA: card.AKA,
		Device:          Device{IMEI: "123456789012345", Model: "Pixel"},
		Purpose:         PurposeActivation,
		HTTPClient:      testSetupHTTPClient(t, server.URL),
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got.Scheme != SchemeO2UK || got.Action != ActionAllowActivation || !got.Entitled {
		t.Fatalf("Result = %+v, want o2 allow activation", got)
	}
	if got.Token == nil || got.Token.Value != "aka-token" {
		t.Fatalf("Token = %+v, want aka-token", got.Token)
	}
	if len(requests) != 2 {
		t.Fatalf("len(requests) = %d, want 2", len(requests))
	}
	if requests[1][0]["aka-challenge-rsp"] != testO2AKAChallengeResponse {
		t.Fatalf("second auth request = %+v, want challenge response", requests[1][0])
	}
	services, ok := requests[1][1]["service-list"].([]any)
	if !ok || len(services) != 2 || services[0] != "VoLTE" || services[1] != "VoWiFi" {
		t.Fatalf("service-list = %+v, want VoLTE and VoWiFi", requests[1][1]["service-list"])
	}
}

func TestO2UKCheckReusesCachedAKAToken(t *testing.T) {
	card := testCard{mcc: "234", mnc: "10", mncLength: 2, aka: testAKAResult(t)}
	o2UKStoreToken(card, "cached-token")
	defer o2UKForgetToken(card)

	var requests [][]map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			t.Fatalf("gzip.NewReader() error = %v", err)
		}
		data, err := io.ReadAll(gz)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		var body []map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		requests = append(requests, body)
		_, _ = io.WriteString(w, `[
			{"message-id":1,"response-code":1000},
			{"message-id":2,"response-code":1000,"service-entitlement":[{"service-name":"VoWiFi","entitlement-status":1000}]},
			{"message-id":3,"response-code":1000}
		]`)
	}))
	defer server.Close()

	got, err := Check(context.Background(), Request{
		Card:            card,
		AuthenticateAKA: card.AKA,
		Device:          Device{IMEI: "123456789012345", Model: "Pixel"},
		Purpose:         PurposeActivation,
		HTTPClient:      testSetupHTTPClient(t, server.URL),
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got.Action != ActionAllowActivation || !got.Entitled {
		t.Fatalf("Result = %+v, want allow activation", got)
	}
	if len(requests) != 1 {
		t.Fatalf("len(requests) = %d, want 1", len(requests))
	}
	if requests[0][0]["aka-token"] != "cached-token" {
		t.Fatalf("auth request = %+v, want cached token", requests[0][0])
	}
	if _, ok := requests[0][0]["aka-challenge-rsp"]; ok {
		t.Fatalf("auth request = %+v, did not want challenge response", requests[0][0])
	}
}

func TestO2UKCheckContinuesWithoutInitialAKAChallenge(t *testing.T) {
	card := testCard{mcc: "234", mnc: "10", mncLength: 2, aka: testAKAResult(t)}
	o2UKForgetToken(card)

	var requests [][]map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			t.Fatalf("gzip.NewReader() error = %v", err)
		}
		data, err := io.ReadAll(gz)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		var body []map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		requests = append(requests, body)
		if len(requests) == 1 {
			_, _ = io.WriteString(w, `[{"message-id":1,"response-code":1000}]`)
			return
		}
		_, _ = io.WriteString(w, `[
			{"message-id":1,"response-code":1000},
			{"message-id":2,"response-code":1000,"service-entitlement":[{"service-name":"VoWiFi","entitlement-status":1000}]},
			{"message-id":3,"response-code":1000}
		]`)
	}))
	defer server.Close()

	got, err := Check(context.Background(), Request{
		Card:            card,
		AuthenticateAKA: card.AKA,
		Device:          Device{IMEI: "123456789012345", Model: "Pixel"},
		Purpose:         PurposeActivation,
		HTTPClient:      testSetupHTTPClient(t, server.URL),
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got.Action != ActionAllowActivation || !got.Entitled {
		t.Fatalf("Result = %+v, want allow activation", got)
	}
	if len(requests) != 2 {
		t.Fatalf("len(requests) = %d, want 2", len(requests))
	}
	if _, ok := requests[1][0]["aka-challenge-rsp"]; ok {
		t.Fatalf("second auth request = %+v, did not want challenge response", requests[1][0])
	}
}

func TestO2UKCarrierMatching(t *testing.T) {
	tests := []struct {
		name      string
		card      testCard
		wantMatch bool
	}{
		{
			name:      "o2 postpaid broad profile",
			card:      testCard{mcc: "234", mnc: "10", mncLength: 2},
			wantMatch: true,
		},
		{
			name:      "o2 postpaid with three digit mnc",
			card:      testCard{mcc: "234", mnc: "010", mncLength: 3},
			wantMatch: true,
		},
		{
			name:      "giffgaff gid is excluded",
			card:      testCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "50"},
			wantMatch: false,
		},
		{
			name:      "giffgaff padded gid is excluded",
			card:      testCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "508FFFFFFFFF4D564E4520202020202020202020"},
			wantMatch: false,
		},
		{
			name:      "giffgaff gid is excluded with three digit mnc",
			card:      testCard{mcc: "234", mnc: "010", mncLength: 3, gid1: "50"},
			wantMatch: false,
		},
		{
			name:      "o2 prepaid gid is excluded",
			card:      testCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "61"},
			wantMatch: false,
		},
		{
			name:      "tesco gid is excluded",
			card:      testCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "0A"},
			wantMatch: false,
		},
		{
			name:      "neighboring gid remains o2",
			card:      testCard{mcc: "234", mnc: "10", mncLength: 2, gid1: "51FFFFFFFF"},
			wantMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isO2UKCarrier(Request{Card: tt.card})
			if got != tt.wantMatch {
				t.Fatalf("isO2UKCarrier() = %t, want %t", got, tt.wantMatch)
			}
		})
	}
}

func TestO2UKCheckMapsGenericDevicesOutcomes(t *testing.T) {
	card := testCard{mcc: "234", mnc: "10", mncLength: 2, aka: testAKAResult(t)}
	tests := []struct {
		name         string
		response     string
		wantAction   Action
		wantEntitled bool
		wantPending  bool
		wantErr      error
	}{
		{
			name: "full authentication success",
			response: `[
				{"message-id":1,"response-code":1000},
				{"message-id":2,"response-code":1000,"service-entitlement":[{"service-name":"VoWiFi","entitlement-status":1000}]},
				{"message-id":3,"response-code":1000}
			]`,
			wantAction:   ActionAllowActivation,
			wantEntitled: true,
		},
		{
			name: "server transient asks caller to wait",
			response: `[
				{"message-id":1,"response-code":1000},
				{"message-id":2,"response-code":1006,"poll-interval":30},
				{"message-id":3,"response-code":1000}
			]`,
			wantAction:  ActionWait,
			wantPending: true,
		},
		{
			name: "not entitled denies activation",
			response: `[
				{"message-id":1,"response-code":1000},
				{"message-id":2,"response-code":1000,"service-entitlement":[{"service-name":"VoWiFi","entitlement-status":1063}]},
				{"message-id":3,"response-code":1000}
			]`,
			wantAction: ActionDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o2UKForgetToken(card)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				gz, err := gzip.NewReader(req.Body)
				if err != nil {
					t.Fatalf("gzip.NewReader() error = %v", err)
				}
				data, err := io.ReadAll(gz)
				if err != nil {
					t.Fatalf("ReadAll() error = %v", err)
				}
				var body []map[string]any
				if err := json.Unmarshal(data, &body); err != nil {
					t.Fatalf("Unmarshal() error = %v", err)
				}
				if _, ok := body[0]["aka-challenge-rsp"]; !ok {
					_, _ = io.WriteString(w, `[{"message-id":1,"response-code":1000,"aka-challenge":"`+testAKAChallenge+`"}]`)
					return
				}
				_, _ = io.WriteString(w, tt.response)
			}))
			defer server.Close()

			got, err := Check(context.Background(), Request{
				Card:            card,
				AuthenticateAKA: card.AKA,
				Device:          Device{IMEI: "123456789012345", Model: "Pixel"},
				Purpose:         PurposeActivation,
				HTTPClient:      testSetupHTTPClient(t, server.URL),
			})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("Check() error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if got.Action != tt.wantAction || got.Entitled != tt.wantEntitled || got.Pending != tt.wantPending {
				t.Fatalf("Result = %+v, want action=%v entitled=%t pending=%t", got, tt.wantAction, tt.wantEntitled, tt.wantPending)
			}
		})
	}
}

func TestO2UKCheckRetriesServerAKAChallengeWithFullAuth(t *testing.T) {
	card := testCard{mcc: "234", mnc: "10", mncLength: 2, aka: testAKAResult(t)}
	o2UKForgetToken(card)
	var requests [][]map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gz, err := gzip.NewReader(req.Body)
		if err != nil {
			t.Fatalf("gzip.NewReader() error = %v", err)
		}
		data, err := io.ReadAll(gz)
		if err != nil {
			t.Fatalf("ReadAll() error = %v", err)
		}
		var body []map[string]any
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}
		requests = append(requests, body)
		switch len(requests) {
		case 1:
			_, _ = io.WriteString(w, `[{"message-id":1,"response-code":1000,"aka-challenge":"`+testAKAChallenge+`"}]`)
		case 2:
			if !strings.Contains(string(data), `"aka-challenge-rsp":"`+testO2AKAChallengeResponse+`"`) {
				t.Fatalf("second request = %s, want challenge response", data)
			}
			_, _ = io.WriteString(w, `[{"message-id":1,"response-code":1003}]`)
		case 3:
			_, _ = io.WriteString(w, `[{"message-id":1,"response-code":1000,"aka-challenge":"`+testAKAChallenge+`"}]`)
		case 4:
			_, _ = io.WriteString(w, `[
				{"message-id":1,"response-code":1000,"aka-token":"new-token"},
				{"message-id":2,"response-code":1000,"service-entitlement":[{"service-name":"VoWiFi","entitlement-status":1000}]},
				{"message-id":3,"response-code":1000}
			]`)
		default:
			t.Fatalf("unexpected extra request %d", len(requests))
		}
	}))
	defer server.Close()

	got, err := Check(context.Background(), Request{
		Card:            card,
		AuthenticateAKA: card.AKA,
		Device:          Device{IMEI: "123456789012345", Model: "Pixel"},
		Purpose:         PurposeActivation,
		HTTPClient:      testSetupHTTPClient(t, server.URL),
	})
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got.Action != ActionAllowActivation || !got.Entitled {
		t.Fatalf("Result = %+v, want allow activation", got)
	}
	if got.Token == nil || got.Token.Value != "new-token" {
		t.Fatalf("Token = %+v, want new-token", got.Token)
	}
	if len(requests) != 4 {
		t.Fatalf("len(requests) = %d, want 4", len(requests))
	}
}

func testSetupHTTPClient(t *testing.T, endpoint string) *http.Client {
	t.Helper()
	u, err := url.Parse(endpoint)
	if err != nil {
		t.Fatalf("url.Parse() error = %v", err)
	}
	return &http.Client{Transport: testSetupTransport{server: u}}
}

type testSetupTransport struct {
	server *url.URL
}

func (tr testSetupTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.URL.Scheme = tr.server.Scheme
	clone.URL.Host = tr.server.Host
	clone.Host = tr.server.Host
	return http.DefaultTransport.RoundTrip(clone)
}
