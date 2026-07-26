package wfcsetup

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	ts43 "github.com/damonto/ts43-go"
)

func TestNSDSCheckE911UpdateUsesBatchedChallengeResponse(t *testing.T) {
	locationOK := true
	locationTC := nsdsResponse{
		MessageID:      nsdsMessageIDManageLocationAndTC,
		Method:         nsdsMethodManageLocationAndTC,
		ResponseCode:   nsdsResponseSuccessful,
		LocationStatus: &locationOK,
		TCStatus:       &locationOK,
		ServerURL:      "https://example.test/e911",
		ServerData:     "token=abc",
		AddressID:      "addr-1",
		AIDExpiration:  nsdsAIDExpiration{Time: time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		requests := readNSDSRequests(t, req)
		switch calls {
		case 1:
			checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication})
			checkNSDSMessageIDs(t, requests, []int{1})
			writeNSDSResponses(t, w, []nsdsResponse{{
				MessageID:    nsdsMessageID3GPPAuthentication,
				Method:       nsdsMethod3GPPAuthentication,
				ResponseCode: nsdsResponseAKAChallenge,
				AKAChallenge: nsdsAKAChallengeText(t),
			}})
		case 2:
			checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication, nsdsMethodServiceEntitlement, nsdsMethodGetMSISDN})
			checkNSDSMessageIDs(t, requests, []int{1, 2, 3})
			if requests[0].AKAChallengeRsp == "" {
				t.Fatal("aka-challenge-rsp is empty")
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
					MSISDN:             "5551234567",
					ServiceFingerprint: "fingerprint-1",
				},
			})
		case 3:
			checkNSDSMethods(t, requests, []string{nsdsMethod3GPPAuthentication, nsdsMethodManageLocationAndTC})
			checkNSDSMessageIDs(t, requests, []int{1, 4})
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
	defer server.Close()

	card := testCard{mcc: "310", mnc: "030", mncLength: 3, aka: testAKAResult(t)}
	got, err := (nsdsFlow{
		req: Request{
			Card:            card,
			AuthenticateAKA: card.AKA,
			Device:          Device{IMEI: "123456789012345", Model: "Pixel", SoftwareVersion: "16"},
			Purpose:         PurposeEmergencyAddressUpdate,
		},
		profile: nsdsProfile{
			Carrier:    "AT&T",
			ServerURL:  server.URL,
			Title:      "Wi-Fi Calling",
			ClientName: "WiFiCallingWebViewController",
		},
	}).Check(context.Background())
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if got.Action != ActionOpenWebsheet || !got.Entitled {
		t.Fatalf("Result = %+v, want open websheet entitled", got)
	}
	if got.MSISDN != "5551234567" {
		t.Fatalf("MSISDN = %q, want 5551234567", got.MSISDN)
	}
	if got.Websheet == nil || got.Websheet.URL != locationTC.ServerURL || got.Websheet.Data != locationTC.ServerData {
		t.Fatalf("Websheet = %+v, want location websheet", got.Websheet)
	}
	if got.E911 == nil || got.E911.AddressID != "addr-1" {
		t.Fatalf("E911 = %+v, want parsed location info", got.E911)
	}
	if calls != 3 {
		t.Fatalf("calls = %d, want 3", calls)
	}
}

func TestNSDSHelpers(t *testing.T) {
	t.Run("device id", func(t *testing.T) {
		got := nsdsDeviceID("123456789012345")
		want := "MTIzNDU2Nzg5MDEyMzQ1"
		if got != want {
			t.Fatalf("nsdsDeviceID() = %q, want %q", got, want)
		}
	})

	t.Run("two digit mnc identity", func(t *testing.T) {
		card := testCard{mcc: "204", mnc: "20", mncLength: 2}
		got, err := nsdsIMSIEAP(card)
		if err != nil {
			t.Fatalf("nsdsIMSIEAP() error = %v", err)
		}
		want := "0204200123456789@nai.epc.mnc020.mcc204.3gppnetwork.org"
		if got != want {
			t.Fatalf("nsdsIMSIEAP() = %q, want %q", got, want)
		}
	})

	t.Run("on demand entitlement", func(t *testing.T) {
		onDemand := true
		got := nsdsVowifiEntitled(nsdsResponse{
			ServiceEntitlementList: []serviceEntitlement{{
				ServiceName:       nsdsServiceVowifi,
				EntitlementStatus: nsdsResponseServiceNotEntitled,
				OnDemandProv:      &onDemand,
			}},
		})
		if !got {
			t.Fatal("nsdsVowifiEntitled() = false, want true")
		}
	})
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

func checkNSDSMessageIDs(t *testing.T, requests []nsdsRequest, want []int) {
	t.Helper()
	got := make([]int, len(requests))
	for i, req := range requests {
		got[i] = req.MessageID
	}
	if !slices.Equal(got, want) {
		t.Fatalf("message IDs = %v, want %v", got, want)
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
	challenge := ts43.AKAChallenge{
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
