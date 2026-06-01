package wfcsetup

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/damonto/vowifi-go/usim"
)

type testCard struct {
	mcc       string
	mnc       string
	mncLength int
	gid1      string
	aka       usim.AKAResult
	akaErr    error
}

func (c testCard) ICCID() string  { return "" }
func (c testCard) IMSI() string   { return c.mcc + c.mnc + "0123456789" }
func (c testCard) MCC() string    { return c.mcc }
func (c testCard) MNC() string    { return c.mnc }
func (c testCard) MNCLength() int { return c.mncLength }
func (c testCard) GID1() string   { return c.gid1 }
func (c testCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return c.aka, c.akaErr
}

func TestCheckE911UpdateSupport(t *testing.T) {
	tests := []struct {
		name           string
		req            Request
		wantSupported  bool
		wantBuiltIn    bool
		wantScheme     Scheme
		wantReasonText string
	}{
		{
			name: "vzw sim is recognized but unsupported",
			req: Request{
				Card: testCard{mcc: "311", mnc: "480", mncLength: 3},
			},
			wantScheme:     SchemeVZW,
			wantReasonText: "unsupported",
		},
		{
			name: "telus carrier app requires eap aka credential",
			req: Request{
				Card: testCard{mcc: "302", mnc: "220", mncLength: 3, gid1: "5455"},
			},
			wantSupported:  true,
			wantBuiltIn:    true,
			wantScheme:     SchemeTelus,
			wantReasonText: "built-in sim eap-aka",
		},
		{
			name: "canada carrier app exposes portal",
			req: Request{
				Card: testCard{mcc: "302", mnc: "720", mncLength: 3},
			},
			wantSupported:  true,
			wantBuiltIn:    true,
			wantScheme:     SchemeCanada,
			wantReasonText: "web portal",
		},
		{
			name: "o2 uk does not expose e911 update",
			req: Request{
				Card: testCard{mcc: "234", mnc: "10", mncLength: 2},
			},
			wantScheme:     SchemeO2UK,
			wantReasonText: "not an emergency address update",
		},
		{
			name: "nsds exposes e911 update",
			req: Request{
				Card: testCard{mcc: "310", mnc: "030", mncLength: 3},
			},
			wantSupported:  true,
			wantBuiltIn:    true,
			wantScheme:     SchemeNSDS,
			wantReasonText: "built-in emergency address",
		},
		{
			name: "missing profile",
			req: Request{
				Card: testCard{mcc: "999", mnc: "99", mncLength: 2},
			},
			wantReasonText: "no wfc setup profile",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CheckE911UpdateSupport(context.Background(), tt.req)
			if err != nil {
				t.Fatalf("CheckE911UpdateSupport() error = %v", err)
			}
			if got.Supported != tt.wantSupported {
				t.Fatalf("Supported = %t, want %t", got.Supported, tt.wantSupported)
			}
			if got.BuiltIn != tt.wantBuiltIn {
				t.Fatalf("BuiltIn = %t, want %t", got.BuiltIn, tt.wantBuiltIn)
			}
			if got.Scheme != tt.wantScheme {
				t.Fatalf("Scheme = %q, want %q", got.Scheme, tt.wantScheme)
			}
			if !strings.Contains(got.Reason, tt.wantReasonText) {
				t.Fatalf("Reason = %q, want substring %q", got.Reason, tt.wantReasonText)
			}
		})
	}
}

func TestSamePLMNDigitsMatchesZeroPaddedMNC(t *testing.T) {
	tests := []struct {
		name          string
		profileMCC    string
		profileMNC    string
		cardMCC       string
		cardMNC       string
		cardMNCLength int
		want          bool
	}{
		{
			name:       "two digit profile matches three digit card without mnc length",
			profileMCC: "234",
			profileMNC: "10",
			cardMCC:    "234",
			cardMNC:    "010",
			want:       true,
		},
		{
			name:       "three digit profile matches two digit card without mnc length",
			profileMCC: "234",
			profileMNC: "010",
			cardMCC:    "234",
			cardMNC:    "10",
			want:       true,
		},
		{
			name:       "different mcc does not match",
			profileMCC: "235",
			profileMNC: "10",
			cardMCC:    "234",
			cardMNC:    "010",
		},
		{
			name:       "different mnc does not match",
			profileMCC: "234",
			profileMNC: "11",
			cardMCC:    "234",
			cardMNC:    "010",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := samePLMNDigits(tt.profileMCC, tt.profileMNC, tt.cardMCC, tt.cardMNC, tt.cardMNCLength)
			if got != tt.want {
				t.Fatalf("samePLMNDigits() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestVZWCheckReturnsUnsupported(t *testing.T) {
	tests := []struct {
		name string
		req  Request
	}{
		{
			name: "vzw sim",
			req: Request{
				Card:    testCard{mcc: "311", mnc: "480", mncLength: 3},
				Purpose: PurposeEmergencyAddressUpdate,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Check(context.Background(), tt.req)
			if err == nil {
				t.Fatal("Check() error is nil")
			}
			if !errors.Is(err, ErrNotImplemented) {
				t.Fatalf("Check() error = %v, want ErrNotImplemented", err)
			}
			if got.Scheme != SchemeVZW || got.Carrier != vzwCarrier || got.Action != ActionDenied || got.Entitled {
				t.Fatalf("Result = %+v, want unsupported vzw denial", got)
			}
		})
	}
}

func TestCanadaCheckReturnsWebsheet(t *testing.T) {
	tests := []struct {
		name           string
		card           testCard
		wantCarrier    string
		wantURL        string
		wantClientName string
	}{
		{
			name:           "rogers sim",
			card:           testCard{mcc: "302", mnc: "720", mncLength: 3},
			wantCarrier:    "Rogers",
			wantURL:        "https://www.rogers.com/AndroidWiFi/",
			wantClientName: "WiFiCallingWebViewController",
		},
		{
			name:        "videotron sim has no js interface",
			card:        testCard{mcc: "302", mnc: "500", mncLength: 3, gid1: "53"},
			wantCarrier: "Videotron",
			wantURL:     "https://fe.videotron.com/a/few/frg/angular-app-v-vowifi-911/latest/index.html#/login",
		},
		{
			name:           "rogers 5g sim",
			card:           testCard{mcc: "302", mnc: "720", mncLength: 3, gid1: "A4"},
			wantCarrier:    "Rogers",
			wantURL:        "https://www.rogers.com/AndroidWiFi/",
			wantClientName: "WiFiCallingWebViewController",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Check(context.Background(), Request{
				Card:    tt.card,
				Purpose: PurposeEmergencyAddressUpdate,
			})
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			if got.Scheme != SchemeCanada || got.Carrier != tt.wantCarrier {
				t.Fatalf("Result = %+v, want canada carrier %q", got, tt.wantCarrier)
			}
			if got.Websheet == nil {
				t.Fatal("Websheet is nil")
			}
			if got.Websheet.URL != tt.wantURL {
				t.Fatalf("Websheet.URL = %q, want %q", got.Websheet.URL, tt.wantURL)
			}
			if got.Websheet.ClientName != tt.wantClientName {
				t.Fatalf("Websheet.ClientName = %q, want %q", got.Websheet.ClientName, tt.wantClientName)
			}
		})
	}
}

func TestCanadaPortalMatching(t *testing.T) {
	tests := []struct {
		name  string
		card  testCard
		match bool
	}{
		{
			name:  "bell broad profile matches when gid is absent",
			card:  testCard{mcc: "302", mnc: "610", mncLength: 3},
			match: true,
		},
		{
			name:  "lucky mobile gid does not fall through to bell",
			card:  testCard{mcc: "302", mnc: "610", mncLength: 3, gid1: "42"},
			match: false,
		},
		{
			name:  "tbaytel gid does not fall through to rogers",
			card:  testCard{mcc: "302", mnc: "720", mncLength: 3, gid1: "BA"},
			match: false,
		},
		{
			name:  "fido gid matches fido",
			card:  testCard{mcc: "302", mnc: "370", mncLength: 3, gid1: "DD"},
			match: true,
		},
		{
			name:  "mts gid does not fall through to fido",
			card:  testCard{mcc: "302", mnc: "370", mncLength: 3, gid1: "2C"},
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := canadaPortalForCard(tt.card)
			if got != tt.match {
				t.Fatalf("canadaPortalForCard() match = %t, want %t", got, tt.match)
			}
		})
	}
}
