package wfcsetup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	ts43 "github.com/damonto/ts43-go"
)

type ts43RoundTripper func(*http.Request) (*http.Response, error)

func (f ts43RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func ts43FlowResponse(req *http.Request, body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}
}

func TestTS43FlowCarrierPolicy(t *testing.T) {
	const available = `{"AppID":"ap2004","EntitlementStatus":1,"TC_Status":2,"AddrStatus":2,"ProvStatus":2,"ServiceFlow_URL":"https://carrier.example/e911"}`
	const needsTerms = `{"AppID":"ap2004","EntitlementStatus":0,"TC_Status":0,"AddrStatus":2,"ProvStatus":2,"ServiceFlow_URL":"https://carrier.example/e911"}`
	for _, tt := range []struct {
		name                    string
		purpose                 Purpose
		show, skip              bool
		application             string
		want                    Action
		wantEntitled, wantError bool
	}{
		{name: "activation portal enabled", show: true, application: needsTerms, want: ActionOpenWebsheet},
		{name: "activation portal disabled", application: needsTerms, want: ActionDenied},
		{name: "skip initial activation", skip: true, want: ActionAllowActivation, wantEntitled: true},
		{name: "address update honors portal switch", purpose: PurposeEmergencyAddressUpdate, application: available, want: ActionDenied, wantEntitled: true},
		{name: "address update ignores skip activation", purpose: PurposeEmergencyAddressUpdate, show: true, skip: true, application: available, want: ActionOpenWebsheet, wantEntitled: true},
		{name: "provisioning pending", application: `{"AppID":"ap2004","EntitlementStatus":3,"TC_Status":2,"AddrStatus":2,"ProvStatus":0}`, want: ActionWait},
		{name: "not provisioned after terms accepted", application: `{"AppID":"ap2004","EntitlementStatus":0,"TC_Status":1,"AddrStatus":1,"ProvStatus":0}`, want: ActionWait},
		{name: "another application is not WFC", application: `{"AppID":"ap2003","EntitlementStatus":1}`, wantError: true},
		{name: "empty setup response is not entitlement", wantError: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			f := ts43Flow{req: Request{
				Card: testCard{mcc: "310", mnc: "260", mncLength: 3}, Purpose: tt.purpose,
				HTTPClient: &http.Client{Transport: ts43RoundTripper(func(req *http.Request) (*http.Response, error) {
					calls++
					body := ""
					if tt.application != "" {
						body = `{"APPLICATION":` + tt.application + `}`
					}
					return ts43FlowResponse(req, body), nil
				})},
			}, wfc: ts43.WFCConfig{Server: "https://carrier.example/entitlement", ShowVoWiFiWebview: tt.show, SkipActivation: tt.skip}}
			got, err := f.Check(t.Context())
			if (err != nil) != tt.wantError {
				t.Fatalf("Check() error = %v, want error %t", err, tt.wantError)
			}
			if tt.wantError {
				return
			}
			if got.Action != tt.want || got.Entitled != tt.wantEntitled {
				t.Fatalf("Check() = %+v, want action %v entitled %t", got, tt.want, tt.wantEntitled)
			}
			if (got.Websheet != nil) != (tt.want == ActionOpenWebsheet) {
				t.Errorf("Websheet = %+v, action = %v", got.Websheet, tt.want)
			}
			if tt.skip && tt.purpose == PurposeActivation && calls != 0 {
				t.Errorf("skipped activation sent %d HTTP requests", calls)
			}
			if tt.want == ActionWait && (!got.Pending || got.RetryAfter <= 0) {
				t.Errorf("pending result = %+v", got)
			}
		})
	}
}

func TestTS43ActivationRecheck(t *testing.T) {
	for _, tt := range []struct {
		name                string
		retryAfter          string
		stayPending, cancel bool
		wantCalls           int
		wantElapsed         time.Duration
	}{
		{name: "server delay is respected", retryAfter: "12", wantCalls: 2, wantElapsed: 12 * time.Second},
		{name: "pending stays pending at retry limit", stayPending: true, wantCalls: 6, wantElapsed: 25 * time.Second},
		{name: "cancel interrupts server delay", retryAfter: "12", cancel: true, wantCalls: 1, wantElapsed: time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				calls := 0
				f := ts43Flow{req: Request{
					Card: testCard{mcc: "310", mnc: "260", mncLength: 3}, Purpose: PurposeActivationRecheck,
					HTTPClient: &http.Client{Transport: ts43RoundTripper(func(req *http.Request) (*http.Response, error) {
						calls++
						body := `{"APPLICATION":{"AppID":"ap2004","EntitlementStatus":3,"TC_Status":2,"AddrStatus":2,"ProvStatus":0}}`
						if calls > 1 && !tt.stayPending {
							body = `{"APPLICATION":{"AppID":"ap2004","EntitlementStatus":1,"TC_Status":2,"AddrStatus":2,"ProvStatus":2}}`
						}
						resp := ts43FlowResponse(req, body)
						if calls == 1 && tt.retryAfter != "" {
							resp.StatusCode = http.StatusServiceUnavailable
							resp.Header.Set("Retry-After", tt.retryAfter)
						}
						return resp, nil
					})},
				}, wfc: ts43.WFCConfig{Server: "https://carrier.example/entitlement"}}
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				if tt.cancel {
					go func() {
						time.Sleep(time.Second)
						cancel()
					}()
				}
				start := time.Now()
				got, err := f.Check(ctx)
				if tt.cancel {
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("Check() error = %v, want cancellation", err)
					}
				} else if err != nil {
					t.Fatal(err)
				} else if got.Pending != tt.stayPending {
					t.Errorf("Check() = %+v, want pending %t", got, tt.stayPending)
				}
				if calls != tt.wantCalls || time.Since(start) != tt.wantElapsed {
					t.Errorf("calls=%d elapsed=%v, want %d %v", calls, time.Since(start), tt.wantCalls, tt.wantElapsed)
				}
			})
		})
	}
}

func TestTS43AddressSupport(t *testing.T) {
	for _, tt := range []struct{ show, skip bool }{{false, false}, {false, true}, {true, false}, {true, true}} {
		t.Run(fmt.Sprintf("show=%t/skip=%t", tt.show, tt.skip), func(t *testing.T) {
			f := ts43Flow{wfc: ts43.WFCConfig{ShowVoWiFiWebview: tt.show, SkipActivation: tt.skip}}
			got, err := f.E911UpdateSupport(t.Context())
			if err != nil || got.Supported != tt.show || got.BuiltIn != tt.show {
				t.Fatalf("E911UpdateSupport() = %+v, %v", got, err)
			}
		})
	}
}

type ts43QualifiedCard struct {
	testCard
	spn, gid2 string
}

func (c ts43QualifiedCard) SPN() string  { return c.spn }
func (c ts43QualifiedCard) GID2() string { return c.gid2 }

func TestTS43DiscoveryPreservesQualifiers(t *testing.T) {
	for _, tt := range []struct {
		name      string
		card      Card
		wantMatch bool
	}{
		{name: "SPN from SIM selects carrier", card: ts43QualifiedCard{testCard: testCard{mcc: "311", mnc: "650"}, spn: "United Wireless", gid2: " AB "}, wantMatch: true},
		{name: "minimal card does not invent SPN", card: testCard{mcc: "311", mnc: "650"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, matched, err := newTS43Flow(Request{Card: tt.card})
			if err != nil || matched != tt.wantMatch {
				t.Fatalf("newTS43Flow() matched = %t, error = %v", matched, err)
			}
			if tt.wantMatch && ts43Identity(tt.card).GID2 != "AB" {
				t.Errorf("GID2 = %q, want AB", ts43Identity(tt.card).GID2)
			}
		})
	}
}
