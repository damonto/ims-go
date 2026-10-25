package wfcsetup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	ts43 "github.com/damonto/ts43-go"
)

const ts43ActivationRecheckMaxAttempts = 6
const ts43ActivationRecheckInterval = 5 * time.Second

var ts43Tokens = struct {
	mu     sync.Mutex
	values map[string]ts43.AuthToken
}{
	values: make(map[string]ts43.AuthToken),
}

type ts43Flow struct {
	req Request
	wfc ts43.WFCConfig
}

func newTS43Flow(req Request) (flow, bool, error) {
	identity := ts43Identity(req.Card)
	wfc, err := req.WFC.Discover(identity)
	if err != nil {
		if errors.Is(err, ts43.ErrWFCConfigNotFound) {
			req.logger().Debug("wfc setup ts43 config not found", "mcc", identity.MCC, "mnc", identity.MNC)
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("discover wfc ts43 setup: %w", err)
	}
	return ts43Flow{req: req, wfc: wfc}, true, nil
}

func (f ts43Flow) Check(ctx context.Context) (Result, error) {
	if f.req.Purpose == PurposeActivationRecheck {
		return f.checkActivationRecheck(ctx)
	}
	return f.checkOnce(ctx)
}

func (f ts43Flow) checkActivationRecheck(ctx context.Context) (Result, error) {
	for attempt := 1; ; attempt++ {
		result, err := f.checkOnce(ctx)
		if err != nil || result.Action != ActionWait || !result.Pending {
			return result, err
		}
		if attempt >= ts43ActivationRecheckMaxAttempts {
			return result, nil
		}
		if err := sleepContext(ctx, max(result.RetryAfter, ts43ActivationRecheckInterval)); err != nil {
			return Result{}, err
		}
	}
}

func (f ts43Flow) checkOnce(ctx context.Context) (Result, error) {
	req := f.req
	if req.Purpose == PurposeActivation && f.wfc.SkipActivation {
		req.logger().Debug("skipping wfc ts43 activation", "carrier", f.wfc.CarrierName)
		return Result{
			Scheme:   SchemeTS43,
			Carrier:  f.wfc.CarrierName,
			Action:   ActionAllowActivation,
			Entitled: true,
		}, nil
	}

	identity := ts43Identity(req.Card)
	device := req.Device.Trimmed()
	checkCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	tokenKey := ts43TokenKey(identity, f.wfc)
	cachedToken := ts43CachedToken(tokenKey)
	check, err := ts43.CheckWFCEntitlement(checkCtx, ts43.Config{
		Logger:     req.Logger,
		HTTPClient: req.HTTPClient,
		Source:     ts43.Endpoint{Channel: ts43Channel{authenticate: req.AuthenticateAKA, identity: identity}},
	}, ts43.WFCEntitlementRequest{
		Identity: identity,
		Device: ts43.Device{
			IMEI:            device.IMEI,
			Vendor:          device.Vendor,
			Model:           device.Model,
			SoftwareVersion: device.SoftwareVersion,
		},
		Config:    f.wfc,
		AuthToken: cachedToken,
	})
	result := Result{
		Scheme:  SchemeTS43,
		Carrier: f.wfc.CarrierName,
	}
	if err != nil {
		if retryAfter, ok := ts43RetryAfter(err); ok {
			result.Action = ActionWait
			result.Pending = true
			result.RetryAfter = retryAfter
			req.logger().Info("wfc ts43 setup pending", "retry_after", retryAfter)
			return result, nil
		}
		return Result{}, fmt.Errorf("check wfc ts43 setup: %w", err)
	}
	ts43StoreToken(tokenKey, check.AuthToken)
	return f.result(check.Status)
}

// result maps carrier status to an action without performing network requests.
func (f ts43Flow) result(status ts43.WFCStatus) (Result, error) {
	mode := status.ActivationMode()
	result := Result{
		Scheme:   SchemeTS43,
		Carrier:  f.wfc.CarrierName,
		Action:   ActionDenied,
		Entitled: mode == ts43.WFCActivationAvailable,
	}
	kind := WebsheetKindEmergencyAddress
	switch mode {
	case ts43.WFCActivationAvailable:
		switch f.req.Purpose {
		case PurposeActivation:
			result.Action = ActionAllowActivation
		case PurposeActivationRecheck, PurposeEmergencyAddressRecheck:
			result.Action = ActionNone
		case PurposeEmergencyAddressUpdate:
			if f.wfc.ShouldShowAddressUpdate(status) {
				result.Action = ActionOpenWebsheet
			}
		}
	case ts43.WFCActivationWebView:
		switch f.req.Purpose {
		case PurposeActivation:
			if f.wfc.ShouldShowWebFlow(status) {
				result.Action = ActionOpenWebsheet
				kind = ts43WebsheetKind(status)
			}
		case PurposeActivationRecheck:
			result.Action = ActionWait
		case PurposeEmergencyAddressRecheck:
			result.Action = ActionDisableWFC
		}
	case ts43.WFCActivationInProgress:
		result.Action = ActionWait
	}
	switch result.Action {
	case ActionWait:
		result.Pending = true
		result.RetryAfter = ts43ActivationRecheckInterval
	case ActionOpenWebsheet:
		sheet, err := ts43Websheet(status, kind, f.wfc)
		if err != nil {
			return Result{}, err
		}
		result.Websheet = sheet
	}
	return result, nil
}

func (f ts43Flow) E911UpdateSupport(context.Context) (E911UpdateSupport, error) {
	reason := "ts43 profile does not expose an emergency address web flow"
	if f.wfc.ShowVoWiFiWebview {
		reason = "ts43 profile exposes a built-in emergency address flow"
	}
	return E911UpdateSupport{
		Supported: f.wfc.ShowVoWiFiWebview,
		BuiltIn:   f.wfc.ShowVoWiFiWebview,
		Scheme:    SchemeTS43,
		Carrier:   f.wfc.CarrierName,
		Reason:    reason,
	}, nil
}

func ts43Websheet(status ts43.WFCStatus, kind WebsheetKind, cfg ts43.WFCConfig) (*Websheet, error) {
	if status.ServiceFlowURL == "" {
		return nil, errors.New("wfc ts43 service flow URL is missing")
	}
	return &Websheet{
		Kind:       kind,
		URL:        status.ServiceFlowURL,
		Data:       status.ServiceFlowUserData,
		Title:      "Wi-Fi Calling",
		ClientName: cfg.WebsheetClientName,
	}, nil
}

func ts43WebsheetKind(status ts43.WFCStatus) WebsheetKind {
	if status.TCStatus == ts43.WFCTCNotAvailable {
		return WebsheetKindTermsAndConditions
	}
	return WebsheetKindEmergencyAddress
}

func ts43TokenKey(identity ts43.Identity, cfg ts43.WFCConfig) string {
	return identity.IMSI + "\x00" + cfg.Server
}

func ts43CachedToken(key string) ts43.AuthToken {
	ts43Tokens.mu.Lock()
	defer ts43Tokens.mu.Unlock()
	token := ts43Tokens.values[key]
	if !token.ExpiresAt.IsZero() && !time.Now().Before(token.ExpiresAt) {
		delete(ts43Tokens.values, key)
		return ts43.AuthToken{}
	}
	token.Cookies = slices.Clone(token.Cookies)
	return token
}

func ts43StoreToken(key string, token ts43.AuthToken) {
	ts43Tokens.mu.Lock()
	defer ts43Tokens.mu.Unlock()
	if token.Value == "" {
		delete(ts43Tokens.values, key)
		return
	}
	token.Cookies = slices.Clone(token.Cookies)
	ts43Tokens.values[key] = token
}

func ts43RetryAfter(err error) (time.Duration, bool) {
	httpErr, ok := errors.AsType[*ts43.HTTPError](err)
	if !ok || httpErr.StatusCode != http.StatusServiceUnavailable {
		return 0, false
	}
	return retryAfterDuration(httpErr.Header), true
}

func retryAfterDuration(header http.Header) time.Duration {
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	seconds, err := strconv.Atoi(value)
	if err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	delay := time.Until(when)
	if delay <= 0 {
		return 0
	}
	return delay
}

type ts43Channel struct {
	authenticate AKAAuthenticator
	identity     ts43.Identity
}

func (c ts43Channel) Identity(context.Context) (*ts43.Identity, error) {
	identity := c.identity
	return &identity, nil
}

func (c ts43Channel) AuthenticateAKA(ctx context.Context, req *ts43.AKARequest) (*ts43.AKAResponse, error) {
	if c.authenticate == nil {
		return nil, errAKAAuthenticatorRequired
	}
	result, err := c.authenticate(ctx, req.Rand, req.Autn)
	if err != nil {
		return nil, err
	}
	if result.Reject {
		return nil, errors.New("USIM rejected AKA challenge")
	}
	return &ts43.AKAResponse{
		Res:  result.RES,
		CK:   result.CK,
		IK:   result.IK,
		Auts: result.AUTS,
	}, nil
}

func ts43Identity(card Card) ts43.Identity {
	identity := ts43.Identity{
		ICCID: card.ICCID(),
		IMSI:  card.IMSI(),
		MCC:   card.MCC(),
		MNC:   card.MNC(),
		GID1:  strings.TrimSpace(card.GID1()),
	}
	// Card's minimal contract is also used by non-TS.43 transports. Preserve
	// additional carrier qualifiers when the SIM implementation exposes them.
	if card, ok := card.(interface{ GID2() string }); ok {
		identity.GID2 = strings.TrimSpace(card.GID2())
	}
	if card, ok := card.(interface{ SPN() string }); ok {
		identity.SPN = card.SPN()
	}
	return identity
}
