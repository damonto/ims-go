package wfcsetup

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	ts43 "github.com/damonto/ts43-go"
	"github.com/damonto/uicc-go/usim"
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
	wfc, err := ts43.DiscoverWFC(identity)
	if err != nil {
		if errors.Is(err, ts43.ErrWFCConfigNotFound) {
			req.logger().Debug("wfc setup ts43 config not found", "mcc", identity.MCC, "mnc", identity.MNC)
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("discovering wfc ts43 setup: %w", err)
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
	for attempt := 0; ; attempt++ {
		result, err := f.checkOnce(ctx)
		if err != nil || result.Action != ActionWait || !result.Pending {
			return result, err
		}
		if attempt >= ts43ActivationRecheckMaxAttempts {
			result.Action = ActionDenied
			result.Pending = false
			result.RetryAfter = 0
			return result, nil
		}
		if err := sleepContext(ctx, ts43ActivationRecheckInterval); err != nil {
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
	check, err := ts43.CheckWFCEntitlementWithToken(checkCtx, ts43.Config{
		Logger: req.Logger,
		Source: ts43.Endpoint{Channel: ts43Channel{card: req.Card, identity: identity}},
	}, identity, ts43.Device{
		IMEI:            device.IMEI,
		Vendor:          device.Vendor,
		Model:           device.Model,
		SoftwareVersion: device.SoftwareVersion,
	}, f.wfc, cachedToken)
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
		return Result{}, fmt.Errorf("checking wfc ts43 setup: %w", err)
	}
	status := check.Status
	ts43StoreToken(tokenKey, check.AuthToken)
	if status.Entitled() {
		result.Entitled = true
		switch req.Purpose {
		case PurposeActivation:
			result.Action = ActionAllowActivation
		case PurposeActivationRecheck:
			result.Action = ActionNone
		case PurposeEmergencyAddressUpdate:
			result.Action = ActionOpenWebsheet
			websheet, err := ts43Websheet(status, WebsheetKindEmergencyAddress, f.wfc)
			if err != nil {
				return Result{}, err
			}
			result.Websheet = websheet
		case PurposeEmergencyAddressRecheck:
			result.Action = ActionNone
		}
		return result, nil
	}
	if status.NeedsUserWebFlow() {
		switch req.Purpose {
		case PurposeActivationRecheck:
			result.Action = ActionWait
			result.Pending = true
			result.RetryAfter = ts43ActivationRecheckInterval
			return result, nil
		case PurposeEmergencyAddressUpdate:
			result.Action = ActionDenied
			return result, nil
		case PurposeEmergencyAddressRecheck:
			result.Action = ActionDisableWFC
			return result, nil
		}
		result.Action = ActionOpenWebsheet
		websheet, err := ts43Websheet(status, ts43WebsheetKind(status), f.wfc)
		if err != nil {
			return Result{}, err
		}
		result.Websheet = websheet
		return result, nil
	}
	if status.InProgress() {
		result.Action = ActionWait
		result.Pending = true
		return result, nil
	}
	result.Action = ActionDenied
	return result, nil
}

func (f ts43Flow) E911UpdateSupport(context.Context) (E911UpdateSupport, error) {
	supported := f.wfc.ShowVoWiFiWebview || f.wfc.SkipActivation
	reason := "ts43 profile does not expose an emergency address web flow"
	if supported {
		reason = "ts43 profile exposes a built-in emergency address flow"
	}
	return E911UpdateSupport{
		Supported: supported,
		BuiltIn:   supported,
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
	token.Cookies = append([]string(nil), token.Cookies...)
	return token
}

func ts43StoreToken(key string, token ts43.AuthToken) {
	ts43Tokens.mu.Lock()
	defer ts43Tokens.mu.Unlock()
	if token.Value == "" {
		delete(ts43Tokens.values, key)
		return
	}
	token.Cookies = append([]string(nil), token.Cookies...)
	ts43Tokens.values[key] = token
}

func ts43RetryAfter(err error) (time.Duration, bool) {
	var httpErr *ts43.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable {
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
	card     Card
	identity ts43.Identity
}

type eapAKACard interface {
	EAPAKA(context.Context, []byte, []byte) (usim.AKAResult, error)
}

func (c ts43Channel) Identity(context.Context) (*ts43.Identity, error) {
	identity := c.identity
	return &identity, nil
}

func (c ts43Channel) AuthenticateAKA(ctx context.Context, req *ts43.AKARequest) (*ts43.AKAResponse, error) {
	result, err := c.authenticateAKA(ctx, req.Rand, req.Autn)
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

func (c ts43Channel) authenticateAKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	if card, ok := c.card.(eapAKACard); ok {
		return card.EAPAKA(ctx, rand, autn)
	}
	return c.card.AKA(ctx, rand, autn)
}

func ts43Identity(card Card) ts43.Identity {
	return ts43.Identity{
		ICCID: card.ICCID(),
		IMSI:  card.IMSI(),
		MCC:   card.MCC(),
		MNC:   card.MNC(),
		GID1:  cardGID1(card),
	}
}
