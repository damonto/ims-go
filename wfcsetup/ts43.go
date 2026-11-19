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

const ts43ActivationRecheckMaxRetries = 6
const ts43ActivationRecheckInterval = 5 * time.Second

type ts43Session struct {
	token         ts43.AuthToken
	configuration ts43.WFCConfiguration
}

type ts43SessionKey struct {
	iccid, imsi, server, entitlementVersion string
}

type ts43SessionEntry struct {
	session    ts43Session
	generation uint64
	inFlight   int
}

type ts43SessionCache struct {
	mu      sync.Mutex
	entries map[ts43SessionKey]*ts43SessionEntry // guarded by mu
}

var ts43Sessions ts43SessionCache

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
	for retries := 0; ; retries++ {
		result, err := f.checkOnce(ctx)
		if err != nil || result.Action != ActionWait || !result.Pending {
			return result, err
		}
		if retries >= ts43ActivationRecheckMaxRetries {
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

	key := newTS43SessionKey(identity, f.wfc)
	session, generation := ts43Sessions.begin(key, req.now())
	var next *ts43Session
	defer func() { ts43Sessions.finish(key, generation, next) }()
	check, err := ts43.CheckWFCEntitlement(checkCtx, ts43.Config{
		Logger:     req.Logger,
		HTTPClient: req.HTTPClient,
		Now:        req.now,
		Source:     ts43.Endpoint{Channel: ts43Channel{authenticate: req.AuthenticateAKA, identity: identity}},
	}, ts43.WFCEntitlementRequest{
		Identity: identity,
		Device: ts43.Device{
			IMEI:            device.IMEI,
			Vendor:          device.Vendor,
			Model:           device.Model,
			SoftwareVersion: device.SoftwareVersion,
		},
		Config:        f.wfc,
		AuthToken:     session.token,
		Configuration: session.configuration,
	})
	result := Result{
		Scheme:  SchemeTS43,
		Carrier: f.wfc.CarrierName,
	}
	if err != nil {
		if check.ConfigurationReset {
			next = &ts43Session{}
		}
		if retryAfter, ok := ts43RetryAfter(err, req.now()); ok {
			result.Action = ActionWait
			result.Pending = true
			result.RetryAfter = retryAfter
			req.logger().Info("wfc ts43 setup pending", "retry_after", retryAfter)
			return result, nil
		}
		return Result{}, fmt.Errorf("check wfc ts43 setup: %w", err)
	}
	next = &ts43Session{token: check.AuthToken}
	if f.wfc.NeedsIMSProvisioning {
		next.configuration = check.Configuration
	}
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
		if f.req.Purpose == PurposeActivation {
			result.Action = ActionWait
		}
	case ts43.WFCActivationUnavailable:
		if f.req.Purpose == PurposeEmergencyAddressUpdate && status.Incompatible() {
			result.Action = ActionDisableWFC
		}
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

func newTS43SessionKey(identity ts43.Identity, cfg ts43.WFCConfig) ts43SessionKey {
	return ts43SessionKey{
		iccid:              identity.ICCID,
		imsi:               identity.IMSI,
		server:             cfg.Server,
		entitlementVersion: cfg.Version,
	}
}

// begin takes a snapshot for a carrier check. The caller must call finish.
func (c *ts43SessionCache) begin(key ts43SessionKey, now time.Time) (ts43Session, uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.entries == nil {
		c.entries = make(map[ts43SessionKey]*ts43SessionEntry)
	}
	entry := c.entries[key]
	if entry == nil {
		entry = &ts43SessionEntry{}
		c.entries[key] = entry
	}
	token := entry.session.token
	if !token.ExpiresAt.IsZero() && !now.Before(token.ExpiresAt) {
		entry.session.token = ts43.AuthToken{}
		entry.generation++
	}
	entry.inFlight++

	session := entry.session
	session.token.Cookies = slices.Clone(session.token.Cookies)
	return session, entry.generation
}

// finish applies next only if the cache still reflects the check's snapshot.
// Keeping the entry while checks are in flight prevents a cleared session from
// being restored by an older response.
func (c *ts43SessionCache) finish(key ts43SessionKey, generation uint64, next *ts43Session) {
	c.mu.Lock()
	defer c.mu.Unlock()

	entry := c.entries[key]
	if next != nil && entry.generation == generation {
		entry.session = *next
		entry.session.token.Cookies = slices.Clone(next.token.Cookies)
		entry.generation++
	}
	entry.inFlight--
	if entry.inFlight == 0 && entry.session.token.Value == "" && !entry.session.configuration.Present {
		delete(c.entries, key)
	}
}

func ts43RetryAfter(err error, now time.Time) (time.Duration, bool) {
	httpErr, ok := errors.AsType[*ts43.HTTPError](err)
	if !ok || httpErr.StatusCode != http.StatusServiceUnavailable {
		return 0, false
	}
	value := strings.TrimSpace(httpErr.Header.Get("Retry-After"))
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds < 0 || seconds > int64((1<<63-1)/time.Second) {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0, false
	}
	return max(0, when.Sub(now)), true
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
