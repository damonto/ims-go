package vowifi

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	ts43http "github.com/damonto/ts43-go/http"
	"github.com/damonto/ts43-go/sim"
	"github.com/damonto/ts43-go/ts43"
	"github.com/damonto/vowifi-go/usim"
)

const defaultWFCEntitlementTimeout = 30 * time.Second

var (
	ErrWFCEntitlementUserActionRequired = errors.New("wfc entitlement requires user action")
	ErrWFCEntitlementPending            = errors.New("wfc entitlement is pending")
	ErrWFCEntitlementDenied             = errors.New("wfc entitlement denied")
)

type WFCEntitlementPurpose int

const (
	WFCEntitlementActivation WFCEntitlementPurpose = iota
	WFCEntitlementEmergencyAddressUpdate
	WFCEntitlementEmergencyAddressRecheck
)

func (p WFCEntitlementPurpose) valid() bool {
	switch p {
	case WFCEntitlementActivation, WFCEntitlementEmergencyAddressUpdate, WFCEntitlementEmergencyAddressRecheck:
		return true
	default:
		return false
	}
}

type WFCEntitlementScheme string

const (
	WFCEntitlementSchemeNone WFCEntitlementScheme = ""
	WFCEntitlementSchemeTS43 WFCEntitlementScheme = "ts43"
	WFCEntitlementSchemeNSDS WFCEntitlementScheme = "nsds"
)

type WFCEntitlementAction int

const (
	WFCEntitlementActionNone WFCEntitlementAction = iota
	WFCEntitlementActionAllowActivation
	WFCEntitlementActionOpenWebsheet
	WFCEntitlementActionWait
	WFCEntitlementActionDenied
	WFCEntitlementActionDisableWFC
)

type WFCWebsheetKind string

const (
	WFCWebsheetKindEmergencyAddress   WFCWebsheetKind = "emergency-address"
	WFCWebsheetKindTermsAndConditions WFCWebsheetKind = "terms-and-conditions"
)

type WFCWebsheet struct {
	Kind       WFCWebsheetKind
	URL        string
	Data       string
	Title      string
	ClientName string
}

type WFCE911Info struct {
	AddressID     string
	AIDExpiration time.Time
	ServerURL     string
	ServerData    string
}

const wfcE911AIDMinimumValidity = 48 * time.Hour

func (i WFCE911Info) ValidAt(now time.Time) bool {
	if i.AIDExpiration.IsZero() {
		return false
	}
	return i.AIDExpiration.Sub(now) >= wfcE911AIDMinimumValidity
}

type WFCEntitlementResult struct {
	Scheme     WFCEntitlementScheme
	Carrier    string
	Action     WFCEntitlementAction
	Entitled   bool
	Pending    bool
	RetryAfter time.Duration
	Websheet   *WFCWebsheet
	E911       *WFCE911Info
}

type WFCEntitlementRequest struct {
	Config      *Config
	Card        Card
	Purpose     WFCEntitlementPurpose
	CurrentE911 *WFCE911Info
	Now         time.Time
}

func (req WFCEntitlementRequest) now() time.Time {
	if req.Now.IsZero() {
		return time.Now()
	}
	return req.Now
}

type WFCEntitlementError struct {
	Err    error
	Result WFCEntitlementResult
}

func (e *WFCEntitlementError) Error() string {
	if e.Result.Websheet != nil && e.Result.Websheet.URL != "" {
		return e.Err.Error() + ": " + e.Result.Websheet.URL
	}
	return e.Err.Error()
}

func (e *WFCEntitlementError) Unwrap() error {
	return e.Err
}

func (c *Client) checkWFCEntitlement(ctx context.Context, cfg *Config, card Card) error {
	result, err := c.CheckWFCEntitlement(ctx, WFCEntitlementRequest{
		Config:  cfg,
		Card:    card,
		Purpose: WFCEntitlementActivation,
	})
	if err != nil {
		return err
	}
	if result.Entitled {
		return nil
	}
	return wfcEntitlementResultError(result)
}

func (c *Client) CheckWFCEntitlement(ctx context.Context, req WFCEntitlementRequest) (WFCEntitlementResult, error) {
	if req.Config == nil {
		return WFCEntitlementResult{}, errors.New("wfc entitlement config is required")
	}
	if req.Card == nil {
		return WFCEntitlementResult{}, errors.New("wfc entitlement card is required")
	}
	if !req.Purpose.valid() {
		return WFCEntitlementResult{}, fmt.Errorf("wfc entitlement purpose %d is invalid", req.Purpose)
	}
	if profile, ok := nsdsWFCProfileForCard(req.Card); ok {
		return c.checkNSDSWFCEntitlement(ctx, req, profile)
	}

	identity := ts43Identity(req.Card)
	wfc, err := ts43.DiscoverWFC(identity)
	if err != nil {
		if errors.Is(err, ts43.ErrWFCConfigNotFound) {
			c.logger.Debug("wfc entitlement config not found", "mcc", identity.MCC, "mnc", identity.MNC)
			return wfcEntitlementConfigNotFoundResult(req.Purpose), nil
		}
		return WFCEntitlementResult{}, fmt.Errorf("discovering wfc entitlement: %w", err)
	}

	return c.checkDiscoveredWFCEntitlement(ctx, req.Config, req.Card, req.Purpose, wfc)
}

func (c *Client) CheckWFCE911Update(ctx context.Context, req WFCEntitlementRequest) (WFCEntitlementResult, error) {
	req.Purpose = WFCEntitlementEmergencyAddressUpdate
	return c.CheckWFCEntitlement(ctx, req)
}

func wfcEntitlementConfigNotFoundResult(purpose WFCEntitlementPurpose) WFCEntitlementResult {
	switch purpose {
	case WFCEntitlementActivation:
		return WFCEntitlementResult{Action: WFCEntitlementActionAllowActivation, Entitled: true}
	case WFCEntitlementEmergencyAddressRecheck:
		return WFCEntitlementResult{Action: WFCEntitlementActionNone}
	default:
		return WFCEntitlementResult{Action: WFCEntitlementActionDenied}
	}
}

func (c *Client) checkDiscoveredWFCEntitlement(ctx context.Context, cfg *Config, card Card, purpose WFCEntitlementPurpose, wfc ts43.WFCConfig) (WFCEntitlementResult, error) {
	if purpose == WFCEntitlementActivation && wfc.SkipActivation {
		c.logger.Debug("skipping wfc activation entitlement", "carrier", wfc.CarrierName)
		return WFCEntitlementResult{
			Scheme:   WFCEntitlementSchemeTS43,
			Carrier:  wfc.CarrierName,
			Action:   WFCEntitlementActionAllowActivation,
			Entitled: true,
		}, nil
	}

	return c.checkTS43WFCEntitlement(ctx, cfg, card, purpose, wfc)
}

func (c *Client) checkTS43WFCEntitlement(ctx context.Context, cfg *Config, card Card, purpose WFCEntitlementPurpose, wfc ts43.WFCConfig) (WFCEntitlementResult, error) {
	identity := ts43Identity(card)
	terminal := cfg.Terminal.trimmed()
	status, err := ts43.CheckWFCEntitlement(ctx, ts43.Config{
		Logger: cfg.Logger,
		Source: ts43.Endpoint{Channel: ts43Channel{card: card, identity: identity}},
	}, identity, ts43.Device{
		IMEI:            terminal.ID,
		Vendor:          terminal.Vendor,
		Model:           terminal.Model,
		SoftwareVersion: terminal.SoftwareVersion,
	}, wfc)
	result := WFCEntitlementResult{
		Scheme:  WFCEntitlementSchemeTS43,
		Carrier: wfc.CarrierName,
	}
	if err != nil {
		retryAfter, ok := ts43RetryAfter(err)
		if ok {
			result.Action = WFCEntitlementActionWait
			result.Pending = true
			result.RetryAfter = retryAfter
			c.logger.Info("wfc entitlement pending", "retry_after", retryAfter)
			return result, nil
		}
		return WFCEntitlementResult{}, fmt.Errorf("checking wfc entitlement: %w", err)
	}
	if status.Entitled() {
		c.logger.Debug("wfc entitlement granted", "carrier", wfc.CarrierName)
		result.Entitled = true
		switch purpose {
		case WFCEntitlementActivation:
			result.Action = WFCEntitlementActionAllowActivation
		case WFCEntitlementEmergencyAddressUpdate:
			result.Action = WFCEntitlementActionOpenWebsheet
			websheet, err := ts43WFCWebsheet(status, WFCWebsheetKindEmergencyAddress)
			if err != nil {
				return WFCEntitlementResult{}, err
			}
			result.Websheet = websheet
		case WFCEntitlementEmergencyAddressRecheck:
			result.Action = WFCEntitlementActionNone
		}
		return result, nil
	}
	if status.NeedsUserWebFlow() {
		switch purpose {
		case WFCEntitlementEmergencyAddressUpdate:
			result.Action = WFCEntitlementActionDenied
			return result, nil
		case WFCEntitlementEmergencyAddressRecheck:
			result.Action = WFCEntitlementActionDisableWFC
			return result, nil
		}
		result.Action = WFCEntitlementActionOpenWebsheet
		websheet, err := ts43WFCWebsheet(status, ts43WFCWebsheetKind(status))
		if err != nil {
			return WFCEntitlementResult{}, err
		}
		result.Websheet = websheet
		return result, nil
	}
	if status.InProgress() {
		result.Action = WFCEntitlementActionWait
		result.Pending = true
		return result, nil
	}
	result.Action = WFCEntitlementActionDenied
	return result, nil
}

func ts43WFCWebsheet(status ts43.WFCStatus, kind WFCWebsheetKind) (*WFCWebsheet, error) {
	if status.ServiceFlowURL == "" {
		return nil, errors.New("wfc service flow URL is missing")
	}
	return &WFCWebsheet{
		Kind:  kind,
		URL:   status.ServiceFlowURL,
		Data:  status.ServiceFlowUserData,
		Title: "Wi-Fi Calling",
	}, nil
}

func ts43WFCWebsheetKind(status ts43.WFCStatus) WFCWebsheetKind {
	if status.TCStatus == ts43.WFCTCNotAvailable {
		return WFCWebsheetKindTermsAndConditions
	}
	return WFCWebsheetKindEmergencyAddress
}

func ts43RetryAfter(err error) (time.Duration, bool) {
	var httpErr *ts43http.HTTPError
	if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusServiceUnavailable {
		return 0, false
	}
	return retryAfterDuration(httpErr.Header), true
}

func retryAfterDuration(header http.Header) time.Duration {
	return retryAfterDurationAt(header, time.Now())
}

func retryAfterDurationAt(header http.Header, now time.Time) time.Duration {
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
	delay := when.Sub(now)
	if delay <= 0 {
		return 0
	}
	return delay
}

func wfcEntitlementResultError(result WFCEntitlementResult) error {
	if result.Entitled {
		return nil
	}
	err := ErrWFCEntitlementDenied
	switch {
	case result.Action == WFCEntitlementActionOpenWebsheet:
		err = ErrWFCEntitlementUserActionRequired
	case result.Action == WFCEntitlementActionWait:
		err = ErrWFCEntitlementPending
	}
	return &WFCEntitlementError{
		Err:    err,
		Result: result,
	}
}

type ts43Channel struct {
	card     Card
	identity sim.Identity
}

type eapAKACard interface {
	EAPAKA(context.Context, []byte, []byte) (usim.AKAResult, error)
}

func (c ts43Channel) Identity(context.Context) (*sim.Identity, error) {
	identity := c.identity
	return &identity, nil
}

func (c ts43Channel) AuthenticateAKA(ctx context.Context, req *sim.AKARequest) (*sim.AKAResponse, error) {
	result, err := c.authenticateAKA(ctx, req.Rand, req.Autn)
	if err != nil {
		return nil, err
	}
	if result.Reject {
		return nil, errors.New("USIM rejected AKA challenge")
	}
	return &sim.AKAResponse{
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

func ts43Identity(card Card) sim.Identity {
	return sim.Identity{
		ICCID: card.ICCID(),
		IMSI:  card.IMSI(),
		MCC:   card.MCC(),
		MNC:   card.MNC(),
		GID1:  cardGID1(card),
	}
}

type nsdsWFCProfile struct {
	Carrier    string
	MCC        string
	MNC        string
	ServerURL  string
	Title      string
	ClientName string
}

var nsdsWFCProfiles = []nsdsWFCProfile{
	{Carrier: "AT&T", MCC: "310", MNC: "030", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "Cricket/AT&T", MCC: "310", MNC: "150", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "AT&T", MCC: "310", MNC: "170", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "AT&T", MCC: "310", MNC: "280", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "AT&T", MCC: "310", MNC: "380", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "AT&T", MCC: "310", MNC: "410", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "AT&T", MCC: "310", MNC: "560", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "AT&T", MCC: "310", MNC: "950", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "AT&T", MCC: "311", MNC: "180", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "FirstNet/AT&T", MCC: "313", MNC: "100", ServerURL: "https://sentitlement2.mobile.att.net/WFC", Title: "Wi-Fi Calling", ClientName: "WiFiCallingWebViewController"},
	{Carrier: "GCI", MCC: "311", MNC: "370", ServerURL: "https://ses.epdg.gci.net/generic_devices", Title: "Wi-Fi Calling", ClientName: "NsdsWebSheetController"},
}

func nsdsWFCProfileForCard(card Card) (nsdsWFCProfile, bool) {
	mcc := strings.TrimSpace(card.MCC())
	mnc := strings.TrimSpace(card.MNC())
	mncLength := cardMNCLength(card)
	for _, profile := range nsdsWFCProfiles {
		if samePLMNDigits(profile.MCC, profile.MNC, mcc, mnc, mncLength) {
			return profile, true
		}
	}
	return nsdsWFCProfile{}, false
}

func (c *Client) checkNSDSWFCEntitlement(ctx context.Context, req WFCEntitlementRequest, profile nsdsWFCProfile) (WFCEntitlementResult, error) {
	if req.Purpose == WFCEntitlementEmergencyAddressRecheck && req.CurrentE911 != nil && req.CurrentE911.ValidAt(req.now()) {
		return WFCEntitlementResult{
			Scheme:   WFCEntitlementSchemeNSDS,
			Carrier:  profile.Carrier,
			Action:   WFCEntitlementActionNone,
			Entitled: true,
			E911:     req.CurrentE911,
		}, nil
	}

	cfg := req.Config
	card := req.Card
	imsiEAP, err := nsdsWFCIMSIEAP(card)
	if err != nil {
		return WFCEntitlementResult{}, err
	}
	client := nsdsWFCClient{
		serverURL:  profile.ServerURL,
		deviceID:   nsdsWFCDeviceID(cfg.Terminal.trimmed().ID),
		deviceName: nsdsWFCDeviceName(*cfg),
		imsiEAP:    imsiEAP,
		userAgent:  nsdsWFCUserAgent(*cfg),
	}

	checkCtx, cancel := context.WithTimeout(ctx, defaultWFCEntitlementTimeout)
	defer cancel()

	status, err := client.checkLocationAndTC(checkCtx, card, req.Purpose)
	if err != nil {
		if nsdsWFCActivationCheckOptional(req.Purpose, err) {
			c.logger.Warn("wfc nsds entitlement check did not complete; continuing activation", "carrier", profile.Carrier, "err", err)
			return WFCEntitlementResult{
				Scheme:   WFCEntitlementSchemeNSDS,
				Carrier:  profile.Carrier,
				Action:   WFCEntitlementActionAllowActivation,
				Entitled: true,
			}, nil
		}
		return WFCEntitlementResult{}, fmt.Errorf("checking wfc nsds entitlement: %w", err)
	}
	result := WFCEntitlementResult{
		Scheme:  WFCEntitlementSchemeNSDS,
		Carrier: profile.Carrier,
		E911:    nsdsWFCE911Info(status.LocationTC),
	}
	if !status.ServiceEntitled {
		result.Action = WFCEntitlementActionDenied
		return result, nil
	}
	if status.Pending {
		result.Action = WFCEntitlementActionWait
		result.Pending = true
		return result, nil
	}
	if status.MSISDN != "" {
		applyNSDSWFCMSISDN(cfg, status.MSISDN)
		c.logger.Debug("wfc nsds msisdn received", "carrier", profile.Carrier, "msisdn", status.MSISDN, "public_identity", cfg.IMS.PublicIdentity)
	}
	if req.Purpose == WFCEntitlementActivation && !status.LocationChecked {
		result.Entitled = true
		result.Action = WFCEntitlementActionAllowActivation
		return result, nil
	}
	if !status.LocationTCOK() {
		if req.Purpose == WFCEntitlementEmergencyAddressRecheck {
			result.Action = WFCEntitlementActionDisableWFC
			return result, nil
		}
		if status.LocationTC.ServerURL == "" {
			return WFCEntitlementResult{}, errors.New("nsds e911 websheet URL is missing")
		}
		c.logger.Warn("wfc nsds entitlement requires user action",
			"carrier", profile.Carrier,
			"url", status.LocationTC.ServerURL,
			"data", status.LocationTC.ServerData,
			"title", profile.Title,
			"client", profile.ClientName,
		)
		result.Action = WFCEntitlementActionOpenWebsheet
		result.Websheet = nsdsWFCWebsheet(profile, status.LocationTC)
		return result, nil
	}
	result.Entitled = true
	switch req.Purpose {
	case WFCEntitlementActivation:
		result.Action = WFCEntitlementActionAllowActivation
	case WFCEntitlementEmergencyAddressUpdate:
		if status.LocationTC.ServerURL == "" {
			return WFCEntitlementResult{}, errors.New("nsds e911 websheet URL is missing")
		}
		result.Action = WFCEntitlementActionOpenWebsheet
		result.Websheet = nsdsWFCWebsheet(profile, status.LocationTC)
	case WFCEntitlementEmergencyAddressRecheck:
		result.Action = WFCEntitlementActionNone
	}
	c.logger.Debug("wfc nsds entitlement granted", "carrier", profile.Carrier)
	return result, nil
}

func nsdsWFCDeviceName(cfg Config) string {
	return cfg.Terminal.trimmed().Model
}

func nsdsWFCUserAgent(cfg Config) string {
	terminal := cfg.Terminal.trimmed()
	if terminal.SoftwareVersion == "" && terminal.Model == "" {
		return ""
	}
	return "Dalvik/2.1.0 (Linux; U; Android " + terminal.SoftwareVersion + "; " + terminal.Model + ")"
}

func nsdsWFCDeviceID(imei string) string {
	imei = strings.TrimSpace(imei)
	if len(imei) >= 14 && allASCIIDigits(imei) {
		imei = fmt.Sprintf("urn:gsma:imei:%s-%s-0", imei[:8], imei[8:14])
	}
	return base64.StdEncoding.EncodeToString([]byte(imei))
}

func allASCIIDigits(value string) bool {
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return value != ""
}

func nsdsWFCIMSIEAP(card Card) (string, error) {
	mcc := strings.TrimSpace(card.MCC())
	mnc := strings.TrimSpace(card.MNC())
	switch n := cardMNCLength(card); n {
	case 2, 3:
		formatted, err := sim.FormatMNC(card.IMSI(), n)
		if err != nil {
			return "", err
		}
		mnc = formatted
	}
	return sim.IMSIEAPIdentity(mcc+mnc, card.IMSI(), ts43.DefaultEAPAkaRealm)
}

func applyNSDSWFCMSISDN(cfg *Config, msisdn string) {
	if strings.TrimSpace(cfg.IMS.PublicIdentity) != "" {
		return
	}
	msisdn = nsdsWFCPublicMSISDN(msisdn)
	if msisdn == "" || cfg.IMS.HomeDomain == "" {
		return
	}
	cfg.IMS.PublicIdentity = "sip:" + msisdn + "@" + cfg.IMS.HomeDomain
}

func nsdsWFCPublicMSISDN(msisdn string) string {
	msisdn = strings.TrimSpace(msisdn)
	if msisdn == "" {
		return ""
	}
	if strings.HasPrefix(msisdn, "+") {
		return msisdn
	}
	switch {
	case len(msisdn) == 10:
		return "+1" + msisdn
	case len(msisdn) == 11 && strings.HasPrefix(msisdn, "1"):
		return "+" + msisdn
	default:
		return msisdn
	}
}

type nsdsWFCClient struct {
	serverURL  string
	deviceID   string
	deviceName string
	imsiEAP    string
	userAgent  string
}

const (
	nsdsMethod3GPPAuthentication     = "3gppAuthentication"
	nsdsMethodServiceEntitlement     = "serviceEntitlementStatus"
	nsdsMethodGetMSISDN              = "getMSISDN"
	nsdsMethodManageLocationAndTC    = "manageLocationAndTC"
	nsdsMethodManageService          = "manageService"
	nsdsMethodManageConnectivity     = "manageConnectivity"
	nsdsMethodManagePushToken        = "managePushToken"
	nsdsMethodRegisteredMSISDN       = "registeredMSISDN"
	nsdsMethodRegisteredDevices      = "registeredDevices"
	nsdsMethodGetToken               = "getToken"
	nsdsServiceVowifi                = "vowifi"
	nsdsServiceVowifiAndVVM          = "vowifi+vvm"
	nsdsResponseSuccessful           = 1000
	nsdsResponseAKAChallenge         = 1003
	nsdsResponseInvalidRequest       = 1004
	nsdsResponseInvalidIPAuth        = 1005
	nsdsResponseAKAAuthFailed        = 1006
	nsdsResponseForbiddenRequest     = 1007
	nsdsResponseInvalidClientID      = 1008
	nsdsResponseMaxDeviceReached     = 1010
	nsdsResponseInvalidDeviceID      = 1020
	nsdsResponseNoEPDG               = 1021
	nsdsResponseCertGenerationFailed = 1022
	nsdsResponseRemovalFailed        = 1023
	nsdsResponseInvalidOwnerID       = 1024
	nsdsResponseInvalidCSR           = 1025
	nsdsResponseDeviceLocked         = 1028
	nsdsResponseInvalidDeviceStatus  = 1029
	nsdsResponseMaxServiceReached    = 1040
	nsdsResponseInvalidFingerprint   = 1041
	nsdsResponseInvalidTargetDevice  = 1042
	nsdsResponseInvalidTargetUser    = 1043
	nsdsResponseMaxServiceInstance   = 1044
	nsdsResponseCopyForbidden        = 1045
	nsdsResponseInvalidServiceName   = 1046
	nsdsResponseServiceNotEntitled   = 1048
	nsdsResponseServiceNotPermitted  = 1049
	nsdsResponseInvalidServiceInstID = 1053
	nsdsResponseInvalidDeviceGroup   = 1054
	nsdsResponseNoMSISDNFound        = 1060
	nsdsResponseCreationFailed       = 1061
	nsdsResponseServerSuspended      = 1063
	nsdsResponseInvalidPushToken     = 1080
	nsdsResponseServerError          = 1111
	nsdsResponse3GPPAuthOngoing      = 1112
	nsdsResponseRequestOngoing       = 1500
	nsdsResponseUnsupportedOperation = 9999
)

const (
	nsdsDefinedUnknown                          = -1
	nsdsDefinedRequest3GPPAuthGenFailure        = 1001
	nsdsDefinedRequest3GPPAuthServerError       = 1002
	nsdsDefinedAKAAuthFailed                    = 1006
	nsdsDefinedRegisteredMSISDNGenFailure       = 1100
	nsdsDefinedManageConnectivityActivateFailed = 1300
	nsdsDefinedManageConnectivityInvalidGroup   = 1301
	nsdsDefinedManageConnectivityConfigFailed   = 1400
	nsdsDefinedManageConnectivityConfigUpdated  = 1302
	nsdsDefinedManageConnectivityDeactivated    = 1305
	nsdsDefinedManageServiceProvisionFailed     = 1500
	nsdsDefinedManageServiceInvalidOwnerID      = 1501
	nsdsDefinedManageServiceMaxInstanceReached  = 1502
	nsdsDefinedManageServiceNotEntitled         = 1503
	nsdsDefinedManageServiceRenewFailed         = 1600
	nsdsDefinedManageServiceRemoveFailed        = 1700
	nsdsDefinedManageServiceInvalidDeviceStatus = 1701
	nsdsDefinedManageServiceInvalidInstanceID   = 1702
	nsdsDefinedManageLocationAndTCFailed        = 1800
	nsdsDefinedManagePushTokenFailed            = 1900
	nsdsDefinedRegisteredDevicesFailed          = 2000
	nsdsDefinedSvcProvisionPending              = 2300
	nsdsDefinedSvcNotProvisioned                = 2301
	nsdsDefinedSvcProvisionCompleted            = 2302
	nsdsDefinedForceToggleOff                   = 2303
	nsdsDefinedVoidWebsheetTransaction          = 2304
	nsdsDefinedInvalidSIMStatus                 = 2401
	nsdsDefinedLocationTCUpdateCancel           = 2500
	nsdsDefinedLocationTCUpdateSuccess          = 2501
	nsdsDefinedLocationTCUpdateNotRequired      = 2502
	nsdsDefinedHTTPTransactionError             = 2600
)

const (
	nsdsMessageID3GPPAuthentication  = 1
	nsdsMessageIDServiceEntitlement  = 2
	nsdsMessageIDGetMSISDN           = 3
	nsdsMessageIDManageLocationAndTC = 2
)

type nsdsRequest struct {
	MessageID          int      `json:"message-id"`
	Method             string   `json:"method"`
	DeviceID           string   `json:"device-id"`
	DeviceType         *int     `json:"device-type,omitempty"`
	OSType             *int     `json:"os-type,omitempty"`
	DeviceName         string   `json:"device-name,omitempty"`
	IMSIEAP            string   `json:"imsi-eap,omitempty"`
	AKAChallengeRsp    string   `json:"aka-challenge-rsp,omitempty"`
	AKAToken           string   `json:"aka-token,omitempty"`
	ServiceList        []string `json:"service-list,omitempty"`
	ServiceFingerprint string   `json:"service-fingerprint,omitempty"`
}

type nsdsResponse struct {
	MessageID              int                  `json:"message-id"`
	Method                 string               `json:"method"`
	ResponseCode           int                  `json:"response-code"`
	AKAChallenge           string               `json:"aka-challenge"`
	AKAToken               string               `json:"aka-token"`
	ServiceEntitlementList []serviceEntitlement `json:"service-entitlement"`
	MSISDN                 string               `json:"msisdn"`
	ServiceFingerprint     string               `json:"service-fingerprint"`
	LocationStatus         *bool                `json:"location-status"`
	TCStatus               *bool                `json:"tc-status"`
	ServerURL              string               `json:"server-url"`
	ServerData             string               `json:"server-data"`
	AddressID              string               `json:"address-id"`
	AIDExpiration          nsdsAIDExpiration    `json:"aid-expiration"`
	ServiceStatus          *int                 `json:"service-status"`
}

type serviceEntitlement struct {
	ServiceName       string `json:"service-name"`
	EntitlementStatus int    `json:"entitlement-status"`
	OnDemandProv      *bool  `json:"on-demand-prov"`
}

type nsdsWFCStatus struct {
	MSISDN          string
	LocationTC      nsdsResponse
	ServiceEntitled bool
	Pending         bool
	LocationChecked bool
}

func (status nsdsWFCStatus) LocationTCOK() bool {
	return status.LocationTC.LocationTCOK()
}

func (c nsdsWFCClient) checkLocationAndTC(ctx context.Context, card Card, purpose WFCEntitlementPurpose) (nsdsWFCStatus, error) {
	authChallenge, err := c.requestChallenge(ctx)
	if err != nil {
		return nsdsWFCStatus{}, err
	}
	challengeResponse, err := nsdsWFCChallengeResponse(ctx, card, c.imsiEAP, authChallenge.AKAChallenge)
	if err != nil {
		return nsdsWFCStatus{}, err
	}
	token := ""
	requests := []nsdsRequest{
		c.authenticationRequest(nsdsMessageID3GPPAuthentication, challengeResponse, token),
		c.serviceEntitlementRequest(nsdsMessageIDServiceEntitlement),
	}
	if purpose != WFCEntitlementActivation {
		requests = append(requests, c.getMSISDNRequest(nsdsMessageIDGetMSISDN))
	}

	responses, err := c.post(ctx, requests)
	if err != nil {
		return nsdsWFCStatus{}, err
	}
	if err := nsdsRequireResponseCode(responses.response(nsdsMessageID3GPPAuthentication), nsdsResponseSuccessful, nsdsMethod3GPPAuthentication); err != nil {
		return nsdsWFCStatus{}, err
	}
	entitlement := responses.response(nsdsMessageIDServiceEntitlement)
	if err := nsdsRequireResponseCode(entitlement, nsdsResponseSuccessful, nsdsMethodServiceEntitlement); err != nil {
		return nsdsWFCStatus{}, err
	}
	if !nsdsVowifiEntitled(entitlement) {
		return nsdsWFCStatus{}, nil
	}
	if purpose == WFCEntitlementActivation {
		return nsdsWFCStatus{ServiceEntitled: true}, nil
	}

	msisdn := responses.response(nsdsMessageIDGetMSISDN)
	if err := nsdsRequireResponseCode(msisdn, nsdsResponseSuccessful, nsdsMethodGetMSISDN); err != nil {
		return nsdsWFCStatus{}, err
	}
	if msisdn.ServiceFingerprint == "" {
		return nsdsWFCStatus{}, errors.New("nsds service fingerprint is missing")
	}

	token = firstNonEmpty(responses.response(nsdsMessageID3GPPAuthentication).AKAToken, token)
	responses, err = c.post(ctx, []nsdsRequest{
		c.authenticationRequest(nsdsMessageID3GPPAuthentication, "", token),
		c.manageLocationAndTCRequest(nsdsMessageIDManageLocationAndTC, msisdn.ServiceFingerprint),
	})
	if err != nil {
		return nsdsWFCStatus{}, err
	}
	if err := nsdsRequireResponseCode(responses.response(nsdsMessageID3GPPAuthentication), nsdsResponseSuccessful, nsdsMethod3GPPAuthentication); err != nil {
		return nsdsWFCStatus{}, err
	}
	locationTC := responses.response(nsdsMessageIDManageLocationAndTC)
	if err := nsdsRequireResponseCode(locationTC, nsdsResponseSuccessful, nsdsMethodManageLocationAndTC); err != nil {
		return nsdsWFCStatus{}, err
	}
	return nsdsWFCStatus{
		MSISDN:          msisdn.MSISDN,
		LocationTC:      locationTC,
		ServiceEntitled: true,
		LocationChecked: true,
	}, nil
}

func (c nsdsWFCClient) requestChallenge(ctx context.Context) (nsdsResponse, error) {
	responses, err := c.post(ctx, []nsdsRequest{c.authenticationRequest(nsdsMessageID3GPPAuthentication, "", "")})
	if err != nil {
		return nsdsResponse{}, err
	}
	response := responses.response(nsdsMessageID3GPPAuthentication)
	if err := nsdsRequireResponseCode(response, nsdsResponseAKAChallenge, nsdsMethod3GPPAuthentication); err != nil {
		return nsdsResponse{}, err
	}
	if response.AKAChallenge == "" {
		return nsdsResponse{}, errors.New("nsds authentication challenge missing")
	}
	return response, nil
}

func (c nsdsWFCClient) authenticationRequest(messageID int, challengeResponse, token string) nsdsRequest {
	return nsdsRequest{
		MessageID:       messageID,
		Method:          nsdsMethod3GPPAuthentication,
		DeviceID:        c.deviceID,
		DeviceType:      new(int),
		OSType:          new(int),
		DeviceName:      c.deviceName,
		IMSIEAP:         c.imsiEAP,
		AKAChallengeRsp: challengeResponse,
		AKAToken:        token,
	}
}

func (c nsdsWFCClient) serviceEntitlementRequest(messageID int) nsdsRequest {
	return nsdsRequest{
		MessageID:   messageID,
		Method:      nsdsMethodServiceEntitlement,
		DeviceID:    c.deviceID,
		ServiceList: []string{nsdsServiceVowifi},
	}
}

func (c nsdsWFCClient) getMSISDNRequest(messageID int) nsdsRequest {
	return nsdsRequest{
		MessageID: messageID,
		Method:    nsdsMethodGetMSISDN,
		DeviceID:  c.deviceID,
	}
}

func (c nsdsWFCClient) manageLocationAndTCRequest(messageID int, fingerprint string) nsdsRequest {
	return nsdsRequest{
		MessageID:          messageID,
		Method:             nsdsMethodManageLocationAndTC,
		DeviceID:           c.deviceID,
		ServiceFingerprint: fingerprint,
	}
}

type nsdsResponses []nsdsResponse

func (responses nsdsResponses) response(messageID int) nsdsResponse {
	for _, response := range responses {
		if response.MessageID == messageID {
			return response
		}
	}
	return nsdsResponse{}
}

func (c nsdsWFCClient) post(ctx context.Context, payload []nsdsRequest) (nsdsResponses, error) {
	var raw bytes.Buffer
	encoder := gzip.NewWriter(&raw)
	if err := json.NewEncoder(encoder).Encode(payload); err != nil {
		_ = encoder.Close()
		return nil, fmt.Errorf("encoding nsds request: %w", err)
	}
	if err := encoder.Close(); err != nil {
		return nil, fmt.Errorf("compressing nsds request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.serverURL, &raw)
	if err != nil {
		return nil, fmt.Errorf("building nsds request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("x-generic-protocol-version", "1.0")
	req.Header.Set("x-generic-version", "1.0")
	req.Header.Set("x-protocol-version", "1")
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	req.Header.Set("Connection", "Keep-Alive")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting nsds request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("posting nsds request: status %s", resp.Status)
	}

	body, err := nsdsResponseBody(resp)
	if err != nil {
		return nil, err
	}
	defer body.Close()
	var responses nsdsResponses
	if err := json.NewDecoder(body).Decode(&responses); err != nil {
		return nil, fmt.Errorf("decoding nsds response: %w", err)
	}
	return responses, nil
}

func nsdsResponseBody(resp *http.Response) (io.ReadCloser, error) {
	if !strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		return io.NopCloser(resp.Body), nil
	}
	reader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("decompressing nsds response: %w", err)
	}
	return reader, nil
}

func nsdsWFCChallengeResponse(ctx context.Context, card Card, imsiEAP, challengeText string) (string, error) {
	var challenge sim.AKAChallenge
	if err := challenge.UnmarshalText([]byte(challengeText)); err != nil {
		return "", fmt.Errorf("decoding nsds aka challenge: %w", err)
	}
	authenticate := card.AKA
	if eapCard, ok := card.(eapAKACard); ok {
		authenticate = eapCard.EAPAKA
	}
	aka, err := authenticate(ctx, challenge.Rand, challenge.Autn)
	if err != nil {
		return "", fmt.Errorf("authenticating nsds aka challenge: %w", err)
	}
	if aka.Reject {
		return "", errors.New("USIM rejected NSDS AKA challenge")
	}
	response := sim.AKAResponse{
		Res:  aka.RES,
		CK:   aka.CK,
		IK:   aka.IK,
		Auts: aka.AUTS,
	}
	text, err := sim.RespondToChallengeBase64(&challenge, &response, imsiEAP)
	if err != nil {
		return "", fmt.Errorf("building nsds aka challenge response: %w", err)
	}
	return text, nil
}

func nsdsRequireResponseCode(response nsdsResponse, want int, method string) error {
	if response.ResponseCode == want {
		return nil
	}
	if response.MessageID == 0 && response.ResponseCode == 0 {
		return nsdsResponseCodeError{Method: method, Want: want, Missing: true}
	}
	return nsdsResponseCodeError{Method: method, Got: response.ResponseCode, Want: want}
}

type nsdsResponseCodeError struct {
	Method  string
	Got     int
	Want    int
	Missing bool
}

func (e nsdsResponseCodeError) Error() string {
	if e.Missing {
		return fmt.Sprintf("nsds %s response missing", e.Method)
	}
	return fmt.Sprintf("nsds %s response code %d (%s), want %d (%s)", e.Method, e.Got, nsdsResponseCodeName(e.Got), e.Want, nsdsResponseCodeName(e.Want))
}

func nsdsWFCActivationCheckOptional(purpose WFCEntitlementPurpose, err error) bool {
	if purpose != WFCEntitlementActivation {
		return false
	}
	var codeErr nsdsResponseCodeError
	return errors.As(err, &codeErr) &&
		!codeErr.Missing &&
		codeErr.Method == nsdsMethod3GPPAuthentication &&
		codeErr.Got == nsdsResponseInvalidRequest
}

func nsdsVowifiEntitled(response nsdsResponse) bool {
	for _, service := range response.ServiceEntitlementList {
		if service.ServiceName != nsdsServiceVowifi {
			continue
		}
		switch service.EntitlementStatus {
		case nsdsResponseSuccessful:
			return true
		case nsdsResponseServiceNotEntitled:
			return service.OnDemandProv != nil && *service.OnDemandProv
		default:
			return false
		}
	}
	return false
}

func nsdsResponseCodeName(code int) string {
	switch code {
	case nsdsDefinedUnknown:
		return "UNKNOWN"
	case nsdsResponseSuccessful:
		return "REQUEST_SUCCESSFUL"
	case nsdsResponseAKAChallenge:
		return "REQUEST_AKA_CHALLENGE"
	case nsdsResponseInvalidRequest:
		return "ERROR_INVALID_REQUEST"
	case nsdsResponseInvalidIPAuth:
		return "ERROR_INVALID_IP_AUTHENTICATION"
	case nsdsResponseAKAAuthFailed:
		return "ERROR_AKA_AUTHENTICATION_FAILED"
	case nsdsResponseForbiddenRequest:
		return "FORBIDDEN_REQUEST"
	case nsdsResponseInvalidClientID:
		return "INVALID_CLIENT_ID"
	case nsdsResponseMaxDeviceReached:
		return "ERROR_MAX_DEVICE_REACHED"
	case nsdsResponseInvalidDeviceID:
		return "ERROR_INVALID_DEVICE_ID"
	case nsdsResponseNoEPDG:
		return "ERROR_NO_EPDG"
	case nsdsResponseCertGenerationFailed:
		return "ERROR_CERTIFICATE_GENERATION_FAILURE"
	case nsdsResponseRemovalFailed:
		return "ERROR_REMOVAL_SERVICE_FAILURE"
	case nsdsResponseInvalidOwnerID:
		return "ERROR_INVALID_OWNERID"
	case nsdsResponseInvalidCSR:
		return "ERROR_INVALID_CSR"
	case nsdsResponseDeviceLocked:
		return "ERROR_DEVICE_LOCKED"
	case nsdsResponseInvalidDeviceStatus:
		return "ERROR_INVALID_DEVICE_STATUS"
	case nsdsResponseMaxServiceReached:
		return "ERROR_MAX_SERVICE_REACHED"
	case nsdsResponseInvalidFingerprint:
		return "ERROR_INVALID_FINGERPRINT"
	case nsdsResponseInvalidTargetDevice:
		return "ERROR_INVALID_TARGET_DEVICEID"
	case nsdsResponseInvalidTargetUser:
		return "ERROR_INVALID_TARGET_USER"
	case nsdsResponseMaxServiceInstance:
		return "ERROR_MAX_SERVICE_INSTANCE_REACHED"
	case nsdsResponseCopyForbidden:
		return "ERROR_COPY_FORBIDDEN"
	case nsdsResponseInvalidServiceName:
		return "ERROR_INVALID_SERVICE_NAME"
	case nsdsResponseServiceNotEntitled:
		return "ERROR_SERVICE_NOT_ENTITLED"
	case nsdsResponseServiceNotPermitted:
		return "ERROR_SERVICE_NOT_PERMITTED"
	case nsdsResponseInvalidServiceInstID:
		return "ERROR_INVALID_SERVICE_INSTANCEID"
	case nsdsResponseInvalidDeviceGroup:
		return "ERROR_INVALID_DEVICE_GROUP"
	case nsdsResponseNoMSISDNFound:
		return "ERROR_NO_MSISDN_FOUND"
	case nsdsResponseCreationFailed:
		return "ERROR_CREATION_FAILURE"
	case nsdsResponseServerSuspended:
		return "ERROR_SERVER_SUSPENDED"
	case nsdsResponseInvalidPushToken:
		return "ERROR_INVALID_PUSH_TOKEN"
	case nsdsResponseServerError:
		return "ERROR_SERVER_ERROR"
	case nsdsResponse3GPPAuthOngoing:
		return "ERROR_3GPP_AUTH_ONGOING"
	case nsdsResponseRequestOngoing:
		return "ERROR_REQUEST_ONGOING"
	case nsdsResponseUnsupportedOperation:
		return "ERROR_UNSUPPORTED_OPERATION"
	default:
		return "ERROR_UNKNOWN"
	}
}

func nsdsDefinedResponseCodeName(code int) string {
	switch code {
	case nsdsDefinedUnknown:
		return "UNKNOWN"
	case nsdsDefinedRequest3GPPAuthGenFailure:
		return "REQUEST_3GPP_AUTH_GEN_FAILURE"
	case nsdsDefinedRequest3GPPAuthServerError:
		return "REQUEST_3GPP_AUTH_SERVER_ERROR"
	case nsdsDefinedAKAAuthFailed:
		return "AKA_AUTH_FAILED"
	case nsdsDefinedRegisteredMSISDNGenFailure:
		return "REGISTERED_MSISDN_GEN_FAILURE"
	case nsdsDefinedManageConnectivityActivateFailed:
		return "MANAGE_CONNECTIVITY_ACTIVATE_GEN_FAILURE"
	case nsdsDefinedManageConnectivityInvalidGroup:
		return "MANAGE_CONNECTIVITY_ACTIVATE_INVALID_DEVICE_GROUP"
	case nsdsDefinedManageConnectivityConfigFailed:
		return "MANAGE_CONNECTIVITY_CONFIGURE_GEN_FAILURE"
	case nsdsDefinedManageConnectivityConfigUpdated:
		return "MANAGE_CONNECTIVITY_NEW_CONFIG_UPDATED"
	case nsdsDefinedManageConnectivityDeactivated:
		return "MANAGE_CONNECTIVITY_DEACTIVATION_SUCCESS_FOR_INVALID_FINGERPRINT"
	case nsdsDefinedManageServiceProvisionFailed:
		return "MANAGE_SERVICE_PROVISION_GEN_FAILURE"
	case nsdsDefinedManageServiceInvalidOwnerID:
		return "MANAGE_SERVICE_PROVISION_INVALID_OWNER_ID"
	case nsdsDefinedManageServiceMaxInstanceReached:
		return "MANAGE_SERVICE_PROVISION_MAX_SVC_INST_REACHED"
	case nsdsDefinedManageServiceNotEntitled:
		return "MANAGE_SERVICE_PROVISION_SVC_NOT_ENTITLED"
	case nsdsDefinedManageServiceRenewFailed:
		return "MANAGE_SERVICE_RENEW_GEN_FAILURE"
	case nsdsDefinedManageServiceRemoveFailed:
		return "MANAGE_SERVICE_REMOVE_GEN_FAILURE"
	case nsdsDefinedManageServiceInvalidDeviceStatus:
		return "MANAGE_SERVICE_REMOVE_INVALID_DEVICE_STATUS"
	case nsdsDefinedManageServiceInvalidInstanceID:
		return "MANAGE_SERVICE_REMOVE_INVALID_SVC_INST_ID"
	case nsdsDefinedManageLocationAndTCFailed:
		return "MANAGE_LOCATION_AND_TC_GEN_FAILURE"
	case nsdsDefinedManagePushTokenFailed:
		return "MANAGE_PUSH_TOKEN_GEN_FAILURE"
	case nsdsDefinedRegisteredDevicesFailed:
		return "REGISTERED_DEVICES_GEN_FAILURE"
	case nsdsDefinedSvcProvisionPending:
		return "SVC_PROVISION_PENDING_ERROR_CODE"
	case nsdsDefinedSvcNotProvisioned:
		return "SVC_NOT_PROVISIONED_ERROR_CODE"
	case nsdsDefinedSvcProvisionCompleted:
		return "SVC_PROVISION_COMPLETED_SUCCESS_CODE"
	case nsdsDefinedForceToggleOff:
		return "FORCE_TOGGLE_OFF_ERROR_CODE"
	case nsdsDefinedVoidWebsheetTransaction:
		return "VOID_WEBSHEET_TRANSACTION"
	case nsdsDefinedInvalidSIMStatus:
		return "INVALID_SIM_STATUS"
	case nsdsDefinedLocationTCUpdateCancel:
		return "LOCATIONANDTC_UPDATE_CANCEL_CODE"
	case nsdsDefinedLocationTCUpdateSuccess:
		return "LOCATIONANDTC_UPDATE_SUCCESS_CODE"
	case nsdsDefinedLocationTCUpdateNotRequired:
		return "LOCATIONANDTC_UPDATE_NOT_REQUIRED"
	case nsdsDefinedHTTPTransactionError:
		return "HTTP_TRANSACTION_ERROR_CODE"
	default:
		return "ERROR_UNKNOWN"
	}
}

func nsdsWFCE911Info(response nsdsResponse) *WFCE911Info {
	if response.AddressID == "" && response.AIDExpiration.Time.IsZero() && response.ServerURL == "" && response.ServerData == "" {
		return nil
	}
	return &WFCE911Info{
		AddressID:     response.AddressID,
		AIDExpiration: response.AIDExpiration.Time,
		ServerURL:     response.ServerURL,
		ServerData:    response.ServerData,
	}
}

func nsdsWFCWebsheet(profile nsdsWFCProfile, response nsdsResponse) *WFCWebsheet {
	if response.ServerURL == "" {
		return nil
	}
	return &WFCWebsheet{
		Kind:       WFCWebsheetKindEmergencyAddress,
		URL:        response.ServerURL,
		Data:       response.ServerData,
		Title:      profile.Title,
		ClientName: profile.ClientName,
	}
}

type nsdsAIDExpiration struct {
	time.Time
}

func (a *nsdsAIDExpiration) UnmarshalText(text []byte) error {
	value := strings.TrimSpace(string(text))
	if value == "" {
		a.Time = time.Time{}
		return nil
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z-0700", "2006-01-02T15:04:05Z-0700"} {
		t, err := time.Parse(layout, value)
		if err == nil {
			a.Time = t
			return nil
		}
	}
	a.Time = time.Time{}
	return nil
}

func (a nsdsAIDExpiration) MarshalText() ([]byte, error) {
	if a.Time.IsZero() {
		return nil, nil
	}
	return []byte(a.Time.Format(time.RFC3339Nano)), nil
}

func (response nsdsResponse) LocationTCOK() bool {
	return nsdsBoolOK(response.LocationStatus) && nsdsBoolOK(response.TCStatus)
}

func nsdsBoolOK(value *bool) bool {
	return value == nil || *value
}
