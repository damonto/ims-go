package wfcsetup

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
	"strings"
	"time"

	"github.com/damonto/ts43-go/sim"
)

const nsdsDefaultEAPAkaRealm = "nai.epc"
const nsdsActivationRecheckMaxAttempts = 6
const nsdsActivationRecheckInterval = 5 * time.Second

type nsdsProfile struct {
	Carrier    string
	MCC        string
	MNC        string
	ServerURL  string
	Title      string
	ClientName string
}

var nsdsProfiles = []nsdsProfile{
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

type nsdsFlow struct {
	req     Request
	profile nsdsProfile
}

func newNSDSFlow(req Request) (flow, bool, error) {
	mcc := strings.TrimSpace(req.Card.MCC())
	mnc := strings.TrimSpace(req.Card.MNC())
	mncLength := cardMNCLength(req.Card)
	for _, profile := range nsdsProfiles {
		if samePLMNDigits(profile.MCC, profile.MNC, mcc, mnc, mncLength) {
			return nsdsFlow{req: req, profile: profile}, true, nil
		}
	}
	return nil, false, nil
}

func (f nsdsFlow) Check(ctx context.Context) (Result, error) {
	if f.req.Purpose == PurposeActivationRecheck {
		return f.checkActivationRecheck(ctx)
	}
	return f.checkOnce(ctx)
}

func (f nsdsFlow) checkActivationRecheck(ctx context.Context) (Result, error) {
	for attempt := 0; ; attempt++ {
		result, err := f.checkOnce(ctx)
		if err != nil || result.Action != ActionWait || !result.Pending {
			return result, err
		}
		if attempt >= nsdsActivationRecheckMaxAttempts {
			result.Action = ActionDenied
			result.Pending = false
			result.RetryAfter = 0
			return result, nil
		}
		if err := sleepContext(ctx, nsdsActivationRecheckInterval); err != nil {
			return Result{}, err
		}
	}
}

func (f nsdsFlow) checkOnce(ctx context.Context) (Result, error) {
	if f.req.Purpose == PurposeEmergencyAddressRecheck && f.req.CurrentE911 != nil && f.req.CurrentE911.ValidAt(f.req.now()) {
		return Result{
			Scheme:   SchemeNSDS,
			Carrier:  f.profile.Carrier,
			Action:   ActionNone,
			Entitled: true,
			E911:     f.req.CurrentE911,
		}, nil
	}

	imsiEAP, err := nsdsIMSIEAP(f.req.Card)
	if err != nil {
		return Result{}, err
	}
	device := f.req.Device.Trimmed()
	client := nsdsClient{
		serverURL:  f.profile.ServerURL,
		deviceID:   nsdsDeviceID(device.IMEI),
		deviceName: device.Model,
		imsiEAP:    imsiEAP,
		userAgent:  nsdsUserAgent(device),
		httpClient: f.req.HTTPClient,
	}

	checkCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	status, err := client.checkLocationAndTC(checkCtx, f.req.Card, f.req.Purpose)
	if err != nil {
		if nsdsActivationCheckOptional(f.req.Purpose, err) {
			f.req.logger().Warn("wfc nsds setup did not complete; continuing activation", "carrier", f.profile.Carrier, "err", err)
			return Result{
				Scheme:   SchemeNSDS,
				Carrier:  f.profile.Carrier,
				Action:   ActionAllowActivation,
				Entitled: true,
			}, nil
		}
		return Result{}, fmt.Errorf("checking wfc nsds setup: %w", err)
	}

	result := Result{
		Scheme:  SchemeNSDS,
		Carrier: f.profile.Carrier,
		E911:    nsdsE911Info(status.LocationTC),
		MSISDN:  status.MSISDN,
	}
	if !status.ServiceEntitled {
		result.Action = ActionDenied
		return result, nil
	}
	if status.Pending {
		result.Action = ActionWait
		result.Pending = true
		return result, nil
	}
	if status.MSISDN != "" {
		f.req.logger().Debug("wfc nsds msisdn received", "carrier", f.profile.Carrier, "msisdn", status.MSISDN)
	}
	if f.req.Purpose == PurposeActivation && !status.LocationChecked {
		result.Entitled = true
		result.Action = ActionAllowActivation
		return result, nil
	}
	if !status.LocationTCOK() {
		if f.req.Purpose == PurposeActivationRecheck {
			result.Action = ActionWait
			result.Pending = true
			result.RetryAfter = nsdsActivationRecheckInterval
			return result, nil
		}
		if f.req.Purpose == PurposeEmergencyAddressRecheck {
			result.Action = ActionDisableWFC
			return result, nil
		}
		if status.LocationTC.ServerURL == "" {
			return Result{}, errors.New("nsds e911 websheet URL is missing")
		}
		f.req.logger().Warn("wfc nsds setup requires user action",
			"carrier", f.profile.Carrier,
			"url", status.LocationTC.ServerURL,
			"data", status.LocationTC.ServerData,
			"title", f.profile.Title,
			"client", f.profile.ClientName,
		)
		result.Action = ActionOpenWebsheet
		result.Websheet = nsdsWebsheet(f.profile, status.LocationTC)
		return result, nil
	}
	result.Entitled = true
	switch f.req.Purpose {
	case PurposeActivation:
		result.Action = ActionAllowActivation
	case PurposeEmergencyAddressUpdate:
		if status.LocationTC.ServerURL == "" {
			return Result{}, errors.New("nsds e911 websheet URL is missing")
		}
		result.Action = ActionOpenWebsheet
		result.Websheet = nsdsWebsheet(f.profile, status.LocationTC)
	case PurposeEmergencyAddressRecheck:
		result.Action = ActionNone
	}
	f.req.logger().Debug("wfc nsds setup granted", "carrier", f.profile.Carrier)
	return result, nil
}

func (f nsdsFlow) E911UpdateSupport(context.Context) (E911UpdateSupport, error) {
	return E911UpdateSupport{
		Supported: true,
		BuiltIn:   true,
		Scheme:    SchemeNSDS,
		Carrier:   f.profile.Carrier,
		Reason:    "nsds profile exposes a built-in emergency address flow",
	}, nil
}

func nsdsUserAgent(device Device) string {
	if device.SoftwareVersion == "" && device.Model == "" {
		return ""
	}
	return "Dalvik/2.1.0 (Linux; U; Android " + device.SoftwareVersion + "; " + device.Model + ")"
}

func nsdsDeviceID(imei string) string {
	imei = strings.TrimSpace(imei)
	return base64.StdEncoding.EncodeToString([]byte(imei))
}

func nsdsIMSIEAP(card Card) (string, error) {
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
	return sim.IMSIEAPIdentity(mcc+mnc, card.IMSI(), nsdsDefaultEAPAkaRealm)
}

type nsdsClient struct {
	serverURL  string
	deviceID   string
	deviceName string
	imsiEAP    string
	userAgent  string
	httpClient *http.Client
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
	nsdsMessageIDManageLocationAndTC = 4
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

type nsdsStatus struct {
	MSISDN          string
	LocationTC      nsdsResponse
	ServiceEntitled bool
	Pending         bool
	LocationChecked bool
}

func (status nsdsStatus) LocationTCOK() bool {
	return status.LocationTC.LocationTCOK()
}

func (c nsdsClient) checkLocationAndTC(ctx context.Context, card Card, purpose Purpose) (nsdsStatus, error) {
	authChallenge, err := c.requestChallenge(ctx)
	if err != nil {
		return nsdsStatus{}, err
	}
	challengeResponse, err := nsdsChallengeResponse(ctx, card, c.imsiEAP, authChallenge.AKAChallenge)
	if err != nil {
		return nsdsStatus{}, err
	}
	token := ""
	requests := []nsdsRequest{
		c.authenticationRequest(nsdsMessageID3GPPAuthentication, challengeResponse, token),
		c.serviceEntitlementRequest(nsdsMessageIDServiceEntitlement),
	}
	if purpose != PurposeActivation {
		requests = append(requests, c.getMSISDNRequest(nsdsMessageIDGetMSISDN))
	}

	responses, err := c.post(ctx, requests)
	if err != nil {
		return nsdsStatus{}, err
	}
	if err := nsdsRequireResponseCode(responses.response(nsdsMessageID3GPPAuthentication), nsdsResponseSuccessful, nsdsMethod3GPPAuthentication); err != nil {
		return nsdsStatus{}, err
	}
	entitlement := responses.response(nsdsMessageIDServiceEntitlement)
	if err := nsdsRequireResponseCode(entitlement, nsdsResponseSuccessful, nsdsMethodServiceEntitlement); err != nil {
		return nsdsStatus{}, err
	}
	if !nsdsVowifiEntitled(entitlement) {
		return nsdsStatus{}, nil
	}
	if purpose == PurposeActivation {
		return nsdsStatus{ServiceEntitled: true}, nil
	}

	msisdn := responses.response(nsdsMessageIDGetMSISDN)
	if err := nsdsRequireResponseCode(msisdn, nsdsResponseSuccessful, nsdsMethodGetMSISDN); err != nil {
		return nsdsStatus{}, err
	}
	if msisdn.ServiceFingerprint == "" {
		return nsdsStatus{}, errors.New("nsds service fingerprint is missing")
	}

	token = nsdsFirstNonEmpty(responses.response(nsdsMessageID3GPPAuthentication).AKAToken, token)
	responses, err = c.post(ctx, []nsdsRequest{
		c.authenticationRequest(nsdsMessageID3GPPAuthentication, "", token),
		c.manageLocationAndTCRequest(nsdsMessageIDManageLocationAndTC, msisdn.ServiceFingerprint),
	})
	if err != nil {
		return nsdsStatus{}, err
	}
	if err := nsdsRequireResponseCode(responses.response(nsdsMessageID3GPPAuthentication), nsdsResponseSuccessful, nsdsMethod3GPPAuthentication); err != nil {
		return nsdsStatus{}, err
	}
	locationTC := responses.response(nsdsMessageIDManageLocationAndTC)
	if err := nsdsRequireResponseCode(locationTC, nsdsResponseSuccessful, nsdsMethodManageLocationAndTC); err != nil {
		return nsdsStatus{}, err
	}
	return nsdsStatus{
		MSISDN:          msisdn.MSISDN,
		LocationTC:      locationTC,
		ServiceEntitled: true,
		LocationChecked: true,
	}, nil
}

func (c nsdsClient) requestChallenge(ctx context.Context) (nsdsResponse, error) {
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

func (c nsdsClient) authenticationRequest(messageID int, challengeResponse, token string) nsdsRequest {
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

func (c nsdsClient) serviceEntitlementRequest(messageID int) nsdsRequest {
	return nsdsRequest{
		MessageID:   messageID,
		Method:      nsdsMethodServiceEntitlement,
		DeviceID:    c.deviceID,
		ServiceList: []string{nsdsServiceVowifi},
	}
}

func (c nsdsClient) getMSISDNRequest(messageID int) nsdsRequest {
	return nsdsRequest{
		MessageID: messageID,
		Method:    nsdsMethodGetMSISDN,
		DeviceID:  c.deviceID,
	}
}

func (c nsdsClient) manageLocationAndTCRequest(messageID int, fingerprint string) nsdsRequest {
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

func (c nsdsClient) post(ctx context.Context, payload []nsdsRequest) (nsdsResponses, error) {
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

	resp, err := setupHTTPClient(c.httpClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting nsds request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
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

func nsdsChallengeResponse(ctx context.Context, card Card, imsiEAP, challengeText string) (string, error) {
	return eapAKAChallengeResponseForIdentity(ctx, card, imsiEAP, challengeText, "nsds aka")
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

func nsdsActivationCheckOptional(purpose Purpose, err error) bool {
	if purpose != PurposeActivation {
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

func nsdsE911Info(response nsdsResponse) *E911Info {
	if response.AddressID == "" && response.AIDExpiration.Time.IsZero() && response.ServerURL == "" && response.ServerData == "" {
		return nil
	}
	return &E911Info{
		AddressID:     response.AddressID,
		AIDExpiration: response.AIDExpiration.Time,
		ServerURL:     response.ServerURL,
		ServerData:    response.ServerData,
	}
}

func nsdsWebsheet(profile nsdsProfile, response nsdsResponse) *Websheet {
	if response.ServerURL == "" {
		return nil
	}
	return &Websheet{
		Kind:       WebsheetKindEmergencyAddress,
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

func nsdsFirstNonEmpty(first string, rest ...string) string {
	if strings.TrimSpace(first) != "" {
		return first
	}
	for _, value := range rest {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
