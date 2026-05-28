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
	"strings"
	"time"

	"github.com/damonto/ts43-go/sim"
	"github.com/damonto/ts43-go/ts43"
)

type WFCEntitlementConfig struct {
	Timeout          time.Duration
	HTTPClient       *http.Client
	TerminalVendor   string
	TerminalModel    string
	TerminalSoftware string
}

var (
	ErrWFCEntitlementUserActionRequired = errors.New("wfc entitlement requires user action")
	ErrWFCEntitlementPending            = errors.New("wfc entitlement is pending")
	ErrWFCEntitlementDenied             = errors.New("wfc entitlement denied")
)

type WFCEntitlementError struct {
	Err    error
	Config ts43.WFCConfig
	Status ts43.WFCStatus
}

type WFCWebsheet struct {
	URL        string
	Data       string
	Title      string
	ClientName string
}

type NSDSWFCEntitlementError struct {
	Err      error
	Carrier  string
	Websheet WFCWebsheet
}

func (e *NSDSWFCEntitlementError) Error() string {
	if e == nil || e.Err == nil {
		return "wfc nsds entitlement failed"
	}
	if e.Websheet.URL != "" {
		return e.Err.Error() + ": " + e.Websheet.URL
	}
	return e.Err.Error()
}

func (e *NSDSWFCEntitlementError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (e *WFCEntitlementError) Error() string {
	if e == nil || e.Err == nil {
		return "wfc entitlement failed"
	}
	if e.Status.ServiceFlowURL != "" {
		return e.Err.Error() + ": " + e.Status.ServiceFlowURL
	}
	return e.Err.Error()
}

func (e *WFCEntitlementError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func (c *Client) checkWFCEntitlement(ctx context.Context, cfg *Config, card Card) error {
	if profile, ok := nsdsWFCProfileForCard(card); ok {
		if err := c.checkNSDSWFCEntitlement(ctx, cfg, card, profile); err != nil {
			return err
		}
		c.logger.Debug("wfc nsds entitlement granted", "carrier", profile.Carrier)
		return nil
	}

	identity := ts43Identity(card)
	wfc, err := ts43.DiscoverWFC(identity)
	if err != nil {
		if errors.Is(err, ts43.ErrWFCConfigNotFound) {
			c.logger.Debug("wfc entitlement config not found", "mcc", identity.MCC, "mnc", identity.MNC)
			return nil
		}
		return fmt.Errorf("discovering wfc entitlement: %w", err)
	}

	status, err := ts43.CheckWFCEntitlement(ctx, ts43.Config{
		Logger:     cfg.Logger,
		HTTPClient: cfg.WFCEntitlement.HTTPClient,
		Entitlement: ts43.Entitlement{
			Timeout: cfg.WFCEntitlement.timeout(),
		},
		Source: ts43.Endpoint{Channel: ts43Channel{card: card, identity: identity}},
	}, identity, ts43.Device{
		IMEI:            cfg.IMEI,
		Vendor:          cfg.WFCEntitlement.TerminalVendor,
		Model:           cfg.WFCEntitlement.TerminalModel,
		SoftwareVersion: cfg.WFCEntitlement.TerminalSoftware,
	}, wfc)
	if err != nil {
		return fmt.Errorf("checking wfc entitlement: %w", err)
	}
	if status.Entitled() {
		c.logger.Debug("wfc entitlement granted", "carrier", wfc.CarrierName)
		return nil
	}

	return fmt.Errorf("checking wfc entitlement: %w", wfcEntitlementError(wfc, status))
}

func (cfg WFCEntitlementConfig) timeout() time.Duration {
	if cfg.Timeout != 0 {
		return cfg.Timeout
	}
	return 30 * time.Second
}

func wfcEntitlementError(cfg ts43.WFCConfig, status ts43.WFCStatus) error {
	err := ErrWFCEntitlementDenied
	switch {
	case status.NeedsUserWebFlow():
		err = ErrWFCEntitlementUserActionRequired
	case status.InProgress():
		err = ErrWFCEntitlementPending
	}
	return &WFCEntitlementError{
		Err:    err,
		Config: cfg,
		Status: status,
	}
}

type ts43Channel struct {
	card     Card
	identity sim.Identity
}

func (c ts43Channel) Identity(context.Context) (*sim.Identity, error) {
	identity := c.identity
	return &identity, nil
}

func (c ts43Channel) AuthenticateAKA(ctx context.Context, req *sim.AKARequest) (*sim.AKAResponse, error) {
	result, err := c.card.AKA(ctx, req.Rand, req.Autn)
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

func (c *Client) checkNSDSWFCEntitlement(ctx context.Context, cfg *Config, card Card, profile nsdsWFCProfile) error {
	client := nsdsWFCClient{
		httpClient: cfg.WFCEntitlement.HTTPClient,
		serverURL:  profile.ServerURL,
		deviceID:   base64.StdEncoding.EncodeToString([]byte(cfg.IMEI)),
		deviceName: nsdsWFCDeviceName(*cfg),
		imsiEAP:    nsdsWFCIMSIEAP(card),
		userAgent:  nsdsWFCUserAgent(*cfg),
	}

	checkCtx, cancel := context.WithTimeout(ctx, cfg.WFCEntitlement.timeout())
	defer cancel()

	status, err := client.checkLocationAndTC(checkCtx, card)
	if err != nil {
		return fmt.Errorf("checking wfc nsds entitlement: %w", err)
	}
	if status.MSISDN != "" {
		applyNSDSWFCMSISDN(cfg, status.MSISDN)
		c.logger.Debug("wfc nsds msisdn received", "carrier", profile.Carrier, "msisdn", status.MSISDN, "public_identity", cfg.IMS.PublicIdentity)
	}
	if !status.LocationTCOK() {
		c.logger.Warn("wfc nsds entitlement requires user action",
			"carrier", profile.Carrier,
			"url", status.LocationTC.ServerURL,
			"data", status.LocationTC.ServerData,
			"title", profile.Title,
			"client", profile.ClientName,
		)
		return fmt.Errorf("checking wfc nsds entitlement: %w", &NSDSWFCEntitlementError{
			Err:     ErrWFCEntitlementUserActionRequired,
			Carrier: profile.Carrier,
			Websheet: WFCWebsheet{
				URL:        status.LocationTC.ServerURL,
				Data:       status.LocationTC.ServerData,
				Title:      profile.Title,
				ClientName: profile.ClientName,
			},
		})
	}
	return nil
}

func nsdsWFCDeviceName(cfg Config) string {
	if cfg.WFCEntitlement.TerminalModel != "" {
		return cfg.WFCEntitlement.TerminalModel
	}
	return "Android"
}

func nsdsWFCUserAgent(cfg Config) string {
	if cfg.WFCEntitlement.TerminalSoftware != "" || cfg.WFCEntitlement.TerminalModel != "" {
		return "Dalvik/2.1.0 (Linux; U; Android " + firstNonEmpty(cfg.WFCEntitlement.TerminalSoftware, "13") + "; " + nsdsWFCDeviceName(cfg) + ")"
	}
	return "Dalvik/2.1.0 (Linux; U; Android 13)"
}

func nsdsWFCIMSIEAP(card Card) string {
	return "0" + card.IMSI() + "@nai.epc.mnc" + strings.TrimSpace(card.MNC()) + ".mcc" + strings.TrimSpace(card.MCC()) + ".3gppnetwork.org"
}

func applyNSDSWFCMSISDN(cfg *Config, msisdn string) {
	if cfg == nil || strings.TrimSpace(cfg.IMS.PublicIdentity) != "" {
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
	httpClient *http.Client
	serverURL  string
	deviceID   string
	deviceName string
	imsiEAP    string
	userAgent  string
}

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
	AIDExpiration          string               `json:"aid-expiration"`
	ServiceStatus          *int                 `json:"service-status"`
}

type serviceEntitlement struct {
	ServiceName       string `json:"service-name"`
	EntitlementStatus int    `json:"entitlement-status"`
}

type nsdsWFCStatus struct {
	MSISDN     string
	LocationTC nsdsResponse
}

func (status nsdsWFCStatus) LocationTCOK() bool {
	return status.LocationTC.LocationTCOK()
}

func (c nsdsWFCClient) checkLocationAndTC(ctx context.Context, card Card) (nsdsWFCStatus, error) {
	authChallenge, err := c.requestChallenge(ctx)
	if err != nil {
		return nsdsWFCStatus{}, err
	}
	challengeResponse, err := nsdsWFCChallengeResponse(ctx, card, c.imsiEAP, authChallenge.AKAChallenge)
	if err != nil {
		return nsdsWFCStatus{}, err
	}

	authenticated, err := c.respondToChallenge(ctx, challengeResponse)
	if err != nil {
		return nsdsWFCStatus{}, err
	}
	token := firstNonEmpty(authenticated.AKAToken, authChallenge.AKAToken)

	responses, err := c.post(ctx, []nsdsRequest{
		c.authenticationRequest(1, "", token),
		c.serviceEntitlementRequest(2),
		c.getMSISDNRequest(3),
	})
	if err != nil {
		return nsdsWFCStatus{}, err
	}
	if err := nsdsRequireResponseCode(responses.response(1), 1000, "3gppAuthentication"); err != nil {
		return nsdsWFCStatus{}, err
	}
	entitlement := responses.response(2)
	if err := nsdsRequireResponseCode(entitlement, 1000, "serviceEntitlementStatus"); err != nil {
		return nsdsWFCStatus{}, err
	}
	if !nsdsVowifiEntitled(entitlement) {
		return nsdsWFCStatus{}, &NSDSWFCEntitlementError{Err: ErrWFCEntitlementDenied}
	}
	msisdn := responses.response(3)
	if err := nsdsRequireResponseCode(msisdn, 1000, "getMSISDN"); err != nil {
		return nsdsWFCStatus{}, err
	}
	if msisdn.ServiceFingerprint == "" {
		return nsdsWFCStatus{}, &NSDSWFCEntitlementError{Err: ErrWFCEntitlementPending}
	}

	token = firstNonEmpty(responses.response(1).AKAToken, token)
	responses, err = c.post(ctx, []nsdsRequest{
		c.authenticationRequest(1, "", token),
		c.manageLocationAndTCRequest(2, msisdn.ServiceFingerprint),
	})
	if err != nil {
		return nsdsWFCStatus{}, err
	}
	if err := nsdsRequireResponseCode(responses.response(1), 1000, "3gppAuthentication"); err != nil {
		return nsdsWFCStatus{}, err
	}
	locationTC := responses.response(2)
	if err := nsdsRequireResponseCode(locationTC, 1000, "manageLocationAndTC"); err != nil {
		return nsdsWFCStatus{}, err
	}
	return nsdsWFCStatus{MSISDN: msisdn.MSISDN, LocationTC: locationTC}, nil
}

func (c nsdsWFCClient) respondToChallenge(ctx context.Context, challengeResponse string) (nsdsResponse, error) {
	responses, err := c.post(ctx, []nsdsRequest{c.authenticationRequest(1, challengeResponse, "")})
	if err != nil {
		return nsdsResponse{}, err
	}
	response := responses.response(1)
	if err := nsdsRequireResponseCode(response, 1000, "3gppAuthentication"); err != nil {
		return nsdsResponse{}, err
	}
	return response, nil
}

func (c nsdsWFCClient) requestChallenge(ctx context.Context) (nsdsResponse, error) {
	responses, err := c.post(ctx, []nsdsRequest{c.authenticationRequest(1, "", "")})
	if err != nil {
		return nsdsResponse{}, err
	}
	response := responses.response(1)
	if err := nsdsRequireResponseCode(response, 1003, "3gppAuthentication"); err != nil {
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
		Method:          "3gppAuthentication",
		DeviceID:        c.deviceID,
		DeviceType:      intPtr(0),
		OSType:          intPtr(0),
		DeviceName:      c.deviceName,
		IMSIEAP:         c.imsiEAP,
		AKAChallengeRsp: challengeResponse,
		AKAToken:        token,
	}
}

func (c nsdsWFCClient) serviceEntitlementRequest(messageID int) nsdsRequest {
	return nsdsRequest{
		MessageID:   messageID,
		Method:      "serviceEntitlementStatus",
		DeviceID:    c.deviceID,
		ServiceList: []string{"vowifi"},
	}
}

func (c nsdsWFCClient) getMSISDNRequest(messageID int) nsdsRequest {
	return nsdsRequest{
		MessageID: messageID,
		Method:    "getMSISDN",
		DeviceID:  c.deviceID,
	}
}

func (c nsdsWFCClient) manageLocationAndTCRequest(messageID int, fingerprint string) nsdsRequest {
	return nsdsRequest{
		MessageID:          messageID,
		Method:             "manageLocationAndTC",
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
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Connection", "Keep-Alive")

	httpClient := c.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	resp, err := httpClient.Do(req)
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
	aka, err := card.AKA(ctx, challenge.Rand, challenge.Autn)
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
		return fmt.Errorf("nsds %s response missing", method)
	}
	return fmt.Errorf("nsds %s response code %d, want %d", method, response.ResponseCode, want)
}

func nsdsVowifiEntitled(response nsdsResponse) bool {
	for _, service := range response.ServiceEntitlementList {
		if service.ServiceName != "vowifi" {
			continue
		}
		switch service.EntitlementStatus {
		case 1000, 1048, 1063:
			return true
		default:
			return false
		}
	}
	return false
}

func (response nsdsResponse) LocationTCOK() bool {
	return nsdsBoolOK(response.LocationStatus) && nsdsBoolOK(response.TCStatus)
}

func nsdsBoolOK(value *bool) bool {
	return value == nil || *value
}

func intPtr(value int) *int {
	return &value
}
