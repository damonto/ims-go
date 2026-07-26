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
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	o2MessageAuthentication     = 1
	o2MessageServiceEntitlement = 2
	o2MessageMSISDN             = 3

	o2ResponseSuccessful       = 1000
	o2ResponseAKAChallenge     = 1003
	o2ResponseInvalidRequest   = 1004
	o2ResponseTransientFailure = 1006
	o2ResponseServerError      = 1111
	o2EntitlementStatusEnabled = 1000
)

var o2UKSIMs = []simMatch{
	{MCC: "234", MNC: "10"},
}

var o2UKExcludedSIMs = []simMatch{
	{MCC: "234", MNC: "10", GID1: "547275554B3030656E"}, // Truphone
	{MCC: "234", MNC: "10", GID1: "636F6E6E65637431"},   // Telna
	{MCC: "234", MNC: "10", GID1: "0A"},                 // Tesco
	{MCC: "234", MNC: "10", GID1: "50"},                 // giffgaff
	{MCC: "234", MNC: "10", GID1: "61"},                 // O2 prepaid
	{MCC: "234", MNC: "10", GID1: "67"},                 // O2 prepaid
	{MCC: "234", MNC: "10", GID1: "85"},                 // O2 prepaid
	{MCC: "234", MNC: "10", GID1: "99"},                 // O2 prepaid
}

type o2ukFlow struct {
	req Request
}

func newO2UKFlow(req Request) (flow, bool, error) {
	if isO2UKCarrier(req) {
		return o2ukFlow{req: req}, true, nil
	}
	return nil, false, nil
}

func (f o2ukFlow) Check(ctx context.Context) (Result, error) {
	client := o2UKClient{
		Card:            f.req.Card,
		AuthenticateAKA: f.req.AuthenticateAKA,
		Device:          f.req.Device,
		HTTPClient:      f.req.HTTPClient,
	}
	result, err := client.Check(ctx)
	result.Carrier = "O2 UK"
	if err != nil {
		return result, wrapResultError(result, err)
	}
	return result, nil
}

func (f o2ukFlow) E911UpdateSupport(context.Context) (E911UpdateSupport, error) {
	return E911UpdateSupport{
		Supported: false,
		BuiltIn:   false,
		Scheme:    SchemeO2UK,
		Carrier:   "O2 UK",
		Reason:    "o2 uk android flow is entitlement polling, not an emergency address update flow",
	}, nil
}

type o2UKClient struct {
	Card            Card
	AuthenticateAKA AKAAuthenticator
	Device          Device
	HTTPClient      *http.Client
}

var o2UKTokens = struct {
	mu     sync.Mutex
	values map[string]string
}{
	values: make(map[string]string),
}

func (c o2UKClient) Check(ctx context.Context) (Result, error) {
	result := Result{
		Scheme:  SchemeO2UK,
		Carrier: "O2 UK",
	}
	if token := o2UKCachedToken(c.Card); token != "" {
		status, err := c.queryEntitlement(ctx, token, "")
		if err != nil {
			return result, err
		}
		if !status.FullAuthenticationRequired {
			return c.resultFromStatus(result, status), nil
		}
		o2UKForgetToken(c.Card)
	}

	challenge, err := c.authenticationChallenge(ctx)
	if err != nil {
		if errors.Is(err, ErrPending) {
			result.Action = ActionWait
			result.Pending = true
		}
		return result, err
	}
	status, err := c.queryEntitlement(ctx, "", challenge)
	if err != nil {
		return result, err
	}
	if status.FullAuthenticationRequired {
		o2UKForgetToken(c.Card)
		challenge, err = c.authenticationChallenge(ctx)
		if err != nil {
			if errors.Is(err, ErrPending) {
				result.Action = ActionWait
				result.Pending = true
			}
			return result, err
		}
		status, err = c.queryEntitlement(ctx, "", challenge)
		if err != nil {
			return result, err
		}
	}
	return c.resultFromStatus(result, status), nil
}

func (c o2UKClient) resultFromStatus(result Result, status o2Status) Result {
	if status.AKAToken != "" {
		o2UKStoreToken(c.Card, status.AKAToken)
		result.Token = &CarrierToken{Type: "aka-token", Value: status.AKAToken}
	}
	if status.Pending {
		result.Action = ActionWait
		result.Pending = true
		if status.PollInterval > 0 {
			result.RetryAfter = status.PollInterval
		}
		return result
	}
	if status.AuthResponseCode == o2ResponseSuccessful && status.EntitlementResponseCode == o2ResponseSuccessful && status.WFCEntitled {
		result.Action = ActionAllowActivation
		result.Entitled = true
		return result
	}
	result.Action = ActionDenied
	return result
}

func (c o2UKClient) authenticationChallenge(ctx context.Context) (string, error) {
	responses, err := c.post(ctx, []o2Request{c.authenticationRequest("", "")})
	if err != nil {
		return "", err
	}
	status := o2Responses(responses).Status()
	if status.AuthResponseCode == o2ResponseServerError {
		return "", ErrPending
	}
	return status.AKAChallenge, nil
}

func (c o2UKClient) queryEntitlement(ctx context.Context, akaToken, challenge string) (o2Status, error) {
	challengeResponse := ""
	if strings.TrimSpace(challenge) != "" {
		response, err := c.challengeResponse(ctx, challenge)
		if err != nil {
			return o2Status{}, err
		}
		if strings.TrimSpace(response) == "" {
			return o2Status{}, ErrExternalCredentialNeeded
		}
		challengeResponse = response
	}
	requests := []o2Request{
		c.authenticationRequest(akaToken, challengeResponse),
		{
			MessageID:   o2MessageServiceEntitlement,
			Method:      "serviceEntitlementStatus",
			DeviceID:    c.deviceID(),
			ServiceList: []string{"VoLTE", "VoWiFi"},
		},
		{
			MessageID: o2MessageMSISDN,
			Method:    "getMSISDN",
			DeviceID:  c.deviceID(),
		},
	}
	responses, err := c.post(ctx, requests)
	if err != nil {
		return o2Status{}, err
	}
	status := o2Responses(responses).Status()
	if status.AuthResponseCode == o2ResponseAKAChallenge {
		status.FullAuthenticationRequired = true
		return status, nil
	}
	if isO2Transient(status.AuthResponseCode, status.EntitlementResponseCode) {
		status.Pending = true
	}
	return status, nil
}

func (c o2UKClient) challengeResponse(ctx context.Context, challenge string) (string, error) {
	response, err := eapAKAChallengeResponse(ctx, eapAKAResponseInput{
		Authenticate: c.AuthenticateAKA,
		Identity:     imsiEAP(c.Card),
		Challenge:    challenge,
		Kind:         akaChallengeKindEAPAKA,
	})
	if err != nil {
		return "", fmt.Errorf("answering o2 uk eap-aka challenge: %w", err)
	}
	return response, nil
}

func (c o2UKClient) authenticationRequest(akaToken, challengeResponse string) o2Request {
	req := o2Request{
		MessageID:  o2MessageAuthentication,
		Method:     "3gppAuthentication",
		DeviceID:   c.deviceID(),
		DeviceType: new(int),
		OSType:     new(int),
		DeviceName: strings.TrimSpace(c.Device.Model),
		IMSIEAP:    imsiEAP(c.Card),
	}
	if strings.TrimSpace(akaToken) != "" {
		req.AKAToken = akaToken
	}
	if strings.TrimSpace(challengeResponse) != "" {
		req.AKAChallengeResponse = challengeResponse
	}
	return req
}

type o2Request struct {
	MessageID            int      `json:"message-id"`
	Method               string   `json:"method"`
	DeviceID             string   `json:"device-id,omitempty"`
	DeviceType           *int     `json:"device-type,omitempty"`
	OSType               *int     `json:"os-type,omitempty"`
	DeviceName           string   `json:"device-name,omitempty"`
	IMSIEAP              string   `json:"imsi-eap,omitempty"`
	AKAToken             string   `json:"aka-token,omitempty"`
	AKAChallengeResponse string   `json:"aka-challenge-rsp,omitempty"`
	ServiceList          []string `json:"service-list,omitempty"`
}

type o2Response struct {
	MessageID               int    `json:"message-id"`
	ResponseCode            int    `json:"response-code"`
	AKAChallenge            string `json:"aka-challenge"`
	AKAToken                string `json:"aka-token"`
	PollInterval            int    `json:"poll-interval"`
	ServiceEntitlementItems []struct {
		ServiceName       string `json:"service-name"`
		EntitlementStatus int    `json:"entitlement-status"`
	} `json:"service-entitlement"`
}

type o2Responses []o2Response

type o2Status struct {
	AuthResponseCode           int
	EntitlementResponseCode    int
	EntitlementStatus          int
	PollInterval               time.Duration
	Pending                    bool
	FullAuthenticationRequired bool
	AKAChallenge               string
	AKAToken                   string
	WFCEntitled                bool
	VoLTEEntitled              bool
	Services                   []string
}

func (c o2UKClient) post(ctx context.Context, requests []o2Request) ([]o2Response, error) {
	data, err := json.Marshal(requests)
	if err != nil {
		return nil, fmt.Errorf("encoding o2 uk request: %w", err)
	}
	var body bytes.Buffer
	gz := gzip.NewWriter(&body)
	if _, err := gz.Write(data); err != nil {
		return nil, fmt.Errorf("compressing o2 uk request: %w", err)
	}
	if err := gz.Close(); err != nil {
		return nil, fmt.Errorf("compressing o2 uk request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://ses.o2.co.uk:443/generic_devices", &body)
	if err != nil {
		return nil, fmt.Errorf("creating o2 uk request: %w", err)
	}
	req.Header.Set("x-generic-protocol-version", "1.0")
	req.Header.Set("x-generic-version", "1.0")
	req.Header.Set("x-protocol-version", "1")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := setupHTTPClient(c.HTTPClient).Do(req)
	if err != nil {
		return nil, fmt.Errorf("posting o2 uk request: %w", err)
	}
	defer resp.Body.Close()
	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading o2 uk response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("posting o2 uk request: http %d: %s", resp.StatusCode, strings.TrimSpace(string(respData)))
	}
	var responses []o2Response
	if err := json.Unmarshal(respData, &responses); err != nil {
		return nil, fmt.Errorf("parsing o2 uk response: %w", err)
	}
	return responses, nil
}

func (responses o2Responses) Status() o2Status {
	status := o2Status{AuthResponseCode: -1, EntitlementResponseCode: -1, EntitlementStatus: -1}
	for _, resp := range responses {
		switch resp.MessageID {
		case o2MessageAuthentication:
			status.AuthResponseCode = resp.ResponseCode
			status.AKAChallenge = resp.AKAChallenge
			status.AKAToken = resp.AKAToken
		case o2MessageServiceEntitlement:
			status.EntitlementResponseCode = resp.ResponseCode
			if resp.PollInterval > 0 {
				status.PollInterval = time.Duration(resp.PollInterval) * time.Second
			}
			for _, item := range resp.ServiceEntitlementItems {
				status.EntitlementStatus = item.EntitlementStatus
				status.Services = append(status.Services, item.ServiceName+"="+strconv.Itoa(item.EntitlementStatus))
				if item.EntitlementStatus != o2EntitlementStatusEnabled {
					continue
				}
				switch strings.ToLower(item.ServiceName) {
				case "vowifi":
					status.WFCEntitled = true
				case "volte":
					status.VoLTEEntitled = true
				}
			}
		}
	}
	return status
}

func isO2Transient(authCode, entitlementCode int) bool {
	return authCode == o2ResponseInvalidRequest ||
		authCode == o2ResponseServerError ||
		entitlementCode == o2ResponseTransientFailure ||
		entitlementCode == o2ResponseServerError
}

func (c o2UKClient) deviceID() string {
	imei := strings.TrimSpace(c.Device.IMEI)
	if imei == "" {
		return ""
	}
	return base64.StdEncoding.EncodeToString([]byte(imei))
}

func isO2UKCarrier(req Request) bool {
	return matchAnySIM(req.Card, o2UKSIMs) && !matchAnySIM(req.Card, o2UKExcludedSIMs)
}

func o2UKCachedToken(card Card) string {
	key := strings.TrimSpace(card.IMSI())
	if key == "" {
		return ""
	}
	o2UKTokens.mu.Lock()
	defer o2UKTokens.mu.Unlock()
	return o2UKTokens.values[key]
}

func o2UKStoreToken(card Card, token string) {
	key := strings.TrimSpace(card.IMSI())
	token = strings.TrimSpace(token)
	if key == "" || token == "" {
		return
	}
	o2UKTokens.mu.Lock()
	defer o2UKTokens.mu.Unlock()
	o2UKTokens.values[key] = token
}

func o2UKForgetToken(card Card) {
	key := strings.TrimSpace(card.IMSI())
	if key == "" {
		return
	}
	o2UKTokens.mu.Lock()
	defer o2UKTokens.mu.Unlock()
	delete(o2UKTokens.values, key)
}
