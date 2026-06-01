package wfcsetup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const telusMaxAttempts = 5

var telusSIMs = []simMatch{
	{MCC: "302", MNC: "220", GID1: "5455"},
	{MCC: "302", MNC: "220", GID1: "4B4F"},
	{MCC: "302", MNC: "220", GID1: "4D4F"},
	{MCC: "302", MNC: "221", GID1: "4B4F"},
	{MCC: "302", MNC: "221", GID1: "4D4F"},
	{MCC: "302", MNC: "221", GID1: "5455"},
}

type telusFlow struct {
	req Request
}

func newTelusFlow(req Request) (flow, bool, error) {
	if !isTelusCarrier(req) {
		return nil, false, nil
	}
	return telusFlow{req: req}, true, nil
}

func (f telusFlow) Check(ctx context.Context) (Result, error) {
	client := telusClient{
		Card:       f.req.Card,
		HTTPClient: f.req.HTTPClient,
	}
	result, err := client.Check(ctx)
	result.Carrier = telusCarrierName(f.req)
	if err != nil {
		return result, wrapResultError(result, err)
	}
	return result, nil
}

func (f telusFlow) E911UpdateSupport(context.Context) (E911UpdateSupport, error) {
	return E911UpdateSupport{
		Supported: true,
		BuiltIn:   true,
		Scheme:    SchemeTelus,
		Carrier:   telusCarrierName(f.req),
		Reason:    "telus ewg flow uses built-in sim eap-aka challenge handling",
	}, nil
}

type telusClient struct {
	Card       Card
	HTTPClient *http.Client
}

func (c telusClient) Check(ctx context.Context) (Result, error) {
	var result Result
	var err error
	for range telusMaxAttempts {
		result, err = c.checkOnce(ctx)
		if err == nil || !telusRetryable(err) {
			return result, err
		}
	}
	return result, err
}

func (c telusClient) checkOnce(ctx context.Context) (Result, error) {
	result := Result{
		Scheme:  SchemeTelus,
		Carrier: "TELUS",
	}
	accessToken, err := c.accessToken(ctx)
	if err != nil {
		result.Action = ActionDenied
		return result, err
	}
	result.Token = &CarrierToken{Type: "telus-access-token", Value: accessToken}

	entitlement, err := c.queryEntitlement(ctx, accessToken)
	if err != nil {
		return result, err
	}
	if entitlement.Pending {
		result.Action = ActionWait
		result.Pending = true
		return result, nil
	}
	if !entitlement.VoWiFiEnabled {
		result.Action = ActionDenied
		return result, nil
	}

	policies, err := c.queryServicePolicies(ctx, accessToken)
	if err != nil {
		return result, err
	}
	result.Entitled = true
	switch {
	case policies.NeedsEmergencyAddress:
		result.Action = ActionOpenWebsheet
		result.Websheet = &Websheet{
			Kind:       WebsheetKindEmergencyAddress,
			URL:        telusServiceURL(policies.ManagementURL, "no-usr-def-n911-addr", policies.ManagementToken),
			Title:      "Wi-Fi Calling",
			ClientName: canadaWebViewClientName,
		}
	case policies.NeedsTermsAndConditions:
		result.Action = ActionOpenWebsheet
		result.Websheet = &Websheet{
			Kind:       WebsheetKindTermsAndConditions,
			URL:        telusServiceURL(policies.ManagementURL, "no-tnc-usr-acpt", policies.ManagementToken),
			Title:      "Wi-Fi Calling",
			ClientName: canadaWebViewClientName,
		}
	default:
		result.Action = ActionAllowActivation
	}
	return result, nil
}

func telusRetryable(err error) bool {
	return err != nil &&
		!errors.Is(err, ErrExternalCredentialNeeded) &&
		!errors.Is(err, context.Canceled) &&
		!errors.Is(err, context.DeadlineExceeded)
}

func (c telusClient) accessToken(ctx context.Context) (string, error) {
	challenge, err := c.queryChallenge(ctx)
	if err != nil {
		return "", err
	}
	response, err := c.challengeResponse(ctx, challenge)
	if err != nil {
		return "", err
	}
	return c.exchangeChallenge(ctx, response)
}

func (c telusClient) challengeResponse(ctx context.Context, challenge string) (string, error) {
	response, err := eapAKAChallengeResponse(ctx, c.Card, challenge)
	if err != nil {
		return "", fmt.Errorf("answering telus eap-aka challenge: %w", err)
	}
	return response, nil
}

func (c telusClient) queryChallenge(ctx context.Context) (string, error) {
	var body struct {
		EAPChallengeResponse string `json:"eapChallengeResponse"`
	}
	if err := c.request(ctx, "https://ent.telus.com/androidgw/entitlements/"+c.Card.IMSI(), &body); err != nil {
		return "", err
	}
	if strings.TrimSpace(body.EAPChallengeResponse) == "" {
		return "", errors.New("telus eap-aka challenge is missing")
	}
	return body.EAPChallengeResponse, nil
}

func (c telusClient) exchangeChallenge(ctx context.Context, response string) (string, error) {
	payload := struct {
		EAPChallengeResponse string `json:"eapChallengeResponse"`
	}{EAPChallengeResponse: response}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encoding telus eap-aka response: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://ent.telus.com/androidgw/eap-aka/dialog", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("creating telus eap-aka request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := setupNoRedirectClient(c.HTTPClient).Do(req)
	if err != nil {
		return "", fmt.Errorf("posting telus eap-aka request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("posting telus eap-aka request: http %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	token := telusAccessTokenFromLocation(resp.Header.Get("Location"))
	if token == "" {
		return "", errors.New("telus eap-aka access token is missing")
	}
	return token, nil
}

type telusEntitlement struct {
	VoWiFiEnabled bool
	Pending       bool
}

func (c telusClient) queryEntitlement(ctx context.Context, token string) (telusEntitlement, error) {
	var entries []struct {
		Type   string `json:"type"`
		Status string `json:"status"`
	}
	endpoint := "https://ent.telus.com/androidgw/entitlements/" + c.Card.IMSI() + "?access_token=" + token
	if err := c.request(ctx, endpoint, &entries); err != nil {
		return telusEntitlement{}, err
	}
	var result telusEntitlement
	for _, entry := range entries {
		if !strings.EqualFold(entry.Type, "vowifi") {
			continue
		}
		switch strings.ToLower(entry.Status) {
		case "enabled":
			result.VoWiFiEnabled = true
		case "pending":
			result.Pending = true
		}
	}
	return result, nil
}

type telusServicePolicies struct {
	ManagementURL           string
	ManagementToken         string
	NeedsEmergencyAddress   bool
	NeedsTermsAndConditions bool
}

func (c telusClient) queryServicePolicies(ctx context.Context, token string) (telusServicePolicies, error) {
	var body struct {
		ManagementURL struct {
			URL         string `json:"url"`
			AccessToken string `json:"access_token"`
		} `json:"managementUrl"`
		ServicePolicies []string `json:"servicePolicies"`
	}
	endpoint := "https://ent.telus.com/androidgw/servicePolicies/" + c.Card.IMSI() + "?access_token=" + token
	if err := c.request(ctx, endpoint, &body); err != nil {
		return telusServicePolicies{}, err
	}
	policies := telusServicePolicies{
		ManagementURL:   body.ManagementURL.URL,
		ManagementToken: body.ManagementURL.AccessToken,
	}
	for _, policy := range body.ServicePolicies {
		switch policy {
		case "no-usr-def-n911-addr":
			policies.NeedsEmergencyAddress = true
		case "no-tnc-usr-acpt":
			policies.NeedsTermsAndConditions = true
		}
	}
	if (policies.NeedsEmergencyAddress || policies.NeedsTermsAndConditions) &&
		(strings.TrimSpace(policies.ManagementURL) == "" || strings.TrimSpace(policies.ManagementToken) == "") {
		return telusServicePolicies{}, errors.New("telus management url is missing")
	}
	return policies, nil
}

func (c telusClient) request(ctx context.Context, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return fmt.Errorf("creating telus request: %w", err)
	}
	resp, err := setupHTTPClient(c.HTTPClient).Do(req)
	if err != nil {
		return fmt.Errorf("querying telus endpoint: %w", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading telus response: %w", err)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("querying telus endpoint: http %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("parsing telus response: %w", err)
	}
	return nil
}

func setupHTTPClient(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return &http.Client{Timeout: defaultTimeout}
}

func setupNoRedirectClient(client *http.Client) *http.Client {
	base := setupHTTPClient(client)
	copy := *base
	copy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	if copy.Timeout == 0 {
		copy.Timeout = defaultTimeout
	}
	return &copy
}

func telusAccessTokenFromLocation(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	u, err := url.Parse(location)
	if err == nil {
		if token := u.Query().Get("access_token"); token != "" {
			return token
		}
	}
	const key = "access_token="
	_, after, ok := strings.Cut(location, key)
	if !ok {
		return ""
	}
	token := after
	if j := strings.IndexByte(token, '&'); j >= 0 {
		token = token[:j]
	}
	return token
}

func telusServiceURL(base, page, token string) string {
	return base + "?page=" + page + "&access_token=" + token
}

func isTelusCarrier(req Request) bool {
	return matchAnySIM(req.Card, telusSIMs)
}

func telusCarrierName(req Request) string {
	gid1 := cardGID1(req.Card)
	switch {
	case matchAnySIM(req.Card, []simMatch{
		{MCC: "302", MNC: "220", GID1: "4B4F"},
		{MCC: "302", MNC: "221", GID1: "4B4F"},
	}):
		return "Koodo"
	case matchAnySIM(req.Card, []simMatch{
		{MCC: "302", MNC: "220", GID1: "4D4F"},
		{MCC: "302", MNC: "221", GID1: "4D4F"},
	}):
		return "Public Mobile"
	case strings.EqualFold(gid1, "5455"):
		return "TELUS"
	}
	return "TELUS"
}
