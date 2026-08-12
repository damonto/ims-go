package registration

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/sip"
	usim "github.com/damonto/wwan-go/sim"
)

const (
	registerAuthorizationHeader      = "Authorization"
	registerProxyAuthorizationHeader = "Proxy-Authorization"
)

type registerAuthChallenge struct {
	challenge           security.Challenge
	authorizationHeader string
	verify              *security.Param
	rawSecurityServer   []string
	publicContactHost   string
}

func (s *Registrar) storeAuthChallenge(challenge security.Challenge, authorizationHeader string) {
	realm := strings.TrimSpace(challenge.Realm)
	if realm == "" {
		realm = strings.TrimPrefix(s.State().RegisterURI, "sip:")
	}
	authorizationHeader = registerAuthorizationHeaderName(authorizationHeader)
	s.mu.Lock()
	if s.authDigestNonce != challenge.Nonce || !strings.EqualFold(s.authDigestAlgorithm, challenge.Algorithm) {
		s.authDigestNonce = ""
		s.authDigestAlgorithm = ""
		s.authDigestPassword = ""
	}
	s.authRealm = realm
	s.authNonce = challenge.Nonce
	s.authAlgorithm = challenge.Algorithm
	s.authQOP = challenge.QOP
	s.authOpaque = challenge.Opaque
	s.authHeader = authorizationHeader
	s.authNonceCount = 0
	s.mu.Unlock()
}

func (s *Registrar) currentAuthState() (string, string, string, string) {
	challenge := s.currentAuthChallenge()
	return challenge.Realm, challenge.Nonce, challenge.Algorithm, challenge.QOP
}

func (s *Registrar) currentAuthChallenge() security.Challenge {
	s.mu.Lock()
	defer s.mu.Unlock()
	realm := s.authRealm
	if realm == "" {
		realm = strings.TrimPrefix(s.state.RegisterURI, "sip:")
	}
	return security.Challenge{
		Realm:     realm,
		Nonce:     s.authNonce,
		Algorithm: s.authAlgorithm,
		QOP:       s.authQOP,
		Opaque:    s.authOpaque,
	}
}

func (s *Registrar) currentAuthorizationHeaderName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return registerAuthorizationHeaderName(s.authHeader)
}

func (s *Registrar) nextAuthNonceCount() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authNonceCount++
	return s.authNonceCount
}

func (s *Registrar) buildRegisterAuthorization(ctx context.Context, challenge security.Challenge) (*security.Authorization, error) {
	if challenge.Nonce == "" {
		return nil, nil
	}
	nonceCount := s.nextAuthNonceCount()
	if password, ok := s.currentDigestCredential(challenge.Nonce, challenge.Algorithm); ok {
		auth, err := s.calculateDigestRegisterAuthorization(challenge, nonceCount, password)
		if err != nil {
			return nil, err
		}
		return auth, nil
	}
	auth, ck, ik, password, err := s.calculateRegisterAuthorization(ctx, challenge, nonceCount)
	if err != nil {
		return nil, err
	}
	s.storeDigestCredential(auth.Algorithm, auth.Nonce, password, ck, ik)
	return auth, nil
}

func (s *Registrar) calculateRegisterAuthorization(ctx context.Context, challenge security.Challenge, nonceCount uint32) (*security.Authorization, []byte, []byte, string, error) {
	if challenge.Nonce == "" {
		return nil, nil, nil, "", nil
	}
	result, err := security.BuildAKAAuthorization(ctx, akaProvider{
		card:       s.card,
		group:      s.group,
		preference: s.cfg.RegistrationPreference,
	}, security.Identity{
		PrivateIdentity: s.State().PrivateIdentity,
		RegisterURI:     s.State().RegisterURI,
		Realm:           defaultRealm(challenge.Realm, s.State().RegisterURI),
	}, challenge, nonceCount)
	if err != nil {
		return nil, nil, nil, "", err
	}
	auth := result.Authorization
	auth.IntegrityProtected = registerIntegrityProtectedValue(auth.Algorithm)
	return &auth, result.EncryptionKey, result.IntegrityKey, result.DigestPassword, nil
}

func (s *Registrar) calculateDigestRegisterAuthorization(challenge security.Challenge, nonceCount uint32, password string) (*security.Authorization, error) {
	result, err := security.BuildDigestAuthorization(security.Identity{
		PrivateIdentity: s.State().PrivateIdentity,
		RegisterURI:     s.State().RegisterURI,
		Realm:           defaultRealm(challenge.Realm, s.State().RegisterURI),
	}, challenge, nonceCount, password)
	if err != nil {
		return nil, err
	}
	result.IntegrityProtected = registerIntegrityProtectedValue(result.Algorithm)
	return &result, nil
}

func (s *Registrar) currentDigestCredential(nonce, algorithm string) (string, bool) {
	normalized, ok := security.NormalizeAKAAlgorithm(algorithm)
	if !ok {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authDigestPassword == "" || s.authDigestNonce != nonce || !strings.EqualFold(s.authDigestAlgorithm, normalized) {
		return "", false
	}
	return s.authDigestPassword, true
}

func (s *Registrar) storeDigestCredential(algorithm, nonce, password string, ck, ik []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if password != "" {
		s.authDigestAlgorithm = algorithm
		s.authDigestNonce = nonce
		s.authDigestPassword = password
	}
	if !registerUsesTLSAKA(algorithm) && len(ik) != 0 {
		s.authIK = append([]byte(nil), ik...)
	}
	if !registerUsesTLSAKA(algorithm) && len(ck) != 0 {
		s.authCK = append([]byte(nil), ck...)
	}
}

func (s *Registrar) applyRegisterChallenge(resp sip.Message) (security.Challenge, error) {
	flow := s.CurrentFlow()
	requiredMode := ""
	if flow.SecurityVerify != nil {
		requiredMode = flow.SecurityVerify.Mod
	}
	parsed, err := parseRegisterChallenge(resp, flow.SecurityClients, requiredMode)
	if err != nil {
		return security.Challenge{}, err
	}
	s.applySelectedSecurityServer(parsed.verify, parsed.rawSecurityServer, parsed.publicContactHost)
	s.storeAuthChallenge(parsed.challenge, parsed.authorizationHeader)
	return parsed.challenge, nil
}

func parseRegisterChallenge(resp sip.Message, offered security.Params, requiredMode string) (registerAuthChallenge, error) {
	parsed, err := selectRegisterChallengeForResponse(resp)
	if err != nil {
		return registerAuthChallenge{}, err
	}
	challenge := parsed.challenge
	if challenge.Algorithm == security.AlgorithmAKAv2SHA256 {
		if !securityServerSupportsTLS(resp.HeadersByName("Security-Server")) {
			return registerAuthChallenge{}, errors.New("applying Security-Server: AKAv2-SHA-256 requires tls security mechanism")
		}
		return registerAuthChallenge{}, errors.New("applying Security-Server: AKAv2-SHA-256 over TLS is not supported by this SIP transport")
	}
	if requiredMode == "" {
		publicHost, behindNAT, err := registerResponseNAT(resp)
		if err != nil {
			return registerAuthChallenge{}, fmt.Errorf("applying registration NAT information: %w", err)
		}
		requiredMode = "trans"
		if behindNAT {
			requiredMode = "UDP-enc-tun"
			parsed.publicContactHost = publicHost
		}
	}
	verify, raw, err := selectSecurityServer(resp.HeadersByName("Security-Server"), offered, requiredMode)
	if err != nil {
		return registerAuthChallenge{}, fmt.Errorf("%w: %w", errSecurityAgreementInvalid, err)
	}
	parsed.verify = verify
	parsed.rawSecurityServer = raw
	return parsed, nil
}

func registerResponseNAT(resp sip.Message) (publicHost string, behind bool, err error) {
	via := resp.Header("Via")
	received := strings.TrimSpace(sip.TopViaReceived(via))
	if received == "" {
		return "", false, nil
	}
	received = strings.TrimSpace(strings.Trim(received, "[]"))
	receivedIP := net.ParseIP(received)
	if receivedIP == nil {
		return "", false, fmt.Errorf("parsing Via received address %q", received)
	}
	sentBy := sip.TopViaSentBy(via)
	if sentBy == "" {
		return "", false, errors.New("parsing Via sent-by address: value is empty")
	}
	sentByHost := sentBy
	if host, _, splitErr := net.SplitHostPort(sentBy); splitErr == nil {
		sentByHost = host
	}
	sentByHost = strings.TrimSpace(strings.Trim(sentByHost, "[]"))
	sentByIP := net.ParseIP(sentByHost)
	if sentByIP == nil {
		return "", false, fmt.Errorf("parsing Via sent-by address %q", sentByHost)
	}

	// Some P-CSCFs always add received, even when the packet source matches
	// sent-by. Compare the addresses so those responses do not force a tunnel.
	return receivedIP.String(), !receivedIP.Equal(sentByIP), nil
}

func selectRegisterChallengeForResponse(resp sip.Message) (registerAuthChallenge, error) {
	challengeHeader, authorizationHeader := registerChallengeHeaders(resp.StatusCode())
	challenge, err := selectRegisterChallenge(challengeHeader, resp.HeadersByName(challengeHeader))
	if err != nil {
		return registerAuthChallenge{}, err
	}
	return registerAuthChallenge{challenge: challenge, authorizationHeader: authorizationHeader}, nil
}

func registerChallengeHeaders(status int) (string, string) {
	if status == sipStatusProxyAuthenticationRequired {
		return "Proxy-Authenticate", registerProxyAuthorizationHeader
	}
	return "WWW-Authenticate", registerAuthorizationHeader
}

func registerAuthorizationHeaderName(value string) string {
	if strings.EqualFold(strings.TrimSpace(value), registerProxyAuthorizationHeader) {
		return registerProxyAuthorizationHeader
	}
	return registerAuthorizationHeader
}

func registerAuthChallengeStatus(status int) bool {
	return status == sipStatusUnauthorized || status == sipStatusProxyAuthenticationRequired
}

func selectRegisterChallenge(headerName string, values []string) (security.Challenge, error) {
	var firstErr error
	seen := false
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		seen = true
		var challenge security.Challenge
		if err := challenge.UnmarshalText([]byte(value)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		if _, err := challenge.SelectedQOP(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		return challenge, nil
	}
	if !seen {
		return security.Challenge{}, fmt.Errorf("selecting auth challenge: %s header is empty", headerName)
	}
	return security.Challenge{}, fmt.Errorf("selecting auth challenge: %w", firstErr)
}

func (s *Registrar) verifyAuthenticationInfo(msg sip.Message, auth *security.Authorization) error {
	raw := strings.TrimSpace(msg.Header("Authentication-Info"))
	if raw == "" {
		return nil
	}
	var info security.Info
	if err := info.UnmarshalText([]byte(raw)); err != nil {
		return err
	}
	if auth == nil {
		return errors.New("authentication-info without authorization")
	}
	password, ok := s.currentDigestCredential(auth.Nonce, auth.Algorithm)
	if !ok {
		return errors.New("authentication-info without digest credential")
	}
	if err := security.VerifyAuthenticationInfo(*auth, info, password); err != nil {
		return err
	}
	return nil
}

func (s *Registrar) applyAuthenticationInfo(msg sip.Message) {
	var info security.Info
	if err := info.UnmarshalText([]byte(msg.Header("Authentication-Info"))); err != nil || info.NextNonce == "" {
		return
	}
	s.mu.Lock()
	s.authNonce = info.NextNonce
	s.authNonceCount = 0
	if s.authDigestPassword != "" {
		s.authDigestNonce = info.NextNonce
	}
	s.mu.Unlock()
}

func (s *Registrar) exchangeAKAFailure(ctx context.Context, challenge security.Challenge, authorizationHeader string, flow Flow, cause error) (sip.Message, error) {
	failure, ok := errors.AsType[*security.AKAChallengeFailure](cause)
	if !ok {
		return sip.Message{}, cause
	}
	auth := s.akaFailureAuthorization(challenge, failure)
	req := s.buildRegisterForFlowWithAuthorizationHeader(&auth, flow.SecurityVerify, flow, authorizationHeader)
	if !failure.SynchronizationFailure() {
		if err := s.sess.Send(ctx, req); err != nil {
			return sip.Message{}, fmt.Errorf("reporting AKA failure: %w", err)
		}
		return sip.Message{}, cause
	}
	resp, err := s.sess.Exchange(ctx, req)
	if err != nil {
		return sip.Message{}, fmt.Errorf("reporting AKA synchronization failure: %w", err)
	}
	if !registerAuthChallengeStatus(resp.StatusCode()) {
		return sip.Message{}, fmt.Errorf("expected authentication challenge after AKA synchronization failure, got %w", sip.NewResponseError(resp))
	}
	return resp, nil
}

func (s *Registrar) exchangeCurrentAKAFailure(ctx context.Context, cause error) (sip.Message, error) {
	authorizationHeader := s.currentAuthorizationHeaderName()
	flow := s.CurrentFlow()
	return s.exchangeAKAFailure(ctx, s.currentAuthChallenge(), authorizationHeader, flow, cause)
}

func (s *Registrar) akaFailureAuthorization(challenge security.Challenge, failure *security.AKAChallengeFailure) security.Authorization {
	auth := security.Authorization{
		Nonce:              challenge.Nonce,
		URI:                s.State().RegisterURI,
		Response:           "",
		Username:           s.State().PrivateIdentity,
		Realm:              defaultRealm(challenge.Realm, s.State().RegisterURI),
		Algorithm:          challenge.Algorithm,
		IntegrityProtected: registerIntegrityProtectedValue(challenge.Algorithm),
		Opaque:             challenge.Opaque,
	}
	if failure.SynchronizationFailure() {
		auth.AUTS = base64.StdEncoding.EncodeToString(failure.AUTS)
	}
	return auth
}

func defaultRealm(realm, registerURI string) string {
	if strings.TrimSpace(realm) != "" {
		return realm
	}
	return strings.TrimPrefix(registerURI, "sip:")
}

type akaProvider struct {
	card       Card
	group      *Group
	preference int
}

func (p akaProvider) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	release, err := p.group.BeginAKA(ctx, p.preference)
	if err != nil {
		return usim.AKAResult{}, fmt.Errorf("waiting for USIM AKA access: %w", err)
	}
	defer release()
	return p.card.AKA(ctx, rand, autn)
}
