package registration

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/sip"
	"github.com/damonto/uicc-go/usim"
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
	s.authHeader = authorizationHeader
	s.authNonceCount = 0
	s.mu.Unlock()
}

func (s *Registrar) currentAuthState() (string, string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	realm := s.authRealm
	if realm == "" {
		realm = strings.TrimPrefix(s.state.RegisterURI, "sip:")
	}
	return realm, s.authNonce, s.authAlgorithm, s.authQOP
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

func (s *Registrar) buildRegisterAuthorization(ctx context.Context, realm, nonce, algorithm, qop string) (*security.Authorization, error) {
	if nonce == "" {
		return nil, nil
	}
	nonceCount := s.nextAuthNonceCount()
	if password, ok := s.currentDigestCredential(nonce, algorithm); ok {
		auth, err := s.calculateDigestRegisterAuthorization(realm, nonce, algorithm, qop, nonceCount, password)
		if err != nil {
			return nil, err
		}
		return auth, nil
	}
	auth, ck, ik, password, err := s.calculateRegisterAuthorization(ctx, realm, nonce, algorithm, qop, nonceCount)
	if err != nil {
		return nil, err
	}
	s.storeDigestCredential(auth.Algorithm, auth.Nonce, password, ck, ik)
	return auth, nil
}

func (s *Registrar) calculateRegisterAuthorization(ctx context.Context, realm, nonce, algorithm, qop string, nonceCount uint32) (*security.Authorization, []byte, []byte, string, error) {
	if nonce == "" {
		return nil, nil, nil, "", nil
	}
	result, err := security.BuildAKAAuthorization(ctx, akaProvider{s.card}, security.Identity{
		PrivateIdentity: s.State().PrivateIdentity,
		RegisterURI:     s.State().RegisterURI,
		Realm:           defaultRealm(realm, s.State().RegisterURI),
	}, security.Challenge{
		Realm:     realm,
		Nonce:     nonce,
		Algorithm: algorithm,
		QOP:       qop,
	}, nonceCount)
	if err != nil {
		return nil, nil, nil, "", err
	}
	auth := result.Authorization
	auth.IntegrityProtected = registerIntegrityProtectedValue(auth.Algorithm)
	return &auth, result.EncryptionKey, result.IntegrityKey, result.DigestPassword, nil
}

func (s *Registrar) calculateDigestRegisterAuthorization(realm, nonce, algorithm, qop string, nonceCount uint32, password string) (*security.Authorization, error) {
	result, err := security.BuildDigestAuthorization(security.Identity{
		PrivateIdentity: s.State().PrivateIdentity,
		RegisterURI:     s.State().RegisterURI,
		Realm:           defaultRealm(realm, s.State().RegisterURI),
	}, security.Challenge{
		Realm:     realm,
		Nonce:     nonce,
		Algorithm: algorithm,
		QOP:       qop,
	}, nonceCount, password)
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
	parsed, err := parseRegisterChallenge(resp)
	if err != nil {
		return security.Challenge{}, err
	}
	s.applySelectedSecurityServer(parsed.verify, parsed.rawSecurityServer)
	s.storeAuthChallenge(parsed.challenge, parsed.authorizationHeader)
	return parsed.challenge, nil
}

func parseRegisterChallenge(resp sip.Message) (registerAuthChallenge, error) {
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
	verify, raw, err := selectSecurityServer(resp.HeadersByName("Security-Server"))
	if err != nil {
		return registerAuthChallenge{}, fmt.Errorf("%w: %w", errSecurityAgreementInvalid, err)
	}
	parsed.verify = verify
	parsed.rawSecurityServer = raw
	return parsed, nil
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
	var info security.Info
	if err := info.UnmarshalText([]byte(msg.Header("Authentication-Info"))); err != nil {
		return err
	}
	if info.RSPAuth == "" {
		return nil
	}
	if auth == nil {
		return errors.New("authentication-info rspauth without authorization")
	}
	password, ok := s.currentDigestCredential(auth.Nonce, auth.Algorithm)
	if !ok {
		return errors.New("authentication-info rspauth without digest credential")
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

func (s *Registrar) exchangeAKAFailure(ctx context.Context, challenge security.Challenge, authorizationHeader string, cause error) (sip.Message, error) {
	var failure *security.AKAChallengeFailure
	if !errors.As(cause, &failure) {
		return sip.Message{}, cause
	}
	auth := s.akaFailureAuthorization(challenge, failure)
	req := s.buildRegisterWithAuthorizationHeader(&auth, s.currentSecurityVerify(), authorizationHeader)
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
	realm, nonce, algorithm, qop := s.currentAuthState()
	authorizationHeader := s.currentAuthorizationHeaderName()
	return s.exchangeAKAFailure(ctx, security.Challenge{
		Realm:     realm,
		Nonce:     nonce,
		Algorithm: algorithm,
		QOP:       qop,
	}, authorizationHeader, cause)
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

type akaProvider struct{ card Card }

func (p akaProvider) AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return p.card.AKA(ctx, rand, autn)
}
