package registration

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) storeAuthChallenge(challenge security.Challenge) {
	realm := strings.TrimSpace(challenge.Realm)
	if realm == "" {
		realm = strings.TrimPrefix(s.State().RegisterURI, "sip:")
	}
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
	s.authNonceCount = 0
	s.mu.Unlock()
}

func (s *Service) currentAuthState() (string, string, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	realm := s.authRealm
	if realm == "" {
		realm = strings.TrimPrefix(s.state.RegisterURI, "sip:")
	}
	return realm, s.authNonce, s.authAlgorithm, s.authQOP
}

func (s *Service) nextAuthNonceCount() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authNonceCount++
	return s.authNonceCount
}

func (s *Service) buildRegisterAuthorization(ctx context.Context, realm, nonce, algorithm, qop string) (*security.Authorization, error) {
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

func (s *Service) calculateRegisterAuthorization(ctx context.Context, realm, nonce, algorithm, qop string, nonceCount uint32) (*security.Authorization, []byte, []byte, string, error) {
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

func (s *Service) calculateDigestRegisterAuthorization(realm, nonce, algorithm, qop string, nonceCount uint32, password string) (*security.Authorization, error) {
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

func (s *Service) currentDigestCredential(nonce, algorithm string) (string, bool) {
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

func (s *Service) storeDigestCredential(algorithm, nonce, password string, ck, ik []byte) {
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

func (s *Service) applyRegisterChallenge(resp sip.Message) (security.Challenge, error) {
	challenge, verify, raw, err := parseRegisterChallenge(resp)
	if err != nil {
		return security.Challenge{}, err
	}
	s.applySelectedSecurityServer(verify, raw)
	s.storeAuthChallenge(challenge)
	return challenge, nil
}

func parseRegisterChallenge(resp sip.Message) (security.Challenge, *security.Param, []string, error) {
	challenge, err := selectRegisterChallenge(resp.HeadersByName("WWW-Authenticate"))
	if err != nil {
		return security.Challenge{}, nil, nil, err
	}
	if challenge.Algorithm == security.AlgorithmAKAv2SHA256 {
		if !securityServerSupportsTLS(resp.HeadersByName("Security-Server")) {
			return security.Challenge{}, nil, nil, errors.New("applying Security-Server: AKAv2-SHA-256 requires tls security mechanism")
		}
		return security.Challenge{}, nil, nil, errors.New("applying Security-Server: AKAv2-SHA-256 over TLS is not supported by this SIP transport")
	}
	verify, raw, err := selectSecurityServer(resp.HeadersByName("Security-Server"))
	if err != nil {
		return security.Challenge{}, nil, nil, fmt.Errorf("%w: %w", errSecurityAgreementInvalid, err)
	}
	return challenge, verify, raw, nil
}

func selectRegisterChallenge(values []string) (security.Challenge, error) {
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
		return security.Challenge{}, errors.New("selecting auth challenge: WWW-Authenticate header is empty")
	}
	return security.Challenge{}, fmt.Errorf("selecting auth challenge: %w", firstErr)
}

func (s *Service) verifyAuthenticationInfo(msg sip.Message, auth *security.Authorization) error {
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

func (s *Service) applyAuthenticationInfo(msg sip.Message) {
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

func (s *Service) exchangeAKAFailure(ctx context.Context, action string, challenge security.Challenge, cause error) (sip.Message, error) {
	var failure *security.AKAChallengeFailure
	if !errors.As(cause, &failure) {
		return sip.Message{}, fmt.Errorf("%s: %w", action, cause)
	}
	auth := s.akaFailureAuthorization(challenge, failure)
	req := s.buildRegister(&auth, s.currentSecurityVerify())
	if !failure.SynchronizationFailure() {
		if err := s.sess.Send(ctx, req); err != nil {
			return sip.Message{}, fmt.Errorf("%s: reporting AKA failure: %w", action, err)
		}
		return sip.Message{}, fmt.Errorf("%s: %w", action, cause)
	}
	resp, err := s.sess.Exchange(ctx, req)
	if err != nil {
		return sip.Message{}, fmt.Errorf("%s: reporting AKA synchronization failure: %w", action, err)
	}
	if resp.StatusCode() != sipStatusUnauthorized {
		return sip.Message{}, fmt.Errorf("%s: expected 401 after AKA synchronization failure, got %w", action, sip.NewResponseError(resp))
	}
	return resp, nil
}

func (s *Service) exchangeCurrentAKAFailure(ctx context.Context, action string, cause error) (sip.Message, error) {
	realm, nonce, algorithm, qop := s.currentAuthState()
	return s.exchangeAKAFailure(ctx, action, security.Challenge{
		Realm:     realm,
		Nonce:     nonce,
		Algorithm: algorithm,
		QOP:       qop,
	}, cause)
}

func (s *Service) akaFailureAuthorization(challenge security.Challenge, failure *security.AKAChallengeFailure) security.Authorization {
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
