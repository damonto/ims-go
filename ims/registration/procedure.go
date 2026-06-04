package registration

import (
	"context"
	"errors"
	"fmt"

	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) beginRegistrationProcedure(ctx context.Context, action string) (func(), error) {
	select {
	case s.registrationGate <- struct{}{}:
		return func() { <-s.registrationGate }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", action, ctx.Err())
	}
}

func (s *Service) awaitRegisterChallenge(ctx context.Context) (sip.Message, error) {
	adjustedExpires := false
	for {
		resp, err := s.sess.Exchange(ctx, s.buildRegister(nil, nil))
		if err != nil {
			return sip.Message{}, fmt.Errorf("registering IMS: %w", err)
		}
		if resp.StatusCode() == sipStatusIntervalTooBrief {
			if err := s.adjustRegisterExpiresFrom423("registering IMS", resp, &adjustedExpires); err != nil {
				return sip.Message{}, err
			}
			continue
		}
		if resp.StatusCode() != sipStatusUnauthorized {
			if initialRegistrationRetryResponse(resp) {
				return sip.Message{}, initialRegistrationRequiredError("registering IMS", resp)
			}
			return sip.Message{}, fmt.Errorf("registering IMS: expected 401, got %d", resp.StatusCode())
		}
		return resp, nil
	}
}

func (s *Service) completeRegistration(ctx context.Context, challenge security.Challenge, initialAuth *security.Authorization) error {
	adjustedExpires := false
	rechallenged := false
	resynchronized := false
	auth := initialAuth
	var pendingSecurity *registerSecurity
	secureTransportStale := false
	committedSecurity := false
	defer func() {
		if !committedSecurity {
			pendingSecurity.close()
		}
	}()
	for {
		if auth == nil {
			var err error
			auth, err = s.buildRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.Algorithm, challenge.QOP)
			if err != nil {
				resp, err := s.exchangeAKAFailure(ctx, "registering IMS", challenge, err)
				if err != nil {
					return err
				}
				if resynchronized {
					return errors.New("registering IMS: repeated AKA synchronization failure")
				}
				nextChallenge, err := s.applyRegisterChallenge(resp)
				if err != nil {
					return fmt.Errorf("registering IMS: %w", err)
				}
				challenge = nextChallenge
				resynchronized = true
				rechallenged = true
				auth = nil
				continue
			}
		}
		if pendingSecurity == nil || secureTransportStale {
			pendingSecurity.close()
			nextSecurity, err := s.openRegisterSecurity(ctx)
			if err != nil {
				return fmt.Errorf("registering IMS: %w", err)
			}
			pendingSecurity = nextSecurity
			secureTransportStale = false
		}
		resp, err := s.exchangeProtectedRegister(ctx, pendingSecurity, auth)
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		if resp.StatusCode() == sipStatusIntervalTooBrief {
			if err := s.adjustRegisterExpiresFrom423("registering IMS", resp, &adjustedExpires); err != nil {
				return err
			}
			rechallenged = false
			auth = nil
			continue
		}
		if resp.StatusCode() == sipStatusUnauthorized {
			if rechallenged {
				return errors.New("registering IMS: repeated 401 response")
			}
			nextChallenge, err := s.applyRegisterChallenge(resp)
			if err != nil {
				return fmt.Errorf("registering IMS: %w", err)
			}
			challenge = nextChallenge
			rechallenged = true
			secureTransportStale = s.currentSecurityVerify() != nil
			auth = nil
			continue
		}
		if resp.StatusCode() != sipStatusOK {
			if initialRegistrationRetryResponse(resp) {
				return initialRegistrationRequiredError("registering IMS", resp)
			}
			return fmt.Errorf("registering IMS: expected 200, got %w", sip.NewResponseError(resp))
		}
		if err := s.verifyAuthenticationInfo(resp, auth); err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		if err := s.commitRegisterSecurity(pendingSecurity); err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		s.applyRegisterSuccess(resp)
		committedSecurity = true
		return nil
	}
}

func (s *Service) reauthenticateRefresh(ctx context.Context, challengeResp sip.Message) error {
	challenge, verify, raw, err := parseRegisterChallenge(challengeResp)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	var auth *security.Authorization
	var ck, ik []byte
	var password string
	resynchronized := false
	for {
		auth, ck, ik, password, err = s.calculateRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.Algorithm, challenge.QOP, 1)
		if err == nil {
			break
		}
		resp, err := s.exchangeAKAFailure(ctx, "refreshing IMS registration", challenge, err)
		if err != nil {
			return err
		}
		if resynchronized {
			return errors.New("refreshing IMS registration: repeated AKA synchronization failure")
		}
		challenge, verify, raw, err = parseRegisterChallenge(resp)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		resynchronized = true
	}

	nextFlow := s.CurrentFlow()
	nextFlow.SecurityVerify = verify
	nextFlow.SecurityServerRaw = append([]string(nil), raw...)
	if verify == nil {
		nextFlow.MessagePort = nextFlow.RegisterPort
		req := s.buildRegisterForFlow(auth, nil, nextFlow)
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("refreshing IMS registration: completing AKAv2 re-authentication: %w", err)
		}
		if resp.StatusCode() != sipStatusOK {
			if reregistrationInitialRequiredStatus(resp.StatusCode()) {
				return initialRegistrationRequiredError("refreshing IMS registration", resp)
			}
			return fmt.Errorf("refreshing IMS registration: expected 200 after AKAv2 re-authentication, got %w", sip.NewResponseError(resp))
		}
		s.commitReauthentication(challenge, nextFlow, nil, nil, password)
		s.applyRegisterSuccess(resp)
		return nil
	}
	nextFlow.SecurityClient = reauthSecurityClient(nextFlow.SecurityClient, nextFlow.RegisterPort)
	nextFlow.SecurityClients = securityClientCapabilities(nextFlow.SecurityClient)
	nextFlow.MessagePort = nextFlow.SecurityClient.PortS

	outbound, err := s.dialSecureTransport(ctx, verify, nextFlow, ck, ik)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	outboundAttachment, err := s.sess.AddTransport(outbound)
	if err != nil {
		outbound.Close()
		return fmt.Errorf("refreshing IMS registration: adding secure IMS transport: %w", err)
	}
	cleanup := []session.Attachment{outboundAttachment}
	committed := false
	defer func() {
		if !committed {
			closeAttachments(cleanup)
		}
	}()

	inboundTransports, inboundAttachments, err := s.startSecureServerTransportsWithKeys(ctx, verify, nextFlow, ck, ik)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	if len(inboundTransports) == 0 {
		return errors.New("refreshing IMS registration: secure inbound transport is not configured")
	}
	cleanup = append(cleanup, inboundAttachments...)

	responseAttachments, err := s.startSecureResponseTransportsWithKeys(ctx, verify, nextFlow, outbound, inboundTransports, ck, ik)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	cleanup = append(cleanup, responseAttachments...)

	req := s.buildRegisterForFlow(auth, verify, nextFlow)
	responseTransports := reauthResponseTransports(outbound, inboundTransports)
	resp, err := s.sess.ExchangeWithTransport(ctx, outbound, req, session.ExchangeOptions{
		AcceptResponseTransport: acceptResponseFrom(responseTransports),
		ResponseTransports:      responseTransports,
	})
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: completing re-authentication: %w", err)
	}
	if resp.StatusCode() != sipStatusOK {
		if reregistrationInitialRequiredStatus(resp.StatusCode()) {
			return initialRegistrationRequiredError("refreshing IMS registration", resp)
		}
		return fmt.Errorf("refreshing IMS registration: expected 200 after re-authentication, got %w", sip.NewResponseError(resp))
	}
	oldExpiresAt := s.currentSecureAssociationExpiresAt()
	oldAttachment, err := s.sess.PromotePrimary(outbound)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: promoting secure IMS transport: %w", err)
	}
	oldServerAttachments := s.replaceSecureServerAttachments(inboundAttachments)
	oldResponseAttachments := s.replaceSecureResponseAttachments(responseAttachments)
	s.closeAttachmentsAfter(append(append(oldServerAttachments, oldResponseAttachments...), oldAttachment), saDrainDelayBefore(oldExpiresAt, s.sess.TransactionTimers()))
	s.commitReauthentication(challenge, nextFlow, ck, ik, password)
	s.applyRegisterSuccess(resp)
	committed = true
	return nil
}

func (s *Service) buildDeregisterMessage(ctx context.Context, verify *security.Param, realm, nonce, algorithm, qop string) (sip.Message, error) {
	auth, err := s.buildRegisterAuthorization(ctx, realm, nonce, algorithm, qop)
	if err != nil {
		return sip.Message{}, fmt.Errorf("deregistering IMS: %w", err)
	}
	return s.buildDeregister(auth, verify), nil
}

func (s *Service) handleDeregisterResponse(resp sip.Message, challenged *bool, realm, nonce, algorithm, qop *string) (bool, error) {
	switch resp.StatusCode() {
	case sipStatusOK:
		return true, nil
	case sipStatusUnauthorized:
		if *challenged {
			return false, errors.New("deregistering IMS: repeated 401 response")
		}
		challenge, err := selectRegisterChallenge(resp.HeadersByName("WWW-Authenticate"))
		if err != nil {
			return false, fmt.Errorf("deregistering IMS: %w", err)
		}
		s.storeAuthChallenge(challenge)
		*realm = challenge.Realm
		*nonce = challenge.Nonce
		*algorithm = challenge.Algorithm
		*qop = challenge.QOP
		*challenged = true
		return false, nil
	default:
		return false, fmt.Errorf("deregistering IMS: unexpected response: %w", sip.NewResponseError(resp))
	}
}
