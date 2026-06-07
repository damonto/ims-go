package registration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Service) Register(ctx context.Context) error {
	release, err := s.beginRegistrationProcedure(ctx)
	if err != nil {
		return fmt.Errorf("registering IMS: %w", err)
	}
	defer release()

	s.logger.Info("registering IMS", "public_identity", s.State().PublicIdentity)
	challengeMsg, err := s.awaitRegisterChallenge(ctx)
	if err != nil {
		return err
	}
	challenge, err := s.applyRegisterChallenge(challengeMsg)
	if err != nil {
		if !errors.Is(err, errSecurityAgreementInvalid) {
			return fmt.Errorf("registering IMS: %w", err)
		}
		s.logger.Info("retrying initial IMS registration after invalid Security-Server", "err", err)
		s.resetRegisterTransaction()
		challengeMsg, err = s.awaitRegisterChallenge(ctx)
		if err != nil {
			return err
		}
		challenge, err = s.applyRegisterChallenge(challengeMsg)
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
	}
	var initialAuth *security.Authorization
	resynchronized := false
	for {
		initialAuth, err = s.buildRegisterAuthorization(ctx, challenge.Realm, challenge.Nonce, challenge.Algorithm, challenge.QOP)
		if err == nil {
			break
		}
		resp, err := s.exchangeAKAFailure(ctx, challenge, s.currentAuthorizationHeaderName(), err)
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		if resynchronized {
			return errors.New("registering IMS: repeated AKA synchronization failure")
		}
		challenge, err = s.applyRegisterChallenge(resp)
		if err != nil {
			return fmt.Errorf("registering IMS: %w", err)
		}
		resynchronized = true
	}
	if err := s.completeRegistration(ctx, challenge, initialAuth); err != nil {
		return err
	}
	state := s.State()
	s.logger.Info("IMS registration established", "public_identity", state.PublicIdentity, "register_expires", state.RegisterExpires, "service_routes", len(state.ServiceRoutes))
	return nil
}

func (s *Service) Subscribe(ctx context.Context) error {
	return s.subscribe(ctx, false)
}

func (s *Service) subscribe(ctx context.Context, retried bool) error {
	if s.isSubscribeUnsupported() {
		return nil
	}
	subscription := s.currentSubscription()
	msg := s.buildSubscribeWithDialog(subscription)
	resp, err := s.sess.Exchange(ctx, msg)
	if err != nil {
		if subscription.active {
			s.resetSubscription()
			s.resetRegInfoVersion()
		}
		return fmt.Errorf("subscribing IMS registration: %w", err)
	}
	if subscription.active && resp.StatusCode() != sipStatusCallTransactionDoesNotExist {
		s.applySubscribeRequestCSeq(msg)
	}
	if resp.StatusCode() == sipStatusBadEvent {
		s.setSubscribeUnsupported(true)
		s.resetSubscription()
		s.logger.Info("registration event subscription unavailable", "status", resp.StatusCode())
		return nil
	}
	if subscription.active && resp.StatusCode() == sipStatusCallTransactionDoesNotExist && !retried {
		s.resetSubscription()
		s.resetRegInfoVersion()
		return s.subscribe(ctx, true)
	}
	if resp.StatusCode() == sipStatusServiceUnavailable {
		if retryAfter, ok := retryAfterDelay(resp); ok {
			return fmt.Errorf("subscribing IMS registration: %w after %w", &subscriptionRetryAfter{retryAfter: retryAfter}, sip.NewResponseError(resp))
		}
	}
	if resp.StatusCode() != sipStatusOK {
		return fmt.Errorf("subscribing IMS registration: expected 200, got %w", sip.NewResponseError(resp))
	}
	s.setSubscribeUnsupported(false)
	s.applySubscribeExpires(resp)
	s.applySubscribeDialog(msg, resp)
	s.logger.Info("registration event subscription active", "expires", s.currentSubscribeExpires())
	return nil
}

func (s *Service) Establish(ctx context.Context) error {
	return s.Register(ctx)
}

func (s *Service) Refresh(ctx context.Context) error {
	release, err := s.beginRegistrationProcedure(ctx)
	if err != nil {
		return fmt.Errorf("refreshing IMS registration: %w", err)
	}
	defer release()

	state := refreshRegisterState{}
	for range 6 {
		req, auth, err := s.buildRefreshRegister(ctx)
		if err != nil {
			resp, err := s.exchangeCurrentAKAFailure(ctx, err)
			if err != nil {
				return fmt.Errorf("refreshing IMS registration: %w", err)
			}
			done, err := s.handleRefreshRegistration(ctx, resp, &state, nil)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			continue
		}
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			if registrationTimeoutRequiresInitial(err) {
				return fmt.Errorf("refreshing IMS registration: %w", initialRegistrationRequiredAfterError(err))
			}
			return fmt.Errorf("refreshing IMS registration: %w", err)
		}
		done, err := s.handleRefreshRegistration(ctx, resp, &state, auth)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return errors.New("refreshing IMS registration: exhausted retries")
}

func (s *Service) Maintain(ctx context.Context) error {
	registerTimer := time.NewTimer(s.refreshInterval())
	defer registerTimer.Stop()
	subscribeTimer := time.NewTimer(s.subscribeRefreshInterval())
	defer subscribeTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-s.registrationEvents:
			return err
		case <-s.subscribeRefreshRequests:
			s.refreshSubscription(ctx)
			resetTimer(subscribeTimer, s.subscribeRefreshInterval())
		case <-registerTimer.C:
			if err := s.Refresh(ctx); err != nil {
				if ctx.Err() != nil && errors.Is(err, ctx.Err()) {
					return ctx.Err()
				}
				return err
			}
			s.logger.Info("IMS registration refreshed", "next_refresh", s.refreshInterval())
			registerTimer.Reset(s.refreshInterval())
		case <-subscribeTimer.C:
			s.refreshSubscription(ctx)
			subscribeTimer.Reset(s.subscribeRefreshInterval())
		}
	}
}

func (s *Service) Deregister(ctx context.Context) error {
	release, err := s.beginRegistrationProcedure(ctx)
	if err != nil {
		return fmt.Errorf("deregistering IMS: %w", err)
	}
	defer release()

	if !s.isRegistered() {
		return nil
	}
	verify := s.currentSecurityVerify()
	realm, nonce, algorithm, qop := s.currentAuthState()
	challenged := false
	for range 2 {
		req, err := s.buildDeregisterMessage(ctx, verify, realm, nonce, algorithm, qop)
		if err != nil {
			return err
		}
		resp, err := s.sess.Exchange(ctx, req)
		if err != nil {
			return fmt.Errorf("deregistering IMS: %w", err)
		}
		done, err := s.handleDeregisterResponse(resp, &challenged, &realm, &nonce, &algorithm, &qop)
		if err != nil {
			return err
		}
		if done {
			s.setRegistered(false)
			s.logger.Info("IMS deregistered")
			return nil
		}
	}
	return errors.New("deregistering IMS: exhausted retries")
}
