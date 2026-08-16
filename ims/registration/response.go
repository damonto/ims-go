package registration

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/security"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

type refreshRegisterState struct {
	adjustedExpires bool
	natPortAdjusted bool
	flow            Flow
}

type pcscfReselectionRequired struct {
	retryAfter time.Duration
}

func (e *pcscfReselectionRequired) Error() string {
	return "p-cscf reselection required"
}

func (e *pcscfReselectionRequired) retryAfterDelay() time.Duration {
	return e.retryAfter
}

func parsePositiveSeconds(value string) (time.Duration, bool) {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func retryAfterDelay(msg sip.Message) (time.Duration, bool) {
	value := strings.TrimSpace(msg.Header("Retry-After"))
	if value == "" {
		return 0, false
	}
	if cut := strings.IndexAny(value, ";("); cut >= 0 {
		value = value[:cut]
	}
	return parsePositiveSeconds(value)
}

func statusClass(status int) int {
	return status / 100
}

// InitialRegistrationRetryAfter returns the Retry-After delay carried by an
// initial registration error. The caller owns scheduling; registration only
// reports the protocol constraint.
func InitialRegistrationRetryAfter(err error) (time.Duration, bool) {
	initial, ok := errors.AsType[*initialRegistrationRequired](err)
	if !ok || initial.retryAfter <= 0 {
		return 0, false
	}
	return initial.retryAfter, true
}

func RetryAfterDelay(err error) (time.Duration, bool) {
	type retryAfterError interface {
		error
		retryAfterDelay() time.Duration
	}
	retryAfter, ok := errors.AsType[retryAfterError](err)
	if !ok {
		return 0, false
	}
	delay := retryAfter.retryAfterDelay()
	return delay, delay > 0
}

func InitialRegistrationRequired(err error) bool {
	_, ok := errors.AsType[*initialRegistrationRequired](err)
	return ok
}

func PCSCFReselectionRequired(err error) bool {
	_, ok := errors.AsType[*pcscfReselectionRequired](err)
	return ok
}

// PCSCFFailoverRequired reports whether a registration response makes the
// current P-CSCF unavailable under TS 24.229 registration recovery rules.
func PCSCFFailoverRequired(err error, timerF time.Duration) bool {
	if PCSCFReselectionRequired(err) {
		return true
	}
	response, ok := errors.AsType[*sip.ResponseError](err)
	if !ok {
		return false
	}
	switch response.StatusCode {
	case sipStatusServerTimeout:
		return true
	case sipStatusServiceUnavailable:
		delay, ok := RetryAfterDelay(err)
		return !ok || delay > timerF
	default:
		if statusClass(response.StatusCode) < 4 || statusClass(response.StatusCode) > 6 {
			return false
		}
		_, hasRetryAfter := RetryAfterDelay(err)
		return !hasRetryAfter
	}
}

func (s *Registrar) adjustRegisterExpiresFrom423(resp sip.Message, adjusted *bool) error {
	if *adjusted {
		return errors.New("repeated 423 response")
	}
	minExpires, err := minExpiresSeconds(resp.Header("Min-Expires"))
	if err != nil {
		return err
	}
	s.setRegisterExpires(max(s.currentRegisterExpires(), time.Duration(minExpires)*time.Second))
	*adjusted = true
	return nil
}

func (s *Registrar) buildRefreshRegister(ctx context.Context, flow Flow) (sip.Message, *security.Authorization, error) {
	auth, err := s.buildRegisterAuthorization(ctx, s.currentAuthChallenge())
	if err != nil {
		return sip.Message{}, nil, err
	}
	return s.buildRegisterForFlow(auth, flow.SecurityVerify, flow), auth, nil
}

func (s *Registrar) handleRefreshRegistration(ctx context.Context, resp sip.Message, state *refreshRegisterState, auth *security.Authorization) (bool, error) {
	if incompatibleNetworkAddressResponse(resp) && state.flow.SecurityVerify != nil && strings.EqualFold(state.flow.SecurityVerify.Mod, "UDP-enc-tun") {
		if state.natPortAdjusted {
			return false, errors.New("repeated incompatible network address response")
		}
		rotateNATProtectedPorts(&state.flow, false)
		state.natPortAdjusted = true
		return false, nil
	}
	switch resp.StatusCode() {
	case sipStatusOK:
		if err := s.verifyAuthenticationInfo(resp, auth); err != nil {
			return false, err
		}
		singleRegistration, err := s.validateRegisterSuccessForFlow(resp, state.flow)
		if err != nil {
			return false, err
		}
		s.registrationCommitMu.Lock()
		if channelClosed(s.registrationMaintenanceStop) {
			s.registrationCommitMu.Unlock()
			return false, errRegistrationStopped
		}
		s.applyRegisterCapability(singleRegistration)
		s.applyRegisterSuccess(resp)
		s.registrationCommitMu.Unlock()
		return true, nil
	case sipStatusUnauthorized, sipStatusProxyAuthenticationRequired:
		if err := s.reauthenticateRefresh(ctx, resp, state.flow); err != nil {
			return false, err
		}
		return true, nil
	case sipStatusIntervalTooBrief:
		if err := s.adjustRegisterExpiresFrom423(resp, &state.adjustedExpires); err != nil {
			return false, err
		}
		return false, nil
	default:
		if resp.StatusCode() == sipStatusUseProxy {
			return false, pcscfReselectionRequiredError(resp)
		}
		if reregistrationInitialRequiredStatus(resp.StatusCode()) {
			return false, initialRegistrationRequiredError(resp)
		}
		return false, fmt.Errorf("unexpected response: %w", sip.NewResponseError(resp))
	}
}

func incompatibleNetworkAddressResponse(resp sip.Message) bool {
	if resp.StatusCode() != sipStatusBadRequest {
		return false
	}
	for _, warning := range sip.ParseWarningValues(resp.HeadersByName("Warning")) {
		if warning.Code == 301 && strings.Contains(strings.ToLower(warning.Text), "incompatible network address") {
			return true
		}
	}
	return false
}

func initialNATPortCollisionResponse(resp sip.Message) bool {
	if !incompatibleNetworkAddressResponse(resp) {
		return false
	}
	_, behindNAT, err := registerResponseNAT(resp)
	return err == nil && behindNAT
}

func initialRegistrationRetryResponse(resp sip.Message) bool {
	return statusClass(resp.StatusCode()) == 4 || statusClass(resp.StatusCode()) == 5 || statusClass(resp.StatusCode()) == 6
}

func reregistrationInitialRequiredStatus(status int) bool {
	switch status {
	case sipStatusForbidden, sipStatusRequestTimeout, sipStatusServerInternalError, sipStatusServerTimeout:
		return true
	default:
		return false
	}
}

func registrationTimeoutRequiresInitial(err error) bool {
	return session.TransactionTimerExpired(err, "F") || session.TransportFailed(err)
}

func initialRegistrationRequiredError(resp sip.Message) error {
	initial := &initialRegistrationRequired{}
	if retryAfter, ok := retryAfterDelay(resp); ok {
		initial.retryAfter = retryAfter
	}
	return fmt.Errorf("%w after %w", initial, sip.NewResponseError(resp))
}

func initialRegistrationRequiredAfterError(err error) error {
	return fmt.Errorf("%w after %w", &initialRegistrationRequired{}, err)
}

func pcscfReselectionRequiredError(resp sip.Message) error {
	reselection := &pcscfReselectionRequired{}
	if retryAfter, ok := retryAfterDelay(resp); ok {
		reselection.retryAfter = retryAfter
	}
	return fmt.Errorf("%w after %w", reselection, sip.NewResponseError(resp))
}

func minExpiresSeconds(value string) (int, error) {
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return 0, fmt.Errorf("parsing min-expires: %w", err)
	}
	if seconds < 0 {
		return 0, fmt.Errorf("parsing min-expires: negative value %d", seconds)
	}
	return seconds, nil
}
