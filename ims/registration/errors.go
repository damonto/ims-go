package registration

import (
	"errors"
	"time"
)

var (
	errRegisterBindingMissing    = errors.New("register response omitted current binding")
	errRegistrationReplaced      = errors.New("ims registration replaced by preferred flow")
	errNetworkDeregistered       = errors.New("ims registration terminated by network")
	errInitialRegistrationNeeded = errors.New("initial registration required")
	errSecureSAExpired           = errors.New("ims security association lifetime expired")
	errSecurityAgreementInvalid  = errors.New("security agreement is invalid")
)

type initialRegistrationRequired struct {
	retryAfter time.Duration
}

func (e *initialRegistrationRequired) Error() string {
	return errInitialRegistrationNeeded.Error()
}

func (e *initialRegistrationRequired) Is(target error) bool {
	return target == errInitialRegistrationNeeded
}

func (e *initialRegistrationRequired) retryAfterDelay() time.Duration {
	return e.retryAfter
}

type subscriptionRetryAfter struct {
	retryAfter time.Duration
}

func (e *subscriptionRetryAfter) Error() string {
	return "registration event subscription retry after"
}

func (e *subscriptionRetryAfter) retryAfterDelay() time.Duration {
	return e.retryAfter
}
