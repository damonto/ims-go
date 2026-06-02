package eapaka

import "errors"

var (
	ErrEAPFailure                    = errors.New("eap failure")
	ErrAKAPrimeAuthenticationFailure = errors.New("aka prime authentication failure")
)
