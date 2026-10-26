// Package eapaka implements EAP-AKA and EAP-AKA' messages and key derivation.
package eapaka

import "errors"

var (
	ErrEAPFailure                    = errors.New("eap failure")
	ErrAKAPrimeAuthenticationFailure = errors.New("aka prime authentication failure")
)
