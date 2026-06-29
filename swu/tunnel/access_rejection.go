package tunnel

import "errors"

var (
	// ErrAccessRejected marks a network rejection where retrying the same
	// ePDG/PLMN/APN selection would violate TS 24.302.
	ErrAccessRejected = errors.New("access rejected")

	ErrPDNConnectionRejected                = errors.New("pdn connection rejected")
	ErrMaxConnectionReached                 = errors.New("max connection reached")
	ErrUserUnknown                          = errors.New("user unknown")
	ErrNoAPNSubscription                    = errors.New("no apn subscription")
	ErrIMEINotAccepted                      = errors.New("imei not accepted")
	ErrUnauthenticatedEmergencyNotSupported = errors.New("unauthenticated emergency not supported")
)

type accessRejectionError struct {
	notifyType uint16
	err        error
}

func (e *accessRejectionError) Error() string {
	return e.err.Error()
}

func (e *accessRejectionError) Unwrap() error {
	return e.err
}

func (e *accessRejectionError) Is(target error) bool {
	if target == ErrAccessRejected {
		return true
	}
	sentinel := accessRejectionSentinel(e.notifyType)
	return sentinel != nil && sentinel == target
}

func AccessRejected(err error) bool {
	return errors.Is(err, ErrAccessRejected)
}

func accessRejectionErrorFor(notifyType uint16, cause error) error {
	if !accessRejectedNotify(notifyType) {
		return cause
	}
	return &accessRejectionError{notifyType: notifyType, err: cause}
}

func accessRejectedNotify(notifyType uint16) bool {
	switch notifyType {
	case notifyTypePDNConnectionRejection,
		notifyTypeMaxConnectionReached,
		notifyTypeNon3GPPAccessToEPCNotAllowed,
		notifyTypeUserUnknown,
		notifyTypeNoAPNSubscription,
		notifyTypePLMNNotAllowed,
		notifyTypeAuthorizationRejected,
		notifyTypeRATTypeNotAllowed,
		notifyTypeIllegalME,
		notifyTypeIMEINotAccepted,
		notifyTypeUnauthenticatedEmergency:
		return true
	default:
		return false
	}
}

func accessRejectionSentinel(notifyType uint16) error {
	switch notifyType {
	case notifyTypePDNConnectionRejection:
		return ErrPDNConnectionRejected
	case notifyTypeMaxConnectionReached:
		return ErrMaxConnectionReached
	case notifyTypeUserUnknown:
		return ErrUserUnknown
	case notifyTypeNoAPNSubscription:
		return ErrNoAPNSubscription
	case notifyTypeIMEINotAccepted:
		return ErrIMEINotAccepted
	case notifyTypeUnauthenticatedEmergency:
		return ErrUnauthenticatedEmergencyNotSupported
	default:
		return nil
	}
}

var ErrNetworkFailure = errors.New("network failure")

type networkFailureError struct {
	err error
}

func (e *networkFailureError) Error() string {
	return e.err.Error()
}

func (e *networkFailureError) Unwrap() error {
	return e.err
}

func (e *networkFailureError) Is(target error) bool {
	return target == ErrNetworkFailure
}

func NetworkFailure(err error) bool {
	return errors.Is(err, ErrNetworkFailure)
}

func networkFailureErrorFor(cause error) error {
	return &networkFailureError{err: cause}
}

// ErrReactivationRequested marks an ePDG request to re-establish the IPsec
// tunnel after releasing the current one.
var ErrReactivationRequested = errors.New("reactivation requested")

// ErrPDNDeactivated marks network initiated PDN connectivity deactivation.
var ErrPDNDeactivated = errors.New("pdn connectivity deactivated")

// ReactivationRequested reports whether the peer explicitly requested tunnel
// re-establishment while releasing the current IPsec tunnel.
func ReactivationRequested(err error) bool {
	return errors.Is(err, ErrReactivationRequested)
}

// PDNDeactivated reports whether the peer deactivated the current PDN
// connectivity without requesting same-PDN reactivation.
func PDNDeactivated(err error) bool {
	return errors.Is(err, ErrPDNDeactivated)
}

func reactivationRequestedError(cause error) error {
	return errors.Join(ErrReactivationRequested, cause)
}

func pdnDeactivatedError(cause error) error {
	return errors.Join(ErrPDNDeactivated, cause)
}
