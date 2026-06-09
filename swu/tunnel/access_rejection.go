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
