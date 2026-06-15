package tunnel

import "errors"

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
