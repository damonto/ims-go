package tunnel

import "errors"

// ErrReactivationRequested marks an ePDG request to re-establish the IPsec
// tunnel after releasing the current one.
var ErrReactivationRequested = errors.New("reactivation requested")

// ReactivationRequested reports whether the peer explicitly requested tunnel
// re-establishment while releasing the current IPsec tunnel.
func ReactivationRequested(err error) bool {
	return errors.Is(err, ErrReactivationRequested)
}

func reactivationRequestedError(cause error) error {
	return errors.Join(ErrReactivationRequested, cause)
}
