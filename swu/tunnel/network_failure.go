package tunnel

import "errors"

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
