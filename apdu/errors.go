package apdu

import (
	"errors"
	"fmt"
)

var (
	ErrMalformedResponse = errors.New("malformed APDU response")
	ErrReaderNotFound    = errors.New("reader not found")
)

type StatusError struct {
	SW uint16
}

func (e StatusError) Error() string {
	return fmt.Sprintf("unexpected status word 0x%04X", e.SW)
}

func IsStatus(err error, sw uint16) bool {
	var statusErr StatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	return statusErr.SW == sw
}

func checkResponse(res Response) error {
	if len(res) < 2 {
		return ErrMalformedResponse
	}
	if !res.OK() {
		return StatusError{SW: res.SW()}
	}
	return nil
}
