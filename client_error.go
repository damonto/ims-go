package vowifi

import (
	"errors"
	"fmt"
)

type ConnectionError struct {
	State ClientState
	Err   error
}

func (e *ConnectionError) Error() string {
	if e.State.Status == "" {
		return e.Err.Error()
	}
	if e.State.LastError != nil {
		return fmt.Sprintf("%s: status %s: last error: %v", e.Err, e.State.Status, e.State.LastError)
	}
	return fmt.Sprintf("%s: status %s", e.Err, e.State.Status)
}

func (e *ConnectionError) Unwrap() error {
	return e.Err
}

func (e *ConnectionError) Is(target error) bool {
	if errors.Is(e.Err, target) {
		return true
	}
	return target == ErrClientNotConnected && clientUnavailableError(e.State) != nil
}

func (e *ConnectionError) Status() ClientStatus {
	return e.State.Status
}

func clientUnavailableError(state ClientState) error {
	if state.Active {
		return nil
	}
	if state.Closed || state.Status == StatusClosed {
		return ErrClientClosed
	}
	if state.Reconnecting || state.Status == StatusReconnecting {
		return ErrClientReconnecting
	}
	if state.Connecting || state.Status == StatusConnecting || state.Status == StatusAuthenticating {
		return ErrClientConnecting
	}
	if state.Status == StatusFailed {
		return ErrClientFailed
	}
	return ErrClientNotConnected
}
