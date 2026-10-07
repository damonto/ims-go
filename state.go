package ims

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type ClientStatus string

const (
	StatusIdle           ClientStatus = "idle"
	StatusConnecting     ClientStatus = "connecting"
	StatusAuthenticating ClientStatus = "authenticating"
	StatusRegistered     ClientStatus = "registered"
	StatusReconnecting   ClientStatus = "reconnecting"
	StatusClosed         ClientStatus = "closed"
	StatusFailed         ClientStatus = "failed"
)

var (
	ErrClientClosed       = errors.New("client is closed")
	ErrClientConnecting   = errors.New("client is connecting")
	ErrClientReconnecting = errors.New("client is reconnecting")
	ErrClientFailed       = errors.New("client failed")
	ErrClientNotConnected = errors.New("client is not connected")
)

type ConnectionError struct {
	State ClientState
	Err   error
}

func (e *ConnectionError) Error() string {
	if e.State.Status == "" {
		return e.Err.Error()
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

type ClientState struct {
	Status       ClientStatus
	TerminalID   string
	Active       bool
	Connecting   bool
	Reconnecting bool
	Closed       bool
	LastError    error
}

type clientState struct {
	done         chan struct{}
	mu           sync.Mutex
	status       ClientStatus
	lastErr      error
	closed       bool
	connecting   bool
	reconnecting bool
	active       *activeConn
	closeWG      sync.WaitGroup
	closeOnce    sync.Once
	closeErr     error // Published by closeOnce to all concurrent Close callers.
	swuBackoff   swuBackoffGate
	swuPDNTypes  swuPDNTypeRestrictionGate
	reconnectSeq atomic.Uint64
}

func (c *Client) State() ClientState {
	return c.state.snapshot(c.cfg.Terminal.ID)
}

func (s *clientState) snapshot(terminalID string) ClientState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked(terminalID)
}

func (s *clientState) snapshotLocked(terminalID string) ClientState {
	status := s.status
	if status == "" {
		status = StatusIdle
	}
	return ClientState{
		Status:       status,
		TerminalID:   terminalID,
		Active:       s.active != nil,
		Connecting:   s.connecting,
		Reconnecting: s.reconnecting,
		Closed:       s.closed,
		LastError:    s.lastErr,
	}
}

func (c *Client) transitionStatus(status ClientStatus, err error) ClientState {
	return c.state.transitionStatus(c.cfg.Terminal.ID, status, err)
}

func (s *clientState) transitionStatus(terminalID string, status ClientStatus, err error) ClientState {
	s.mu.Lock()
	switch {
	case status != "":
		s.status = status
	case s.status == "":
		status = StatusIdle
		s.status = status
	}
	if err != nil {
		s.lastErr = err
	}
	snapshot := s.snapshotLocked(terminalID)
	s.mu.Unlock()
	return snapshot
}

func (c *Client) connectionError(err error) error {
	return c.state.connectionError(c.cfg.Terminal.ID, err)
}

func (s *clientState) connectionError(terminalID string, err error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connectionErrorLocked(terminalID, err)
}

func (s *clientState) connectionErrorLocked(terminalID string, err error) error {
	state := s.snapshotLocked(terminalID)
	if err == nil {
		err = clientUnavailableError(state)
	}
	return &ConnectionError{
		State: state,
		Err:   err,
	}
}

func (c *Client) currentActive() (*activeConn, error) {
	return c.state.currentActive(c.cfg.Terminal.ID)
}

func (s *clientState) currentActive(terminalID string) (*activeConn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil {
		return nil, s.connectionErrorLocked(terminalID, nil)
	}
	return s.active, nil
}

func (s *clientState) reserveConnect(internal bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClientClosed
	}
	if s.active != nil {
		return errors.New("already connected")
	}
	if s.connecting || (!internal && s.reconnecting) {
		return errors.New("connection in progress")
	}
	s.connecting = true
	return nil
}

func (s *clientState) finishConnectAttempt() {
	s.mu.Lock()
	s.connecting = false
	s.mu.Unlock()
}

func (s *clientState) commitActive(active *activeConn) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("client closed during setup")
	}
	if s.active != nil {
		return errors.New("already connected")
	}
	s.active = active
	s.connecting = false
	return nil
}

func (s *clientState) reserveCloseTask() (func(), bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, false
	}
	s.closeWG.Add(1)
	s.mu.Unlock()
	return func() {
		s.closeWG.Done()
	}, true
}

func (s *clientState) detachActive(active *activeConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.active != active {
		return false
	}
	s.active = nil
	return true
}

func (s *clientState) isClosed() bool {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	return closed
}

func (s *clientState) startReconnect() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.reconnecting {
		return false
	}
	s.reconnecting = true
	return true
}

func (s *clientState) finishReconnect() {
	s.mu.Lock()
	s.reconnecting = false
	s.mu.Unlock()
}

func (s *clientState) beginClose() (*activeConn, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, false
	}
	s.closed = true
	s.connecting = false
	s.reconnecting = false
	active := s.active
	s.active = nil
	close(s.done)
	return active, true
}

func (s *clientState) waitCloseTasks(timeout time.Duration) bool {
	done := make(chan struct{})
	go func() {
		s.closeWG.Wait()
		close(done)
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func (s *clientState) doClose(fn func() error) error {
	s.closeOnce.Do(func() {
		s.closeErr = fn()
	})
	return s.closeErr
}

func (s *clientState) nextReconnectID() uint64 {
	return s.reconnectSeq.Add(1)
}

func (s *clientState) imsSnapshot(active *activeConn) imsStack {
	s.mu.Lock()
	defer s.mu.Unlock()
	return active.ims
}

func (s *clientState) detachIMS(active *activeConn) imsStack {
	s.mu.Lock()
	defer s.mu.Unlock()
	stack := active.ims
	active.ims = imsStack{}
	// Resource cleanup can publish callbacks, so the caller closes this copy
	// only after releasing the client state lock.
	return stack
}

func (s *clientState) restoreIMS(active *activeConn, ims imsStack, access accessSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("connecting client: %w", ErrClientClosed)
	}
	if s.active != active {
		return errors.New("active connection changed")
	}
	active.ims = ims
	if access != nil {
		active.access = access
	}
	return nil
}

func (c *Client) withStateLock(fn func(*clientState)) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	fn(&c.state)
}

func currentIMSEndpoint[T any](c *Client, pick func(imsStack) *T) (*T, error) {
	active, err := c.currentActive()
	if err != nil {
		return nil, err
	}
	if active.tunnel != nil {
		if _, err := active.tunnel.ReadyInfo(); err != nil {
			return nil, c.connectionError(fmt.Errorf("%w: tunnel not ready: %w", ErrClientNotConnected, err))
		}
	}
	service := pick(c.state.imsSnapshot(active))
	if service == nil {
		return nil, c.connectionError(ErrClientNotConnected)
	}
	return service, nil
}
