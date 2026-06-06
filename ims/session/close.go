package session

import (
	"context"
	"errors"
	"time"
)

var (
	errSessionClosed = errors.New("session is closed")
)

func (s *Session) Close() error {
	state, ok := s.beginClose()
	if !ok {
		return nil
	}

	closeErr := closeTransports(state.transports)
	notifyErr := closeErr
	if notifyErr == nil {
		notifyErr = errSessionClosed
	}
	s.finishClose(state.handlers, notifyErr)
	return errors.Join(closeErr, s.waitReadLoops())
}

type closeState struct {
	transports []Transport
	handlers   []*handlerEntry
}

func (s *Session) beginClose() (closeState, bool) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return closeState{}, false
	}
	s.closed = true
	primary := s.primary
	aux := append([]Transport(nil), s.aux...)
	transports := uniqueTransports(append(aux, primary))
	handlers := s.handlerSnapshotCopy()
	closedCh := s.closedCh
	s.active = make(map[Transport]struct{})
	s.responseRoutes = make(map[Transport]Transport)
	s.mu.Unlock()
	close(closedCh)

	return closeState{
		transports: transports,
		handlers:   handlers,
	}, true
}

func closeTransports(transports []Transport) error {
	var err error
	for _, transport := range transports {
		err = errors.Join(err, transport.Close())
	}
	return err
}

func (s *Session) finishClose(handlers []*handlerEntry, notifyErr error) {
	s.abortTransactions(notifyErr)
	s.clearServerTransactions()
	s.notifyHandlersOnce(handlers, notifyErr)
}

func (s *Session) waitReadLoops() error {
	done := make(chan struct{})
	go func() {
		s.readWG.Wait()
		close(done)
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-done:
		return nil
	case <-timer.C:
		return context.DeadlineExceeded
	}
}
