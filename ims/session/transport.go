package session

import (
	"context"
	"errors"
	"fmt"
	"net"
)

func (s *Session) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.primary.LocalAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.primary.RemoteAddr()
}

func (s *Session) WaitTransportsIdle(ctx context.Context, transports ...Transport) error {
	watched, err := transportSet(transports)
	if err != nil {
		return err
	}
	if len(watched) == 0 {
		return nil
	}
	for {
		s.mu.Lock()
		if s.transportsIdle(watched) {
			s.mu.Unlock()
			return nil
		}
		if s.closed {
			s.mu.Unlock()
			return errors.New("waiting for transport transactions: session is closed")
		}
		changed := s.txChanged
		closed := s.closedCh
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-closed:
			return errors.New("waiting for transport transactions: session is closed")
		case <-changed:
		}
	}
}

func (s *Session) ensureOpen(action string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("%s: session is closed", action)
	}
	return nil
}

func (s *Session) ensureActiveTransport(action string, transport Transport) error {
	if transport == nil {
		return fmt.Errorf("%s: transport is nil", action)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.active[transport]; !ok {
		return fmt.Errorf("%s: transport is not active", action)
	}
	return nil
}

func (s *Session) isRunning() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

func (s *Session) primaryTransport() Transport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.primary
}

func (s *Session) isTransportActive(transport Transport) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.active[transport]
	return ok
}

func (s *Session) removeFailedAuxTransport(transport Transport) bool {
	s.mu.Lock()
	if s.closed || transport == s.primary {
		s.mu.Unlock()
		return false
	}
	if _, ok := s.active[transport]; !ok {
		s.mu.Unlock()
		return true
	}
	delete(s.active, transport)
	s.removeResponseRoutesFor(transport)
	s.aux = removeTransport(s.aux, transport)
	s.notifyTransactionsChanged()
	s.mu.Unlock()
	_ = transport.Close()
	return true
}

func (s *Session) transportsIdle(transports map[Transport]struct{}) bool {
	for _, tx := range s.transactions {
		if _, ok := transports[tx.transport]; ok {
			return false
		}
	}
	for _, tx := range s.serverTxs {
		if _, ok := transports[tx.transport]; ok {
			return false
		}
	}
	return true
}

func (s *Session) notifyTransactionsChanged() {
	close(s.txChanged)
	s.txChanged = make(chan struct{})
}

func transportSet(transports []Transport) (map[Transport]struct{}, error) {
	set := make(map[Transport]struct{}, len(transports))
	for _, transport := range transports {
		if transport == nil {
			return nil, errors.New("waiting for transport transactions: transport is nil")
		}
		set[transport] = struct{}{}
	}
	return set, nil
}

func removeTransport(transports []Transport, target Transport) []Transport {
	next := transports[:0]
	for _, transport := range transports {
		if transport == target {
			continue
		}
		next = append(next, transport)
	}
	return next
}

func uniqueTransports(transports []Transport) []Transport {
	seen := make(map[Transport]struct{}, len(transports))
	unique := make([]Transport, 0, len(transports))
	for _, transport := range transports {
		if _, ok := seen[transport]; ok {
			continue
		}
		seen[transport] = struct{}{}
		unique = append(unique, transport)
	}
	return unique
}
