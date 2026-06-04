package session

import (
	"context"
	"sync"
	"time"
)

func (s *Session) markReady() {
	s.mu.Lock()
	if s.ready {
		s.mu.Unlock()
		return
	}
	s.ready = true
	startedCh := s.startedCh
	s.mu.Unlock()
	close(startedCh)
}

func (s *Session) finishRunning() {
	s.mu.Lock()
	s.running = false
	s.runtime = nil
	s.mu.Unlock()
}

func (s *Session) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	s.mu.Lock()
	closedCh := s.closedCh
	s.mu.Unlock()
	return contextWithDoneTimeout(closedCh, timeout)
}

func contextWithDoneTimeout(done <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-done:
			cancel()
		case <-stop:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			cancel()
		})
	}
}
