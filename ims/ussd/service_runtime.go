package ussd

import (
	"context"
	"sync"
	"time"
)

func (s *Service) startBackgroundTask(task func(done <-chan struct{})) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	done := s.done
	s.bgWG.Go(func() {
		task(done)
	})
	s.mu.Unlock()
}

func (s *Service) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	s.mu.Lock()
	done := s.done
	s.mu.Unlock()
	return contextWithDoneTimeout(done, timeout)
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
