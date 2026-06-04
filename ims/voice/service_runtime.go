package voice

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
	done := s.bgDone
	s.bgWG.Go(func() {
		task(done)
	})
	s.mu.Unlock()
}

func (s *Service) backgroundContext() (context.Context, context.CancelFunc) {
	s.mu.Lock()
	done := s.bgDone
	s.mu.Unlock()
	return contextWithDone(done)
}

func (s *Service) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	s.mu.Lock()
	done := s.bgDone
	s.mu.Unlock()
	return contextWithDoneTimeout(done, timeout)
}

func contextWithDone(done <-chan struct{}) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	return cancelContextWithDone(ctx, cancel, done)
}

func contextWithDoneTimeout(done <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return cancelContextWithDone(ctx, cancel, done)
}

func cancelContextWithDone(ctx context.Context, cancel context.CancelFunc, done <-chan struct{}) (context.Context, context.CancelFunc) {
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
