package sms

import (
	"context"
	"sync"
	"time"
)

func (s *Service) startBackgroundTask(task func(done <-chan struct{})) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	done := s.done
	s.bgWG.Go(func() {
		task(done)
	})
	s.mu.Unlock()
	return true
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
