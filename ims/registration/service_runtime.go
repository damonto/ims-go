package registration

import (
	"context"
	"sync"
	"time"
)

func (s *Service) startBackgroundTaskLocked(task func()) bool {
	if s.closed {
		return false
	}
	s.bgWG.Go(task)
	return true
}

func (s *Service) closeDoneLocked() {
	if s.closed {
		return
	}
	s.closed = true
	close(s.done)
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
