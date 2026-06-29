package registration

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

const (
	registrationKeepAliveWriteTimeout = 5 * time.Second
	registrationKeepAliveMinPercent   = 80
	registrationKeepAliveMaxPercent   = 100
)

var registrationKeepAliveInterval = randomizedRegistrationKeepAliveInterval

type registrationKeepAlive struct {
	stopOnce sync.Once
	stopCh   chan struct{}
}

func newRegistrationKeepAlive() *registrationKeepAlive {
	return &registrationKeepAlive{stopCh: make(chan struct{})}
}

func (k *registrationKeepAlive) stop() {
	k.stopOnce.Do(func() {
		close(k.stopCh)
	})
}

func (k *registrationKeepAlive) done() <-chan struct{} {
	return k.stopCh
}

func (s *Registrar) applyRegisterKeepAlive(resp sip.Message) {
	recommended, interval, ok := registerKeepAliveTimingFromResponse(resp)
	if !ok {
		s.stopRegistrationKeepAlive("not_negotiated")
		return
	}
	s.startRegistrationKeepAlive(recommended, interval)
}

func registerKeepAliveIntervalFromResponse(resp sip.Message) (time.Duration, bool) {
	_, interval, ok := registerKeepAliveTimingFromResponse(resp)
	return interval, ok
}

func registerKeepAliveTimingFromResponse(resp sip.Message) (time.Duration, time.Duration, bool) {
	recommended, ok := parsePositiveSeconds(sip.TopViaKeep(resp.Header("Via")))
	if !ok {
		return 0, 0, false
	}
	interval := registrationKeepAliveInterval(recommended)
	if interval <= 0 {
		return 0, 0, false
	}
	return recommended, interval, true
}

func randomizedRegistrationKeepAliveInterval(recommended time.Duration) time.Duration {
	if recommended <= 0 {
		return 0
	}
	span := int64(registrationKeepAliveMaxPercent - registrationKeepAliveMinPercent + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(span))
	if err != nil {
		return percentageDuration(recommended, registrationKeepAliveMinPercent)
	}
	percent := registrationKeepAliveMinPercent + int(n.Int64())
	return percentageDuration(recommended, percent)
}

func percentageDuration(duration time.Duration, percent int) time.Duration {
	base := duration / 100
	rem := duration % 100
	return base*time.Duration(percent) + rem*time.Duration(percent)/100
}

func (s *Registrar) startRegistrationKeepAlive(recommended, interval time.Duration) {
	keepalive := newRegistrationKeepAlive()

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		keepalive.stop()
		return
	}
	old := s.registrationKeepAlive
	done := s.done
	s.registrationKeepAlive = keepalive
	if !s.startBackgroundTaskLocked(func() {
		s.runRegistrationKeepAlive(done, keepalive, interval)
	}) {
		s.registrationKeepAlive = old
		s.mu.Unlock()
		keepalive.stop()
		return
	}
	s.mu.Unlock()

	if old != nil {
		old.stop()
	}
	s.logger.Info("IMS RFC6223 keepalive active", "recommended", recommended, "interval", interval, "transport", sip.TransportToken(s.sess.LocalAddr()), "remote_addr", s.sess.RemoteAddr())
}

func (s *Registrar) stopRegistrationKeepAlive(reason string) {
	s.mu.Lock()
	keepalive := s.registrationKeepAlive
	s.registrationKeepAlive = nil
	s.mu.Unlock()

	if keepalive != nil {
		keepalive.stop()
		s.logger.Info("IMS RFC6223 keepalive stopped", "reason", reason)
	}
}

func (s *Registrar) runRegistrationKeepAlive(done <-chan struct{}, keepalive *registrationKeepAlive, interval time.Duration) {
	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			err := s.sendRegistrationKeepAlive(done, keepalive)
			if err != nil {
				s.logger.Warn("IMS RFC6223 keepalive failed", "err", err)
				s.publishRegistrationEvent(err)
				return
			}
			s.logger.Debug("IMS RFC6223 keepalive sent", "interval", interval, "transport", sip.TransportToken(s.sess.LocalAddr()), "remote_addr", s.sess.RemoteAddr())
			timer.Reset(interval)
		case <-done:
			return
		case <-keepalive.done():
			return
		}
	}
}

func (s *Registrar) sendRegistrationKeepAlive(done <-chan struct{}, keepalive *registrationKeepAlive) error {
	ctx, cancel := registrationKeepAliveWriteContext(done, keepalive.done(), registrationKeepAliveWriteTimeout)
	defer cancel()

	if err := s.sess.SendKeepAlive(ctx); err != nil {
		if registrationKeepAliveStopped(done, keepalive.done()) {
			return nil
		}
		return fmt.Errorf("sending IMS keepalive: %w", err)
	}
	return nil
}

func registrationKeepAliveWriteContext(done, stopped <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	stopWait := make(chan struct{})
	var once sync.Once

	go func() {
		select {
		case <-done:
			cancel()
		case <-stopped:
			cancel()
		case <-stopWait:
		}
	}()

	return ctx, func() {
		once.Do(func() {
			close(stopWait)
			cancel()
		})
	}
}

func registrationKeepAliveStopped(done, stopped <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
	}
	select {
	case <-stopped:
		return true
	default:
		return false
	}
}
