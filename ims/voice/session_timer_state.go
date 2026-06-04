package voice

import (
	"errors"
	"fmt"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (c *Call) applySessionTimerUACResponse(resp sip.Message, allowFallback bool) error {
	return c.applySessionTimerResponse(resp, true, allowFallback)
}

func (c *Call) applySessionTimerUASResponse(resp sip.Message) error {
	return c.applySessionTimerResponse(resp, false, false)
}

func (c *Call) applySessionTimerResponse(resp sip.Message, localWasUAC bool, allowUACFallback bool) error {
	value := resp.Header("Session-Expires")
	if value == "" {
		if tokenHeaderContains(resp, "Require", sessionTimerOption) {
			return errors.New("handling session timer: Require timer without Session-Expires")
		}
		if allowUACFallback {
			timer, ok := c.localSessionTimerFallback(localWasUAC)
			if !ok {
				c.stopSessionTimer()
				return nil
			}
			c.replaceSessionTimer(timer)
			return nil
		}
		c.stopSessionTimer()
		return nil
	}
	h, ok := parseSessionExpiresHeader(value)
	if !ok || h.refresher == "" {
		return fmt.Errorf("handling session timer: invalid Session-Expires %q", value)
	}
	interval := time.Duration(h.seconds) * time.Second
	if interval < defaultMinSessionExpires {
		return fmt.Errorf("handling session timer: Session-Expires %q is below %s", value, defaultMinSessionExpires)
	}
	localRefresher := h.refresher == sessionRefresherUAC
	if !localWasUAC {
		localRefresher = h.refresher == sessionRefresherUAS
	}
	timer := sessionTimerState{
		active:         true,
		interval:       interval,
		minSE:          durationSeconds(defaultMinSessionExpires),
		localRefresher: localRefresher,
	}
	c.mu.Lock()
	if c.sessionTimer.minSE > timer.minSE {
		timer.minSE = c.sessionTimer.minSE
	}
	c.mu.Unlock()
	c.replaceSessionTimer(timer)
	return nil
}

func (c *Call) localSessionTimerFallback(localWasUAC bool) (sessionTimerState, bool) {
	if !localWasUAC || !c.service.cfg.SessionTimer {
		return sessionTimerState{}, false
	}
	c.mu.Lock()
	current := c.sessionTimer
	c.mu.Unlock()
	if !current.active && c.service.cfg.SessionExpires == 0 {
		return sessionTimerState{}, false
	}
	seconds := sessionExpiresSeconds(c.service.cfg, c.inviteRequest)
	timer := sessionTimerState{
		active:         true,
		interval:       time.Duration(seconds) * time.Second,
		minSE:          durationSeconds(defaultMinSessionExpires),
		localRefresher: true,
	}
	if current.minSE > timer.minSE {
		timer.minSE = current.minSE
	}
	if timer.minSE > seconds {
		timer.interval = time.Duration(timer.minSE) * time.Second
	}
	return timer, true
}

func (c *Call) stopSessionTimer() {
	c.mu.Lock()
	stop := c.sessionTimerStop
	c.sessionTimerStop = nil
	c.sessionTimer = sessionTimerState{}
	c.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (c *Call) replaceSessionTimer(timer sessionTimerState) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	old := c.sessionTimerStop
	stop := make(chan struct{})
	c.sessionTimer = timer
	c.sessionTimerStop = stop
	c.mu.Unlock()

	if old != nil {
		close(old)
	}
	c.service.startBackgroundTask(func(done <-chan struct{}) {
		c.runSessionTimer(timer, stop, done)
	})
}

func (c *Call) runSessionTimer(timer sessionTimerState, stop, done <-chan struct{}) {
	delay := sessionRefreshDelay(timer)
	t := time.NewTimer(delay)
	defer t.Stop()
	select {
	case <-done:
		return
	case <-stop:
		return
	case <-t.C:
	}
	if timer.localRefresher {
		c.refreshSession()
		return
	}
	c.expireUnrefreshedSession()
}

func sessionRefreshDelay(timer sessionTimerState) time.Duration {
	if timer.localRefresher {
		return timer.interval / 2
	}
	beforeExpiration := min(32*time.Second, timer.interval/3)
	delay := timer.interval - beforeExpiration
	if delay <= 0 {
		return timer.interval / 2
	}
	return delay
}
