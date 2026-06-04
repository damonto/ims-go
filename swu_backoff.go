package vowifi

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
)

var errSWUBackoffDeactivated = errors.New("swu backoff deactivated")

type swuBackoffGate struct {
	entries map[swuBackoffKey]swuBackoffEntry
}

type swuBackoffKey struct {
	scope swutunnel.BackoffScope
	epdg  string
	mcc   string
	mnc   string
	apn   string
}

type swuBackoffEntry struct {
	until       time.Time
	deactivated bool
}

func (c *Client) recordSWUBackoff(err error, now time.Time) {
	c.withStateLock(func(s *clientState) {
		policy, ok := swuBackoffPolicyFor(c.cfg, err)
		if !ok {
			return
		}
		key, ok := swuBackoffKeyFor(c.cfg, c.card, policy.Scope)
		if !ok {
			return
		}
		c.recordSWUBackoffLocked(s, key, policy, now)
	})
}

func (c *Client) recordSWUBackoffLocked(s *clientState, key swuBackoffKey, policy swutunnel.BackoffPolicy, now time.Time) {
	if !policy.Deactivated && policy.Delay == 0 {
		delete(s.swuBackoff.entries, key)
		return
	}
	if s.swuBackoff.entries == nil {
		s.swuBackoff.entries = make(map[swuBackoffKey]swuBackoffEntry)
	}
	entry := swuBackoffEntry{deactivated: policy.Deactivated}
	if !policy.Deactivated {
		entry.until = now.Add(policy.Delay)
	}
	current, exists := s.swuBackoff.entries[key]
	if !exists || entry.deactivated || entry.until.After(current.until) {
		s.swuBackoff.entries[key] = entry
	}
}

func swuBackoffPolicyFor(cfg Config, err error) (swutunnel.BackoffPolicy, bool) {
	if policy, ok := swutunnel.BackoffPolicyFor(err); ok {
		return policy, true
	}
	if swutunnel.NetworkFailure(err) {
		return swutunnel.BackoffPolicy{
			Delay: cfg.ReconnectDelay,
			Scope: swutunnel.BackoffScopeEPDG,
		}, cfg.ReconnectDelay > 0
	}
	if errors.Is(err, swutunnel.ErrNoAPNSubscription) {
		return swutunnel.BackoffPolicy{
			Delay: cfg.ReconnectDelay,
			Scope: swutunnel.BackoffScopePLMNAPN,
		}, cfg.ReconnectDelay > 0
	}
	return swutunnel.BackoffPolicy{}, false
}

func (c *Client) clearCurrentSWUBackoff() {
	c.withStateLock(func(s *clientState) {
		for _, key := range c.swuBackoffKeys() {
			delete(s.swuBackoff.entries, key)
		}
	})
}

func (c *Client) waitSWUBackoff(ctx context.Context) error {
	for {
		delay, deactivated, active := c.swuBackoffDelay(time.Now())
		if !active {
			return nil
		}
		if deactivated {
			return fmt.Errorf("preparing connect: %w", errSWUBackoffDeactivated)
		}
		c.logger.Info("waiting for SWu backoff", "delay", delay)
		if err := sleepContext(ctx, delay); err != nil {
			return fmt.Errorf("waiting for swu backoff: %w", err)
		}
	}
}

func (c *Client) swuBackoffDelay(now time.Time) (time.Duration, bool, bool) {
	var delay time.Duration
	var deactivated bool
	c.withStateLock(func(s *clientState) {
		for _, key := range c.swuBackoffKeys() {
			entry, ok := s.swuBackoff.entries[key]
			if !ok {
				continue
			}
			if entry.deactivated {
				deactivated = true
				return
			}
			if !entry.until.After(now) {
				delete(s.swuBackoff.entries, key)
				continue
			}
			delay = max(delay, entry.until.Sub(now))
		}
	})
	if deactivated {
		return 0, true, true
	}
	return delay, false, delay > 0
}

func (c *Client) swuBackoffKeys() []swuBackoffKey {
	keys := make([]swuBackoffKey, 0, 2)
	for _, scope := range []swutunnel.BackoffScope{swutunnel.BackoffScopeEPDG, swutunnel.BackoffScopePLMNAPN} {
		key, ok := swuBackoffKeyFor(c.cfg, c.card, scope)
		if ok {
			keys = append(keys, key)
		}
	}
	return keys
}

func swuBackoffKeyFor(cfg Config, card Card, scope swutunnel.BackoffScope) (swuBackoffKey, bool) {
	key := swuBackoffKey{scope: scope}
	if scope == swutunnel.BackoffScopeEPDG {
		epdg := strings.ToLower(strings.TrimSpace(cfg.EPDG))
		if epdg == "" {
			return swuBackoffKey{}, false
		}
		key.epdg = epdg
		return key, true
	}
	if scope != swutunnel.BackoffScopePLMNAPN {
		return swuBackoffKey{}, false
	}
	if card == nil {
		return swuBackoffKey{}, false
	}
	mcc, mnc, ok := normalizedBackoffPLMN(card)
	if !ok {
		return swuBackoffKey{}, false
	}
	key.mcc = mcc
	key.mnc = mnc
	key.apn = swuBackoffAPNFor(cfg)
	return key, true
}

func swuBackoffAPNFor(cfg Config) string {
	apn := strings.ToLower(strings.TrimSpace(cfg.Tunnel.APN))
	if apn == "" {
		return swutunnel.DefaultAPN
	}
	return apn
}

func normalizedBackoffPLMN(card Card) (string, string, bool) {
	mcc := strings.TrimSpace(card.MCC())
	if len(mcc) != 3 {
		return "", "", false
	}
	mnc := strings.TrimSpace(card.MNC())
	switch len(mnc) {
	case 2:
		mnc = "0" + mnc
	case 3:
	default:
		return "", "", false
	}
	return mcc, mnc, true
}
