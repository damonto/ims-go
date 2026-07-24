package registration

import (
	"context"
	"fmt"
	"sync"
)

// Group serializes REGISTER transactions and USIM AKA operations shared by
// multiple IMS access flows. Its zero value is ready to use.
type Group struct {
	register priorityGate
	aka      priorityGate

	// Once a registrar omits Require: outbound, only one flow may keep an
	// ordinary registration. A higher-preference flow may replace the owner;
	// lower-preference flows wait until the owner is released.
	mu                              sync.Mutex
	singleRegistration              bool
	singleRegistrationID            uint32
	singleRegistrationPreference    int
	singleRegistrationOwnerReleased chan struct{}
	singleRegistrationOwnerRevoke   func(context.Context) error
}

// BeginRegistration waits until this registration transaction can run.
// Higher preference values are selected first; equal values remain FIFO.
func (g *Group) BeginRegistration(ctx context.Context, preference int) (func(), error) {
	return g.register.acquire(ctx, preference)
}

func (g *Group) beginRegistrationForFlow(ctx context.Context, registrationID uint32, preference int) (func(), error) {
	for {
		release, err := g.register.acquire(ctx, preference)
		if err != nil {
			return nil, err
		}
		for {
			wait, revoke := g.claimRegistration(registrationID, preference)
			if revoke != nil {
				if err := revoke(ctx); err != nil {
					release()
					return nil, fmt.Errorf("replacing single registration: %w", err)
				}
				continue
			}
			if wait == nil {
				return release, nil
			}
			release()

			select {
			case <-wait:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			break
		}
	}
}

func (g *Group) beginDeregistrationForFlow(ctx context.Context, registrationID uint32, preference int) (func(), bool, error) {
	release, err := g.register.acquire(ctx, preference)
	if err != nil {
		return nil, false, err
	}
	g.mu.Lock()
	registered := !g.singleRegistration || g.singleRegistrationID == 0 || g.singleRegistrationID == registrationID
	g.mu.Unlock()
	if registered {
		return release, true, nil
	}
	release()
	return func() {}, false, nil
}

// BeginAKA waits until this USIM AKA operation can run.
// Higher preference values are selected first; equal values remain FIFO.
func (g *Group) BeginAKA(ctx context.Context, preference int) (func(), error) {
	return g.aka.acquire(ctx, preference)
}

func (g *Group) claimRegistration(registrationID uint32, preference int) (<-chan struct{}, func(context.Context) error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.singleRegistration {
		return nil, nil
	}
	if g.singleRegistrationID == 0 || g.singleRegistrationID == registrationID {
		g.singleRegistrationID = registrationID
		g.singleRegistrationPreference = preference
		return nil, nil
	}
	if preference > g.singleRegistrationPreference && g.singleRegistrationOwnerRevoke != nil {
		return nil, g.singleRegistrationOwnerRevoke
	}
	if preference > g.singleRegistrationPreference {
		g.singleRegistrationID = registrationID
		g.singleRegistrationPreference = preference
		return nil, nil
	}
	if g.singleRegistrationOwnerReleased == nil {
		g.singleRegistrationOwnerReleased = make(chan struct{})
	}
	return g.singleRegistrationOwnerReleased, nil
}

func (g *Group) useSingleRegistration(registrationID uint32, preference int) {
	g.setSingleRegistrationOwner(registrationID, preference, nil)
}

func (g *Group) setSingleRegistrationOwner(registrationID uint32, preference int, revoke func(context.Context) error) {
	g.mu.Lock()
	g.singleRegistration = true
	g.singleRegistrationID = registrationID
	g.singleRegistrationPreference = preference
	g.singleRegistrationOwnerRevoke = revoke
	g.mu.Unlock()
}

func (g *Group) releaseSingleRegistration(registrationID uint32) {
	g.mu.Lock()
	if g.singleRegistration && g.singleRegistrationID == registrationID {
		g.singleRegistration = false
		g.singleRegistrationID = 0
		g.singleRegistrationPreference = 0
		g.singleRegistrationOwnerRevoke = nil
		if g.singleRegistrationOwnerReleased != nil {
			close(g.singleRegistrationOwnerReleased)
			g.singleRegistrationOwnerReleased = nil
		}
	}
	g.mu.Unlock()
}

func (g *Group) multipleRegistrationEnabled() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return !g.singleRegistration
}

type priorityGate struct {
	mu      sync.Mutex
	held    bool
	next    uint64
	waiters []*priorityWaiter
}

type priorityWaiter struct {
	preference int
	sequence   uint64
	ready      chan struct{}
}

func (g *priorityGate) acquire(ctx context.Context, preference int) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	g.mu.Lock()
	if !g.held && len(g.waiters) == 0 {
		g.held = true
		g.mu.Unlock()
		return g.releaseOnce(), nil
	}
	waiter := &priorityWaiter{
		preference: preference,
		sequence:   g.next,
		ready:      make(chan struct{}),
	}
	g.next++
	g.waiters = append(g.waiters, waiter)
	g.mu.Unlock()

	select {
	case <-waiter.ready:
		return g.releaseOnce(), nil
	case <-ctx.Done():
		if g.cancel(waiter) {
			return nil, ctx.Err()
		}
		// The waiter was granted while cancellation raced with notification.
		// Consume the grant and pass ownership to the next waiter.
		<-waiter.ready
		g.release()
		return nil, ctx.Err()
	}
}

func (g *priorityGate) releaseOnce() func() {
	var once sync.Once
	return func() {
		once.Do(g.release)
	}
}

func (g *priorityGate) cancel(waiter *priorityWaiter) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for i, queued := range g.waiters {
		if queued != waiter {
			continue
		}
		g.waiters = append(g.waiters[:i], g.waiters[i+1:]...)
		return true
	}
	return false
}

func (g *priorityGate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.waiters) == 0 {
		g.held = false
		return
	}

	selected := 0
	for i := 1; i < len(g.waiters); i++ {
		candidate := g.waiters[i]
		current := g.waiters[selected]
		if candidate.preference > current.preference ||
			(candidate.preference == current.preference && candidate.sequence < current.sequence) {
			selected = i
		}
	}
	waiter := g.waiters[selected]
	g.waiters = append(g.waiters[:selected], g.waiters[selected+1:]...)
	close(waiter.ready)
}
