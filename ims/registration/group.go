package registration

import (
	"context"
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
	singleRegistrationOwnerRetire   func()
}

// BeginRegistration waits until this registration transaction can run.
// Higher preference values are selected first; equal values remain FIFO.
func (g *Group) BeginRegistration(ctx context.Context, preference int) (func(), error) {
	return g.register.acquire(ctx, preference)
}

// WaitForRegistration waits until this flow may attempt a REGISTER without
// retaining the transaction gate. It is used by a replaced fallback flow
// before rebuilding its IMS connection.
func (g *Group) WaitForRegistration(ctx context.Context, registrationID uint32, preference int) error {
	release, err := g.beginRegistrationForFlow(ctx, registrationID, preference)
	if err != nil {
		return err
	}
	release()
	return nil
}

func (g *Group) beginRegistrationForFlow(ctx context.Context, registrationID uint32, preference int) (func(), error) {
	return g.beginRegistrationForFlowUntil(ctx, registrationID, preference, nil)
}

func (g *Group) beginRegistrationForFlowUntil(
	ctx context.Context,
	registrationID uint32,
	preference int,
	stop <-chan struct{},
) (func(), error) {
	for {
		release, err := g.register.acquireUntil(ctx, preference, stop)
		if err != nil {
			return nil, err
		}
		if channelClosed(stop) {
			release()
			return nil, errRegistrationStopped
		}
		wait := g.registrationWait(registrationID, preference)
		if wait == nil {
			return release, nil
		}
		release()

		select {
		case <-wait:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-stop:
			return nil, errRegistrationStopped
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

func (g *Group) registrationWait(registrationID uint32, preference int) <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.singleRegistration {
		return nil
	}
	if g.singleRegistrationID == 0 || g.singleRegistrationID == registrationID {
		return nil
	}
	if preference > g.singleRegistrationPreference {
		// The preferred flow registers first. A successful REGISTER replaces the
		// old network binding; only then does setSingleRegistrationOwner retire
		// the previous local registrar.
		return nil
	}
	if g.singleRegistrationOwnerReleased == nil {
		g.singleRegistrationOwnerReleased = make(chan struct{})
	}
	return g.singleRegistrationOwnerReleased
}

func (g *Group) useSingleRegistration(registrationID uint32, preference int) {
	g.setSingleRegistrationOwner(registrationID, preference, nil)
}

func (g *Group) setSingleRegistrationOwner(registrationID uint32, preference int, retire func()) func() {
	g.mu.Lock()
	var previousRetire func()
	if g.singleRegistration && g.singleRegistrationID != 0 && g.singleRegistrationID != registrationID {
		previousRetire = g.singleRegistrationOwnerRetire
	}
	g.singleRegistration = true
	g.singleRegistrationID = registrationID
	g.singleRegistrationPreference = preference
	g.singleRegistrationOwnerRetire = retire
	g.mu.Unlock()
	return previousRetire
}

func (g *Group) releaseSingleRegistration(registrationID uint32) {
	g.mu.Lock()
	if g.singleRegistration && g.singleRegistrationID == registrationID {
		g.singleRegistration = false
		g.singleRegistrationID = 0
		g.singleRegistrationPreference = 0
		g.singleRegistrationOwnerRetire = nil
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
	return g.acquireUntil(ctx, preference, nil)
}

func (g *priorityGate) acquireUntil(ctx context.Context, preference int, stop <-chan struct{}) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if channelClosed(stop) {
		return nil, errRegistrationStopped
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
	case <-stop:
		if g.cancel(waiter) {
			return nil, errRegistrationStopped
		}
		// The waiter was granted while retirement raced with notification.
		// Consume the grant and pass ownership to the next waiter.
		<-waiter.ready
		g.release()
		return nil, errRegistrationStopped
	}
}

func channelClosed(ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-ch:
		return true
	default:
		return false
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
