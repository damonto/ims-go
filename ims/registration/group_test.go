package registration

import (
	"context"
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestGroupSelectsHigherPreferenceThenFIFO(t *testing.T) {
	tests := []struct {
		name  string
		gate  func(*Group) *priorityGate
		begin func(*Group, context.Context, int) (func(), error)
	}{
		{
			name: "REGISTER transactions",
			gate: func(group *Group) *priorityGate { return &group.register },
			begin: func(group *Group, ctx context.Context, preference int) (func(), error) {
				return group.BeginRegistration(ctx, preference)
			},
		},
		{
			name: "AKA operations",
			gate: func(group *Group) *priorityGate { return &group.aka },
			begin: func(group *Group, ctx context.Context, preference int) (func(), error) {
				return group.BeginAKA(ctx, preference)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &Group{}
			release, err := tt.begin(group, context.Background(), 0)
			if err != nil {
				t.Fatalf("acquiring initial owner: %v", err)
			}

			order := make(chan string)
			start := func(name string, preference int) {
				go func() {
					release, err := tt.begin(group, context.Background(), preference)
					if err != nil {
						order <- "error: " + err.Error()
						return
					}
					order <- name
					release()
				}()
			}

			start("low-first", 500)
			waitForWaiterCount(t, tt.gate(group), 1)
			start("high-first", 1000)
			waitForWaiterCount(t, tt.gate(group), 2)
			start("high-second", 1000)
			waitForWaiterCount(t, tt.gate(group), 3)

			release()
			for _, want := range []string{"high-first", "high-second", "low-first"} {
				select {
				case got := <-order:
					if got != want {
						t.Fatalf("acquisition order got %q, want %q", got, want)
					}
				case <-time.After(time.Second):
					t.Fatalf("waiting for %q to acquire", want)
				}
			}
		})
	}
}

func TestGroupRemovesCanceledWaiter(t *testing.T) {
	tests := []struct {
		name  string
		gate  func(*Group) *priorityGate
		begin func(*Group, context.Context, int) (func(), error)
	}{
		{
			name: "REGISTER transaction",
			gate: func(group *Group) *priorityGate { return &group.register },
			begin: func(group *Group, ctx context.Context, preference int) (func(), error) {
				return group.BeginRegistration(ctx, preference)
			},
		},
		{
			name: "AKA operation",
			gate: func(group *Group) *priorityGate { return &group.aka },
			begin: func(group *Group, ctx context.Context, preference int) (func(), error) {
				return group.BeginAKA(ctx, preference)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &Group{}
			release, err := tt.begin(group, context.Background(), 0)
			if err != nil {
				t.Fatalf("acquiring initial owner: %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			errCh := make(chan error, 1)
			go func() {
				_, err := tt.begin(group, ctx, 1000)
				errCh <- err
			}()
			waitForWaiterCount(t, tt.gate(group), 1)
			cancel()

			select {
			case err := <-errCh:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("acquire error = %v, want context.Canceled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for canceled waiter")
			}
			waitForWaiterCount(t, tt.gate(group), 0)
			release()
		})
	}
}

func TestGroupSingleRegistrationFallback(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "higher preference replaces current owner",
			run: func(t *testing.T) {
				group := &Group{}
				group.useSingleRegistration(2, 500)

				release, err := group.beginRegistrationForFlow(context.Background(), 1, 1000)
				if err != nil {
					t.Fatalf("acquiring preferred flow: %v", err)
				}
				release()

				group.mu.Lock()
				owner := group.singleRegistrationID
				preference := group.singleRegistrationPreference
				group.mu.Unlock()
				if owner != 1 || preference != 1000 {
					t.Fatalf("owner = (%d, %d), want (1, 1000)", owner, preference)
				}
			},
		},
		{
			name: "lower preference waits for owner release",
			run: func(t *testing.T) {
				group := &Group{}
				group.useSingleRegistration(1, 1000)

				acquired := make(chan error, 1)
				go func() {
					release, err := group.beginRegistrationForFlow(context.Background(), 2, 500)
					if err == nil {
						release()
					}
					acquired <- err
				}()
				waitForSingleRegistrationWaiter(t, group)

				select {
				case err := <-acquired:
					t.Fatalf("lower-preference flow acquired before release: %v", err)
				default:
				}
				group.releaseSingleRegistration(1)

				select {
				case err := <-acquired:
					if err != nil {
						t.Fatalf("acquiring fallback flow: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("waiting for fallback flow")
				}
				if !group.multipleRegistrationEnabled() {
					t.Fatal("multiple registration capability was not reprobed after owner release")
				}
			},
		},
		{
			name: "waiting flow observes context cancellation",
			run: func(t *testing.T) {
				group := &Group{}
				group.useSingleRegistration(1, 1000)
				ctx, cancel := context.WithCancel(context.Background())
				errCh := make(chan error, 1)
				go func() {
					_, err := group.beginRegistrationForFlow(ctx, 2, 500)
					errCh <- err
				}()
				waitForSingleRegistrationWaiter(t, group)
				cancel()

				select {
				case err := <-errCh:
					if !errors.Is(err, context.Canceled) {
						t.Fatalf("waiting flow error = %v, want context.Canceled", err)
					}
				case <-time.After(time.Second):
					t.Fatal("waiting for canceled flow")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestGroupRevokesLowerPreferenceOwnerBeforeReplacement(t *testing.T) {
	wantErr := errors.New("deregister rejected")
	tests := []struct {
		name      string
		revokeErr error
		wantErr   error
	}{
		{name: "replacement waits for deregistration"},
		{name: "replacement stops when deregistration fails", revokeErr: wantErr, wantErr: wantErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &Group{}
			revoked := false
			group.setSingleRegistrationOwner(2, 500, func(context.Context) error {
				revoked = true
				if tt.revokeErr == nil {
					group.releaseSingleRegistration(2)
				}
				return tt.revokeErr
			})

			release, err := group.beginRegistrationForFlow(context.Background(), 1, 1000)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("beginRegistrationForFlow() error = %v, want %v", err, tt.wantErr)
			}
			if release != nil {
				release()
			}
			if !revoked {
				t.Fatal("old owner was not revoked")
			}

			group.mu.Lock()
			owner := group.singleRegistrationID
			group.mu.Unlock()
			if tt.wantErr == nil && owner != 0 {
				t.Fatalf("owner = %d, want released before replacement", owner)
			}
			if tt.wantErr != nil && owner != 2 {
				t.Fatalf("owner = %d, want original owner 2 after failed revocation", owner)
			}
		})
	}
}

func TestGroupDeregistersOnlySingleRegistrationOwner(t *testing.T) {
	group := &Group{}
	group.useSingleRegistration(1, 1000)
	tests := []struct {
		name           string
		registrationID uint32
		preference     int
		wantSend       bool
	}{
		{name: "owner removes network binding", registrationID: 1, preference: 1000, wantSend: true},
		{name: "replaced flow skips network deregistration", registrationID: 2, preference: 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			release, send, err := group.beginDeregistrationForFlow(context.Background(), tt.registrationID, tt.preference)
			if err != nil {
				t.Fatalf("beginDeregistrationForFlow() error = %v", err)
			}
			defer release()
			if send != tt.wantSend {
				t.Fatalf("beginDeregistrationForFlow() send = %t, want %t", send, tt.wantSend)
			}
		})
	}
}

func waitForSingleRegistrationWaiter(t *testing.T, group *Group) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		group.mu.Lock()
		waiting := group.singleRegistrationOwnerReleased != nil
		group.mu.Unlock()
		if waiting {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("single-registration waiter was not queued")
}

func waitForWaiterCount(t *testing.T, gate *priorityGate, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		gate.mu.Lock()
		got := len(gate.waiters)
		gate.mu.Unlock()
		if got == want {
			return
		}
		runtime.Gosched()
	}
	t.Fatalf("waiter count did not reach %d", want)
}
