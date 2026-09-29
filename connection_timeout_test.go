package ims

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestSetupContextBoundsRegistrationWait(t *testing.T) {
	tests := []struct {
		name        string
		internal    bool
		parentLimit time.Duration
		want        time.Duration
	}{
		{name: "initial connect", want: initialConnectTimeout},
		{name: "automatic reconnect", internal: true, want: reconnectAttemptTimeout},
		{name: "caller deadline takes precedence", parentLimit: time.Second, want: time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				client := newStandaloneClient(t)
				parent := t.Context()
				if tt.parentLimit != 0 {
					var cancel context.CancelFunc
					parent, cancel = context.WithTimeout(parent, tt.parentLimit)
					defer cancel()
				}
				ctx, stop := client.newSetupContext(parent, tt.internal)
				defer stop()
				group := NewRegistrationGroup()
				release, err := group.BeginRegistration(t.Context(), 0)
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				started := time.Now()
				if _, err := group.BeginRegistration(ctx, 0); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("registration wait = %v, want deadline exceeded", err)
				}
				if elapsed := time.Since(started); elapsed != tt.want {
					t.Fatalf("registration wait = %v, want %v", elapsed, tt.want)
				}
			})
		})
	}
}
