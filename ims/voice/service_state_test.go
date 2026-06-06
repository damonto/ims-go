package voice

import (
	"testing"
)

func TestCallStateTransitions(t *testing.T) {
	tests := []struct {
		name string
		from CallState
		to   CallState
		want bool
	}{
		{name: "new call may enter dialing", to: CallStateDialing, want: true},
		{name: "dialing can ring", from: CallStateDialing, to: CallStateRinging, want: true},
		{name: "dialing can enter early media", from: CallStateDialing, to: CallStateEarlyMedia, want: true},
		{name: "ringing can answer", from: CallStateRinging, to: CallStateAnswering, want: true},
		{name: "ringing can be confirmed after reliable provisional", from: CallStateRinging, to: CallStateConfirmed, want: true},
		{name: "answering becomes active", from: CallStateAnswering, to: CallStateActive, want: true},
		{name: "confirmed can become active", from: CallStateConfirmed, to: CallStateActive, want: true},
		{name: "active can end", from: CallStateActive, to: CallStateEnding, want: true},
		{name: "any non terminal can fail", from: CallStateRinging, to: CallStateFailed, want: true},
		{name: "ended cannot become active", from: CallStateEnded, to: CallStateActive},
		{name: "failed cannot become ringing", from: CallStateFailed, to: CallStateRinging},
		{name: "ending cannot go active", from: CallStateEnding, to: CallStateActive},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := callCanTransition(tt.from, tt.to); got != tt.want {
				t.Fatalf("callCanTransition(%q, %q) = %t, want %t", tt.from, tt.to, got, tt.want)
			}
		})
	}
}
