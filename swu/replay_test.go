package swu

import (
	"math"
	"testing"
)

func TestReplayWindowAccept(t *testing.T) {
	tests := []struct {
		name      string
		sequences []uint32
		want      []bool
	}{
		{
			name:      "reject zero and duplicate",
			sequences: []uint32{0, 1, 1, 2},
			want:      []bool{false, true, false, true},
		},
		{
			name:      "accept out of order inside window",
			sequences: []uint32{10, 12, 11},
			want:      []bool{true, true, true},
		},
		{
			name:      "reject too old outside window",
			sequences: []uint32{70, 5},
			want:      []bool{true, false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var window replayWindow
			for i, sequence := range tt.sequences {
				if got := window.Accept(sequence); got != tt.want[i] {
					t.Fatalf("Accept(%d) = %t, want %t", sequence, got, tt.want[i])
				}
			}
		})
	}
}

func TestNextESPSequence(t *testing.T) {
	tests := []struct {
		name   string
		start  uint32
		want   uint32
		wantOK bool
	}{
		{name: "increment", start: 0, want: 1, wantOK: true},
		{name: "overflow", start: math.MaxUint32, want: 0, wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sequence := tt.start
			got, ok := nextESPSequence(&sequence)
			if ok != tt.wantOK {
				t.Fatalf("ok = %t, want %t", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Fatalf("got = %d, want %d", got, tt.want)
			}
		})
	}
}
