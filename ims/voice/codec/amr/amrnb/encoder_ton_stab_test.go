package amrnb

import "testing"

func TestToneStabilityRejectsShortLSPWithoutChangingState(t *testing.T) {
	tests := []struct {
		name string
		lsp  []int16
	}{
		{name: "nil", lsp: nil},
		{name: "short", lsp: make([]int16, lpcOrder-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := tonStabState{count: 3}
			before := state

			if _, err := state.checkLSP(tt.lsp); err == nil {
				t.Fatal("checkLSP() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("checkLSP() changed tone state after rejecting input")
			}
		})
	}
}
