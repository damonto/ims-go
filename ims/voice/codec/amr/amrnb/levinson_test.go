package amrnb

import "testing"

func TestLevinsonZeroCorrelation(t *testing.T) {
	state := newLevinsonState()
	rh := [lpcCoeffCount]int16{16384}
	rl := [lpcCoeffCount]int16{}
	got, err := state.levinson(rh[:], rl[:])
	if err != nil {
		t.Fatalf("levinson() error = %v", err)
	}

	if got.a[0] != 4096 {
		t.Fatalf("a[0] = %d, want 4096", got.a[0])
	}
	for i := 1; i < lpcCoeffCount; i++ {
		if got.a[i] != 0 {
			t.Fatalf("a[%d] = %d, want 0", i, got.a[i])
		}
	}
	for i, value := range got.rc {
		if value != 0 {
			t.Fatalf("rc[%d] = %d, want 0", i, value)
		}
	}
}

func TestLevinsonRampCorrelation(t *testing.T) {
	state := newLevinsonState()
	input := make([]int16, len(window20040))
	for i := range input {
		input[i] = int16((i % 29) * 41)
	}
	corr, err := autocorrelation(input, window20040[:])
	if err != nil {
		t.Fatalf("autocorrelation() error = %v", err)
	}
	rh, rl := lagWindow(corr.rh, corr.rl)
	got, err := state.levinson(rh[:], rl[:])
	if err != nil {
		t.Fatalf("levinson() error = %v", err)
	}

	wantA := [...]int16{4096, -3917, 13, 14, 15, 9, 13, 4, 7, 13, -49}
	wantRC := [...]int16{-31001, 367, 271, 160}
	for i := range wantA {
		if got.a[i] != wantA[i] {
			t.Fatalf("a[%d] = %d, want %d", i, got.a[i], wantA[i])
		}
	}
	for i := range wantRC {
		if got.rc[i] != wantRC[i] {
			t.Fatalf("rc[%d] = %d, want %d", i, got.rc[i], wantRC[i])
		}
	}
}

func TestLevinsonUnstableFallsBackToOldA(t *testing.T) {
	state := newLevinsonState()
	state.oldA = [lpcCoeffCount]int16{4096, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	rh := [lpcCoeffCount]int16{16384, 16384}
	rl := [lpcCoeffCount]int16{}
	got, err := state.levinson(rh[:], rl[:])
	if err != nil {
		t.Fatalf("levinson() error = %v", err)
	}

	for i := range state.oldA {
		if got.a[i] != state.oldA[i] {
			t.Fatalf("a[%d] = %d, want fallback %d", i, got.a[i], state.oldA[i])
		}
	}
	for i, value := range got.rc {
		if value != 0 {
			t.Fatalf("rc[%d] = %d, want 0 after unstable fallback", i, value)
		}
	}
}

func TestLevinsonRejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name string
		rh   []int16
		rl   []int16
	}{
		{name: "short high words", rh: make([]int16, lpcCoeffCount-1), rl: make([]int16, lpcCoeffCount)},
		{name: "short low words", rh: make([]int16, lpcCoeffCount), rl: make([]int16, lpcCoeffCount-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newLevinsonState()
			before := state

			if _, err := state.levinson(tt.rh, tt.rl); err == nil {
				t.Fatal("levinson() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("levinson() changed state after rejecting input")
			}
		})
	}
}
