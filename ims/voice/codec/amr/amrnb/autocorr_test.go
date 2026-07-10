package amrnb

import "testing"

func TestAutocorrelationZeroInput(t *testing.T) {
	input := make([]int16, len(window20040))

	got, err := autocorrelation(input, window20040[:])
	if err != nil {
		t.Fatalf("autocorrelation() error = %v", err)
	}

	if got.norm != 30 {
		t.Fatalf("norm = %d, want 30", got.norm)
	}
	if got.rh[0] != 0x4000 || got.rl[0] != 0 {
		t.Fatalf("r[0] = %d/%d, want 16384/0", got.rh[0], got.rl[0])
	}
	for i := 1; i <= lpcOrder; i++ {
		if got.rh[i] != 0 || got.rl[i] != 0 {
			t.Fatalf("r[%d] = %d/%d, want 0/0", i, got.rh[i], got.rl[i])
		}
	}
}

func TestAutocorrelationImpulse(t *testing.T) {
	input := make([]int16, len(window20040))
	input[0] = 3000

	got, err := autocorrelation(input, window20040[:])
	if err != nil {
		t.Fatalf("autocorrelation() error = %v", err)
	}

	if got.norm != 14 {
		t.Fatalf("norm = %d, want 14", got.norm)
	}
	wantH := [...]int16{28800, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	wantL := [...]int16{8192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 0; i <= lpcOrder; i++ {
		if got.rh[i] != wantH[i] || got.rl[i] != wantL[i] {
			t.Fatalf("r[%d] = %d/%d, want %d/%d", i, got.rh[i], got.rl[i], wantH[i], wantL[i])
		}
	}
}

func TestAutocorrelationRampIsSymmetricLagPositive(t *testing.T) {
	input := make([]int16, len(window20040))
	for i := range input {
		input[i] = int16((i % 31) * 37)
	}

	got, err := autocorrelation(input, window20040[:])
	if err != nil {
		t.Fatalf("autocorrelation() error = %v", err)
	}

	if got.norm <= 0 {
		t.Fatalf("norm = %d, want positive normalization", got.norm)
	}
	if got.rh[0] <= 0 {
		t.Fatalf("r[0].hi = %d, want positive energy", got.rh[0])
	}
	for i := 1; i <= lpcOrder; i++ {
		if got.rh[i] < 0 {
			t.Fatalf("r[%d].hi = %d, want non-negative for positive ramp", i, got.rh[i])
		}
	}
}

func TestAutocorrelationRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		input  []int16
		window []int16
	}{
		{name: "empty window", input: []int16{1}, window: nil},
		{name: "short input", input: make([]int16, len(window20040)-1), window: window20040[:]},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := autocorrelation(tt.input, tt.window); err == nil {
				t.Fatal("autocorrelation() error = nil, want invalid input error")
			}
		})
	}
}
