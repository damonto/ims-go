package amrnb

import "testing"

func TestAzToLSPRoundTripFromKnownLSP(t *testing.T) {
	source := [lpcOrder]int16{
		30000, 25000, 20000, 15000, 10000,
		5000, 0, -5000, -10000, -15000,
	}
	a := lspToAz(source[:])

	got, err := azToLSP(a[:], make([]int16, lpcOrder))
	if err != nil {
		t.Fatalf("azToLSP() error = %v", err)
	}

	for i := range source {
		delta := got[i] - source[i]
		if delta < 0 {
			delta = -delta
		}
		if delta > 900 {
			t.Fatalf("lsp[%d] = %d, want near %d", i, got[i], source[i])
		}
	}
}

func TestAzToLSPFallbackWhenRootsMissing(t *testing.T) {
	old := [lpcOrder]int16{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	a := [lpcCoeffCount]int16{
		4096, -4096, -4096, -4096, -4096, -4096,
		-4096, -4096, -4096, -4096, -4096,
	}
	got, err := azToLSP(a[:], old[:])
	if err != nil {
		t.Fatalf("azToLSP() error = %v", err)
	}

	if got != old {
		t.Fatalf("fallback LSP = %v, want %v", got, old)
	}
}

func TestAzToLSPRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		a    []int16
		old  []int16
	}{
		{name: "short LPC", a: make([]int16, lpcCoeffCount-1), old: make([]int16, lpcOrder)},
		{name: "short old LSP", a: make([]int16, lpcCoeffCount), old: make([]int16, lpcOrder-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := azToLSP(tt.a, tt.old); err == nil {
				t.Fatal("azToLSP() error = nil, want invalid input error")
			}
		})
	}
}
