package amrnb

import "testing"

func TestAReflZeroCoefficients(t *testing.T) {
	refl := reflectionCoefficients(make([]int16, lpcOrder))

	for i, got := range refl {
		if got != 0 {
			t.Fatalf("refl[%d] = %d, want 0", i, got)
		}
	}
}

func TestAReflSingleStableCoefficient(t *testing.T) {
	a := make([]int16, lpcOrder)
	a[0] = 1000
	refl := reflectionCoefficients(a)

	if refl[0] != 8000 {
		t.Fatalf("refl[0] = %d, want 8000", refl[0])
	}
	for i := 1; i < lpcOrder; i++ {
		if refl[i] != 0 {
			t.Fatalf("refl[%d] = %d, want 0", i, refl[i])
		}
	}
}

func TestAReflUnstableCoefficientsZeroOutput(t *testing.T) {
	a := make([]int16, lpcOrder)
	a[lpcOrder-1] = 4096
	refl := reflectionCoefficients(a)

	for i, got := range refl {
		if got != 0 {
			t.Fatalf("refl[%d] = %d, want reset 0", i, got)
		}
	}
}
