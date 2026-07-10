package amrwb

import "testing"

func TestPreemphasis2DoublesWithZeroTilt(t *testing.T) {
	x := []int16{100, -200, 300}
	var mem int16

	mem = preemphasis2(x, 0, mem)

	want := []int16{200, -400, 600}
	for i, got := range x {
		if got != want[i] {
			t.Fatalf("x[%d] = %d, want %d", i, got, want[i])
		}
	}
	if mem != 300 {
		t.Fatalf("mem = %d, want 300", mem)
	}
}

func TestInnovationSearchTargetCopiesResidualSecondHalf(t *testing.T) {
	aq := make([]int16, lpcCoeffCount)
	aq[0] = 4096
	weightedA := make([]int16, lpcCoeffCount)
	weightedA[0] = 4096
	target := make([]int16, subframeSamples)
	residual := make([]int16, subframeSamples)
	for i := range target {
		target[i] = int16((i%13 - 6) * 100)
		residual[i] = int16(i + 1)
	}
	cn, err := innovationSearchTarget(aq, weightedA, target, residual)
	if err != nil {
		t.Fatalf("innovationSearchTarget() error = %v", err)
	}
	for i := subframeSamples / 2; i < subframeSamples; i++ {
		if cn[i] != residual[i] {
			t.Fatalf("cn[%d] = %d, want residual %d", i, cn[i], residual[i])
		}
	}
	if allZeroSamples(cn[:subframeSamples/2]) {
		t.Fatal("first-half innovation target is all zero")
	}
}
