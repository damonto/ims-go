package amrwb

import "testing"

func TestConvolveImpulseResponse(t *testing.T) {
	var x [subframeSamples]int16
	copy(x[:], []int16{100, -200, 300, -400})
	var h [subframeSamples]int16
	h[0] = 32767

	y, err := convolve(x[:], h[:])
	if err != nil {
		t.Fatalf("convolve() error = %v", err)
	}
	for i, got := range y[:4] {
		if got != x[i] {
			t.Fatalf("y[%d] = %d, want %d", i, got, x[i])
		}
	}
}

func TestInterpolatePitchCorrelationIntegerPoint(t *testing.T) {
	corr := []int16{0, 0, 1000, 2000, 3000, 4000, 3000, 2000, 1000, 0, 0}

	got, err := interpolatePitchCorrelation(corr, 5, 0)
	if err != nil {
		t.Fatalf("interpolatePitchCorrelation() error = %v", err)
	}

	if got <= 0 {
		t.Fatalf("interpolatePitchCorrelation() = %d, want positive peak", got)
	}
}

func TestPitchFR4FindsSyntheticLag(t *testing.T) {
	const (
		offset = pitchMax + interpolationLen
		period = 50
	)
	excitation := make([]int16, offset+subframeSamples)
	pattern := make([]int16, period)
	for i := range pattern {
		pattern[i] = int16((i%11 - 5) * 512)
	}
	for i := range excitation {
		excitation[i] = pattern[i%period]
	}
	xn := make([]int16, subframeSamples)
	copy(xn, excitation[offset-period:offset-period+subframeSamples])
	h := make([]int16, subframeSamples)
	h[0] = 32767

	t0, frac, err := pitchFR4(
		excitation,
		offset,
		xn,
		h,
		period-8,
		period+8,
		0,
		pitchMin,
		pitchFrac1_9b,
	)

	if err != nil {
		t.Fatalf("pitchFR4() error = %v", err)
	}
	if t0 != period || frac != 0 {
		t.Fatalf("pitchFR4() = %d/%d, want %d/0", t0, frac, period)
	}
}

func TestNormalizedPitchCorrelationRejectsShortExcitation(t *testing.T) {
	xn := make([]int16, subframeSamples)
	h := make([]int16, subframeSamples)
	corr := make([]int16, 1)

	if err := normalizedPitchCorrelation(nil, 0, xn, h, 34, 34, corr); err == nil {
		t.Fatal("normalizedPitchCorrelation(short) error = nil")
	}
}
