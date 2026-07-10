package amrwb

import "testing"

func TestPredictAdaptiveCodebookConstantHistory(t *testing.T) {
	const offset = pitchMax + interpolationLen
	excitation := make([]int16, offset+subframeSamples)
	for i := range excitation[:offset] {
		excitation[i] = 1000
	}

	predictAdaptiveCodebook(excitation, offset, 64, 0, subframeSamples)

	for i, got := range excitation[offset : offset+subframeSamples] {
		if got < 990 || got > 1010 {
			t.Fatalf("excitation[%d] = %d, want close to 1000", i, got)
		}
	}
}

func TestPredictAdaptiveCodebookFractionChangesOutput(t *testing.T) {
	const offset = pitchMax + interpolationLen
	excitation0 := make([]int16, offset+subframeSamples)
	excitation1 := make([]int16, offset+subframeSamples)
	for i := range excitation0[:offset] {
		value := int16((i % 17) * 100)
		excitation0[i] = value
		excitation1[i] = value
	}

	predictAdaptiveCodebook(excitation0, offset, 64, 0, subframeSamples)
	predictAdaptiveCodebook(excitation1, offset, 64, 1, subframeSamples)

	if excitation0[offset] == excitation1[offset] &&
		excitation0[offset+1] == excitation1[offset+1] {
		t.Fatal("fractional lag did not change predicted excitation")
	}
}
