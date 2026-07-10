package amrwb

import "testing"

func TestPitchGainUnity(t *testing.T) {
	xn := make([]int16, subframeSamples)
	y1 := make([]int16, subframeSamples)
	for i := range xn {
		xn[i] = int16((i%9 - 4) * 128)
		y1[i] = xn[i]
	}
	got, err := pitchGain(xn, y1)
	if err != nil {
		t.Fatalf("pitchGain() error = %v", err)
	}

	if got.gain < 16380 || got.gain > 16388 {
		t.Fatalf("pitchGain(unity) = %d, want near 16384", got.gain)
	}
	if got.coeff[0] == 0 || got.coeff[2] == 0 {
		t.Fatalf("coeff = %v, want populated correlations", got.coeff)
	}
}

func TestPitchGainNegativeCorrelation(t *testing.T) {
	xn := make([]int16, subframeSamples)
	y1 := make([]int16, subframeSamples)
	for i := range xn {
		xn[i] = 1000
		y1[i] = -1000
	}
	got, err := pitchGain(xn, y1)
	if err != nil {
		t.Fatalf("pitchGain() error = %v", err)
	}

	if got.gain != 0 {
		t.Fatalf("pitchGain(negative) = %d, want 0", got.gain)
	}
}

func TestPitchGainSaturatesAtOnePointTwo(t *testing.T) {
	xn := make([]int16, subframeSamples)
	y1 := make([]int16, subframeSamples)
	for i := range xn {
		xn[i] = 3000
		y1[i] = 1000
	}
	got, err := pitchGain(xn, y1)
	if err != nil {
		t.Fatalf("pitchGain() error = %v", err)
	}

	if got.gain != 19661 {
		t.Fatalf("pitchGain(saturated) = %d, want 19661", got.gain)
	}
}
