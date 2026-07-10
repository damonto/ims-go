package amrnb

import "testing"

func TestConvolveIdentityImpulse(t *testing.T) {
	var x [subframeSamples]int16
	var h [subframeSamples]int16
	h[0] = 4096
	for i := range x {
		x[i] = int16(i*31 - 500)
	}

	y := convolve(x[:], h[:])

	if y != x {
		t.Fatalf("convolve identity = %v, want %v", y, x)
	}
}

func TestConvolveTwoTapImpulse(t *testing.T) {
	var x [subframeSamples]int16
	var h [subframeSamples]int16
	x[0], x[1], x[2] = 1000, 2000, -1000
	h[0], h[1] = 4096, 2048

	y := convolve(x[:], h[:])

	want := [3]int16{1000, 2500, 0}
	for i := range want {
		if y[i] != want[i] {
			t.Fatalf("y[%d] = %d, want %d", i, y[i], want[i])
		}
	}
}

func TestPitchGainUnity(t *testing.T) {
	var xn [subframeSamples]int16
	var y1 [subframeSamples]int16
	for i := range xn {
		xn[i] = int16((i%7)*100 + 200)
		y1[i] = xn[i]
	}

	got, err := pitchGain(Mode590, xn[:], y1[:])
	if err != nil {
		t.Fatalf("pitchGain() error = %v", err)
	}

	if got.gain != 16384 {
		t.Fatalf("pitchGain unity = %d, want 16384", got.gain)
	}
	if got.coeff[0] == 0 || got.coeff[2] == 0 {
		t.Fatalf("gCoeff = %v, want non-zero energy and correlation", got.coeff)
	}
}

func TestPitchGainNegativeCorrelationIsZero(t *testing.T) {
	var xn [subframeSamples]int16
	var y1 [subframeSamples]int16
	for i := range xn {
		xn[i] = 800
		y1[i] = -800
	}

	got, err := pitchGain(Mode590, xn[:], y1[:])
	if err != nil {
		t.Fatalf("pitchGain() error = %v", err)
	}

	if got.gain != 0 {
		t.Fatalf("pitchGain negative correlation = %d, want 0", got.gain)
	}
}

func TestPitchGainSaturatesAtOnePointTwo(t *testing.T) {
	var xn [subframeSamples]int16
	var y1 [subframeSamples]int16
	for i := range xn {
		xn[i] = 4000
		y1[i] = 1000
	}

	got, err := pitchGain(Mode590, xn[:], y1[:])
	if err != nil {
		t.Fatalf("pitchGain() error = %v", err)
	}

	if got.gain != 19661 {
		t.Fatalf("pitchGain saturated = %d, want 19661", got.gain)
	}
}

func TestPitchGainRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		xn   []int16
		y1   []int16
	}{
		{name: "invalid mode", mode: ModeDTX, xn: make([]int16, subframeSamples), y1: make([]int16, subframeSamples)},
		{name: "short target", mode: Mode590, xn: make([]int16, subframeSamples-1), y1: make([]int16, subframeSamples)},
		{name: "short filtered signal", mode: Mode590, xn: make([]int16, subframeSamples), y1: make([]int16, subframeSamples-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := pitchGain(tt.mode, tt.xn, tt.y1); err == nil {
				t.Fatal("pitchGain() error = nil, want invalid input error")
			}
		})
	}
}

func TestApplyKnownPitchUpdatesTargetAndResidual(t *testing.T) {
	exc := make([]int16, len((Encoder{}).oldExc))
	wantExc := make([]int16, len(exc))
	base := encoderExcOffset - 40
	for i := range subframeSamples {
		sample := int16((i%5)*120 + 300)
		exc[base+i] = sample
		wantExc[base+i] = sample
	}
	if err := predictAdaptiveCodebook(wantExc, encoderExcOffset, 40, 0, subframeSamples, true); err != nil {
		t.Fatalf("predictAdaptiveCodebook() error = %v", err)
	}
	var h1 [subframeSamples]int16
	h1[0] = 4096
	var xn [subframeSamples]int16
	var res [subframeSamples]int16
	copy(xn[:], wantExc[encoderExcOffset:encoderExcOffset+subframeSamples])
	copy(res[:], xn[:])

	got, err := applyKnownPitch(knownPitchInput{
		mode:               Mode590,
		excitation:         exc,
		excitationOffset:   encoderExcOffset,
		h1:                 h1[:],
		xn:                 xn[:],
		residual:           res[:],
		t0:                 40,
		t0Frac:             0,
		useThirdResolution: true,
	})

	if err != nil {
		t.Fatalf("applyKnownPitch() error = %v", err)
	}
	if got.gainPit < 16380 || got.gainPit > 16384 {
		t.Fatalf("gainPit = %d, want near 16384", got.gainPit)
	}
	for i := range subframeSamples {
		want := wantExc[encoderExcOffset+i]
		if got.yl[i] != want {
			t.Fatalf("yl[%d] = %d, want %d", i, got.yl[i], want)
		}
		pitchPart := int16((int32(want) * int32(got.gainPit)) >> 14)
		wantResidual := want - pitchPart
		if got.xn2[i] != wantResidual || res[i] != wantResidual {
			t.Fatalf("sample %d xn2/res = %d/%d, want %d", i, got.xn2[i], res[i], wantResidual)
		}
	}
}
