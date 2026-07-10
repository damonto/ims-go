package amrnb

import "testing"

func TestPitchRangeClampsLowerBound(t *testing.T) {
	t0Min, t0Max := pitchRange(21, 5, 10, pitchMin, pitchMax)

	if t0Min != pitchMin || t0Max != 30 {
		t.Fatalf("pitchRange lower = %d/%d, want 20/30", t0Min, t0Max)
	}
}

func TestPitchRangeClampsUpperBound(t *testing.T) {
	t0Min, t0Max := pitchRange(140, 3, 6, pitchMin, pitchMax)

	if t0Min != 137 || t0Max != pitchMax {
		t.Fatalf("pitchRange upper = %d/%d, want 137/%d", t0Min, t0Max, pitchMax)
	}
}

func TestInterpolate3or6TablePoint(t *testing.T) {
	corr := make([]int16, 20)
	corr[10] = 32767

	got := interpolate3or6(corr, 10, 0, false)

	if got != 29518 {
		t.Fatalf("interpolate3or6 table point = %d, want 29518", got)
	}
}

func TestSearchFracNormalizesThirdResolutionLeftEdge(t *testing.T) {
	corr := make([]int16, 20)

	lag, frac := searchFrac(10, -2, -2, corr, true)

	if lag != 9 || frac != 1 {
		t.Fatalf("searchFrac left edge = %d/%d, want 9/1", lag, frac)
	}
}

func TestSearchFracNormalizesThirdResolutionRightEdge(t *testing.T) {
	corr := make([]int16, 20)

	lag, frac := searchFrac(10, 2, 2, corr, true)

	if lag != 11 || frac != -1 {
		t.Fatalf("searchFrac right edge = %d/%d, want 11/-1", lag, frac)
	}
}

func TestSearchFracNormalizesSixthResolutionLeftEdge(t *testing.T) {
	corr := make([]int16, 20)

	lag, frac := searchFrac(10, -3, -3, corr, false)

	if lag != 9 || frac != 3 {
		t.Fatalf("searchFrac sixth left edge = %d/%d, want 9/3", lag, frac)
	}
}

func TestNormCorrPeaksAtMatchingLag(t *testing.T) {
	exc := make([]int16, len((Encoder{}).oldExc))
	offset := encoderExcOffset
	for i := range subframeSamples {
		exc[offset-40+i] = int16((i%11)*173 - 700)
	}
	var xn [subframeSamples]int16
	copy(xn[:], exc[offset-40:offset])
	var h [subframeSamples]int16
	h[0] = 4096
	corr, err := normCorr(normCorrRequest{
		excitation:       exc,
		excitationOffset: offset,
		target:           xn[:],
		impulse:          h[:],
		tMin:             36,
		tMax:             44,
	})
	if err != nil {
		t.Fatalf("normCorr() error = %v", err)
	}

	bestLag := int16(36)
	bestCorr := corr[bestLag]
	for lag := int16(37); lag <= 44; lag++ {
		if corr[lag] >= bestCorr {
			bestLag = lag
			bestCorr = corr[lag]
		}
	}
	if bestLag != 40 {
		t.Fatalf("best lag = %d corr=%d, want 40 corr=%d", bestLag, bestCorr, corr[40])
	}
}

func TestPitchFrFullSearchRoundTrip(t *testing.T) {
	exc := make([]int16, len((Encoder{}).oldExc))
	offset := encoderExcOffset
	for i := range subframeSamples {
		exc[offset-40+i] = int16((i%13)*127 - 500)
	}
	var xn [subframeSamples]int16
	copy(xn[:], exc[offset-40:offset])
	var h [subframeSamples]int16
	h[0] = 4096
	state := pitchFrState{}

	got, err := state.pitch(Mode590, []int16{40, 40}, exc, offset, xn[:], h[:], 0)
	if err != nil {
		t.Fatalf("pitch() error = %v", err)
	}

	if got.t0 != 40 || got.t0Frac != 0 || !got.useThirdResolution {
		t.Fatalf("pitch = %d/%d third=%v, want 40/0 true", got.t0, got.t0Frac, got.useThirdResolution)
	}
	t0, frac := decodeLag3(got.index, 0, 0, 0, 0, false)
	if t0 != got.t0 || frac != got.t0Frac {
		t.Fatalf("decoded index %d = %d/%d, want %d/%d", got.index, t0, frac, got.t0, got.t0Frac)
	}
	if state.prevT0 != got.t0 {
		t.Fatalf("prevT0 = %d, want %d", state.prevT0, got.t0)
	}
}

func TestNormCorrRejectsInvalidInput(t *testing.T) {
	validExcitation := make([]int16, len((Encoder{}).oldExc))
	validTarget := make([]int16, subframeSamples)
	validImpulse := make([]int16, subframeSamples)
	tests := []struct {
		name string
		req  normCorrRequest
	}{
		{
			name: "short target",
			req: normCorrRequest{
				excitation:       validExcitation,
				excitationOffset: encoderExcOffset,
				target:           make([]int16, subframeSamples-1),
				impulse:          validImpulse,
				tMin:             36,
				tMax:             44,
			},
		},
		{
			name: "reversed lag range",
			req: normCorrRequest{
				excitation:       validExcitation,
				excitationOffset: encoderExcOffset,
				target:           validTarget,
				impulse:          validImpulse,
				tMin:             44,
				tMax:             36,
			},
		},
		{
			name: "missing excitation history",
			req: normCorrRequest{
				excitation:       validExcitation,
				excitationOffset: 20,
				target:           validTarget,
				impulse:          validImpulse,
				tMin:             18,
				tMax:             30,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := normCorr(tt.req); err == nil {
				t.Fatal("normCorr() error = nil, want invalid input error")
			}
		})
	}
}

func TestPitchFrRejectsInvalidInputWithoutChangingState(t *testing.T) {
	validExcitation := make([]int16, len((Encoder{}).oldExc))
	validTarget := make([]int16, subframeSamples)
	validImpulse := make([]int16, subframeSamples)
	validLags := []int16{40, 40}
	tests := []struct {
		name           string
		mode           Mode
		tOp            []int16
		excitation     []int16
		target         []int16
		impulse        []int16
		subframeOffset int16
	}{
		{
			name: "invalid mode", mode: ModeDTX, tOp: validLags, excitation: validExcitation,
			target: validTarget, impulse: validImpulse,
		},
		{
			name: "short open-loop lags", mode: Mode590, tOp: []int16{40}, excitation: validExcitation,
			target: validTarget, impulse: validImpulse,
		},
		{
			name: "invalid subframe offset", mode: Mode590, tOp: validLags, excitation: validExcitation,
			target: validTarget, impulse: validImpulse, subframeOffset: 1,
		},
		{
			name: "short target", mode: Mode590, tOp: validLags, excitation: validExcitation,
			target: validTarget[:subframeSamples-1], impulse: validImpulse,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := pitchFrState{prevT0: 40}
			before := state

			_, err := state.pitch(
				tt.mode,
				tt.tOp,
				tt.excitation,
				encoderExcOffset,
				tt.target,
				tt.impulse,
				tt.subframeOffset,
			)
			if err == nil {
				t.Fatal("pitch() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("pitch() changed state after rejecting input")
			}
		})
	}
}
