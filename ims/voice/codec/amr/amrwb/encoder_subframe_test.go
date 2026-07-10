package amrwb

import "testing"

func TestEncoderSynthesisFilterIdentityHalvesInput(t *testing.T) {
	a := make([]int16, lpcCoeffCount)
	a[0] = 4096
	x := make([]int16, subframeSamples)
	for i := range x {
		x[i] = int16((i%4 + 1) * 100)
		if i%2 == 1 {
			x[i] = -x[i]
		}
	}
	mem := make([]int16, lpcOrder)

	got, err := encoderSynthesisFilter(a, x, mem, subframeSamples)
	if err != nil {
		t.Fatalf("encoderSynthesisFilter() error = %v", err)
	}
	for i, sample := range got.signal {
		want := x[i] / 2
		if sample != want {
			t.Fatalf("signal[%d] = %d, want %d", i, sample, want)
		}
	}
	if got.memory[lpcOrder-1] != got.signal[len(got.signal)-1] {
		t.Fatalf("memory tail = %d, want %d", got.memory[lpcOrder-1], got.signal[len(got.signal)-1])
	}
}

func TestUpdateTargetSubtractsPitchContribution(t *testing.T) {
	x := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)
	for i := range x {
		x[i] = 1000
		y[i] = 1000
	}

	x2, err := updateTarget(x, y, 8192)
	if err != nil {
		t.Fatalf("updateTarget() error = %v", err)
	}
	if x2[0] != 500 {
		t.Fatalf("x2[0] = %d, want 500", x2[0])
	}
}

func TestImpulseResponseProducesNonZeroResponse(t *testing.T) {
	a := make([]int16, lpcCoeffCount)
	aq := make([]int16, lpcCoeffCount)
	a[0] = 4096
	aq[0] = 4096

	h1, err := impulseResponse(a, aq)
	if err != nil {
		t.Fatalf("impulseResponse() error = %v", err)
	}
	if h1[0] == 0 {
		t.Fatal("h1[0] = 0, want non-zero weighted synthesis response")
	}
}

func TestSubframePrimitivesRejectShortBuffersWithoutWrites(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "update target",
			run: func(t *testing.T) {
				got, err := updateTarget(make([]int16, subframeSamples-1), make([]int16, subframeSamples), 0)
				if err == nil {
					t.Fatal("updateTarget() error = nil")
				}
				if got != ([subframeSamples]int16{}) {
					t.Fatalf("result = %v, want zero value", got)
				}
			},
		},
		{
			name: "synthesis filter",
			run: func(t *testing.T) {
				memory := make([]int16, lpcOrder)
				got, err := encoderSynthesisFilter(make([]int16, lpcCoeffCount-1), make([]int16, subframeSamples), memory, subframeSamples)
				if err == nil {
					t.Fatal("encoderSynthesisFilter() error = nil")
				}
				if got != (encoderSynthesisResult{}) {
					t.Fatalf("result = %v, want zero value", got)
				}
			},
		},
		{
			name: "impulse response",
			run: func(t *testing.T) {
				got, err := impulseResponse(make([]int16, lpcCoeffCount-1), make([]int16, lpcCoeffCount))
				if err == nil {
					t.Fatal("impulseResponse() error = nil")
				}
				if got != ([subframeSamples]int16{}) {
					t.Fatalf("result = %v, want zero value", got)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestPitchSearchRangeClampsToCodecBounds(t *testing.T) {
	low := pitchSearchRange(20)
	if low.t0Min != pitchMin || low.t0Max != pitchMin+15 {
		t.Fatalf("low range = %+v, want %d..%d", low, pitchMin, pitchMin+15)
	}
	high := pitchSearchRange(240)
	if high.t0Max != pitchMax || high.t0Min != pitchMax-15 {
		t.Fatalf("high range = %+v, want %d..%d", high, pitchMax-15, pitchMax)
	}
}
