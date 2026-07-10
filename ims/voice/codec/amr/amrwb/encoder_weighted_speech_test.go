package amrwb

import (
	"slices"
	"testing"
)

func TestEncoderResidualIdentityDoublesSignal(t *testing.T) {
	a := make([]int16, lpcCoeffCount)
	a[0] = 4096
	x := make([]int16, lpcOrder+4)
	for i := lpcOrder; i < len(x); i++ {
		x[i] = int16((i - lpcOrder + 1) * 100)
	}
	y := make([]int16, 4)

	if err := encoderResidual(a, x, y); err != nil {
		t.Fatalf("encoderResidual() error = %v", err)
	}
	for i, got := range y {
		want := int16((i + 1) * 200)
		if got != want {
			t.Fatalf("y[%d] = %d, want %d", i, got, want)
		}
	}
}

func TestEncoderResidualRejectsShortBuffers(t *testing.T) {
	tests := []struct {
		name string
		a    []int16
		x    []int16
		y    []int16
	}{
		{
			name: "LPC coefficients",
			a:    make([]int16, lpcCoeffCount-1),
			x:    make([]int16, lpcOrder+1),
			y:    []int16{123},
		},
		{
			name: "speech history",
			a:    make([]int16, lpcCoeffCount),
			x:    make([]int16, lpcOrder),
			y:    []int16{123},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := slices.Clone(tt.y)

			if err := encoderResidual(tt.a, tt.x, tt.y); err == nil {
				t.Fatal("encoderResidual() error = nil")
			}
			if !slices.Equal(tt.y, before) {
				t.Fatalf("output = %v, want unchanged %v", tt.y, before)
			}
		})
	}
}

func TestDeemphasis2DividesByTwoWithZeroTilt(t *testing.T) {
	x := []int16{100, -200, 300}
	var mem int16

	mem = deemphasis2(x, 0, mem)

	want := []int16{50, -100, 150}
	for i, got := range x {
		if got != want[i] {
			t.Fatalf("x[%d] = %d, want %d", i, got, want[i])
		}
	}
	if mem != 150 {
		t.Fatalf("mem = %d, want 150", mem)
	}
}

func TestScaleSignalRound(t *testing.T) {
	x := []int16{101, -101}

	scaleSignalRound(x, -1)

	if x[0] != 51 || x[1] != -50 {
		t.Fatalf("scale -1 = %v, want rounded half [51 -50]", x)
	}
	scaleSignalRound(x, 1)
	if x[0] != 102 || x[1] != -100 {
		t.Fatalf("scale +1 = %v, want [102 -100]", x)
	}
}

func TestDecimateWeightedSpeechBy2(t *testing.T) {
	var x [frameSamples12k8]int16
	copy(x[:], []int16{100, 200, 300, 400, 500, 600})
	copy(x[frameSamples12k8-3:], []int16{400, 500, 600})
	memory := [3]int16{-300, -200, -100}

	got := decimateWeightedSpeechBy2(x, memory)
	if got.signal[0] == 0 && got.signal[1] == 0 && got.signal[2] == 0 {
		t.Fatalf("decimated prefix = %v, want non-zero samples", got.signal[:3])
	}
	wantMem := []int16{400, 500, 600}
	for i, value := range got.memory {
		if value != wantMem[i] {
			t.Fatalf("memory[%d] = %d, want %d", i, value, wantMem[i])
		}
	}
}

func TestBuildWeightedSpeechFromLPCAnalysis(t *testing.T) {
	enc := newPreparedEncoder(t, Mode885)
	params := make([]int16, mustParameterCount(t, Mode885))
	lpc, _, err := enc.encodeLPCParameters(params)
	if err != nil {
		t.Fatalf("encodeLPCParameters() error = %v", err)
	}

	got, err := enc.buildWeightedSpeech(lpc.a[:])

	if err != nil {
		t.Fatalf("buildWeightedSpeech() error = %v", err)
	}
	nonZero := false
	for _, sample := range got.wsp {
		if sample != 0 {
			nonZero = true
			break
		}
	}
	if !nonZero {
		t.Fatal("weighted speech is all zero")
	}
	if enc.oldWspShift != got.shift {
		t.Fatalf("oldWspShift = %d, want %d", enc.oldWspShift, got.shift)
	}
}
