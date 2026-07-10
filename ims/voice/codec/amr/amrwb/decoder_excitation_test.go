package amrwb

import "testing"

func TestPreemphasisLeavesFirstSample(t *testing.T) {
	signal := []int16{1000, 2000, -1000, 500}

	preemphasis(signal, 16384)

	want := []int16{1000, 1500, -2000, 1000}
	for i := range want {
		if signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d", i, signal[i], want[i])
		}
	}
}

func TestSharpenPitchAddsDelayedContribution(t *testing.T) {
	signal := []int16{1000, 2000, 3000, 4000}

	sharpenPitch(signal, 2, 16384)

	want := []int16{1000, 2000, 3500, 5000}
	for i := range want {
		if signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d", i, signal[i], want[i])
		}
	}
}

func TestNextNoiseKnownSequence(t *testing.T) {
	seed := int16(randomInitialSeed)

	first := nextNoise(seed)
	second := nextNoise(first)

	if first != 3242 {
		t.Fatalf("first = %d, want 3242", first)
	}
	if second != 23867 {
		t.Fatalf("second = %d, want 23867", second)
	}
}
