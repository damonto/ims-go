package amrwb

import "testing"

func TestNearestHFGainIndex(t *testing.T) {
	for i, gain := range hpGain {
		if got := nearestHFGainIndex(gain); got != int16(i) {
			t.Fatalf("nearestHFGainIndex(%d) = %d, want %d", gain, got, i)
		}
		if got := nearestHFGainIndexSquared(gain); got != int16(i) {
			t.Fatalf("nearestHFGainIndexSquared(%d) = %d, want %d", gain, got, i)
		}
	}
}

func TestHighBandCorrectionIndexRange(t *testing.T) {
	var state encoderHighBandState
	state.reset()

	var aq [lpcCoeffCount]int16
	aq[0] = 4096
	var exc [subframeSamples]int16
	for i := range exc {
		exc[i] = int16(64 + i)
	}
	var speech [subframeSamples16k]int16
	for i := range speech {
		speech[i] = int16(i * 32)
	}

	got, err := state.correctionIndex(aq[:], exc[:], 0, speech[:], encoderDTXHangConst)
	if err != nil {
		t.Fatalf("correctionIndex() error = %v", err)
	}
	if got < 0 || got >= 16 {
		t.Fatalf("correctionIndex = %d outside 4 bits", got)
	}
}

func TestHighBandCorrectionParameterIndex(t *testing.T) {
	if got := highBandCorrectionParameterIndex(Mode2385, 18); got != 19 {
		t.Fatalf("Mode2385 HF parameter index = %d, want 19", got)
	}
	if got := highBandCorrectionParameterIndex(Mode2305, 18); got != -1 {
		t.Fatalf("Mode2305 HF parameter index = %d, want -1", got)
	}
}
