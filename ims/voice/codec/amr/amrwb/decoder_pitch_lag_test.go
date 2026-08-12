package amrwb

import "testing"

func TestDecodePitchLag8BitFirstSubframe(t *testing.T) {
	t0, frac, state := decodePitchLag(0, nBits660, 0, pitchLagState{})

	if t0 != pitchMin || frac != 0 {
		t.Fatalf("lag = %d frac %d, want %d/0", t0, frac, pitchMin)
	}
	if state.t0Min != pitchMin || state.t0Max != pitchMin+15 {
		t.Fatalf("range = %d..%d, want %d..%d", state.t0Min, state.t0Max, pitchMin, pitchMin+15)
	}
}

func TestDecodePitchLag8BitIntegerRegion(t *testing.T) {
	index := int16((pitchFrac1At8Bits-pitchMin)*2 + 3)

	t0, frac, _ := decodePitchLag(index, nBits660, 0, pitchLagState{})

	if t0 != pitchFrac1At8Bits+3 || frac != 0 {
		t.Fatalf("lag = %d frac %d, want %d/0", t0, frac, pitchFrac1At8Bits+3)
	}
}

func TestDecodePitchLag9BitFirstSubframeRegions(t *testing.T) {
	t0, frac, _ := decodePitchLag(1, nBits1265, 0, pitchLagState{})
	if t0 != pitchMin || frac != 1 {
		t.Fatalf("quarter region lag = %d frac %d, want %d/1", t0, frac, pitchMin)
	}

	index := int16(((pitchFrac2 - pitchMin) << 2) + 3)
	t0, frac, _ = decodePitchLag(index, nBits1265, 0, pitchLagState{})
	if t0 != pitchFrac2+1 || frac != 2 {
		t.Fatalf("half region lag = %d frac %d, want %d/2", t0, frac, pitchFrac2+1)
	}
}

func TestDecodePitchLagDeltaSubframe(t *testing.T) {
	state := pitchLagState{t0Min: 50, t0Max: 65}

	t0, frac, _ := decodePitchLag(5, nBits1265, 1, state)

	if t0 != 51 || frac != 1 {
		t.Fatalf("lag = %d frac %d, want 51/1", t0, frac)
	}
}
