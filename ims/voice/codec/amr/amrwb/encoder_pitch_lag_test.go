package amrwb

import "testing"

func TestEncodePitchLag8BitFirstSubframeRoundTrip(t *testing.T) {
	index, state := encodePitchLag(60, 2, nBits660, 0, pitchLagState{})
	t0, frac, decodedState := decodePitchLag(index, nBits660, 0, pitchLagState{})

	if t0 != 60 || frac != 2 {
		t.Fatalf("decoded lag = %d/%d, want 60/2", t0, frac)
	}
	if decodedState != state {
		t.Fatalf("decoded state = %+v, encoded state %+v", decodedState, state)
	}
}

func TestEncodePitchLag9BitFirstSubframeRoundTrip(t *testing.T) {
	tests := []struct {
		t0   int16
		frac int16
	}{
		{t0: 70, frac: 3},
		{t0: 140, frac: 2},
		{t0: 180, frac: 0},
	}
	for _, tt := range tests {
		index, state := encodePitchLag(tt.t0, tt.frac, nBits1265, 0, pitchLagState{})
		t0, frac, decodedState := decodePitchLag(index, nBits1265, 0, pitchLagState{})
		if t0 != tt.t0 || frac != tt.frac {
			t.Fatalf("decoded lag = %d/%d, want %d/%d", t0, frac, tt.t0, tt.frac)
		}
		if decodedState != state {
			t.Fatalf("decoded state = %+v, encoded state %+v", decodedState, state)
		}
	}
}

func TestEncodePitchLagDeltaRoundTrip(t *testing.T) {
	state := pitchLagState{t0Min: 52, t0Max: 67}

	index, next := encodePitchLag(57, 2, nBits660, 1, state)
	t0, frac, decodedState := decodePitchLag(index, nBits660, 1, state)
	if t0 != 57 || frac != 2 {
		t.Fatalf("8-bit delta decoded lag = %d/%d, want 57/2", t0, frac)
	}
	if decodedState != next {
		t.Fatalf("8-bit delta state = %+v, want %+v", decodedState, next)
	}

	index, next = encodePitchLag(61, 3, nBits1265, 1, state)
	t0, frac, decodedState = decodePitchLag(index, nBits1265, 1, state)
	if t0 != 61 || frac != 3 {
		t.Fatalf("9-bit delta decoded lag = %d/%d, want 61/3", t0, frac)
	}
	if decodedState != next {
		t.Fatalf("9-bit delta state = %+v, want %+v", decodedState, next)
	}
}
