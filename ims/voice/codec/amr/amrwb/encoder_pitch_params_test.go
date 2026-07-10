package amrwb

import "testing"

func TestEncodeSubframePitchLagWidths(t *testing.T) {
	state := initialPitchLagState(70)

	first := encodeSubframePitchLag(Mode885, 0, 90, 70, 0, state)
	second := encodeSubframePitchLag(Mode885, 1, 90, 72, 2, first.state)
	third := encodeSubframePitchLag(Mode1265, 2, 100, 100, 0, second.state)
	fourth := encodeSubframePitchLag(Mode1265, 3, 100, 102, 3, third.state)

	if first.width != 8 || second.width != 5 {
		t.Fatalf("Mode885 pitch widths = %d/%d, want 8/5", first.width, second.width)
	}
	if third.width != 9 || fourth.width != 6 {
		t.Fatalf("Mode1265 pitch widths = %d/%d, want 9/6", third.width, fourth.width)
	}
	if third.pitFlag != 0 {
		t.Fatalf("third subframe pitFlag = %d, want reset flag 0", third.pitFlag)
	}
}

func TestEncodeSubframePitchLagRoundTrip(t *testing.T) {
	state := initialPitchLagState(80)
	first := encodeSubframePitchLag(Mode1265, 0, 100, 80, 0, state)
	t0, frac, decodedState := decodePitchLag(first.index, nBits1265, first.pitFlag, state)
	if t0 != 80 || frac != 0 {
		t.Fatalf("first decoded lag = %d/%d, want 80/0", t0, frac)
	}
	if decodedState != first.state {
		t.Fatalf("first decoded state = %+v, want %+v", decodedState, first.state)
	}

	second := encodeSubframePitchLag(Mode1265, 1, 100, 82, 3, first.state)
	t0, frac, decodedState = decodePitchLag(second.index, nBits1265, second.pitFlag, first.state)
	if t0 != 82 || frac != 3 {
		t.Fatalf("second decoded lag = %d/%d, want 82/3", t0, frac)
	}
	if decodedState != second.state {
		t.Fatalf("second decoded state = %+v, want %+v", decodedState, second.state)
	}

	third := encodeSubframePitchLag(Mode1265, 2, 110, 110, 0, second.state)
	resetState := pitchSearchRange(110)
	t0, frac, decodedState = decodePitchLag(third.index, nBits1265, third.pitFlag, resetState)
	if t0 != 110 || frac != 0 {
		t.Fatalf("third decoded lag = %d/%d, want 110/0", t0, frac)
	}
	if decodedState != third.state {
		t.Fatalf("third decoded state = %+v, want %+v", decodedState, third.state)
	}
}
