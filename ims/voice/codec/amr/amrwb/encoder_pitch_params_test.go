package amrwb

import "testing"

func TestEncodeSubframePitchLagWidths(t *testing.T) {
	state := initialPitchLagState(70)

	first := encodeSubframePitchLag(subframePitchLagInput{mode: Mode885, subframe: 0, openLoop: 90, lag: 70, state: state})
	second := encodeSubframePitchLag(subframePitchLagInput{mode: Mode885, subframe: 1, openLoop: 90, lag: 72, fraction: 2, state: first.state})
	third := encodeSubframePitchLag(subframePitchLagInput{mode: Mode1265, subframe: 2, openLoop: 100, lag: 100, state: second.state})
	fourth := encodeSubframePitchLag(subframePitchLagInput{mode: Mode1265, subframe: 3, openLoop: 100, lag: 102, fraction: 3, state: third.state})

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
	first := encodeSubframePitchLag(subframePitchLagInput{mode: Mode1265, subframe: 0, openLoop: 100, lag: 80, state: state})
	t0, frac, decodedState := decodePitchLag(first.index, nBits1265, first.pitFlag, state)
	if t0 != 80 || frac != 0 {
		t.Fatalf("first decoded lag = %d/%d, want 80/0", t0, frac)
	}
	if decodedState != first.state {
		t.Fatalf("first decoded state = %+v, want %+v", decodedState, first.state)
	}

	second := encodeSubframePitchLag(subframePitchLagInput{mode: Mode1265, subframe: 1, openLoop: 100, lag: 82, fraction: 3, state: first.state})
	t0, frac, decodedState = decodePitchLag(second.index, nBits1265, second.pitFlag, first.state)
	if t0 != 82 || frac != 3 {
		t.Fatalf("second decoded lag = %d/%d, want 82/3", t0, frac)
	}
	if decodedState != second.state {
		t.Fatalf("second decoded state = %+v, want %+v", decodedState, second.state)
	}

	third := encodeSubframePitchLag(subframePitchLagInput{mode: Mode1265, subframe: 2, openLoop: 110, lag: 110, state: second.state})
	resetState := pitchSearchRange(110)
	t0, frac, decodedState = decodePitchLag(third.index, nBits1265, third.pitFlag, resetState)
	if t0 != 110 || frac != 0 {
		t.Fatalf("third decoded lag = %d/%d, want 110/0", t0, frac)
	}
	if decodedState != third.state {
		t.Fatalf("third decoded state = %+v, want %+v", decodedState, third.state)
	}
}
