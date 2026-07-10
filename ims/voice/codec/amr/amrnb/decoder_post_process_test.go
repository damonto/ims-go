package amrnb

import "testing"

func TestPostProcessZeroInput(t *testing.T) {
	var state postProcessState
	signal := make([]int16, FrameSamples)

	state.process(signal)

	for i, sample := range signal {
		if sample != 0 {
			t.Fatalf("signal[%d] = %d, want 0", i, sample)
		}
	}
	if state != (postProcessState{}) {
		t.Fatalf("state after zero input = %+v, want zero", state)
	}
}

func TestPostProcessImpulse(t *testing.T) {
	var state postProcessState
	signal := []int16{1000, 0, 0, 0, 0, 0}

	state.process(signal)

	want := []int16{1880, -126, -123, -119, -116, -112}
	for i := range want {
		if signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d; full signal=%v", i, signal[i], want[i], signal)
		}
	}
	if state.x0 != 0 || state.x1 != 0 {
		t.Fatalf("input history = %d/%d, want zero tail", state.x0, state.x1)
	}
}

func TestPostProcessChunkedMatchesWhole(t *testing.T) {
	whole := []int16{1000, -2000, 3000, -4000, 5000, -6000, 7000, -8000}
	chunked := append([]int16(nil), whole...)

	var wholeState postProcessState
	wholeState.process(whole)

	var chunkState postProcessState
	chunkState.process(chunked[:3])
	chunkState.process(chunked[3:])

	for i := range whole {
		if chunked[i] != whole[i] {
			t.Fatalf("chunked[%d] = %d, want whole %d", i, chunked[i], whole[i])
		}
	}
	if chunkState != wholeState {
		t.Fatalf("chunk state = %+v, want whole state %+v", chunkState, wholeState)
	}
}
