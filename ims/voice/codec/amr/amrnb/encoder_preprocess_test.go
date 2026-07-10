package amrnb

import "testing"

func TestEncoderPreprocessZeroInput(t *testing.T) {
	var state encoderPreprocessState
	signal := make([]int16, FrameSamples)

	state.process(signal)

	for i, sample := range signal {
		if sample != 0 {
			t.Fatalf("signal[%d] = %d, want 0", i, sample)
		}
	}
	if state != (encoderPreprocessState{}) {
		t.Fatalf("state after zero input = %+v, want zero", state)
	}
}

func TestEncoderPreprocessImpulse(t *testing.T) {
	var state encoderPreprocessState
	signal := []int16{32767, 0, 0, 0, 0, 0, 0, 0}

	state.process(signal)

	want := []int16{15192, -1428, -1375, -1320, -1262, -1203, -1143, -1082}
	for i := range want {
		if signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d", i, signal[i], want[i])
		}
	}
}

func TestEncoderPreprocessStreamingMatchesSingleCall(t *testing.T) {
	input := []int16{3000, -2000, 1000, 0, 500, -500, 250, -250}
	whole := append([]int16(nil), input...)
	split := append([]int16(nil), input...)
	var wholeState encoderPreprocessState
	var splitState encoderPreprocessState

	wholeState.process(whole)
	splitState.process(split[:3])
	splitState.process(split[3:])

	for i := range whole {
		if split[i] != whole[i] {
			t.Fatalf("split[%d] = %d, want %d", i, split[i], whole[i])
		}
	}
	if splitState != wholeState {
		t.Fatalf("split state = %+v, want %+v", splitState, wholeState)
	}
}
