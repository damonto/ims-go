package amrwb

import "testing"

func TestDecoderCoreStateResetAll(t *testing.T) {
	state := newDecoderCoreState()

	if state.oldT0 != initialOldT0 || !state.firstFrame {
		t.Fatalf("pitch/frame state = %d/%v, want %d/true", state.oldT0, state.firstFrame, initialOldT0)
	}
	if state.qOld != qMax {
		t.Fatalf("qOld = %d, want %d", state.qOld, qMax)
	}
	for i, got := range state.qSubframe {
		if got != qMax {
			t.Fatalf("qSubframe[%d] = %d, want %d", i, got, qMax)
		}
	}
	if state.seed != randomInitialSeed || state.seed2 != randomInitialSeed || state.seed3 != randomInitialSeed {
		t.Fatalf("seeds = %d/%d/%d, want %d", state.seed, state.seed2, state.seed3, randomInitialSeed)
	}
	for i, want := range initialISP {
		if state.ispOld[i] != want {
			t.Fatalf("ispOld[%d] = %d, want %d", i, state.ispOld[i], want)
		}
	}
	for i, want := range initialISF {
		if state.isfOld[i] != want {
			t.Fatalf("isfOld[%d] = %d, want %d", i, state.isfOld[i], want)
		}
	}
}

func TestDecoderCoreStatePartialResetPreservesSynthesisState(t *testing.T) {
	state := newDecoderCoreState()
	state.memDeemph = 17
	state.seed = 99
	state.ispOld[0] = 123
	state.oldExc[0] = 7

	state.reset(false)

	if state.oldExc[0] != 0 {
		t.Fatalf("oldExc[0] = %d, want cleared 0", state.oldExc[0])
	}
	if state.memDeemph != 17 || state.seed != 99 || state.ispOld[0] != 123 {
		t.Fatalf("partial reset did not preserve full-reset fields")
	}
	if state.oldT0 != initialOldT0 || !state.firstFrame {
		t.Fatalf("partial reset pitch/frame = %d/%v, want %d/true", state.oldT0, state.firstFrame, initialOldT0)
	}
}
