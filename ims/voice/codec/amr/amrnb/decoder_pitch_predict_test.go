package amrnb

import "testing"

func TestPredictAdaptiveCodebookZeroInput(t *testing.T) {
	exc := make([]int16, subframeSamples+pitchMax+interpolationLen)
	if err := predictAdaptiveCodebook(exc, pitchMax+interpolationLen, 40, 0, subframeSamples, true); err != nil {
		t.Fatalf("predictAdaptiveCodebook() error = %v", err)
	}
	for i := range subframeSamples {
		if exc[pitchMax+interpolationLen+i] != 0 {
			t.Fatalf("exc[%d] = %d, want 0", i, exc[pitchMax+interpolationLen+i])
		}
	}
}

func TestPredictAdaptiveCodebookImpulseThirdResolution(t *testing.T) {
	exc := make([]int16, subframeSamples+pitchMax+interpolationLen+interpolationTaps)
	offset := pitchMax + interpolationLen
	base := offset - 40
	exc[base] = 32767

	if err := predictAdaptiveCodebook(exc, offset, 40, 0, 4, true); err != nil {
		t.Fatalf("predictAdaptiveCodebook() error = %v", err)
	}

	want := []int16{29442, 3143, -2783, 2259}
	for i := range want {
		if exc[offset+i] != want[i] {
			t.Fatalf("exc[%d] = %d, want %d", i, exc[offset+i], want[i])
		}
	}
}

func TestPredictAdaptiveCodebookFractionAdjustsBase(t *testing.T) {
	exc := make([]int16, subframeSamples+pitchMax+interpolationLen+interpolationTaps)
	offset := pitchMax + interpolationLen
	base := offset - 40 - 1
	exc[base] = 32767

	if err := predictAdaptiveCodebook(exc, offset, 40, 1, 1, false); err != nil {
		t.Fatalf("predictAdaptiveCodebook() error = %v", err)
	}

	if exc[offset] != 8693 {
		t.Fatalf("exc[0] = %d, want 8693", exc[offset])
	}
}

func TestPredictAdaptiveCodebookRejectsInvalidBounds(t *testing.T) {
	exc := make([]int16, 20)
	if err := predictAdaptiveCodebook(exc, 5, 40, 0, 1, true); err == nil {
		t.Fatal("predictAdaptiveCodebook(short history) error = nil")
	}
	if err := predictAdaptiveCodebook(exc, -1, 1, 0, 1, true); err == nil {
		t.Fatal("predictAdaptiveCodebook(negative offset) error = nil")
	}
	if err := predictAdaptiveCodebook(exc, 10, 1, 0, -1, true); err == nil {
		t.Fatal("predictAdaptiveCodebook(negative samples) error = nil")
	}
}

func TestDecoderCorePredictPitchUsesExcitationOffset(t *testing.T) {
	state := newDecoderCoreState()
	base := state.excOffset - 40
	state.oldExc[base] = 32767

	if err := state.predictPitch(40, 0, true); err != nil {
		t.Fatalf("predictPitch() error = %v", err)
	}

	if state.oldExc[state.excOffset] != 29442 {
		t.Fatalf("current excitation = %d, want 29442", state.oldExc[state.excOffset])
	}
}
