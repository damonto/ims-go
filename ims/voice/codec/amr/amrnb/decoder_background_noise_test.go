package amrnb

import "testing"

func TestFrameEnergy(t *testing.T) {
	silence := make([]int16, FrameSamples)
	if got := frameEnergy(silence); got != 0 {
		t.Fatalf("frameEnergy(silence) = %d, want 0", got)
	}

	speech := make([]int16, FrameSamples)
	for i := range speech {
		speech[i] = 40
	}
	if got := frameEnergy(speech); got != 31 {
		t.Fatalf("frameEnergy(40s) = %d, want 31", got)
	}

	loud := make([]int16, FrameSamples)
	for i := range loud {
		loud[i] = 32767
	}
	if got := frameEnergy(loud); got != 32767 {
		t.Fatalf("frameEnergy(loud) = %d, want saturation 32767", got)
	}
}

func TestBackgroundNoiseDetectorHangover(t *testing.T) {
	var state backgroundNoiseState
	for i := range state.frameEnergyHist {
		state.frameEnergyHist[i] = 100
	}
	speech := make([]int16, FrameSamples)
	for i := range speech {
		speech[i] = 40
	}
	ltp := make([]int16, ltpGainHistoryLen)
	voicedHangover := int16(0)

	var got bool
	got, voicedHangover = state.detect(ltp, speech, voicedHangover)
	if got {
		t.Fatalf("first detect = %v, want no background decision yet", got)
	}
	got, voicedHangover = state.detect(ltp, speech, voicedHangover)
	if !got {
		t.Fatalf("second detect = %v, want background noise", got)
	}
	if state.bgHangover != 2 {
		t.Fatalf("bgHangover = %d, want 2", state.bgHangover)
	}
	if voicedHangover != 2 {
		t.Fatalf("voicedHangover = %d, want 2", voicedHangover)
	}
}

func TestBackgroundNoiseDetectorVoicedHangoverReset(t *testing.T) {
	var state backgroundNoiseState
	ltp := make([]int16, ltpGainHistoryLen)
	for i := range ltp {
		ltp[i] = 16000
	}
	speech := make([]int16, FrameSamples)
	voicedHangover := int16(7)

	_, voicedHangover = state.detect(ltp, speech, voicedHangover)

	if voicedHangover != 0 {
		t.Fatalf("voicedHangover = %d, want reset to 0", voicedHangover)
	}
}

func TestDecoderCoreResetClearsBackgroundNoiseState(t *testing.T) {
	state := newDecoderCoreState()
	state.background.frameEnergyHist[0] = 100
	state.background.bgHangover = 5

	state.reset(Mode475)

	if state.background.frameEnergyHist[0] != 0 || state.background.bgHangover != 0 {
		t.Fatalf("background after reset = %+v", state.background)
	}
}
