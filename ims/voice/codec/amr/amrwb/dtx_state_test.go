package amrwb

import "testing"

func TestWBDecoderDTXReset(t *testing.T) {
	var state dtxDecState
	state.reset()

	if state.trueSIDPeriodInv != 1<<13 {
		t.Fatalf("trueSIDPeriodInv = %d, want %d", state.trueSIDPeriodInv, 1<<13)
	}
	if state.cngSeed != randomInitialSeed || state.ditherSeed != randomInitialSeed {
		t.Fatalf("seeds = %d/%d, want %d", state.cngSeed, state.ditherSeed, randomInitialSeed)
	}
	if state.dtxHangoverCount != dtxHangConst {
		t.Fatalf("dtxHangoverCount = %d, want %d", state.dtxHangoverCount, dtxHangConst)
	}
	if state.decAnaElapsed != dtxInitialElapsedCount {
		t.Fatalf("decAnaElapsed = %d, want %d", state.decAnaElapsed, dtxInitialElapsedCount)
	}
	if state.globalState != dtxStateSpeech {
		t.Fatalf("globalState = %d, want speech", state.globalState)
	}
	if state.logEnergy != 3500 || state.oldLogEnergy != 3500 {
		t.Fatalf("log energy = %d/%d, want 3500/3500", state.logEnergy, state.oldLogEnergy)
	}
	for i, want := range initialISF {
		if state.isf[i] != want || state.isfOld[i] != want {
			t.Fatalf("isf[%d] = %d/%d, want %d", i, state.isf[i], state.isfOld[i], want)
		}
	}
	for i, got := range state.logEnergyHist {
		if got != 3500>>3 {
			t.Fatalf("logEnergyHist[%d] = %d, want %d", i, got, 3500>>3)
		}
	}
}

func TestWBDecoderDTXRXHandlerSIDUpdate(t *testing.T) {
	var state dtxDecState
	state.reset()

	newState := state.rxHandler(rxSIDUpdate)

	if newState != dtxStateDTX {
		t.Fatalf("newState = %d, want DTX", newState)
	}
	if state.sinceLastSID != 1 {
		t.Fatalf("sinceLastSID = %d, want 1", state.sinceLastSID)
	}
	if !state.sidFrame || !state.validData {
		t.Fatalf("SID flags = %v/%v, want true/true", state.sidFrame, state.validData)
	}
	if state.decAnaElapsed != 1 {
		t.Fatalf("decAnaElapsed = %d, want 1", state.decAnaElapsed)
	}
}

func TestWBDecoderDTXRXHandlerSpeechGood(t *testing.T) {
	var state dtxDecState
	state.reset()
	state.sinceLastSID = 12

	newState := state.rxHandler(rxSpeechGood)

	if newState != dtxStateSpeech {
		t.Fatalf("newState = %d, want speech", newState)
	}
	if state.sinceLastSID != 0 {
		t.Fatalf("sinceLastSID = %d, want 0", state.sinceLastSID)
	}
	if state.dtxHangoverCount != dtxHangConst {
		t.Fatalf("dtxHangoverCount = %d, want %d", state.dtxHangoverCount, dtxHangConst)
	}
}

func TestWBDecoderDTXRXHandlerEmptyThresholdMutes(t *testing.T) {
	var state dtxDecState
	state.reset()
	state.globalState = dtxStateDTX
	state.sinceLastSID = dtxMaxEmptyThreshold

	newState := state.rxHandler(rxNoData)

	if newState != dtxStateMute {
		t.Fatalf("newState = %d, want mute", newState)
	}
	if state.sinceLastSID != dtxMaxEmptyThreshold+1 {
		t.Fatalf("sinceLastSID = %d, want %d", state.sinceLastSID, dtxMaxEmptyThreshold+1)
	}
	if !state.dtxHangoverAdded {
		t.Fatal("dtxHangoverAdded = false, want true")
	}
}
