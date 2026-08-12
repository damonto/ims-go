package amrnb

import "testing"

func TestDTXDecStateReset(t *testing.T) {
	state := dtxDecState{}
	state.reset()

	if state.sinceLastSID != 0 {
		t.Fatalf("sinceLastSID = %d, want 0", state.sinceLastSID)
	}
	if state.trueSIDPeriodInv != 1<<13 {
		t.Fatalf("trueSIDPeriodInv = %d, want %d", state.trueSIDPeriodInv, 1<<13)
	}
	if state.logEnergy != dtxInitialLogEnergy || state.oldLogEnergy != dtxInitialLogEnergy {
		t.Fatalf("log energy = %d/%d, want %d", state.logEnergy, state.oldLogEnergy, dtxInitialLogEnergy)
	}
	if state.pnSeedRX != pnInitialSeed {
		t.Fatalf("pnSeedRX = %#x, want %#x", state.pnSeedRX, pnInitialSeed)
	}
	if state.globalState != dtxStateDTX {
		t.Fatalf("globalState = %d, want %d", state.globalState, dtxStateDTX)
	}
	if state.dtxHangoverCount != dtxHangConst {
		t.Fatalf("dtxHangoverCount = %d, want %d", state.dtxHangoverCount, dtxHangConst)
	}
	if state.decAnaElapsed != dtxInitialElapsedCount {
		t.Fatalf("decAnaElapsed = %d, want %d", state.decAnaElapsed, dtxInitialElapsedCount)
	}
	for i, want := range initialLSP {
		if state.lsp[i] != want || state.lspOld[i] != want {
			t.Fatalf("lsp[%d] = %d/%d, want %d", i, state.lsp[i], state.lspOld[i], want)
		}
	}
	for hist := range dtxHistorySize {
		for i, want := range meanLSF {
			if got := state.lsfHist[hist*lpcOrder+i]; got != want {
				t.Fatalf("lsfHist[%d][%d] = %d, want %d", hist, i, got, want)
			}
		}
		if state.logEnergyHist[hist] != dtxInitialLogEnergy {
			t.Fatalf("logEnergyHist[%d] = %d, want %d", hist, state.logEnergyHist[hist], dtxInitialLogEnergy)
		}
	}
}

func TestDTXRXHandlerSIDUpdate(t *testing.T) {
	state := dtxDecState{}
	state.reset()

	newState := state.nextRXState(RXSIDUpdate)

	if newState != dtxStateDTX {
		t.Fatalf("newState = %d, want %d", newState, dtxStateDTX)
	}
	if state.sinceLastSID != 1 {
		t.Fatalf("sinceLastSID = %d, want 1", state.sinceLastSID)
	}
	if state.decAnaElapsed != 1 {
		t.Fatalf("decAnaElapsed = %d, want 1", state.decAnaElapsed)
	}
	if state.dtxHangoverCount != dtxHangConst-1 {
		t.Fatalf("dtxHangoverCount = %d, want %d", state.dtxHangoverCount, dtxHangConst-1)
	}
	if state.sidFrame != 1 || state.validData != 1 {
		t.Fatalf("SID flags = sid %d valid %d, want 1/1", state.sidFrame, state.validData)
	}
}

func TestDTXRXHandlerSpeechGood(t *testing.T) {
	state := dtxDecState{}
	state.reset()
	state.sinceLastSID = 12

	newState := state.nextRXState(RXSpeechGood)

	if newState != dtxStateSpeech {
		t.Fatalf("newState = %d, want %d", newState, dtxStateSpeech)
	}
	if state.sinceLastSID != 0 {
		t.Fatalf("sinceLastSID = %d, want 0", state.sinceLastSID)
	}
	if state.dtxHangoverCount != dtxHangConst {
		t.Fatalf("dtxHangoverCount = %d, want %d", state.dtxHangoverCount, dtxHangConst)
	}
}

func TestDTXRXHandlerEmptyThresholdMutes(t *testing.T) {
	state := dtxDecState{}
	state.reset()
	state.sinceLastSID = dtxMaxEmptyThreshold

	newState := state.nextRXState(RXNoData)

	if newState != dtxStateMute {
		t.Fatalf("newState = %d, want %d", newState, dtxStateMute)
	}
	if state.sinceLastSID != dtxMaxEmptyThreshold+1 {
		t.Fatalf("sinceLastSID = %d, want %d", state.sinceLastSID, dtxMaxEmptyThreshold+1)
	}
	if state.dtxHangoverAdded != 1 {
		t.Fatalf("dtxHangoverAdded = %d, want 1", state.dtxHangoverAdded)
	}
}

func TestDTXUpdateSIDDecodesValidData(t *testing.T) {
	state := dtxDecState{}
	state.reset()
	state.sidFrame = 1
	state.validData = 1
	state.sinceLastSID = 4
	params := []int16{2, 1, 2, 3, 10}
	lsfState := newDPLSFState()
	predState := newGainPredState()

	if err := state.updateSID(&lsfState, &predState, Mode740, params); err != nil {
		t.Fatalf("updateSID() error = %v", err)
	}

	if state.trueSIDPeriodInv != 8192 {
		t.Fatalf("trueSIDPeriodInv = %d, want 8192", state.trueSIDPeriodInv)
	}
	if state.sinceLastSID != 0 || state.dataUpdated != 0 {
		t.Fatalf("SID counters before synthesis = since %d updated %d, want 0/0", state.sinceLastSID, state.dataUpdated)
	}
	if state.logEnergy != 0 || state.oldLogEnergy != 0 {
		t.Fatalf("log energy = %d/%d, want 0/0", state.logEnergy, state.oldLogEnergy)
	}
	if predState.pastQuaEn[0] != -9000 {
		t.Fatalf("pastQuaEn[0] = %d, want -9000", predState.pastQuaEn[0])
	}
	if predState.pastQuaEnMR122[0] != -1495 {
		t.Fatalf("pastQuaEnMR122[0] = %d, want -1495", predState.pastQuaEnMR122[0])
	}
	for i, got := range lsfState.pastRQ {
		if got != 0 {
			t.Fatalf("pastRQ[%d] = %d, want reset 0", i, got)
		}
	}

	state.finishSIDUpdate()
	if state.sinceLastSID != 0 || state.dataUpdated != 1 {
		t.Fatalf("SID counters after synthesis = since %d updated %d, want 0/1", state.sinceLastSID, state.dataUpdated)
	}
}

func TestCoreResetDTXPreservesDTXState(t *testing.T) {
	state := newDecoderCoreState()
	state.dtx.sinceLastSID = 9
	state.dtx.globalState = dtxStateMute

	state.reset(ModeDTX)

	if state.dtx.sinceLastSID != 9 {
		t.Fatalf("sinceLastSID = %d, want preserved 9", state.dtx.sinceLastSID)
	}
	if state.dtx.globalState != dtxStateMute {
		t.Fatalf("globalState = %d, want %d", state.dtx.globalState, dtxStateMute)
	}

	state.reset(Mode475)
	if state.dtx.sinceLastSID != 0 || state.dtx.globalState != dtxStateDTX {
		t.Fatalf("speech reset DTX state = since %d global %d, want 0/%d", state.dtx.sinceLastSID, state.dtx.globalState, dtxStateDTX)
	}
}
