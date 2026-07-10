package amrnb

import "testing"

func TestDecoderCoreStateInitialReset(t *testing.T) {
	state := newDecoderCoreState()

	if state.excOffset != pitchMax+interpolationLen {
		t.Fatalf("excOffset = %d, want %d", state.excOffset, pitchMax+interpolationLen)
	}
	for i := range pitchMax + interpolationLen {
		if state.oldExc[i] != 0 {
			t.Fatalf("oldExc[%d] = %d, want 0", i, state.oldExc[i])
		}
	}
	for i, want := range initialLSP {
		if state.lspOld[i] != want {
			t.Fatalf("lspOld[%d] = %d, want %d", i, state.lspOld[i], want)
		}
	}
	for i, value := range state.memSyn {
		if value != 0 {
			t.Fatalf("memSyn[%d] = %d, want 0", i, value)
		}
	}
	if state.sharp != sharpMin {
		t.Fatalf("sharp = %d, want %d", state.sharp, sharpMin)
	}
	if state.oldT0 != initialOldT0 || state.t0LagBuff != initialOldT0 {
		t.Fatalf("pitch state = oldT0 %d t0LagBuff %d, want %d", state.oldT0, state.t0LagBuff, initialOldT0)
	}
	if state.nodataSeed != noDataSeed {
		t.Fatalf("nodataSeed = %d, want %d", state.nodataSeed, noDataSeed)
	}
}

func TestDecoderCoreResetSpeechModeRefreshesSpeechHistory(t *testing.T) {
	state := newDecoderCoreState()
	state.oldExc[0] = 11
	state.oldExc[pitchMax+interpolationLen] = 12
	state.memSyn[0] = 13
	state.lspOld[0] = 14
	state.excEnergyHist[0] = 15
	state.ltpGainHistory[0] = 16
	state.nodataSeed = 17
	state.overflow = true

	state.reset(Mode1220)

	if state.oldExc[0] != 0 {
		t.Fatalf("oldExc[0] = %d, want 0", state.oldExc[0])
	}
	if state.oldExc[pitchMax+interpolationLen] != 12 {
		t.Fatalf("oldExc tail = %d, want preserved 12", state.oldExc[pitchMax+interpolationLen])
	}
	if state.memSyn[0] != 0 {
		t.Fatalf("memSyn[0] = %d, want 0", state.memSyn[0])
	}
	if state.lspOld[0] != initialLSP[0] {
		t.Fatalf("lspOld[0] = %d, want %d", state.lspOld[0], initialLSP[0])
	}
	if state.excEnergyHist[0] != 0 || state.ltpGainHistory[0] != 0 {
		t.Fatalf("histories = exc %d ltp %d, want 0", state.excEnergyHist[0], state.ltpGainHistory[0])
	}
	if state.nodataSeed != noDataSeed {
		t.Fatalf("nodataSeed = %d, want %d", state.nodataSeed, noDataSeed)
	}
	if state.overflow {
		t.Fatal("overflow = true, want false")
	}
}

func TestDecoderCoreResetDTXPreservesSpeechHistory(t *testing.T) {
	state := newDecoderCoreState()
	state.memSyn[0] = 21
	state.lspOld[0] = 22
	state.excEnergyHist[0] = 23
	state.ltpGainHistory[0] = 24

	state.reset(ModeDTX)

	if state.memSyn[0] != 21 {
		t.Fatalf("memSyn[0] = %d, want preserved 21", state.memSyn[0])
	}
	if state.lspOld[0] != 22 {
		t.Fatalf("lspOld[0] = %d, want preserved 22", state.lspOld[0])
	}
	if state.excEnergyHist[0] != 23 {
		t.Fatalf("excEnergyHist[0] = %d, want preserved 23", state.excEnergyHist[0])
	}
	if state.ltpGainHistory[0] != 0 {
		t.Fatalf("ltpGainHistory[0] = %d, want 0", state.ltpGainHistory[0])
	}
	if state.prevBF || state.prevPDF || state.state != 0 {
		t.Fatalf("bad frame state = %v/%v/%d, want false/false/0", state.prevBF, state.prevPDF, state.state)
	}
}

func TestDecoderResetResetsCoreAndPreviousMode(t *testing.T) {
	dec := NewDecoder()
	dec.prevMode = Mode1220
	dec.core.memSyn[0] = 31
	dec.core.lspOld[0] = 32

	dec.Reset()

	if dec.prevMode != Mode475 {
		t.Fatalf("prevMode = %d, want %d", dec.prevMode, Mode475)
	}
	if dec.core.memSyn[0] != 0 {
		t.Fatalf("core.memSyn[0] = %d, want 0", dec.core.memSyn[0])
	}
	if dec.core.lspOld[0] != initialLSP[0] {
		t.Fatalf("core.lspOld[0] = %d, want %d", dec.core.lspOld[0], initialLSP[0])
	}
}
