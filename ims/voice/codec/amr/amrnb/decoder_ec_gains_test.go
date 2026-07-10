package amrnb

import "testing"

func TestGmedNReturnsMedianValue(t *testing.T) {
	values := []int16{1, 5, 2, 5, 3}

	got := gmedN(values)

	if got != 3 {
		t.Fatalf("gmedN() = %d, want 3", got)
	}
}

func TestECGainPitchResetConcealAndUpdate(t *testing.T) {
	var state ecGainPitchState
	state.reset()

	if got := state.conceal(0); got != 0 {
		t.Fatalf("conceal after reset = %d, want 0", got)
	}

	gain := int16(20000)
	gain = state.update(false, false, gain)
	if gain != 20000 {
		t.Fatalf("good gain after update = %d, want 20000", gain)
	}
	if state.pastGainPit != 16384 {
		t.Fatalf("pastGainPit = %d, want capped 16384", state.pastGainPit)
	}

	gain = 22000
	gain = state.update(false, true, gain)
	if gain != 20000 {
		t.Fatalf("prev-bad limited gain = %d, want previous good 20000", gain)
	}
}

func TestECGainCodeResetConcealAndUpdate(t *testing.T) {
	var state ecGainCodeState
	state.reset()
	pred := newGainPredState()

	if got := state.conceal(&pred, 0); got != 0 {
		t.Fatalf("conceal after reset = %d, want 0", got)
	}
	if pred.pastQuaEn[0] != -8192 || pred.pastQuaEnMR122[0] != minEnergyMR122 {
		t.Fatalf("predictor after conceal = %d/%d, want saturated averages %d/%d",
			pred.pastQuaEn[0], pred.pastQuaEnMR122[0], -8192, minEnergyMR122)
	}

	gain := int16(100)
	gain = state.update(false, false, gain)
	if state.prevGC != 100 || state.pastGainCode != 100 || state.gbuf[4] != 100 {
		t.Fatalf("code update state = %+v, want prev/past/tail 100", state)
	}

	gain = 150
	gain = state.update(false, true, gain)
	if gain != 100 {
		t.Fatalf("prev-bad limited code gain = %d, want previous good 100", gain)
	}
}

func TestDecoderCoreResetInitializesECGainStates(t *testing.T) {
	state := newDecoderCoreState()

	if state.ecGainPitch.pbuf[0] != 1640 || state.ecGainPitch.prevGP != 16384 {
		t.Fatalf("pitch EC state after reset = %+v", state.ecGainPitch)
	}
	if state.ecGainCode.gbuf[0] != 1 || state.ecGainCode.prevGC != 1 {
		t.Fatalf("code EC state after reset = %+v", state.ecGainCode)
	}
}
