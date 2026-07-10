package amrnb

import "testing"

func TestSynthesizeComfortNoiseUpdatesState(t *testing.T) {
	state := newDecoderCoreState()
	state.lastDTXState = dtxStateDTX
	oldSeed := state.dtx.pnSeedRX

	got := state.synthesizeComfortNoise(nil)

	if len(got) != FrameSamples {
		t.Fatalf("samples = %d, want %d", len(got), FrameSamples)
	}
	if state.dtx.pnSeedRX == oldSeed {
		t.Fatal("pnSeedRX did not advance")
	}
	if state.cbGainAvg.hangVar != 20 || state.cbGainAvg.hangCount != 0 {
		t.Fatalf("cb gain hang = %d/%d, want 20/0", state.cbGainAvg.hangVar, state.cbGainAvg.hangCount)
	}
	for subframe := 1; subframe < 4; subframe++ {
		for i := range lpcCoeffCount {
			gotCoeff := state.az[subframe*lpcCoeffCount+i]
			wantCoeff := state.az[i]
			if gotCoeff != wantCoeff {
				t.Fatalf("az[%d][%d] = %d, want %d", subframe, i, gotCoeff, wantCoeff)
			}
		}
	}
}
