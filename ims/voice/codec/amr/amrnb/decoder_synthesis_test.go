package amrnb

import "testing"

func TestSynFiltIdentityUpdatesMemory(t *testing.T) {
	a := []int16{4096, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	x := make([]int16, subframeSamples)
	for i := range x {
		x[i] = int16(i - 20)
	}
	y := make([]int16, subframeSamples)
	var mem [lpcOrder]int16

	mem = synthesisFilter(a, x, y, mem[:])

	for i := range x {
		if y[i] != x[i] {
			t.Fatalf("y[%d] = %d, want %d", i, y[i], x[i])
		}
	}
	for i := range lpcOrder {
		want := x[subframeSamples-lpcOrder+i]
		if mem[i] != want {
			t.Fatalf("mem[%d] = %d, want %d", i, mem[i], want)
		}
	}
}

func TestSynFiltUsesPastOutputMemory(t *testing.T) {
	a := []int16{4096, 1024, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	x := []int16{1000, 0, 0, 0}
	y := make([]int16, len(x))
	mem := [lpcOrder]int16{0, 0, 0, 0, 0, 0, 0, 0, 0, 400}

	synthesisFilter(a, x, y, mem[:])

	want := []int16{900, -225, 56, -14}
	for i := range want {
		if y[i] != want[i] {
			t.Fatalf("y[%d] = %d, want %d; y=%v", i, y[i], want[i], y)
		}
	}
	if mem[9] != 400 {
		t.Fatalf("input memory changed: %v", mem)
	}
}

func TestResidualIdentity(t *testing.T) {
	a := []int16{4096, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	x := make([]int16, lpcOrder+subframeSamples)
	for i := lpcOrder; i < len(x); i++ {
		x[i] = int16(i * 3)
	}
	y := make([]int16, subframeSamples)

	residual(a, x, y)

	for i := range y {
		want := x[i+lpcOrder]
		if y[i] != want {
			t.Fatalf("y[%d] = %d, want %d", i, y[i], want)
		}
	}
}

func TestCombineExcitationKnownVector(t *testing.T) {
	exc := []int16{1000, -2000, 3000, -4000}
	code := []int16{8191, -8192, 4096, -4096}

	combineExcitationWithMode(exc, code, 8192, 64, Mode740)

	want := []int16{532, -1032, 1516, -2016}
	for i := range want {
		if exc[i] != want[i] {
			t.Fatalf("exc[%d] = %d, want %d; exc=%v", i, exc[i], want[i], exc)
		}
	}
}

func TestCombineExcitationMR122UsesHalfPitch(t *testing.T) {
	exc := []int16{1000, -2000}
	code := []int16{4096, -4096}

	combineExcitationWithMode(exc, code, 8192, 64, Mode1220)

	want := []int16{532, -1032}
	for i := range want {
		if exc[i] != want[i] {
			t.Fatalf("exc[%d] = %d, want %d; exc=%v", i, exc[i], want[i], exc)
		}
	}
}

func TestAddPitchContribution(t *testing.T) {
	code := make([]int16, subframeSamples)
	code[0] = 1000
	code[1] = -2000

	addPitchContribution(code, 2, 8192)

	if code[2] != 250 || code[3] != -500 || code[4] != 62 {
		t.Fatalf("pitch contribution code[2:5] = %v, want [250 -500 62]", code[2:5])
	}
}

func TestDecoderCoreSynthesizeCurrentSubframe(t *testing.T) {
	state := newDecoderCoreState()
	for subframe := range 4 {
		state.az[subframe*lpcCoeffCount] = 4096
	}
	exc := state.currentExcitation()
	for i := range exc {
		exc[i] = int16(i * 10)
	}
	code := make([]int16, subframeSamples)
	code[0] = 8191
	code[1] = -8192

	got := state.synthesizeCurrentSubframe(0, code, 8192, 64, 64, Mode740, nil)

	if got[0] != 32 || got[1] != -27 || got[2] != 10 || got[39] != 195 {
		t.Fatalf("synthesized samples = first %v last %d", got[:4], got[39])
	}
	if state.memSyn[0] != got[30] || state.memSyn[9] != got[39] {
		t.Fatalf("memSyn = %v, want trailing synthesized samples", state.memSyn)
	}
	historyStart := pitchMax + interpolationLen - subframeSamples
	if state.oldExc[historyStart] != 32 || state.oldExc[pitchMax+interpolationLen-1] != 195 {
		t.Fatalf("advanced excitation tail = %v", state.oldExc[historyStart:pitchMax+interpolationLen])
	}
}

func TestDecoderCoreSynthesizeKeepsPhaseDispersionOutOfLTPFeedback(t *testing.T) {
	state := newDecoderCoreState()
	state.az[0] = 4096
	code := make([]int16, subframeSamples)
	code[0] = 8192

	got := state.synthesizeCurrentSubframe(0, code, 0, 128, 64, Mode590, nil)

	historyStart := pitchMax + interpolationLen - subframeSamples
	if state.oldExc[historyStart] != 64 {
		t.Fatalf("feedback excitation = %d, want original code gain result 64", state.oldExc[historyStart])
	}
	if got[0] == state.oldExc[historyStart] {
		t.Fatalf("synthesis output matched feedback; phase-dispersed path was not kept separate")
	}
}

func TestDecoderCoreSynthesizeUpdatesExcitationEnergyHistory(t *testing.T) {
	state := newDecoderCoreState()
	state.az[0] = 4096
	code := make([]int16, subframeSamples)
	code[0] = 8192

	state.synthesizeCurrentSubframe(0, code, 0, 128, 128, Mode740, nil)

	if state.excEnergyHist[excitationHistoryLen-1] == 0 {
		t.Fatalf("excitation energy history tail = 0, want non-zero update")
	}
}

func TestDecoderCoreSynthesizeSkipsEnergyHistoryDuringBackgroundBadFrameRecovery(t *testing.T) {
	state := newDecoderCoreState()
	state.az[0] = 4096
	state.inBackgroundNoise = true
	state.prevBF = true
	state.state = 3
	for i := range state.excEnergyHist {
		state.excEnergyHist[i] = int16(i + 1)
	}
	code := make([]int16, subframeSamples)
	code[0] = 8192

	state.synthesizeCurrentSubframe(0, code, 0, 128, 128, Mode740, nil)

	for i, got := range state.excEnergyHist {
		if want := int16(i + 1); got != want {
			t.Fatalf("excEnergyHist[%d] = %d, want preserved %d", i, got, want)
		}
	}
}

func TestDecoderCoreSynthesizeCurrentSubframeReusesDestination(t *testing.T) {
	state := newDecoderCoreState()
	state.az[0] = 4096
	dst := make([]int16, 0, subframeSamples)

	got := state.synthesizeCurrentSubframe(0, make([]int16, subframeSamples), 0, 0, 0, Mode740, dst)

	if len(got) != subframeSamples {
		t.Fatalf("len(got) = %d, want %d", len(got), subframeSamples)
	}
	if cap(got) != cap(dst) {
		t.Fatalf("destination was not reused")
	}
}
