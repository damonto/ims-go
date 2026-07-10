package amrnb

import (
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestPhaseDispersionSelectFilterTracksOnset(t *testing.T) {
	var state phaseDispersionState
	state.prevCbGain = 64

	got := state.selectFilter(256, 0)

	if got != 1 {
		t.Fatalf("filter = %d, want one step less dispersion on onset", got)
	}
	if state.onset != phaseOnLength {
		t.Fatalf("onset = %d, want %d", state.onset, phaseOnLength)
	}
	if state.prevCbGain != 256 {
		t.Fatalf("prevCbGain = %d, want 256", state.prevCbGain)
	}
}

func TestPhaseDispersionSelectFilterLocksToMaximumDispersion(t *testing.T) {
	var state phaseDispersionState
	state.lock()

	got := state.selectFilter(64, 20000)

	if got != 0 {
		t.Fatalf("locked filter = %d, want maximum dispersion", got)
	}
	state.release()
	if state.lockFull != 0 {
		t.Fatalf("lockFull = %d, want released state", state.lockFull)
	}
}

func TestPhaseDispersionSkipsLowCodeGain(t *testing.T) {
	var state phaseDispersionState

	got := state.selectFilter(9, 0)

	if got != 2 {
		t.Fatalf("low code gain filter = %d, want no dispersion", got)
	}
}

func TestPhaseDispersionDispersesMR590Innovation(t *testing.T) {
	var state phaseDispersionState
	innovation := make([]int16, subframeSamples)
	innovation[0] = 8192

	state.disperseInnovation(Mode590, 0, innovation)
	for i := range 6 {
		want := fxp.Mult(8192, phaseImpLow[i])
		if innovation[i] != want {
			t.Fatalf("innovation[%d] = %d, want %d; head=%v", i, innovation[i], want, innovation[:6])
		}
	}
}

func TestPhaseDispersionUsesMR795Impulse(t *testing.T) {
	var state phaseDispersionState
	innovation := make([]int16, subframeSamples)
	innovation[0] = 8192

	state.disperseInnovation(Mode795, 0, innovation)

	want := fxp.Mult(8192, phaseImpLowMR795[0])
	if innovation[0] != want {
		t.Fatalf("MR795 innovation[0] = %d, want %d", innovation[0], want)
	}
	if innovation[0] == fxp.Mult(8192, phaseImpLow[0]) {
		t.Fatalf("MR795 used the generic low dispersion impulse")
	}
}

func TestPhaseDispersionApplyMatchesCombineWhenInactive(t *testing.T) {
	var state phaseDispersionState
	excitation := []int16{1000, -2000, 3000, -4000}
	code := []int16{8191, -8192, 4096, -4096}

	state.apply(Mode740, excitation, 64, 8192, code, 8192, 1)

	want := []int16{532, -1032, 1516, -2016}
	for i := range want {
		if excitation[i] != want[i] {
			t.Fatalf("excitation[%d] = %d, want %d; excitation=%v", i, excitation[i], want[i], excitation)
		}
	}
}
