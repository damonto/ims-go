package amrwb

import (
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestAGC2AMRWBReturnsOnZeroOutputEnergy(t *testing.T) {
	var in [subframeSamples]int16
	copy(in[:], []int16{1000, -1000, 500})
	var out [subframeSamples]int16

	out = agc2AMRWB(in, out)

	for i, got := range out {
		if got != 0 {
			t.Fatalf("out[%d] = %d, want 0", i, got)
		}
	}
}

func TestAGC2AMRWBMutesWhenInputEnergyIsZero(t *testing.T) {
	var in [subframeSamples]int16
	var out [subframeSamples]int16
	copy(out[:], []int16{1000, -1000, 500, -500})

	out = agc2AMRWB(in, out)

	for i, got := range out {
		if got != 0 {
			t.Fatalf("out[%d] = %d, want muted output", i, got)
		}
	}
}

func TestAGC2AMRWBPreservesMatchingEnergy(t *testing.T) {
	var in [subframeSamples]int16
	copy(in[:], []int16{1000, -1000, 500, -500})
	out := in

	out = agc2AMRWB(in, out)

	want := []int16{1000, -1000, 500, -500}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("out[%d] = %d, want %d", i, out[i], want[i])
		}
	}
}

func TestOneOverSqrtWBRejectsNonPositive(t *testing.T) {
	if got := oneOverSqrtWB(0); got != fxp.Max32 {
		t.Fatalf("oneOverSqrtWB(0) = %#x, want %#x", got, fxp.Max32)
	}
}
