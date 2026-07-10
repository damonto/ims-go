package amrwb

import (
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestEncoderLevinsonStableCorrelation(t *testing.T) {
	var x [lpcWindowSamples]int16
	for i := range x {
		x[i] = int16((i%31 - 15) * 256)
	}
	window := flatWindow()
	state := newEncoderLevinsonState()

	corr, err := encoderAutocorrelation(x[:], window[:])
	if err != nil {
		t.Fatalf("encoderAutocorrelation() error = %v", err)
	}
	rh, rl := encoderLagWindow(corr.rh, corr.rl)
	got, err := state.levinson(rh[:], rl[:])
	if err != nil {
		t.Fatalf("levinson() error = %v", err)
	}
	if got.a[0] != 4096 {
		t.Fatalf("levinson() a[0] = %d, want 4096", got.a[0])
	}
	nonZero := false
	for i := 1; i <= lpcOrder; i++ {
		if got.a[i] != 0 {
			nonZero = true
			break
		}
	}
	if !nonZero {
		t.Fatal("levinson() all LPC coefficients are zero")
	}
	if state.oldA != ([lpcOrder]int16{}) {
		return
	}
	t.Fatal("levinson() did not persist old A(z)")
}

func TestEncoderLevinsonUnstableFallsBackToOldA(t *testing.T) {
	state := newEncoderLevinsonState()
	for i := range state.oldA {
		state.oldA[i] = int16(i + 1)
	}
	state.oldRC[0] = 11
	state.oldRC[1] = 22
	var rh [lpcOrder + 1]int16
	var rl [lpcOrder + 1]int16
	rh[0] = 16384
	rh[1] = 16383

	got, err := state.levinson(rh[:], rl[:])
	if err != nil {
		t.Fatalf("levinson() error = %v", err)
	}
	if got.a[0] != 4096 {
		t.Fatalf("levinson() a[0] = %d, want 4096", got.a[0])
	}
	for i := range state.oldA {
		if got.a[i+1] != state.oldA[i] {
			t.Fatalf("levinson() fallback a[%d] = %d, want %d", i+1, got.a[i+1], state.oldA[i])
		}
	}
	if got.rc[0] != 11 || got.rc[1] != 22 {
		t.Fatalf("levinson() fallback rc = (%d,%d), want (11,22)", got.rc[0], got.rc[1])
	}
}

func TestEncoderDiv32(t *testing.T) {
	got := fxp.Div32(0x20000000, 0x4000, 0)
	if got < 0x3ffff000 || got > 0x40001000 {
		t.Fatalf("fxp.Div32(0.25/0.5) = %#x, want about 0x40000000", uint32(got))
	}
}
