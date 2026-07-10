package amrwb

import (
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestEncoderAutocorrelationZeroSignal(t *testing.T) {
	var x [lpcWindowSamples]int16
	window := flatWindow()

	corr, err := encoderAutocorrelation(x[:], window[:])
	if err != nil {
		t.Fatalf("encoderAutocorrelation() error = %v", err)
	}

	if corr.norm == 0 {
		t.Fatal("encoderAutocorrelation() norm = 0, want normalized energy")
	}
	if corr.rh[0] <= 0 {
		t.Fatalf("encoderAutocorrelation() rh[0] = %d, want positive guard energy", corr.rh[0])
	}
	for i := 1; i <= lpcOrder; i++ {
		if corr.rh[i] != 0 || corr.rl[i] != 0 {
			t.Fatalf("encoderAutocorrelation() r[%d] = (%d,%d), want zero", i, corr.rh[i], corr.rl[i])
		}
	}
}

func TestEncoderAutocorrelationImpulse(t *testing.T) {
	var x [lpcWindowSamples]int16
	window := flatWindow()
	x[0] = 8192

	corr, err := encoderAutocorrelation(x[:], window[:])
	if err != nil {
		t.Fatalf("encoderAutocorrelation() error = %v", err)
	}

	r0 := fxp.LComp(corr.rh[0], corr.rl[0])
	if r0 <= 0 {
		t.Fatalf("encoderAutocorrelation() r[0] = %d, want positive", r0)
	}
	for i := 1; i <= lpcOrder; i++ {
		if corr.rh[i] != 0 || corr.rl[i] != 0 {
			t.Fatalf("encoderAutocorrelation() r[%d] = (%d,%d), want zero", i, corr.rh[i], corr.rl[i])
		}
	}
}

func TestEncoderAutocorrelationRejectsShortBuffers(t *testing.T) {
	window := flatWindow()
	tests := []struct {
		name   string
		x      []int16
		window []int16
	}{
		{name: "short input", window: window[:]},
		{name: "empty window", x: window[:]},
		{name: "oversized window", x: make([]int16, lpcWindowSamples+1), window: make([]int16, lpcWindowSamples+1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := encoderAutocorrelation(tt.x, tt.window); err == nil {
				t.Fatal("encoderAutocorrelation() error = nil")
			}
		})
	}
}

func TestEncoderLagWindowPreservesEnergyAndScalesLags(t *testing.T) {
	var rh [lpcOrder + 1]int16
	var rl [lpcOrder + 1]int16
	rh[0], rl[0] = fxp.LExtract(0x40000000)
	for i := 1; i <= lpcOrder; i++ {
		rh[i], rl[i] = fxp.LExtract(0x20000000)
	}

	rh, rl = encoderLagWindow(rh, rl)

	r0 := fxp.LComp(rh[0], rl[0])
	if r0 != 0x40000000 {
		t.Fatalf("encoderLagWindow() r[0] = %#x, want 0x40000000", uint32(r0))
	}
	for i := 1; i <= lpcOrder; i++ {
		got := fxp.LComp(rh[i], rl[i])
		if got <= 0 || got >= 0x20000000 {
			t.Fatalf("encoderLagWindow() r[%d] = %#x, want positive attenuation", i, uint32(got))
		}
	}
}

func TestEncoderMpy32MatchesReferenceExpansion(t *testing.T) {
	got := fxp.Mpy32(16384, 0, 16384, 0)
	if got != 0x20000000 {
		t.Fatalf("fxp.Mpy32(0.5,0.5) = %#x, want 0x20000000", uint32(got))
	}

	got = fxp.Mpy32(32767, 32767, 32767, 32767)
	if got <= 0 {
		t.Fatalf("fxp.Mpy32(max,max) = %#x, want positive saturated-style value", uint32(got))
	}
}

func flatWindow() [lpcWindowSamples]int16 {
	var window [lpcWindowSamples]int16
	for i := range window {
		window[i] = fxp.Max16
	}
	return window
}
