package amrwb

import (
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestEncoderGainQuantizerSelectsValidWidths(t *testing.T) {
	var state encoderGainQuantState
	state.reset()
	sf := encoderSubframePitch{gain: 12000}
	sf.code[0] = 512

	got := state.quantize(Mode885, &sf, false)

	if got.nbits != 6 {
		t.Fatalf("Mode885 gain bits = %d, want 6", got.nbits)
	}
	if got.index < 0 || got.index >= 1<<6 {
		t.Fatalf("Mode885 gain index = %d outside 6 bits", got.index)
	}
	if got.pitch == 0 || got.code == 0 {
		t.Fatalf("quantized gains = pitch %d code %d, want non-zero", got.pitch, got.code)
	}
	if state.pastQuaEn[0] == -14336 {
		t.Fatal("past quantized energy was not updated")
	}

	got = state.quantize(Mode1265, &sf, false)
	if got.nbits != 7 {
		t.Fatalf("Mode1265 gain bits = %d, want 7", got.nbits)
	}
	if got.index < 0 || got.index >= 1<<7 {
		t.Fatalf("Mode1265 gain index = %d outside 7 bits", got.index)
	}
}

func TestEncoderGainQuantizerUsesInnovationEnergy(t *testing.T) {
	var sparseState encoderGainQuantState
	sparseState.reset()
	var sparse [subframeSamples]int16
	sparse[0] = 512
	gSparse, expSparse := sparseState.predictedCodeGain(sparse[:])

	var denseState encoderGainQuantState
	denseState.reset()
	var dense [subframeSamples]int16
	for i := range dense {
		dense[i] = 512
	}
	gDense, expDense := denseState.predictedCodeGain(dense[:])

	sparseGain := fxp.Shl32(fxp.LMult(1000, gSparse), expSparse+4)
	denseGain := fxp.Shl32(fxp.LMult(1000, gDense), expDense+4)
	if sparseGain <= denseGain {
		t.Fatalf("predicted code gain sparse/dense = %d/%d, want sparse greater", sparseGain, denseGain)
	}
}

func TestEncoderGainQuantizerIsNotClosestPitchSearch(t *testing.T) {
	var state encoderGainQuantState
	state.reset()
	sf := encoderSubframePitch{gain: 12000}
	sf.code[0] = 512

	got := state.quantize(Mode1265, &sf, false)
	closest := closestPitchIndexForTest(gainTable7Bit[:], sf.gain)

	if got.index == closest {
		t.Fatalf("gain index = %d, want weighted search to differ from closest pitch index", got.index)
	}
}

func TestGainParameterIndex(t *testing.T) {
	tests := []struct {
		mode  Mode
		pitch int
		want  int
	}{
		{mode: Mode660, pitch: 5, want: 7},
		{mode: Mode885, pitch: 8, want: 13},
		{mode: Mode1265, pitch: 8, want: 14},
		{mode: Mode1825, pitch: 8, want: 18},
		{mode: Mode2385, pitch: 8, want: 18},
	}
	for _, tt := range tests {
		if got := gainParameterIndex(tt.mode, tt.pitch); got != tt.want {
			t.Fatalf("gainParameterIndex(%d, %d) = %d, want %d",
				tt.mode, tt.pitch, got, tt.want)
		}
	}
}

func closestPitchIndexForTest(table []int16, pitch int16) int16 {
	best := 0
	bestDist := int32(fxp.Max32)
	for i := 0; i+1 < len(table); i += 2 {
		dist := int32(table[i]) - int32(pitch)
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			bestDist = dist
			best = i >> 1
		}
	}
	return int16(best)
}
