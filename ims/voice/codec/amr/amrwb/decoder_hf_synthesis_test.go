package amrwb

import "testing"

func TestGenerateHFNoiseAdvancesSeed(t *testing.T) {
	seed := int16(randomInitialSeed)

	hf, seed := generateHFNoise(seed)

	if seed == randomInitialSeed {
		t.Fatal("seed did not advance")
	}
	if hf[0] == 0 && hf[1] == 0 {
		t.Fatal("HF noise starts with all zeros")
	}
}

func TestScaleHFNoiseToExcitation(t *testing.T) {
	var hf [subframeSamples16k]int16
	exc := make([]int16, subframeSamples)
	for i := range hf {
		hf[i] = 128
	}
	for i := range exc {
		exc[i] = 2048
	}

	hf, err := scaleHFNoiseToExcitation(hf, exc, 0)
	if err != nil {
		t.Fatalf("scaleHFNoiseToExcitation() error = %v", err)
	}

	if hf[0] == 128 || hf[0] == 0 {
		t.Fatalf("hf[0] = %d, want adjusted non-zero sample", hf[0])
	}
}

func TestHFGainFromTiltReturnsFloorForSilence(t *testing.T) {
	var synth [subframeSamples]int16

	got := hfGainFromTilt(synth, [6]int16{}, 0)

	if got.gain != 3277 {
		t.Fatalf("HF gain = %d, want floor 3277", got.gain)
	}
}

func TestApplyHFGain(t *testing.T) {
	hf := make([]int16, subframeSamples16k)
	hf[0] = 1000

	applyHFGain(hf, 16384)

	if hf[0] != 500 {
		t.Fatalf("hf[0] = %d, want 500", hf[0])
	}
}

func TestApplyHFCorrectionGain(t *testing.T) {
	hf := make([]int16, subframeSamples16k)
	hf[0] = 1000

	if err := applyHFCorrectionGain(hf, 15); err != nil {
		t.Fatalf("applyHFCorrectionGain() error = %v", err)
	}

	if hf[0] != 1996 {
		t.Fatalf("hf[0] = %d, want 1996", hf[0])
	}
}
