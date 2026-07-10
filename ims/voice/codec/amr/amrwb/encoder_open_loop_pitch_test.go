package amrwb

import "testing"

func TestInverseSqrtNormalizedTablePoint(t *testing.T) {
	frac, exp := inverseSqrtNormalized(0x40000000, 0)

	if frac != 0x5a820000 {
		t.Fatalf("inverseSqrtNormalized(0.5) frac = %#x, want table value 0x5a820000", uint32(frac))
	}
	if exp != 1 {
		t.Fatalf("inverseSqrtNormalized(0.5) exp = %d, want 1", exp)
	}
}

func TestMedianOpenLoopLagUpdatesHistory(t *testing.T) {
	history := [5]int16{40, 50, 60, 70, 80}

	got, history := updateOpenLoopLagHistory(30, history)

	if got != 50 {
		t.Fatalf("medianOpenLoopLag() = %d, want 50", got)
	}
	want := []int16{30, 40, 50, 60, 70}
	for i := range want {
		if history[i] != want[i] {
			t.Fatalf("history[%d] = %d, want %d", i, history[i], want[i])
		}
	}
}

func TestHighpassWeightedSpeechUpdatesMemory(t *testing.T) {
	wsp := make([]int16, 32)
	for i := range wsp {
		wsp[i] = int16((i%8 - 4) * 256)
	}

	got, err := highpassWeightedSpeech(wsp, [9]int16{})
	if err != nil {
		t.Fatalf("highpassWeightedSpeech() error = %v", err)
	}
	nonZero := false
	for _, sample := range got.signal[:len(wsp)] {
		if sample != 0 {
			nonZero = true
			break
		}
	}
	if !nonZero {
		t.Fatal("highpassWeightedSpeech() output is all zero")
	}
	if got.memory[6] == 0 && got.memory[7] == 0 && got.memory[8] == 0 {
		t.Fatal("highpassWeightedSpeech() input memory was not updated")
	}
}

func TestScaleHighpassWeightedSpeechMemory(t *testing.T) {
	memory := [9]int16{1, 0, 2, 0, 3, 0, 100, -100, 50}

	memory = scaleHighpassWeightedSpeechMemory(memory, 1)

	if memory[0] != 2 || memory[2] != 4 || memory[4] != 6 {
		t.Fatalf("scaled DPF memory = %v, want high parts doubled", memory[:6])
	}
	if memory[6] != 200 || memory[7] != -200 || memory[8] != 100 {
		t.Fatalf("scaled input memory = %v, want doubled", memory[6:9])
	}
}

func TestPitchMedOLFindsPeriodicLag(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode885})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	var wsp [oldWspSamples + frameSamples12k8/2]int16
	for i := range wsp {
		if i%20 < 10 {
			wsp[i] = 1000
		} else {
			wsp[i] = -1000
		}
	}

	got, err := enc.pitchMedOL(wsp[:], oldWspSamples, frameSamples12k8/4)

	if err != nil {
		t.Fatalf("pitchMedOL() error = %v", err)
	}
	if got < openLoopPitchMin || got > openLoopPitchMax {
		t.Fatalf("pitchMedOL() = %d outside search range", got)
	}
	if enc.olGain == 0 {
		t.Fatal("pitchMedOL() did not update normalized gain")
	}
}

func TestEstimateOpenLoopPitchUpdatesHistory(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode885})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	var weighted encoderWeightedSpeech
	for i := range weighted.wsp {
		weighted.wsp[i] = int16((i%17 - 8) * 128)
	}

	t0, t02, err := enc.estimateOpenLoopPitch(weighted)

	if err != nil {
		t.Fatalf("estimateOpenLoopPitch() error = %v", err)
	}
	if t0 < pitchMin || t0 > pitchMax || t02 < pitchMin || t02 > pitchMax {
		t.Fatalf("open-loop lags = %d/%d outside full-rate pitch range", t0, t02)
	}
	if enc.oldWsp == ([oldWspSamples]int16{}) {
		t.Fatal("estimateOpenLoopPitch() did not advance oldWsp")
	}
}
