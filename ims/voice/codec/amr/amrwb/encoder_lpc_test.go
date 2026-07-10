package amrwb

import "testing"

func TestEncoderLPCAnalyzeProducesSubframeFilters(t *testing.T) {
	enc, err := NewEncoder(Config{Mode: Mode2385})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	var pcm [FrameSamples]int16
	for i := range pcm {
		pcm[i] = int16((i%80 - 40) * 128)
	}

	if _, err := enc.prepareFrame(pcm[:]); err != nil {
		t.Fatalf("prepareFrame() error = %v", err)
	}
	got, err := enc.lpc.analyze(enc.oldSpeech[:], enc.speech12k8[:])

	if err != nil {
		t.Fatalf("analyze() error = %v", err)
	}
	for subframe := range 4 {
		if got.a[subframe*lpcCoeffCount] != 4096 {
			t.Fatalf("A[%d][0] = %d, want 4096", subframe, got.a[subframe*lpcCoeffCount])
		}
	}
	nonZero := false
	for _, coeff := range got.a[1:] {
		if coeff != 0 {
			nonZero = true
			break
		}
	}
	if !nonZero {
		t.Fatal("analyze() produced all-zero LPC coefficients")
	}
}

func TestUpdateEncoderOldSpeechUsesFrameTailAndLookahead(t *testing.T) {
	var oldSpeech [encoderOldSpeechSamples]int16
	var speech [frameSamples12k8 + lpcLookahead12k8]int16
	for i := range speech {
		speech[i] = int16(i + 1)
	}

	if err := updateEncoderOldSpeech(oldSpeech[:], speech[:]); err != nil {
		t.Fatalf("updateEncoderOldSpeech() error = %v", err)
	}
	for i, got := range oldSpeech {
		want := speech[frameSamples12k8-encoderOldSpeechSamples+lpcLookahead12k8+i]
		if got != want {
			t.Fatalf("oldSpeech[%d] = %d, want %d", i, got, want)
		}
	}
}
