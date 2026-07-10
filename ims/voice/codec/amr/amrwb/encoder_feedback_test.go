package amrwb

import "testing"

func TestAnalyzePitchSubframesUpdatesFeedbackState(t *testing.T) {
	enc := newPreparedEncoder(t, Mode1265)
	params := make([]int16, mustParameterCount(t, Mode1265))
	analysis, err := enc.analyzeSpeech(params)
	if err != nil {
		t.Fatalf("analyzeSpeech() error = %v", err)
	}

	if _, err := enc.analyzePitchSubframes(analysis, params); err != nil {
		t.Fatalf("analyzePitchSubframes() error = %v", err)
	}

	if allZeroSamples(enc.oldExc[:]) {
		t.Fatal("old excitation was not updated")
	}
	if allZeroSamples(enc.memSyn[:]) {
		t.Fatal("synthesis memory was not updated")
	}
	if enc.tiltCode < 0 || enc.tiltCode > 16384 {
		t.Fatalf("tiltCode = %d, want 0..16384", enc.tiltCode)
	}
	if enc.gainQuant.pastQuaEn == [gainPredOrder]int16{-14336, -14336, -14336, -14336} {
		t.Fatal("gain quantizer history was not updated")
	}
}
