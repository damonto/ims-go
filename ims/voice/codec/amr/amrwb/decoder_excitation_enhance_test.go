package amrwb

import "testing"

func TestEnhanceCodeGainMovesThresholdAndGain(t *testing.T) {
	threshold := int32(1000000)

	out, threshold := enhanceCodeGain(threshold, 500000, 0, 20000)

	if threshold <= 500000 {
		t.Fatalf("threshold = %d, want moved upward from gain", threshold)
	}
	if out <= 0 {
		t.Fatalf("enhanced gain = %d, want positive", out)
	}
}

func TestEnhanceCodeGainDecaysAboveThreshold(t *testing.T) {
	threshold := int32(1000000)

	out, threshold := enhanceCodeGain(threshold, 2000000, 0, 20000)

	if threshold >= 2000000 {
		t.Fatalf("threshold = %d, want decayed below gain", threshold)
	}
	if out <= 0 {
		t.Fatalf("enhanced gain = %d, want positive", out)
	}
}

func TestBuildEnhancedExcitationUsesCodeAndPitch(t *testing.T) {
	var exc [subframeSamples]int16
	var code [subframeSamples]int16
	exc[0] = 100
	code[0] = 512
	code[1] = 128

	got := buildEnhancedExcitation(exc, code, 10000, 1<<16, 0, 16000)

	if got.scaledGainCode == 0 {
		t.Fatal("scaled gain code = 0, want non-zero")
	}
	if got.excitation[0] == 100 {
		t.Fatalf("excitation[0] = %d, want enhanced output", got.excitation[0])
	}
}
