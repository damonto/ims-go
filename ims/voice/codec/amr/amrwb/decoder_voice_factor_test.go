package amrwb

import "testing"

func TestVoiceFactorVoicedDominates(t *testing.T) {
	var exc [subframeSamples]int16
	var code [subframeSamples]int16
	for i := range exc {
		exc[i] = 512
	}

	got := voiceFactor(exc, -3, 12000, code, 1)

	if got < 30000 {
		t.Fatalf("voiceFactor voiced = %d, want close to 32767", got)
	}
}

func TestVoiceFactorUnvoicedDominates(t *testing.T) {
	var exc [subframeSamples]int16
	var code [subframeSamples]int16
	for i := range code {
		code[i] = 512
	}

	got := voiceFactor(exc, -3, 0, code, 16000)

	if got > -30000 {
		t.Fatalf("voiceFactor unvoiced = %d, want close to -32767", got)
	}
}

func TestVoiceFactorIncreasesWithPitchGain(t *testing.T) {
	var exc [subframeSamples]int16
	var code [subframeSamples]int16
	for i := range exc {
		exc[i] = 512
		code[i] = 512
	}

	low := voiceFactor(exc, -3, 1000, code, 12000)
	high := voiceFactor(exc, -3, 16000, code, 12000)

	if high <= low {
		t.Fatalf("voiceFactor low/high = %d/%d, want higher pitch gain to increase voicing", low, high)
	}
}
