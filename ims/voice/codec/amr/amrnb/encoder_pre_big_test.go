package amrnb

import "testing"

func TestPreBigIdentityLPCCopiesSpeechFrame(t *testing.T) {
	var az [azFrameCount]int16
	for subframe := range 4 {
		az[subframe*lpcCoeffCount] = 4096
	}
	speech := make([]int16, lpcLookaheadSamples+FrameSamples)
	for i := range speech {
		speech[i] = int16(i*17 - 1200)
	}
	var memW [lpcOrder]int16

	first, err := preBig(Mode590, az, 0, speech, memW)
	if err != nil {
		t.Fatalf("preBig(first) error = %v", err)
	}
	second, err := preBig(Mode590, az, FrameSamples/2, speech, first.memW)
	if err != nil {
		t.Fatalf("preBig(second) error = %v", err)
	}
	var wsp [FrameSamples]int16
	copy(wsp[:FrameSamples/2], first.samples[:])
	copy(wsp[FrameSamples/2:], second.samples[:])
	for i := range FrameSamples {
		want := speech[lpcLookaheadSamples+i]
		if wsp[i] != want {
			t.Fatalf("wsp[%d] = %d, want %d", i, wsp[i], want)
		}
	}
}

func TestPreBigRejectsShortBuffers(t *testing.T) {
	var az [azFrameCount]int16
	var memW [lpcOrder]int16

	if _, err := preBig(Mode590, az, 0, make([]int16, lpcLookaheadSamples), memW); err == nil {
		t.Fatal("preBig() error = nil, want short speech error")
	}
}
