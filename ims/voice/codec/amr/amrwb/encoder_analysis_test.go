package amrwb

import "testing"

func TestAnalyzeSpeechBuildsEncoderFrontEnd(t *testing.T) {
	enc := newPreparedEncoder(t, Mode885)
	params := make([]int16, mustParameterCount(t, Mode885))

	got, err := enc.analyzeSpeech(params)

	if err != nil {
		t.Fatalf("analyzeSpeech() error = %v", err)
	}
	if params[0] != 1 {
		t.Fatalf("params[0] = %d, want VAD flag 1", params[0])
	}
	if got.tOp < pitchMin || got.tOp > pitchMax || got.tOp2 < pitchMin || got.tOp2 > pitchMax {
		t.Fatalf("open-loop lags = %d/%d outside pitch range", got.tOp, got.tOp2)
	}
	if got.quantLPC.indexCount != 7 {
		t.Fatalf("quantLPC index count = %d, want 7", got.quantLPC.indexCount)
	}
	if got.weighted.wsp == ([frameSamples12k8 / 2]int16{}) {
		t.Fatal("weighted speech is all zero")
	}
	if enc.oldWsp == ([oldWspSamples]int16{}) {
		t.Fatal("oldWsp history was not advanced")
	}
}

func TestAnalyzeSpeechMode660UsesSingleOpenLoopLag(t *testing.T) {
	enc := newPreparedEncoder(t, Mode660)
	params := make([]int16, mustParameterCount(t, Mode660))

	got, err := enc.analyzeSpeech(params)

	if err != nil {
		t.Fatalf("analyzeSpeech() error = %v", err)
	}
	if got.tOp != got.tOp2 {
		t.Fatalf("Mode660 open-loop lags = %d/%d, want single full-frame lag", got.tOp, got.tOp2)
	}
	if got.quantLPC.indexCount != 5 {
		t.Fatalf("quantLPC index count = %d, want 5", got.quantLPC.indexCount)
	}
	if params[3] >= 1<<14 {
		t.Fatalf("packed 6.60 ISF index = %d, want 14-bit value", params[3])
	}
}
