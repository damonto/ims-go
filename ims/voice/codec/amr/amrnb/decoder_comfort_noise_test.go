package amrnb

import "testing"

func TestPseudoNoiseKnownSequence(t *testing.T) {
	seed := int32(pnInitialSeed)
	got, seed := pseudoNoise(seed, 8)

	if got != 26 {
		t.Fatalf("pseudoNoise() = %d, want 26", got)
	}
	if seed != 0x33f08169 {
		t.Fatalf("seed = %#x, want 0x33f08169", seed)
	}
}

func TestBuildCNParamKnownMode475Vector(t *testing.T) {
	seed := noDataSeed
	got, seed, err := buildCNParam(seed, Mode475, nil)
	if err != nil {
		t.Fatalf("buildCNParam() error = %v", err)
	}

	if seed != 3242 {
		t.Fatalf("seed = %d, want 3242", seed)
	}
	want := []int16{168, 59, 81, 106, 6, 1, 70, 10, 17, 3, 7, 21, 2, 250, 0, 104, 3}
	if len(got) != len(want) {
		t.Fatalf("params = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("params[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestBuildCNParamErrorPreservesSeed(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
	}{
		{name: "negative mode", mode: Mode(-1)},
		{name: "unknown mode", mode: Mode(99)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			seed := int16(noDataSeed)

			_, nextSeed, err := buildCNParam(seed, tt.mode, nil)
			if err == nil {
				t.Fatal("buildCNParam() error = nil")
			}
			if nextSeed != seed {
				t.Fatalf("seed = %d, want unchanged %d", nextSeed, seed)
			}
		})
	}
}

func TestBuildCNCodeKnownVector(t *testing.T) {
	seed := pnInitialSeed
	got, seed := buildCNCode(seed, nil)

	wantPositions := map[int]int16{
		0:  -4096,
		3:  4096,
		6:  -4096,
		7:  4096,
		8:  -4096,
		14: 4096,
		15: -4096,
		19: 4096,
		22: 4096,
		31: -4096,
	}
	for i, sample := range got {
		want := wantPositions[i]
		if sample != want {
			t.Fatalf("code[%d] = %d, want %d; non-zero=%v", i, sample, want, nonZeroSamples(got))
		}
	}
	if seed != 0x3b4974cf {
		t.Fatalf("seed = %#x, want 0x3b4974cf", seed)
	}
}

func nonZeroSamples(samples []int16) map[int]int16 {
	out := make(map[int]int16)
	for i, sample := range samples {
		if sample != 0 {
			out[i] = sample
		}
	}
	return out
}

func TestDecodeNoDataBuildsCNParamsInSpeechState(t *testing.T) {
	dec := NewDecoder()
	dec.core.dtx.globalState = dtxStateSpeech

	pcm, err := dec.Decode(nil, Frame{Mode: ModeNoData})
	if err != nil {
		t.Fatalf("Decode(no-data speech state) error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("pcm length = %d, want %d", len(pcm), FrameSamples)
	}

	want := []int16{168, 59, 81, 106, 6, 1, 70, 10, 17, 3, 7, 21, 2, 250, 0, 104, 3}
	if len(dec.params) != len(want) {
		t.Fatalf("params = %d, want %d", len(dec.params), len(want))
	}
	for i := range want {
		if dec.params[i] != want[i] {
			t.Fatalf("params[%d] = %d, want %d", i, dec.params[i], want[i])
		}
	}
	if dec.core.nodataSeed != 3242 {
		t.Fatalf("nodataSeed = %d, want 3242", dec.core.nodataSeed)
	}
}

func TestDecodeLostUsesSpeechConcealmentState(t *testing.T) {
	dec := NewDecoder()
	size, err := FrameBytes(Mode590)
	if err != nil {
		t.Fatalf("FrameBytes() error = %v", err)
	}
	if _, err := dec.Decode(nil, Frame{Mode: Mode590, Quality: true, Data: make([]byte, size)}); err != nil {
		t.Fatalf("Decode(good speech) error = %v", err)
	}

	pcm, err := dec.DecodeLost(nil)

	if err != nil {
		t.Fatalf("DecodeLost() error = %v", err)
	}
	if len(pcm) != FrameSamples {
		t.Fatalf("pcm length = %d, want %d", len(pcm), FrameSamples)
	}
	if !dec.core.prevBF {
		t.Fatalf("prevBF = %v, want bad-frame marker", dec.core.prevBF)
	}
}
