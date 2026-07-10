package amrnb

import "testing"

func TestSubframePreprocessEncodeIdentityLPC(t *testing.T) {
	a := make([]int16, lpcCoeffCount)
	aq := make([]int16, lpcCoeffCount)
	a[0], aq[0] = 4096, 4096
	speech := make([]int16, lpcLookaheadSamples+FrameSamples)
	for i := range speech {
		speech[i] = int16(i*13 - 700)
	}
	var memErr [lpcOrder]int16
	var memW0 [lpcOrder]int16
	got, err := subframePreprocessEncode(subframePreprocessInput{
		mode:        Mode590,
		lpc:         a,
		quantLPC:    aq,
		speech:      speech,
		frameOffset: subframeSamples,
		memErr:      memErr[:],
		memW0:       memW0[:],
	})
	if err != nil {
		t.Fatalf("subframePreprocessEncode() error = %v", err)
	}

	if got.h1[0] != 4096 {
		t.Fatalf("h1[0] = %d, want 4096", got.h1[0])
	}
	for i := 1; i < subframeSamples; i++ {
		if got.h1[i] != 0 {
			t.Fatalf("h1[%d] = %d, want 0", i, got.h1[i])
		}
	}
	for i := range subframeSamples {
		want := speech[lpcLookaheadSamples+subframeSamples+i]
		if got.res[i] != want || got.exc[i] != want || got.error[i] != want || got.xn[i] != want {
			t.Fatalf(
				"sample %d res/exc/error/xn = %d/%d/%d/%d, want %d",
				i,
				got.res[i],
				got.exc[i],
				got.error[i],
				got.xn[i],
				want,
			)
		}
	}
}

func TestSubframePreprocessEncodeRejectsInvalidInput(t *testing.T) {
	a := make([]int16, lpcCoeffCount)
	aq := make([]int16, lpcCoeffCount)
	speech := make([]int16, lpcLookaheadSamples+FrameSamples)
	var memErr [lpcOrder]int16
	var memW0 [lpcOrder]int16
	tests := []struct {
		name   string
		a      []int16
		aq     []int16
		speech []int16
		offset int
	}{
		{
			name:   "short LPC",
			a:      a[:lpcCoeffCount-1],
			aq:     aq,
			speech: speech,
		},
		{
			name:   "short speech",
			a:      a,
			aq:     aq,
			speech: speech[:len(speech)-1],
		},
		{
			name:   "negative offset",
			a:      a,
			aq:     aq,
			speech: speech,
			offset: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := subframePreprocessEncode(subframePreprocessInput{
				mode:        Mode590,
				lpc:         tt.a,
				quantLPC:    tt.aq,
				speech:      tt.speech,
				frameOffset: tt.offset,
				memErr:      memErr[:],
				memW0:       memW0[:],
			})
			if err == nil {
				t.Fatal("subframePreprocessEncode() error = nil")
			}
		})
	}
}
