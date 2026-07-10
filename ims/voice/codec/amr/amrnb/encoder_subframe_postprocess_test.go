package amrnb

import "testing"

func TestSubframePostprocessEncodeUpdatesEncoderState(t *testing.T) {
	aq := make([]int16, lpcCoeffCount)
	aq[0] = 4096
	speech := make([]int16, FrameSamples)
	synth := make([]int16, FrameSamples)
	exc := make([]int16, FrameSamples)
	var sub encoderSubframeAnalysis
	var memSyn [lpcOrder]int16
	var memErr [lpcOrder]int16
	var memW0 [lpcOrder]int16
	for i := range subframeSamples {
		exc[i] = int16(100 + i)
		sub.fixed.code[i] = 4096
		sub.pitch.yl[i] = 300
		sub.fixed.y2[i] = 200
		sub.xn[i] = 500
		speech[i] = int16(1000 - i)
	}

	sharp, err := subframePostprocessEncode(
		subframePostprocessInput{
			mode:       Mode590,
			offset:     0,
			gainPit:    10000,
			gainCode:   1200,
			quantLPC:   aq,
			speech:     speech,
			synth:      synth,
			sub:        &sub,
			memSyn:     memSyn[:],
			memErr:     memErr[:],
			memW0:      memW0[:],
			excitation: exc,
		},
	)
	if err != nil {
		t.Fatalf("subframePostprocessEncode() error = %v", err)
	}

	if sharp != 10000 {
		t.Fatalf("sharp = %d, want pitch gain", sharp)
	}
	if exc[0] == 100 {
		t.Fatal("excitation was not updated")
	}
	if memSyn[lpcOrder-1] == 0 {
		t.Fatal("synthesis memory was not updated")
	}
	if memErr[0] == 0 {
		t.Fatal("error memory was not updated")
	}
	if memW0[0] == 0 {
		t.Fatal("weighting memory was not updated")
	}
}

func TestSubframePostprocessEncodeRejectsInvalidInput(t *testing.T) {
	aq := make([]int16, lpcCoeffCount)
	speech := make([]int16, FrameSamples)
	synth := make([]int16, FrameSamples)
	exc := make([]int16, FrameSamples)
	var sub encoderSubframeAnalysis
	var memSyn [lpcOrder]int16
	var memErr [lpcOrder]int16
	var memW0 [lpcOrder]int16
	tests := []struct {
		name   string
		aq     []int16
		sub    *encoderSubframeAnalysis
		exc    []int16
		offset int
	}{
		{
			name: "missing subframe",
			aq:   aq,
			exc:  exc,
		},
		{
			name: "short excitation",
			aq:   aq,
			sub:  &sub,
			exc:  exc[:subframeSamples-1],
		},
		{
			name:   "negative offset",
			aq:     aq,
			sub:    &sub,
			exc:    exc,
			offset: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := subframePostprocessEncode(
				subframePostprocessInput{
					mode:       Mode590,
					offset:     tt.offset,
					gainPit:    10000,
					gainCode:   1200,
					quantLPC:   tt.aq,
					speech:     speech,
					synth:      synth,
					sub:        tt.sub,
					memSyn:     memSyn[:],
					memErr:     memErr[:],
					memW0:      memW0[:],
					excitation: tt.exc,
				},
			)
			if err == nil {
				t.Fatal("subframePostprocessEncode() error = nil")
			}
		})
	}
}
