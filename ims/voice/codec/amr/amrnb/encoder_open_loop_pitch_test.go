package amrnb

import (
	"slices"
	"testing"
)

func TestOpenLoopPitch(t *testing.T) {
	tests := []struct {
		name  string
		mode  Mode
		fill  func([]int16)
		check func(*testing.T, [2]int16)
	}{
		{
			name: "MR590 periodic lag",
			mode: Mode590,
			fill: func(history []int16) {
				for i := range history {
					if i%40 == 0 {
						history[i] = 3000
					}
				}
			},
			check: func(t *testing.T, tOp [2]int16) {
				t.Helper()
				if tOp[0] != tOp[1] || tOp[0] < 39 || tOp[0] > 40 {
					t.Fatalf("T_op = %v, want both lags near the 40-sample period", tOp)
				}
			},
		},
		{
			name: "MR475 full-frame lag",
			mode: Mode475,
			fill: func(history []int16) {
				for i := range history {
					if i%50 < 25 {
						history[i] = 900
					} else {
						history[i] = -900
					}
				}
			},
			check: func(t *testing.T, tOp [2]int16) {
				t.Helper()
				if tOp[0] != tOp[1] {
					t.Fatalf("T_op = %v, want full-frame lag copied", tOp)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			history := make([]int16, pitchMax+FrameSamples)
			tt.fill(history)

			tOp, err := openLoopPitch(tt.mode, history)
			if err != nil {
				t.Fatalf("openLoopPitch() error = %v", err)
			}
			tt.check(t, tOp)
		})
	}
}

func TestOpenLoopPitchRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		mode    Mode
		history []int16
	}{
		{name: "short history", mode: Mode590, history: make([]int16, pitchMax+FrameSamples-1)},
		{name: "missing MR102 state", mode: Mode1020, history: make([]int16, pitchMax+FrameSamples)},
		{name: "invalid mode", mode: ModeNoData, history: make([]int16, pitchMax+FrameSamples)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := openLoopPitch(tt.mode, tt.history); err == nil {
				t.Fatal("openLoopPitch() error = nil, want invalid input error")
			}
		})
	}
}

func TestOpenLoopPitchRejectsInputBeforeChangingState(t *testing.T) {
	tests := []struct {
		name       string
		historyLen int
		oldLags    []int16
		gainFlags  []int16
	}{
		{
			name:       "short history",
			historyLen: pitchMax + FrameSamples - 1,
			oldLags:    []int16{31, 32, 33, 34, 35},
			gainFlags:  []int16{1, 1},
		},
		{
			name:       "short old lags",
			historyLen: pitchMax + FrameSamples,
			oldLags:    []int16{31, 32, 33, 34},
			gainFlags:  []int16{1, 1},
		},
		{
			name:       "short gain flags",
			historyLen: pitchMax + FrameSamples,
			oldLags:    []int16{31, 32, 33, 34, 35},
			gainFlags:  []int16{1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			weighted := pitchOLWeightState{oldT0Med: 37, adaW: 12, wghtFlag: 1}
			oldLags := slices.Clone(tt.oldLags)
			gainFlags := slices.Clone(tt.gainFlags)
			beforeWeighted := weighted
			beforeOldLags := slices.Clone(oldLags)
			beforeGainFlags := slices.Clone(gainFlags)

			_, err := openLoopPitchWithState(openLoopPitchInput{
				mode:       Mode1020,
				wspHistory: make([]int16, tt.historyLen),
				weighted:   &weighted,
				oldLags:    oldLags,
				olGainFlag: gainFlags,
			})
			if err == nil {
				t.Fatal("openLoopPitchWithState() error = nil, want invalid input error")
			}
			if weighted != beforeWeighted {
				t.Fatal("openLoopPitchWithState() changed weighted pitch state after rejecting input")
			}
			if !slices.Equal(oldLags, beforeOldLags) {
				t.Fatal("openLoopPitchWithState() changed old lags after rejecting input")
			}
			if !slices.Equal(gainFlags, beforeGainFlags) {
				t.Fatal("openLoopPitchWithState() changed gain flags after rejecting input")
			}
		})
	}
}
