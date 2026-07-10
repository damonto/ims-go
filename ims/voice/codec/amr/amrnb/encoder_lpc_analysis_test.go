package amrnb

import "testing"

func TestEncoderLPCAnalyze(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		period     int
		scale      int
		offset     int
		wantMidLPC bool
	}{
		{name: "MR795", mode: Mode795, period: 23, scale: 53},
		{name: "MR122", mode: Mode1220, period: 19, scale: 67, offset: -300, wantMidLPC: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newEncoderLPCState()
			speech := make([]int16, len(window20040))
			for i := range speech {
				speech[i] = int16((i%tt.period)*tt.scale + tt.offset)
			}

			a, err := state.analyze(tt.mode, speech)
			if err != nil {
				t.Fatalf("analyze() error = %v", err)
			}
			if a[3*lpcCoeffCount] != 4096 {
				t.Fatalf("final LPC a[0] = %d, want 4096", a[3*lpcCoeffCount])
			}
			if allZero(a[3*lpcCoeffCount+1 : 4*lpcCoeffCount]) {
				t.Fatal("final LPC coefficients are all zero")
			}
			if tt.wantMidLPC {
				if a[lpcCoeffCount] != 4096 {
					t.Fatalf("mid LPC a[0] = %d, want 4096", a[lpcCoeffCount])
				}
				if a[lpcCoeffCount+1] == 0 && a[3*lpcCoeffCount+1] == 0 {
					t.Fatal("MR122 LPC coefficients were not populated")
				}
			}
		})
	}
}

func TestEncoderLPCAnalyzeRejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name   string
		mode   Mode
		speech []int16
	}{
		{name: "short speech", mode: Mode795, speech: make([]int16, len(window20040)-1)},
		{name: "invalid mode", mode: ModeNoData, speech: make([]int16, len(window20040))},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newEncoderLPCState()
			before := state

			if _, err := state.analyze(tt.mode, tt.speech); err == nil {
				t.Fatal("analyze() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("analyze() changed LPC state after rejecting input")
			}
		})
	}
}
