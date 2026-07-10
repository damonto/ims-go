package amrnb

import "testing"

func TestInterpolateLSF(t *testing.T) {
	oldLSF := []int16{400, 800, 1200, 1600, 2000, 2400, 2800, 3200, 3600, 4000}
	newLSF := []int16{800, 1200, 1600, 2000, 2400, 2800, 3200, 3600, 4000, 4400}
	out, err := interpolateLSF(oldLSF, newLSF, 0)
	if err != nil {
		t.Fatalf("interpolateLSF(0) error = %v", err)
	}
	if out[0] != 500 || out[9] != 4100 {
		t.Fatalf("subframe 0 LSF = %v, want first/last 500/4100", out)
	}

	out, err = interpolateLSF(oldLSF, newLSF, 1)
	if err != nil {
		t.Fatalf("interpolateLSF(1) error = %v", err)
	}
	if out[0] != 600 || out[9] != 4200 {
		t.Fatalf("subframe 1 LSF = %v, want first/last 600/4200", out)
	}

	out, err = interpolateLSF(oldLSF, newLSF, 2)
	if err != nil {
		t.Fatalf("interpolateLSF(2) error = %v", err)
	}
	if out[0] != 700 || out[9] != 4300 {
		t.Fatalf("subframe 2 LSF = %v, want first/last 700/4300", out)
	}

	out, err = interpolateLSF(oldLSF, newLSF, 3)
	if err != nil {
		t.Fatalf("interpolateLSF(3) error = %v", err)
	}
	if out[0] != 800 || out[9] != 4400 {
		t.Fatalf("subframe 3 LSF = %v, want first/last 800/4400", out)
	}
}

func TestInterpolateLSFRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name     string
		oldLSF   []int16
		newLSF   []int16
		subframe int
	}{
		{name: "short old LSF", oldLSF: make([]int16, lpcOrder-1), newLSF: make([]int16, lpcOrder)},
		{name: "short new LSF", oldLSF: make([]int16, lpcOrder), newLSF: make([]int16, lpcOrder-1)},
		{name: "invalid subframe", oldLSF: make([]int16, lpcOrder), newLSF: make([]int16, lpcOrder), subframe: 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := interpolateLSF(tt.oldLSF, tt.newLSF, tt.subframe); err == nil {
				t.Fatal("interpolateLSF() error = nil, want invalid input error")
			}
		})
	}
}

func TestCBGainAverageBypassesHighModesButUpdatesState(t *testing.T) {
	var state cbGainAverageState
	gain := state.average(cbGainAverageInput{
		mode:       Mode740,
		gainCode:   120,
		lsf:        meanLSF5[:],
		lsfAverage: meanLSF5[:],
	})

	if gain != 120 {
		t.Fatalf("gain = %d, want passthrough 120", gain)
	}
	if state.history[cbGainHistoryLen-1] != 120 || state.hangCount != 1 {
		t.Fatalf("state = %+v, want history tail 120 and hangCount 1", state)
	}
}

func TestCBGainAverageSmoothsEligibleModeAfterHangCount(t *testing.T) {
	var state cbGainAverageState
	state.hangCount = 40
	for i := range state.history {
		state.history[i] = 10
	}

	gain := state.average(cbGainAverageInput{
		mode:       Mode590,
		gainCode:   100,
		lsf:        meanLSF5[:],
		lsfAverage: meanLSF5[:],
	})

	if gain >= 100 {
		t.Fatalf("gain = %d, want smoothed below raw gain 100", gain)
	}
	if state.history[cbGainHistoryLen-1] != 100 {
		t.Fatalf("history tail = %d, want raw gain 100", state.history[cbGainHistoryLen-1])
	}
}

func TestDecoderCoreResetClearsCBGainAverage(t *testing.T) {
	state := newDecoderCoreState()
	state.cbGainAvg.history[0] = 100
	state.cbGainAvg.hangVar = 2
	state.cbGainAvg.hangCount = 3

	state.reset(Mode475)

	if state.cbGainAvg != (cbGainAverageState{}) {
		t.Fatalf("cbGainAvg after reset = %+v, want zero", state.cbGainAvg)
	}
}
