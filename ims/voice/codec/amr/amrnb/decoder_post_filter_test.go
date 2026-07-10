package amrnb

import "testing"

func TestWeightLPCKeepsLeadingCoefficient(t *testing.T) {
	a := []int16{4096, 1000, -2000, 3000, -4000, 5000, -6000, 7000, -8000, 9000, -10000}
	out, err := weightLPC(a, postFilterGamma4[:])
	if err != nil {
		t.Fatalf("weightLPC() error = %v", err)
	}

	if out[0] != 4096 {
		t.Fatalf("out[0] = %d, want 4096", out[0])
	}
	if out[1] != 700 {
		t.Fatalf("out[1] = %d, want rounded weighted coefficient 700", out[1])
	}
}

func TestWeightLPCRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		a      []int16
		factor []int16
	}{
		{name: "short LPC", a: make([]int16, lpcCoeffCount-1), factor: make([]int16, lpcOrder)},
		{name: "short factors", a: make([]int16, lpcCoeffCount), factor: make([]int16, lpcOrder-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := weightLPC(tt.a, tt.factor); err == nil {
				t.Fatal("weightLPC() error = nil, want invalid input error")
			}
		})
	}
}

func TestPreemphasisUsesPastMemory(t *testing.T) {
	mem := int16(100)
	signal := []int16{1000, 2000, -1000}

	mem = preemphasis(signal, 16384, mem)

	want := []int16{950, 1500, -2000}
	for i := range want {
		if signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d; signal=%v", i, signal[i], want[i], signal)
		}
	}
	if mem != -1000 {
		t.Fatalf("mem = %d, want original tail -1000", mem)
	}
}

func TestPostFilterAGCZeroOutputClearsPastGain(t *testing.T) {
	var state postFilterState
	state.reset()

	state.agc(make([]int16, subframeSamples), make([]int16, subframeSamples), postFilterAGCFactor)

	if state.pastGain != 0 {
		t.Fatalf("pastGain = %d, want 0 after zero output energy", state.pastGain)
	}
}

func TestPostFilterProcessUpdatesHistory(t *testing.T) {
	var state postFilterState
	state.reset()
	speech := make([]int16, FrameSamples)
	for i := range speech {
		speech[i] = int16(i - 80)
	}
	var az [azFrameCount]int16
	for subframe := range 4 {
		az[subframe*lpcCoeffCount] = 4096
	}

	filtered, err := state.process(Mode740, speech, az)
	if err != nil {
		t.Fatalf("process() error = %v", err)
	}

	if state.synthBuf[0] != 70 || state.synthBuf[lpcOrder-1] != 79 {
		t.Fatalf("history tail = %v, want original final 10 input samples", state.synthBuf[:lpcOrder])
	}
	if state.pastGain == 4096 {
		t.Fatalf("pastGain was not updated")
	}
	if filtered == [FrameSamples]int16{} {
		t.Fatal("filtered speech is all zero")
	}
}

func TestPostFilterProcessRejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name   string
		mode   Mode
		speech []int16
	}{
		{name: "invalid mode", mode: ModeNoData, speech: make([]int16, FrameSamples)},
		{name: "short speech", mode: Mode740, speech: make([]int16, FrameSamples-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state postFilterState
			state.reset()
			before := state

			if _, err := state.process(tt.mode, tt.speech, [azFrameCount]int16{}); err == nil {
				t.Fatal("process() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("process() changed post-filter state after rejecting input")
			}
		})
	}
}
