package amrwb

import "testing"

func TestEncoderVADResetInitializesReferenceState(t *testing.T) {
	var state encoderVADState
	state.background[0] = 999
	state.speechLevel = 1

	state.reset()
	for i := range vadBands {
		if state.background[i] != vadNoiseInit ||
			state.oldLevel[i] != vadNoiseInit ||
			state.average[i] != vadNoiseInit ||
			state.subLevel[i] != 0 {
			t.Fatalf("band %d reset = bckr %d old %d avg %d sub %d",
				i, state.background[i], state.oldLevel[i], state.average[i], state.subLevel[i])
		}
	}
	if state.speechLevel != vadSpeechLevelInit || state.vadReg != 0 || state.toneFlag != 0 {
		t.Fatalf("reset scalar state = speech %d vad %d tone %d",
			state.speechLevel, state.vadReg, state.toneFlag)
	}
}

func TestEncoderVADFilterBankSilence(t *testing.T) {
	var state encoderVADState
	state.reset()
	input := make([]int16, vadFrameLen)

	level, err := state.filterBank(input)
	if err != nil {
		t.Fatalf("filterBank() error = %v", err)
	}
	for i, got := range level {
		if got != 0 {
			t.Fatalf("level[%d] = %d, want 0 for silence", i, got)
		}
	}
}

func TestEncoderVADFilterBankTracksEnergyBands(t *testing.T) {
	var state encoderVADState
	state.reset()
	input := make([]int16, vadFrameLen)
	for i := range input {
		if i%4 < 2 {
			input[i] = 1200
		} else {
			input[i] = -1200
		}
	}

	level, err := state.filterBank(input)
	if err != nil {
		t.Fatalf("filterBank() error = %v", err)
	}

	var sum int
	for _, value := range level {
		if value < 0 {
			t.Fatalf("negative VAD level %d", value)
		}
		sum += int(value)
	}
	if sum == 0 {
		t.Fatal("filterBank() returned zero energy for non-zero input")
	}
	if state.subLevel == ([vadBands]int16{}) {
		t.Fatal("filterBank() did not update sub-frame level memory")
	}
}

func TestEncoderVADFilterBankRejectsShortInput(t *testing.T) {
	tests := []struct {
		name      string
		inputSize int
	}{
		{name: "empty input", inputSize: 0},
		{name: "short input", inputSize: vadFrameLen - 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state encoderVADState
			state.reset()
			before := state

			level, err := state.filterBank(make([]int16, tt.inputSize))
			if err == nil {
				t.Fatal("filterBank() error = nil")
			}
			if level != ([vadBands]int16{}) {
				t.Fatalf("level = %v, want zero value", level)
			}
			if state != before {
				t.Fatal("filterBank() changed state after input validation error")
			}
		})
	}
}

func TestEncoderVADDecisionSilence(t *testing.T) {
	var state encoderVADState
	state.reset()
	input := make([]int16, vadFrameLen)

	active, err := state.decide(input)
	if err != nil {
		t.Fatalf("decide(silence) error = %v", err)
	}
	if active {
		t.Fatal("decide(silence) = true, want false")
	}
	if state.prevPowerSum != 0 {
		t.Fatalf("prevPowerSum = %d, want 0 for silence", state.prevPowerSum)
	}
	if (state.vadReg & 0x4000) != 0 {
		t.Fatalf("vadReg = %#x, want no active decision bit", state.vadReg)
	}
}

func TestEncoderVADDecisionTracksRepeatedSpeech(t *testing.T) {
	var state encoderVADState
	state.reset()
	input := make([]int16, vadFrameLen)
	for i := range input {
		if i%4 < 2 {
			input[i] = 9000
		} else {
			input[i] = -9000
		}
	}

	var speech bool
	for range 6 {
		active, err := state.decide(input)
		if err != nil {
			t.Fatalf("decide(repeated speech) error = %v", err)
		}
		speech = active || speech
	}

	if !speech {
		t.Fatal("decide(repeated speech-like input) never returned true")
	}
	if state.burstCount == 0 {
		t.Fatal("burstCount was not updated for repeated speech-like input")
	}
	if state.speechEstimateCount == 0 {
		t.Fatal("speechEstimateCount was not advanced")
	}
}

func TestEncoderVADDecisionRejectsShortInput(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{name: "one sample short", size: vadFrameLen - 1},
		{name: "empty", size: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state encoderVADState
			state.reset()
			before := state

			if _, err := state.decide(make([]int16, tt.size)); err == nil {
				t.Fatal("decide(short input) error = nil")
			}
			if state != before {
				t.Fatal("decide() changed state after input validation error")
			}
		})
	}
}
