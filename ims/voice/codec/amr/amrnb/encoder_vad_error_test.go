package amrnb

import "testing"

func TestEncoderVADRejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name     string
		pcmLen   int
		powerLen int
	}{
		{name: "short pcm", pcmLen: FrameSamples - 1, powerLen: FrameSamples},
		{name: "long pcm", pcmLen: FrameSamples + 1, powerLen: FrameSamples},
		{name: "short power", pcmLen: FrameSamples, powerLen: FrameSamples - 1},
		{name: "long power", pcmLen: FrameSamples, powerLen: FrameSamples + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state encoderVADState
			state.reset()
			before := state

			if _, err := state.activeWithPower(make([]int16, tt.pcmLen), make([]int16, tt.powerLen)); err == nil {
				t.Fatal("activeWithPower() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("activeWithPower() changed VAD state after rejecting input")
			}
		})
	}
}

func TestEncoderVAD2RejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name   string
		pcmLen int
	}{
		{name: "short pcm", pcmLen: FrameSamples - 1},
		{name: "long pcm", pcmLen: FrameSamples + 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state encoderVAD2State
			state.reset()
			before := state

			if _, err := state.active(make([]int16, tt.pcmLen)); err == nil {
				t.Fatal("active() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("active() changed VAD2 state after rejecting input")
			}
		})
	}
}

func TestEncoderVoiceActiveRejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name string
		vad  VADOption
	}{
		{name: "VAD1", vad: VAD1},
		{name: "VAD2", vad: VAD2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder, err := NewEncoder(Config{Mode: Mode590, VAD: tt.vad})
			if err != nil {
				t.Fatalf("NewEncoder() error = %v", err)
			}
			beforeVAD := encoder.vad
			beforeVAD2 := encoder.vad2

			if _, err := encoder.voiceActive(make([]int16, FrameSamples-1)); err == nil {
				t.Fatal("voiceActive() error = nil, want invalid input error")
			}
			if encoder.vad != beforeVAD || encoder.vad2 != beforeVAD2 {
				t.Fatal("voiceActive() changed VAD state after rejecting input")
			}
		})
	}
}
