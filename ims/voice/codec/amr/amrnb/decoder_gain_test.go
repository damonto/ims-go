package amrnb

import "testing"

func TestDGainPitchKnownTable(t *testing.T) {
	tests := []struct {
		name  string
		mode  Mode
		index int16
		want  int16
	}{
		{name: "first", mode: Mode795, index: 0, want: 0},
		{name: "middle", mode: Mode795, index: 7, want: 13107},
		{name: "mr122_clears_two_low_bits", mode: Mode1220, index: 14, want: 18840},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dGainPitch(tt.mode, tt.index)

			if got != tt.want {
				t.Fatalf("dGainPitch(%d, %d) = %d, want %d", tt.mode, tt.index, got, tt.want)
			}
		})
	}
}

func TestDGainCodeKnownVectors(t *testing.T) {
	code := make([]int16, subframeSamples)
	code[0] = 8191
	code[7] = -8192
	code[19] = 4096

	tests := []struct {
		name        string
		mode        Mode
		index       int16
		want        int16
		wantHistory [gainPredTaps]int16
	}{
		{name: "MR795", mode: Mode795, index: 17, want: 37, wantHistory: [gainPredTaps]int16{2044, minEnergy, minEnergy, minEnergy}},
		{name: "MR122", mode: Mode1220, index: 17, want: 16, wantHistory: [gainPredTaps]int16{2044, minEnergy, minEnergy, minEnergy}},
		{name: "index_masks_to_31", mode: Mode795, index: 63, want: 398, wantHistory: [gainPredTaps]int16{23097, minEnergy, minEnergy, minEnergy}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newGainPredState()

			got := dGainCode(&state, tt.mode, tt.index, code)

			if got != tt.want {
				t.Fatalf("dGainCode = %d, want %d", got, tt.want)
			}
			if state.pastQuaEn != tt.wantHistory {
				t.Fatalf("pastQuaEn = %v, want %v", state.pastQuaEn, tt.wantHistory)
			}
		})
	}
}

func TestDecGainKnownVectors(t *testing.T) {
	code := make([]int16, subframeSamples)
	code[0] = 8191
	code[7] = -8192
	code[19] = 4096

	tests := []struct {
		name      string
		mode      Mode
		index     int16
		evenSubfr int16
		wantPit   int16
		wantCode  int16
		wantEner  int16
	}{
		{name: "MR475_even", mode: Mode475, index: 0, evenSubfr: 1, wantPit: 812, wantCode: 0, wantEner: -30825},
		{name: "MR475_odd", mode: Mode475, index: 0, evenSubfr: 0, wantPit: 542, wantCode: 0, wantEner: -30028},
		{name: "MR67_highrate", mode: Mode670, index: 4, wantPit: 2373, wantCode: 4, wantEner: -9394},
		{name: "MR59_lowrate", mode: Mode590, index: 7, wantPit: 11304, wantCode: 7, wantEner: -8609},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newGainPredState()

			gotPit, gotCode := decGain(&state, tt.mode, tt.index, code, tt.evenSubfr)

			if gotPit != tt.wantPit || gotCode != tt.wantCode {
				t.Fatalf("decGain = (%d, %d), want (%d, %d)",
					gotPit, gotCode, tt.wantPit, tt.wantCode)
			}
			if state.pastQuaEn[0] != tt.wantEner {
				t.Fatalf("pastQuaEn[0] = %d, want %d", state.pastQuaEn[0], tt.wantEner)
			}
		})
	}
}
