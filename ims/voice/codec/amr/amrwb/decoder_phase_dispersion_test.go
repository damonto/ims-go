package amrwb

import "testing"

func TestPhaseDispersionMode(t *testing.T) {
	tests := []struct {
		mode Mode
		want int16
	}{
		{mode: Mode660, want: 0},
		{mode: Mode885, want: 1},
		{mode: Mode1265, want: 2},
		{mode: Mode2385, want: 2},
	}

	for _, tt := range tests {
		if got := phaseDispersionMode(tt.mode); got != tt.want {
			t.Fatalf("phaseDispersionMode(%d) = %d, want %d", tt.mode, got, tt.want)
		}
	}
}

func TestPhaseDispersionOffKeepsCode(t *testing.T) {
	var code [subframeSamples]int16
	code[0] = 4096

	got := phaseDispersion(1000, 20000, code, 2, [8]int16{})

	if got.code[0] != 4096 {
		t.Fatalf("code[0] = %d, want unchanged 4096", got.code[0])
	}
}

func TestPhaseDispersionLowPitchSpreadsPulse(t *testing.T) {
	var code [subframeSamples]int16
	code[0] = 4096
	memory := [8]int16{1: 1000}

	got := phaseDispersion(1000, 1000, code, 0, memory)

	if got.code[0] == 4096 {
		t.Fatal("code[0] did not change after high dispersion")
	}
	if got.code[1] == 0 {
		t.Fatal("code[1] = 0, want pulse spread")
	}
	if got.memory[0] != 0 {
		t.Fatalf("prev state = %d, want 0", got.memory[0])
	}
	if got.memory[2] != 1000 {
		t.Fatalf("pitch history head = %d, want 1000", got.memory[2])
	}
}

func TestPhaseDispersionOnsetRaisesState(t *testing.T) {
	var code [subframeSamples]int16
	code[0] = 4096
	memory := [8]int16{1: 100}

	got := phaseDispersion(1000, 1000, code, 0, memory)

	if got.memory[0] != 1 {
		t.Fatalf("prev state = %d, want onset-raised state 1", got.memory[0])
	}
}
