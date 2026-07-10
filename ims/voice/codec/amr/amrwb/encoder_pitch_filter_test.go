package amrwb

import "testing"

func TestFilterPitchExcitationUsesPreviousAndNextSamples(t *testing.T) {
	history := make([]int16, subframeSamples+2)
	history[0] = 10
	history[1] = 20
	history[2] = 30
	history[3] = 40
	got, err := filterPitchExcitation(history)
	if err != nil {
		t.Fatalf("filterPitchExcitation() error = %v", err)
	}
	if got[0] != 20 {
		t.Fatalf("got[0] = %d, want 20", got[0])
	}
	if got[1] != 30 {
		t.Fatalf("got[1] = %d, want 30", got[1])
	}
}

func TestPitchSelectParameterIndex(t *testing.T) {
	if got := pitchSelectParameterIndex(Mode885, 0); got != -1 {
		t.Fatalf("Mode885 select index = %d, want -1", got)
	}
	if got := pitchSelectParameterIndex(Mode1265, 0); got != 9 {
		t.Fatalf("Mode1265 subframe 0 select index = %d, want 9", got)
	}
	if got := pitchSelectParameterIndex(Mode2385, 3); got != 45 {
		t.Fatalf("Mode2385 subframe 3 select index = %d, want 45", got)
	}
}
