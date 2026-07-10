package amrwb

import "testing"

func TestDecoderCoreDecodeLPCMode660ConsumesSplitISF(t *testing.T) {
	state := newDecoderCoreState()
	params := []int16{1, 0, 0, 0, 0}

	got, err := state.decodeLPC(Mode660, params, false)

	if err != nil {
		t.Fatalf("decodeLPC() error = %v", err)
	}
	if got.paramsAfter != 5 {
		t.Fatalf("paramsAfter = %d, want 5", got.paramsAfter)
	}
	if got.isf[0] != 1265 {
		t.Fatalf("isf[0] = %d, want 1265", got.isf[0])
	}
	if got.az[0] != 4096 {
		t.Fatalf("az[0] = %d, want 4096", got.az[0])
	}
}

func TestDecoderCoreDecodeLPCMode885ConsumesSevenISFIndices(t *testing.T) {
	state := newDecoderCoreState()
	params := []int16{1, 0, 0, 0, 0, 0, 0, 0}

	got, err := state.decodeLPC(Mode885, params, false)

	if err != nil {
		t.Fatalf("decodeLPC() error = %v", err)
	}
	if got.paramsAfter != 8 {
		t.Fatalf("paramsAfter = %d, want 8", got.paramsAfter)
	}
	if got.isf[0] != 1646 {
		t.Fatalf("isf[0] = %d, want 1646", got.isf[0])
	}
	if state.firstFrame {
		t.Fatal("firstFrame = true, want false")
	}
}

func TestISFStabilityClampsNegative(t *testing.T) {
	var current [lpcOrder]int16
	var old [lpcOrder]int16
	for i := range current {
		current[i] = 16000
		old[i] = 128
	}

	if got := isfStability(current[:], old[:]); got != 0 {
		t.Fatalf("stability = %d, want 0", got)
	}
}

func TestDecoderCoreDecodeLPCRejectsShortBuffers(t *testing.T) {
	tests := []struct {
		name   string
		params []int16
	}{
		{name: "short params", params: []int16{1}},
		{name: "invalid ISF index", params: []int16{1, -1, 0, 0, 0, 0, 0, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newDecoderCoreState()
			before := state

			if _, err := state.decodeLPC(Mode885, tt.params, false); err == nil {
				t.Fatal("decodeLPC() error = nil")
			}
			if state != before {
				t.Fatal("decodeLPC() changed state after input validation error")
			}
		})
	}
}
