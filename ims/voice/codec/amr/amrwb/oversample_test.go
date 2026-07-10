package amrwb

import "testing"

func TestOversample12k8To16kUsesHistoryDelay(t *testing.T) {
	var memory [oversampleMemory]int16
	memory[oversampleDelay] = 1000

	got := oversample12k8To16k([subframeSamples]int16{}, memory)
	want := []int16{1000, 231, -182, 115, -49}
	for i := range want {
		if got.signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d", i, got.signal[i], want[i])
		}
	}
}

func TestOversample12k8To16kUpdatesMemory(t *testing.T) {
	var signal [subframeSamples]int16
	copy(signal[subframeSamples-4:], []int16{1, 2, 3, 4})
	got := oversample12k8To16k(signal, [oversampleMemory]int16{})

	wantTail := []int16{1, 2, 3, 4}
	for i := range wantTail {
		value := got.memory[oversampleMemory-len(wantTail)+i]
		if value != wantTail[i] {
			t.Fatalf("memory tail[%d] = %d, want %d", i, value, wantTail[i])
		}
	}
}
