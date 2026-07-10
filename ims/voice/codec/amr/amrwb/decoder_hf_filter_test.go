package amrwb

import "testing"

func TestBandPass6k7kImpulse(t *testing.T) {
	var signal [subframeSamples16k]int16
	signal[0] = 32767
	signal[subframeSamples16k-1] = 32767

	got := bandPass6k7k(signal, [hfFIRMemory]int16{})

	want := []int16{-8, 12, 8, -7}
	for i := range want {
		if got.signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d", i, got.signal[i], want[i])
		}
	}
	if got.memory[hfFIRMemory-1] != 8191 {
		t.Fatalf("memory tail = %d, want scaled impulse 8191", got.memory[hfFIRMemory-1])
	}
}

func TestLowPass7kImpulse(t *testing.T) {
	var signal [subframeSamples16k]int16
	signal[0] = 32767
	signal[subframeSamples16k-1] = 32767

	got := lowPass7k(signal, [hfFIRMemory]int16{})

	want := []int16{-21, 47, -89, 146}
	for i := range want {
		if got.signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d", i, got.signal[i], want[i])
		}
	}
	if got.memory[hfFIRMemory-1] != 32767 {
		t.Fatalf("memory tail = %d, want impulse 32767", got.memory[hfFIRMemory-1])
	}
}
