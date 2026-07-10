package amrwb

import "testing"

func TestHighpass50HzAt12k8Impulse(t *testing.T) {
	signal := []int16{1000, 0, 0}

	memory := highpass50HzAt12k8(signal, [6]int16{})

	want := []int16{990, -21, -21}
	for i := range want {
		if signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d", i, signal[i], want[i])
		}
	}
	if memory[4] != 0 || memory[5] != 0 {
		t.Fatalf("input history = [%d %d], want [0 0]", memory[4], memory[5])
	}
}

func TestHighpass400HzAt12k8Impulse(t *testing.T) {
	signal := []int16{1000, 0, 0}

	memory := highpass400HzAt12k8(signal, [6]int16{})

	want := []int16{56, -12, -14}
	for i := range want {
		if signal[i] != want[i] {
			t.Fatalf("signal[%d] = %d, want %d", i, signal[i], want[i])
		}
	}
	if memory[4] != 0 || memory[5] != 0 {
		t.Fatalf("input history = [%d %d], want [0 0]", memory[4], memory[5])
	}
}

func TestAMRWBShl1RoundSaturates(t *testing.T) {
	if got := amrWBShl1Round(0x40000000); got != 32767 {
		t.Fatalf("positive saturation = %d, want 32767", got)
	}
	if got := amrWBShl1Round(-0x40000001); got != -32768 {
		t.Fatalf("negative saturation = %d, want -32768", got)
	}
}
