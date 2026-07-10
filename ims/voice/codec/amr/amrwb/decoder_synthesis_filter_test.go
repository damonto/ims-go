package amrwb

import "testing"

func TestWBSynthesisFilterIdentity(t *testing.T) {
	a := make([]int16, lpcOrder+1)
	a[0] = 4096
	x := make([]int16, subframeSamples16k)
	for i := range x {
		x[i] = int16((i + 1) * 100)
	}
	mem := make([]int16, lpcOrder)

	got, err := wbSynthesisFilter(a, x, mem)
	if err != nil {
		t.Fatalf("wbSynthesisFilter() error = %v", err)
	}

	for i := range x {
		want := x[i] / 2
		if got.signal[i] != want {
			t.Fatalf("signal[%d] = %d, want %d", i, got.signal[i], want)
		}
	}
	if got.memory[0] != got.signal[len(x)-lpcOrder] || got.memory[lpcOrder-1] != got.signal[len(x)-1] {
		t.Fatalf("memory tail was not updated from output")
	}
}

func TestDeemphasis32UsesMemory(t *testing.T) {
	var xHi [subframeSamples]int16
	var xLo [subframeSamples]int16
	xHi[0] = 1
	mem := int16(100)

	got := deemphasis32(xHi, xLo, 0, mem)

	if got.signal[0] != 16 || got.signal[1] != 0 {
		t.Fatalf("signal[:2] = %v, want [16 0]", got.signal[:2])
	}
	if got.memory != got.signal[subframeSamples-1] {
		t.Fatalf("memory = %d, want %d", got.memory, got.signal[subframeSamples-1])
	}
}

func TestSynthesisFilter32SplitsExcitation(t *testing.T) {
	a := make([]int16, lpcOrder+1)
	a[0] = 4096
	exc := []int16{1000, -1000}

	gotSignal, err := synthesisFilter32(a, exc, 0, [lpcOrder]int16{}, [lpcOrder]int16{})
	if err != nil {
		t.Fatalf("synthesisFilter32() error = %v", err)
	}

	for i := range exc {
		got := (int32(gotSignal.high[i]) << 16) + (int32(gotSignal.low[i]) << 4)
		want := int32(exc[i]) << 12
		if got != want {
			t.Fatalf("split[%d] reconstructs %d, want %d", i, got, want)
		}
	}
}

func TestSynthesisFilter32UsesHistory(t *testing.T) {
	a := make([]int16, lpcOrder+1)
	a[0] = 4096
	a[1] = 4096
	exc := []int16{0}
	var historyHigh [lpcOrder]int16
	historyHigh[lpcOrder-1] = 4

	got, err := synthesisFilter32(a, exc, 0, historyHigh, [lpcOrder]int16{})
	if err != nil {
		t.Fatalf("synthesisFilter32() error = %v", err)
	}

	if got.high[0] >= 0 {
		t.Fatalf("hi history feedback = %d, want negative", got.high[0])
	}
}

func TestScaleSignalLeftRight(t *testing.T) {
	left := []int16{1000, -1000}
	scaleSignal(left, 1)
	if left[0] != 2000 || left[1] != -2000 {
		t.Fatalf("left = %v, want [2000 -2000]", left)
	}

	right := []int16{1001, -1001}
	scaleSignal(right, -1)
	if right[0] != 501 || right[1] != -500 {
		t.Fatalf("right = %v, want [501 -500]", right)
	}

	saturated := []int16{32767}
	scaleSignal(saturated, -1)
	if saturated[0] != 16384 {
		t.Fatalf("saturated = %v, want [16384]", saturated)
	}
}
