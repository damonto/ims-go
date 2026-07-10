package amrnb

import "testing"

func TestDPLSFStateReset(t *testing.T) {
	state := newDPLSFState()

	if state.pastRQ != [lpcOrder]int16{} {
		t.Fatalf("pastRQ after reset = %v", state.pastRQ)
	}
	if state.pastLSFQ != meanLSF5 {
		t.Fatalf("pastLSFQ after reset = %v, want %v", state.pastLSFQ, meanLSF5)
	}
}

func TestDPLSFStateInitFromPastRQClampsIndex(t *testing.T) {
	state := newDPLSFState()

	state.initFromPastRQ(4)
	want := [lpcOrder]int16{-564, -943, -1520, -965, -814, -526, -322, -2, 159, 657}
	if state.pastRQ != want {
		t.Fatalf("pastRQ index 4 = %v, want %v", state.pastRQ, want)
	}

	state.initFromPastRQ(99)
	want = [lpcOrder]int16{-314, -191, -203, -330, -160, -103, -51, 131, 338, 515}
	if state.pastRQ != want {
		t.Fatalf("pastRQ clamped high = %v, want %v", state.pastRQ, want)
	}
}

func TestReorderLSFEnforcesMinimumDistance(t *testing.T) {
	lsf := []int16{0, 10, 900, 901, 902, 2000, 2100, 2101, 4096, 4097}

	reorderLSF(lsf, lsfGap)

	want := []int16{205, 410, 900, 1105, 1310, 2000, 2205, 2410, 4096, 4301}
	for i := range want {
		if lsf[i] != want[i] {
			t.Fatalf("lsf[%d] = %d, want %d; lsf=%v", i, lsf[i], want[i], lsf)
		}
	}
}
