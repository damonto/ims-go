package amrnb

import "testing"

func TestLagWindowLeavesZeroLagUnchanged(t *testing.T) {
	rh := [lpcOrder + 1]int16{16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384, 16384}
	rl := [lpcOrder + 1]int16{1234}

	rh, rl = lagWindow(rh, rl)

	if rh[0] != 16384 || rl[0] != 1234 {
		t.Fatalf("r[0] = %d/%d, want 16384/1234", rh[0], rl[0])
	}
	for i := 1; i <= lpcOrder; i++ {
		if rh[i] <= 0 || rh[i] >= 16384 {
			t.Fatalf("r[%d].hi = %d, want positive attenuation", i, rh[i])
		}
	}
}

func TestLagWindowKnownVector(t *testing.T) {
	rh := [lpcOrder + 1]int16{30000, 25000, 22000, 19000, 16000, 13000, 10000, 7000, 4000, 2000, 1000}
	rl := [lpcOrder + 1]int16{0, 100, 200, 300, 400, 500, 600, 700, 800, 900, 1000}

	rh, rl = lagWindow(rh, rl)

	wantH := [...]int16{30000, 24969, 21900, 18809, 15716, 12642, 9607, 6628, 3725, 1827, 894}
	wantL := [...]int16{0, 24989, 10600, 6796, 23129, 28027, 7247, 22566, 8843, 26877, 27753}
	for i := 0; i <= lpcOrder; i++ {
		if rh[i] != wantH[i] || rl[i] != wantL[i] {
			t.Fatalf("r[%d] = %d/%d, want %d/%d", i, rh[i], rl[i], wantH[i], wantL[i])
		}
	}
}
