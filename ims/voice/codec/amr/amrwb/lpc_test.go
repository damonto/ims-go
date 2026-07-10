package amrwb

import "testing"

func TestISFToISPTablePoints(t *testing.T) {
	isf := make([]int16, lpcOrder)
	isf[0] = 0
	isf[1] = 8192
	isf[2] = 16256
	isf[lpcOrder-1] = 4096

	isp, err := isfToISP(isf)
	if err != nil {
		t.Fatalf("isfToISP() error = %v", err)
	}

	if isp[0] != 32767 {
		t.Fatalf("isp[0] = %d, want 32767", isp[0])
	}
	if isp[1] != 0 {
		t.Fatalf("isp[1] = %d, want 0", isp[1])
	}
	if isp[2] != -32758 {
		t.Fatalf("isp[2] = %d, want -32758", isp[2])
	}
	if isp[lpcOrder-1] != 0 {
		t.Fatalf("last isp = %d, want 0 after doubled ISF table lookup", isp[lpcOrder-1])
	}
}

func TestISPToAzInitialProducesStableShape(t *testing.T) {
	az, err := ispToAz(initialISP[:], false)
	if err != nil {
		t.Fatalf("ispToAz() error = %v", err)
	}

	if az[0] != 4096 {
		t.Fatalf("az[0] = %d, want 4096", az[0])
	}
	if az[lpcOrder] != 184 {
		t.Fatalf("az[%d] = %d, want 184", lpcOrder, az[lpcOrder])
	}
}

func TestInterpolateISPBuildsFourSubframes(t *testing.T) {
	az, err := interpolateISP(initialISP[:], initialISP[:])
	if err != nil {
		t.Fatalf("interpolateISP() error = %v", err)
	}

	single, err := ispToAz(initialISP[:], false)
	if err != nil {
		t.Fatalf("ispToAz() error = %v", err)
	}
	for subframe := range 4 {
		for i := range lpcCoeffCount {
			got := az[subframe*lpcCoeffCount+i]
			if got != single[i] {
				t.Fatalf("az[%d][%d] = %d, want %d", subframe, i, got, single[i])
			}
		}
	}
}

func TestNormalizeAMRWBKnownRegions(t *testing.T) {
	tests := []struct {
		value int32
		want  int16
	}{
		{value: 0x10000000, want: 2},
		{value: 0x01000000, want: 6},
		{value: 0x00100000, want: 10},
		{value: 0x00010000, want: 14},
	}

	for _, tt := range tests {
		if got := normalizeAMRWB(tt.value); got != tt.want {
			t.Fatalf("normalizeAMRWB(%#x) = %d, want %d", tt.value, got, tt.want)
		}
	}
}

func TestWeightLPC(t *testing.T) {
	var a [lpcCoeffCount]int16
	copy(a[:], []int16{4096, 1000, -1000, 2000})

	ap, err := weightLPC(a[:], 16384)
	if err != nil {
		t.Fatalf("weightLPC() error = %v", err)
	}

	want := []int16{4096, 500, -250, 250}
	for i := range want {
		if ap[i] != want[i] {
			t.Fatalf("ap[%d] = %d, want %d", i, ap[i], want[i])
		}
	}
}

func TestReorderISF(t *testing.T) {
	isf := [lpcOrder]int16{0, 10, 20, 500}

	isf = reorderISF(isf, 128)

	want := []int16{128, 256, 384, 512}
	for i := range want {
		if isf[i] != want[i] {
			t.Fatalf("isf[%d] = %d, want %d", i, isf[i], want[i])
		}
	}
}

func TestMedian5(t *testing.T) {
	got := median5([]int16{30, 10, 50, 20, 40})

	if got != 30 {
		t.Fatalf("median5() = %d, want 30", got)
	}
}
