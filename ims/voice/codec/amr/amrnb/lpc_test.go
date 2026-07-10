package amrnb

import "testing"

func TestLSFToLSPTablePoints(t *testing.T) {
	lsf := [lpcOrder]int16{0, 4096, 8192, 12288, 16384, 16384, 16384, 16384, 16384, 16384}
	lsp := lsfToLsp(lsf[:])

	want := []int16{32767, 23170, 0, -23170, -32729}
	for i := range want {
		if lsp[i] != want[i] {
			t.Fatalf("lsp[%d] = %d, want %d", i, lsp[i], want[i])
		}
	}
}

func TestLSPToLSFTablePoints(t *testing.T) {
	lsp := []int16{
		lspCosTable[0],
		lspCosTable[8],
		lspCosTable[16],
		lspCosTable[24],
		lspCosTable[32],
		lspCosTable[40],
		lspCosTable[48],
		lspCosTable[56],
		lspCosTable[60],
		lspCosTable[63],
	}
	lsf := lspToLsf(lsp)

	want := []int16{0, 2048, 4096, 6144, 8192, 10240, 12288, 14336, 15360, 16128}
	for i := range want {
		if lsf[i] != want[i] {
			t.Fatalf("lsf[%d] = %d, want %d", i, lsf[i], want[i])
		}
	}
}

func TestLSPAvgResetAndUpdate(t *testing.T) {
	state := newLSPAvgState()

	if state.meanSave != meanLSF5 {
		t.Fatalf("meanSave after reset = %v, want %v", state.meanSave, meanLSF5)
	}

	state.update([]int16{0, 1000, 2000, 3000, 4000, 5000, 6000, 7000, 8000, 9000})

	want := [lpcOrder]int16{1163, 1905, 3193, 4771, 6303, 7622, 9245, 10437, 11960, 12949}
	if state.meanSave != want {
		t.Fatalf("meanSave after update = %v, want %v", state.meanSave, want)
	}
}

func TestLSPToAzKnownVector(t *testing.T) {
	az := lspToAz(initialLSP[:])

	want := []int16{4096, -3750, 6003, -4924, 5959, -4316, 4045, -2402, 1808, -729, 346}
	for i := range want {
		if az[i] != want[i] {
			t.Fatalf("az[%d] = %d, want %d", i, az[i], want[i])
		}
	}
}

func TestIntLPC1To3UsesFourSubframes(t *testing.T) {
	var oldLSP [lpcOrder]int16
	var newLSP [lpcOrder]int16
	copy(oldLSP[:], initialLSP[:])
	for i := range newLSP {
		newLSP[i] = initialLSP[i] - int16((i+1)*512)
	}
	az := interpolateLPC1To3(oldLSP[:], newLSP[:])
	for subframe := range 4 {
		if got := az[subframe*lpcCoeffCount]; got != 4096 {
			t.Fatalf("subframe %d az[0] = %d, want 4096", subframe, got)
		}
	}
	if az[1] == az[3*lpcCoeffCount+1] {
		t.Fatalf("first and fourth subframe LPC coefficients unexpectedly match: %d", az[1])
	}
}

func TestIntLPC1And3UsesMidpoint(t *testing.T) {
	var midLSP [lpcOrder]int16
	var newLSP [lpcOrder]int16
	copy(midLSP[:], initialLSP[:])
	copy(newLSP[:], initialLSP[:])
	for i := range midLSP {
		midLSP[i] -= int16((i + 1) * 300)
		newLSP[i] -= int16((i + 1) * 600)
	}
	az := interpolateLPC1And3(initialLSP[:], midLSP[:], newLSP[:])

	if az[0] != 4096 || az[lpcCoeffCount] != 4096 ||
		az[2*lpcCoeffCount] != 4096 || az[3*lpcCoeffCount] != 4096 {
		t.Fatalf("interpolated LPC filters do not start with unity: %v", az)
	}
	if az[lpcCoeffCount+1] == az[3*lpcCoeffCount+1] {
		t.Fatalf("mid and final LPC coefficients unexpectedly match: %d", az[lpcCoeffCount+1])
	}
}
