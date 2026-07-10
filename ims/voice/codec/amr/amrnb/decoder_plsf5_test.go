package amrnb

import "testing"

func TestDecode5ResidualsSignBit(t *testing.T) {
	got, err := decode5Residuals([]int16{0, 0, 1, 0, 0})
	if err != nil {
		t.Fatalf("decode5Residuals() error = %v", err)
	}

	want1 := [lpcOrder]int16{-451, -1065, -1631, -1600, 1812, 2275, -1857, -1681, -1002, -929}
	want2 := [lpcOrder]int16{-529, -1305, -1796, -2290, 1879, 2537, -1857, -1755, -1096, -1203}
	if got.lsf1 != want1 {
		t.Fatalf("lsf1R = %v, want %v", got.lsf1, want1)
	}
	if got.lsf2 != want2 {
		t.Fatalf("lsf2R = %v, want %v", got.lsf2, want2)
	}
}

func TestDPLSF5GoodFrameKnownVector(t *testing.T) {
	state := newDPLSFState()
	got, err := state.decode5([]int16{3, 17, 41, 9, 12})
	if err != nil {
		t.Fatalf("decode5() error = %v", err)
	}

	wantPastRQ := [lpcOrder]int16{-331, -556, -572, -619, 640, 1376, -1142, -1158, -567, -228}
	wantPastLSF := [lpcOrder]int16{1053, 1521, 2848, 4489, 7382, 9498, 9703, 9934, 12147, 13473}
	wantLSP1 := [lpcOrder]int16{32078, 31351, 27911, 21316, 4614, -8193, -9434, -11245, -23825, -28522}
	wantLSP2 := [lpcOrder]int16{32098, 31382, 27998, 21354, 5068, -8120, -9361, -10741, -22529, -27787}

	if state.pastRQ != wantPastRQ {
		t.Fatalf("pastRQ = %v, want %v", state.pastRQ, wantPastRQ)
	}
	if state.pastLSFQ != wantPastLSF {
		t.Fatalf("pastLSFQ = %v, want %v; lsp1=%v lsp2=%v", state.pastLSFQ, wantPastLSF, got.lsp1, got.lsp2)
	}
	if got.lsp1 != wantLSP1 {
		t.Fatalf("lsp1 = %v, want %v", got.lsp1, wantLSP1)
	}
	if got.lsp2 != wantLSP2 {
		t.Fatalf("lsp2 = %v, want %v", got.lsp2, wantLSP2)
	}
}

func TestDPLSF5BadFrameMovesTowardMean(t *testing.T) {
	state := newDPLSFState()
	for i := range state.pastLSFQ {
		state.pastLSFQ[i] = meanLSF5[i] + int16((i+1)*100)
		state.pastRQ[i] = int16((i + 1) * 20)
	}
	got := state.conceal5()

	wantPastRQ := [lpcOrder]int16{82, 164, 246, 328, 410, 492, 574, 655, 737, 820}
	wantPastLSF := [lpcOrder]int16{1478, 2266, 3704, 5487, 7216, 8691, 10527, 11850, 13567, 14650}
	wantLSP := [lpcOrder]int16{31454, 29718, 24837, 16239, 6095, -3131, -14185, -21141, -28103, -30968}

	if state.pastRQ != wantPastRQ {
		t.Fatalf("pastRQ = %v, want %v", state.pastRQ, wantPastRQ)
	}
	if state.pastLSFQ != wantPastLSF {
		t.Fatalf("pastLSFQ = %v, want %v; lsp1=%v lsp2=%v", state.pastLSFQ, wantPastLSF, got.lsp1, got.lsp2)
	}
	if got.lsp1 != wantLSP || got.lsp2 != wantLSP {
		t.Fatalf("lsp1/lsp2 = %v/%v, want %v", got.lsp1, got.lsp2, wantLSP)
	}
}

func TestDPLSF5RejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name    string
		indices []int16
	}{
		{name: "short indices", indices: []int16{1, 2, 3, 4}},
		{name: "negative index", indices: []int16{-1, 2, 3, 4, 5}},
		{name: "negative signed index", indices: []int16{1, 2, -1, 4, 5}},
		{name: "large index", indices: []int16{32767, 2, 3, 4, 5}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newDPLSFState()
			before := state

			if _, err := state.decode5(tt.indices); err == nil {
				t.Fatal("decode5() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("decode5() changed PLSF state after rejecting input")
			}
		})
	}
}
