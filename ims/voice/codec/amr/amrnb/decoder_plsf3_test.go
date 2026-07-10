package amrnb

import "testing"

func TestDecode3ResidualsModeBranches(t *testing.T) {
	tests := []struct {
		name    string
		mode    Mode
		indices []int16
		want    [lpcOrder]int16
	}{
		{
			name:    "MR475",
			mode:    Mode475,
			indices: []int16{1, 2, 3},
			want:    [lpcOrder]int16{154, -56, -735, 414, 67, -267, 619, 260, 183, 96},
		},
		{
			name:    "MR795",
			mode:    Mode795,
			indices: []int16{511, 4, 5},
			want:    [lpcOrder]int16{1587, 3149, 2603, 414, 67, -267, 1788, 1227, 455, 129},
		},
		{
			name:    "MR740",
			mode:    Mode740,
			indices: []int16{10, 20, 30},
			want:    [lpcOrder]int16{721, 1000, 2154, -85, -390, -725, 9, 392, 83, 94},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decode3Residuals(tt.mode, tt.indices)
			if err != nil {
				t.Fatalf("decode3Residuals() error = %v", err)
			}

			if got != tt.want {
				t.Fatalf("decode3Residuals = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDPLSF3GoodFrameKnownVector(t *testing.T) {
	state := newDPLSFState()
	lsp, err := state.decode3(Mode740, []int16{10, 20, 30})
	if err != nil {
		t.Fatalf("decode3() error = %v", err)
	}

	wantPastRQ := [lpcOrder]int16{721, 1000, 2154, -85, -390, -725, 9, 392, 83, 94}
	wantPastLSF := [lpcOrder]int16{2267, 3272, 5932, 6137, 6582, 7657, 10056, 11621, 12849, 13808}
	wantLSP := [lpcOrder]int16{29716, 26522, 13757, 12580, 9953, 3355, -11462, -20021, -25520, -28850}
	if state.pastRQ != wantPastRQ {
		t.Fatalf("pastRQ = %v, want %v; pastLSF=%v lsp=%v", state.pastRQ, wantPastRQ, state.pastLSFQ, lsp)
	}
	if state.pastLSFQ != wantPastLSF {
		t.Fatalf("pastLSFQ = %v, want %v; lsp=%v", state.pastLSFQ, wantPastLSF, lsp)
	}
	if lsp != wantLSP {
		t.Fatalf("lsp = %v, want %v", lsp, wantLSP)
	}
}

func TestDPLSF3BadFrameKnownVector(t *testing.T) {
	state := newDPLSFState()
	for i := range state.pastLSFQ {
		state.pastLSFQ[i] = meanLSF3[i] + int16((i+1)*120)
		state.pastRQ[i] = int16((i + 1) * 30)
	}
	lsp, err := state.conceal3(Mode590)
	if err != nil {
		t.Fatalf("conceal3() error = %v", err)
	}

	wantPastRQ := [lpcOrder]int16{99, 196, 289, 383, 474, 583, 688, 792, 901, 1020}
	wantPastLSF := [lpcOrder]int16{1653, 2487, 4101, 5919, 7511, 9029, 10802, 12092, 13737, 14793}
	wantLSP := [lpcOrder]int16{31126, 29105, 23147, 13831, 4265, -5236, -15721, -22279, -28630, -31249}
	if state.pastRQ != wantPastRQ {
		t.Fatalf("pastRQ = %v, want %v; pastLSF=%v lsp=%v", state.pastRQ, wantPastRQ, state.pastLSFQ, lsp)
	}
	if state.pastLSFQ != wantPastLSF {
		t.Fatalf("pastLSFQ = %v, want %v; lsp=%v", state.pastLSFQ, wantPastLSF, lsp)
	}
	if lsp != wantLSP {
		t.Fatalf("lsp = %v, want %v", lsp, wantLSP)
	}
}

func TestDPLSF3RejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name    string
		mode    Mode
		indices []int16
	}{
		{name: "short indices", mode: Mode740, indices: []int16{1, 2}},
		{name: "negative index", mode: Mode740, indices: []int16{-1, 2, 3}},
		{name: "large index", mode: Mode740, indices: []int16{32767, 2, 3}},
		{name: "MR122 mode", mode: Mode1220, indices: []int16{1, 2, 3}},
		{name: "invalid mode", mode: ModeNoData, indices: []int16{1, 2, 3}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newDPLSFState()
			before := state

			if _, err := state.decode3(tt.mode, tt.indices); err == nil {
				t.Fatal("decode3() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("decode3() changed PLSF state after rejecting input")
			}
		})
	}
}
