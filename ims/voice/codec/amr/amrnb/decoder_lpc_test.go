package amrnb

import "testing"

func TestDecoderCoreDecodeMR122LPC(t *testing.T) {
	state := newDecoderCoreState()

	consumed, err := state.decodeMR122LPC([]int16{3, 17, 41, 9, 12, 99}, false)

	if err != nil {
		t.Fatalf("decodeMR122LPC error = %v", err)
	}
	if consumed != 5 {
		t.Fatalf("consumed = %d, want 5", consumed)
	}
	wantLSP := [lpcOrder]int16{32098, 31382, 27998, 21354, 5068, -8120, -9361, -10741, -22529, -27787}
	if state.lspOld != wantLSP {
		t.Fatalf("lspOld = %v, want %v", state.lspOld, wantLSP)
	}
	for subframe := range 4 {
		if got := state.az[subframe*lpcCoeffCount]; got != 4096 {
			t.Fatalf("subframe %d LPC a[0] = %d, want 4096", subframe, got)
		}
	}
	if state.az[lpcCoeffCount+1] == state.az[3*lpcCoeffCount+1] {
		t.Fatalf("mid and final LPC coefficients unexpectedly match: %d", state.az[lpcCoeffCount+1])
	}
}

func TestDecoderCoreDecodeMR122LPCBadFrame(t *testing.T) {
	state := newDecoderCoreState()
	for i := range state.lsfState.pastLSFQ {
		state.lsfState.pastLSFQ[i] = meanLSF5[i] + int16((i+1)*100)
	}

	consumed, err := state.decodeMR122LPC([]int16{0, 0, 0, 0, 0}, true)

	if err != nil {
		t.Fatalf("decodeMR122LPC bad frame error = %v", err)
	}
	if consumed != 5 {
		t.Fatalf("consumed = %d, want 5", consumed)
	}
	wantLSP := [lpcOrder]int16{31454, 29718, 24837, 16239, 6095, -3131, -14185, -21141, -28103, -30968}
	if state.lspOld != wantLSP {
		t.Fatalf("lspOld = %v, want %v", state.lspOld, wantLSP)
	}
}

func TestDecoderCoreDecodeMR122LPCRejectsShortParams(t *testing.T) {
	state := newDecoderCoreState()

	if _, err := state.decodeMR122LPC([]int16{1, 2, 3, 4}, false); err == nil {
		t.Fatal("decodeMR122LPC short params error = nil, want error")
	}
}

func TestDecoderCoreDecodeLPC3(t *testing.T) {
	state := newDecoderCoreState()

	consumed, err := state.decodeLPC3(Mode740, []int16{10, 20, 30, 99}, false)

	if err != nil {
		t.Fatalf("decodeLPC3 error = %v", err)
	}
	if consumed != 3 {
		t.Fatalf("consumed = %d, want 3", consumed)
	}
	wantLSP := [lpcOrder]int16{29716, 26522, 13757, 12580, 9953, 3355, -11462, -20021, -25520, -28850}
	if state.lspOld != wantLSP {
		t.Fatalf("lspOld = %v, want %v", state.lspOld, wantLSP)
	}
	for subframe := range 4 {
		if got := state.az[subframe*lpcCoeffCount]; got != 4096 {
			t.Fatalf("subframe %d LPC a[0] = %d, want 4096", subframe, got)
		}
	}
}

func TestDecoderCoreDecodeLPC3RejectsShortParams(t *testing.T) {
	state := newDecoderCoreState()

	if _, err := state.decodeLPC3(Mode740, []int16{1, 2}, false); err == nil {
		t.Fatal("decodeLPC3 short params error = nil, want error")
	}
}
