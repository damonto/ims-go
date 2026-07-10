package amrnb

import "testing"

func TestEncoderLSPProcess(t *testing.T) {
	tests := []struct {
		name       string
		mode       Mode
		midScale   int16
		finalScale int16
		wantParams int
	}{
		{name: "MR590", mode: Mode590, finalScale: 160, wantParams: 3},
		{name: "MR122", mode: Mode1220, midScale: 110, finalScale: 190, wantParams: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newEncoderLSPState()
			var az [azFrameCount]int16
			var midLSP, finalLSP [lpcOrder]int16
			copy(midLSP[:], initialLSP[:])
			copy(finalLSP[:], initialLSP[:])
			for i := range finalLSP {
				if tt.midScale != 0 {
					midLSP[i] -= int16(i+1) * tt.midScale
				}
				finalLSP[i] -= int16(i+1) * tt.finalScale
			}
			if tt.midScale != 0 {
				coeff := lspToAz(midLSP[:])
				copy(az[lpcCoeffCount:2*lpcCoeffCount], coeff[:])
			}
			coeff := lspToAz(finalLSP[:])
			copy(az[3*lpcCoeffCount:4*lpcCoeffCount], coeff[:])

			got, err := state.process(tt.mode, tt.mode, az)
			if err != nil {
				t.Fatalf("process() error = %v", err)
			}
			if got.written != tt.wantParams {
				t.Fatalf("written params = %d, want %d", got.written, tt.wantParams)
			}
			assertLSPNear(t, got.lspNew[:], finalLSP[:], 16)
			if got.azQ[0] != 4096 || got.azQ[3*lpcCoeffCount] != 4096 {
				t.Fatalf("quantized LPC headers = %d/%d, want 4096", got.azQ[0], got.azQ[3*lpcCoeffCount])
			}
			if state.lspOld != got.lspNew {
				t.Fatalf("state lspOld = %v, want %v", state.lspOld, got.lspNew)
			}
		})
	}
}

func TestEncoderLSPProcessRejectsInvalidModeWithoutChangingState(t *testing.T) {
	tests := []struct {
		name     string
		reqMode  Mode
		usedMode Mode
	}{
		{name: "requested mode", reqMode: ModeNoData, usedMode: Mode590},
		{name: "used mode", reqMode: Mode590, usedMode: ModeNoData},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newEncoderLSPState()
			before := state

			if _, err := state.process(tt.reqMode, tt.usedMode, [azFrameCount]int16{}); err == nil {
				t.Fatal("process() error = nil, want invalid mode error")
			}
			if state != before {
				t.Fatal("process() changed LSP state after rejecting input")
			}
		})
	}
}

func assertLSPNear(t *testing.T, got []int16, want []int16, tolerance int16) {
	t.Helper()
	for i := range want {
		delta := got[i] - want[i]
		if delta < 0 {
			delta = -delta
		}
		if delta > tolerance {
			t.Fatalf("lsp[%d] = %d, want near %d", i, got[i], want[i])
		}
	}
}
