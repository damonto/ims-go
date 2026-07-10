package amrnb

import (
	"fmt"
	"testing"
)

func TestQuantize3IndicesDecodeToSameLSP(t *testing.T) {
	modes := []Mode{Mode475, Mode590, Mode795, ModeDTX}
	for _, mode := range modes {
		t.Run(fmt.Sprintf("mode_%d", mode), func(t *testing.T) {
			var lsp [lpcOrder]int16
			copy(lsp[:], initialLSP[:])
			for i := range lsp {
				lsp[i] -= int16((i + 1) * 180)
			}

			enc := newDPLSFState()
			dec := newDPLSFState()
			quantized, err := enc.quantize3(mode, lsp[:])
			if err != nil {
				t.Fatalf("quantize3() error = %v", err)
			}
			if mode == ModeDTX {
				dec.initFromPastRQ(quantized.predInit)
			}
			want, err := dec.decode3(mode, quantized.indices[:])
			if err != nil {
				t.Fatalf("decode3() error = %v", err)
			}

			if quantized.lsp != want {
				t.Fatalf("quantized LSP = %v, decoded %v with indices %v", quantized.lsp, want, quantized.indices)
			}
		})
	}
}

func TestQuantize5IndicesDecodeToSameLSP(t *testing.T) {
	var lsp1 [lpcOrder]int16
	var lsp2 [lpcOrder]int16
	copy(lsp1[:], initialLSP[:])
	copy(lsp2[:], initialLSP[:])
	for i := range lsp1 {
		lsp1[i] -= int16((i + 1) * 140)
		lsp2[i] -= int16((i + 1) * 220)
	}

	enc := newDPLSFState()
	dec := newDPLSFState()
	quantized, err := enc.quantize5(lsp1[:], lsp2[:])
	if err != nil {
		t.Fatalf("quantize5() error = %v", err)
	}
	decoded, err := dec.decode5(quantized.indices[:])
	if err != nil {
		t.Fatalf("decode5() error = %v", err)
	}
	if quantized.lsp1 != decoded.lsp1 || quantized.lsp2 != decoded.lsp2 {
		t.Fatalf(
			"quantized LSP = %v/%v, decoded %v/%v with indices %v",
			quantized.lsp1,
			quantized.lsp2,
			decoded.lsp1,
			decoded.lsp2,
			quantized.indices,
		)
	}
}

func TestPLSFQuantizersRejectInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name string
		run  func(*dPLSFState) error
	}{
		{
			name: "PLSF3 short LSP",
			run: func(state *dPLSFState) error {
				_, err := state.quantize3(Mode590, make([]int16, lpcOrder-1))
				return err
			},
		},
		{
			name: "PLSF3 invalid mode",
			run: func(state *dPLSFState) error {
				_, err := state.quantize3(Mode1220, make([]int16, lpcOrder))
				return err
			},
		},
		{
			name: "PLSF5 short first LSP",
			run: func(state *dPLSFState) error {
				_, err := state.quantize5(make([]int16, lpcOrder-1), make([]int16, lpcOrder))
				return err
			},
		},
		{
			name: "PLSF5 short second LSP",
			run: func(state *dPLSFState) error {
				_, err := state.quantize5(make([]int16, lpcOrder), make([]int16, lpcOrder-1))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newDPLSFState()
			before := state

			if err := tt.run(&state); err == nil {
				t.Fatal("quantizer error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("quantizer changed PLSF state after rejecting input")
			}
		})
	}
}

func TestLSFWeightRejectsShortInput(t *testing.T) {
	tests := []struct {
		name string
		lsf  []int16
	}{
		{name: "nil", lsf: nil},
		{name: "short", lsf: make([]int16, lpcOrder-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := lsfWeight(tt.lsf); err == nil {
				t.Fatal("lsfWeight() error = nil, want short input error")
			}
		})
	}
}
