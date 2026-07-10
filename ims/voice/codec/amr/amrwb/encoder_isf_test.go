package amrwb

import (
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestISPToISFRoundTripInitialISF(t *testing.T) {
	isp, err := isfToISP(initialISF[:])
	if err != nil {
		t.Fatalf("isfToISP() error = %v", err)
	}

	isf, err := ispToISF(isp[:])
	if err != nil {
		t.Fatalf("ispToISF() error = %v", err)
	}
	for i := range initialISF {
		delta := fxp.Abs16(fxp.Sub16(isf[i], initialISF[i]))
		if delta > 4 {
			t.Fatalf("ispToISF() isf[%d] = %d, want near %d", i, isf[i], initialISF[i])
		}
	}
}

func TestEncoderISFQuantize46MatchesDecodePath(t *testing.T) {
	var state encoderISFQuantState

	quantized, err := state.quantize46(initialISF[:])
	if err != nil {
		t.Fatalf("quantize46() error = %v", err)
	}
	var past [lpcOrder]int16
	decoder := isfDecodeState{pastResidual: past[:]}
	decoded, err := decoder.decode46(quantized.indices[:])
	if err != nil {
		t.Fatalf("decode46() error = %v", err)
	}
	for i := range quantized.isf {
		if quantized.isf[i] != decoded[i] {
			t.Fatalf("quantize46() isfQ[%d] = %d, decoded %d", i, quantized.isf[i], decoded[i])
		}
	}
	if state.pastISFQ == ([lpcOrder]int16{}) {
		t.Fatal("quantize46() did not update past residual")
	}
}

func TestEncoderISFQuantize36MatchesDecodePath(t *testing.T) {
	var state encoderISFQuantState

	quantized, err := state.quantize36(initialISF[:])
	if err != nil {
		t.Fatalf("quantize36() error = %v", err)
	}
	var past [lpcOrder]int16
	decoder := isfDecodeState{pastResidual: past[:]}
	decoded, err := decoder.decode36(quantized.indices[:quantized.indexCount])
	if err != nil {
		t.Fatalf("decode36() error = %v", err)
	}
	for i := range quantized.isf {
		if quantized.isf[i] != decoded[i] {
			t.Fatalf("quantize36() isfQ[%d] = %d, decoded %d", i, quantized.isf[i], decoded[i])
		}
	}
}
