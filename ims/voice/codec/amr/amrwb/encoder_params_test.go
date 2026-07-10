package amrwb

import "testing"

func TestEncodeLPCParametersMode660(t *testing.T) {
	enc := newPreparedEncoder(t, Mode660)
	params := make([]int16, mustParameterCount(t, Mode660))

	_, quant, err := enc.encodeLPCParameters(params)

	if err != nil {
		t.Fatalf("encodeLPCParameters() error = %v", err)
	}
	if params[0] != 1 {
		t.Fatalf("vad flag = %d, want 1", params[0])
	}
	if quant.indexCount != 5 {
		t.Fatalf("indexCount = %d, want 5", quant.indexCount)
	}
	if params[3] >= 1<<14 {
		t.Fatalf("packed 6.60 ISF split index = %d, want 14-bit value", params[3])
	}
	if _, err := (Params{Mode: Mode660, Values: params}).Pack(nil); err != nil {
		t.Fatalf("Params.Pack() error = %v", err)
	}
	var dec decoderCoreState
	dec.reset(true)
	if _, err := dec.decodeLPC(Mode660, params, false); err != nil {
		t.Fatalf("decodeLPC(generated params) error = %v", err)
	}
}

func TestEncodeLPCParametersMode885(t *testing.T) {
	enc := newPreparedEncoder(t, Mode885)
	params := make([]int16, mustParameterCount(t, Mode885))

	_, quant, err := enc.encodeLPCParameters(params)

	if err != nil {
		t.Fatalf("encodeLPCParameters() error = %v", err)
	}
	if quant.indexCount != 7 {
		t.Fatalf("indexCount = %d, want 7", quant.indexCount)
	}
	if _, err := (Params{Mode: Mode885, Values: params}).Pack(nil); err != nil {
		t.Fatalf("Params.Pack() error = %v", err)
	}
	var dec decoderCoreState
	dec.reset(true)
	if _, err := dec.decodeLPC(Mode885, params, false); err != nil {
		t.Fatalf("decodeLPC(generated params) error = %v", err)
	}
}

func TestEncodeLPCParametersRejectsShortBufferWithoutChangingState(t *testing.T) {
	tests := []struct {
		name string
		mode Mode
		size int
	}{
		{name: "6.60 mode", mode: Mode660, size: 4},
		{name: "8.85 mode", mode: Mode885, size: 7},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			enc := newPreparedEncoder(t, tt.mode)
			lpcBefore := enc.lpc
			isfBefore := enc.isfQuant
			pitchClipBefore := enc.pitchClip

			if _, _, err := enc.encodeLPCParameters(make([]int16, tt.size)); err == nil {
				t.Fatal("encodeLPCParameters() error = nil")
			}
			if enc.lpc != lpcBefore || enc.isfQuant != isfBefore || enc.pitchClip != pitchClipBefore {
				t.Fatal("encodeLPCParameters() changed encoder state after input validation error")
			}
		})
	}
}

func newPreparedEncoder(t *testing.T, mode Mode) *Encoder {
	t.Helper()
	enc, err := NewEncoder(Config{Mode: mode})
	if err != nil {
		t.Fatalf("NewEncoder() error = %v", err)
	}
	var pcm [FrameSamples]int16
	for i := range pcm {
		pcm[i] = int16((i%97 - 48) * 96)
	}
	if _, err := enc.prepareFrame(pcm[:]); err != nil {
		t.Fatalf("prepareFrame() error = %v", err)
	}
	return enc
}

func mustParameterCount(t *testing.T, mode Mode) int {
	t.Helper()
	count, err := ParameterCount(mode)
	if err != nil {
		t.Fatalf("ParameterCount() error = %v", err)
	}
	return count
}
