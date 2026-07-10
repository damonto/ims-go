package amrnb

import (
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestAGCEnergyNew(t *testing.T) {
	signal := make([]int16, subframeSamples)
	for i := range signal {
		signal[i] = 100
	}

	if got := agcEnergyNew(signal); got != 50000 {
		t.Fatalf("agcEnergyNew() = %d, want 50000", got)
	}

	loud := make([]int16, subframeSamples)
	for i := range loud {
		loud[i] = 32767
	}
	if got := agcEnergyNew(loud); got != fxp.Max32 {
		t.Fatalf("agcEnergyNew(loud) = %d, want saturated fallback %d", got, fxp.Max32)
	}
}

func TestInvSqrt(t *testing.T) {
	tests := []struct {
		name string
		in   int32
		want int32
	}{
		{name: "non-positive", in: 0, want: 0x3fffffff},
		{name: "quarter", in: 0x20000000, want: 0x0000b504},
		{name: "half", in: 0x40000000, want: 0x00007fff},
	}
	for _, tt := range tests {
		if got := invSqrt(tt.in); got != tt.want {
			t.Fatalf("%s invSqrt(%#x) = %#x, want %#x", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestAGC2ScalesOutputTowardInputEnergy(t *testing.T) {
	in := make([]int16, subframeSamples)
	out := make([]int16, subframeSamples)
	for i := range in {
		in[i] = 200
		out[i] = 100
	}

	agc2(in, out)

	if out[0] <= 100 {
		t.Fatalf("out[0] = %d, want scaled above 100", out[0])
	}
	for i, sample := range out {
		if sample != out[0] {
			t.Fatalf("out[%d] = %d, want uniform %d", i, sample, out[0])
		}
	}
}

func TestAGC2ZeroInputSilencesOutput(t *testing.T) {
	in := make([]int16, subframeSamples)
	out := make([]int16, subframeSamples)
	for i := range out {
		out[i] = 100
	}

	agc2(in, out)

	for i, sample := range out {
		if sample != 0 {
			t.Fatalf("out[%d] = %d, want 0", i, sample)
		}
	}
}
