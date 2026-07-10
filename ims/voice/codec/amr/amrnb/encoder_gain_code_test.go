package amrnb

import "testing"

func TestQuantizeMR122CodeGainMatchesDecoderGain(t *testing.T) {
	var enc encoderGainState
	enc.reset()
	dec := newGainPredState()

	code := make([]int16, subframeSamples)
	code[0] = 4096
	code[7] = -4096
	xn2 := make([]int16, subframeSamples)
	y2 := make([]int16, subframeSamples)
	xn2[0] = 2400
	xn2[7] = -2200
	y2[0] = 1800
	y2[7] = -1600

	got, err := enc.quantizeMR122(code, xn2, y2)
	if err != nil {
		t.Fatalf("quantizeMR122() error = %v", err)
	}
	decodedGain := dGainCode(&dec, Mode1220, got.index, code)

	if got.index < 0 || got.index > 31 {
		t.Fatalf("index = %d, want 0..31", got.index)
	}
	if got.gain == 0 {
		t.Fatal("quantized gain is zero")
	}
	if decodedGain != got.gain {
		t.Fatalf("decoded gain = %d, want encoder gain %d", decodedGain, got.gain)
	}
	if enc.pred.pastQuaEn[0] != dec.pastQuaEn[0] {
		t.Fatalf("predictor energy = %d, want decoder %d", enc.pred.pastQuaEn[0], dec.pastQuaEn[0])
	}
}

func TestGCodeReturnsZeroForNegativeCorrelation(t *testing.T) {
	xn2 := make([]int16, subframeSamples)
	y2 := make([]int16, subframeSamples)
	xn2[0] = 2000
	y2[0] = -2000

	got, err := gCode(xn2, y2)
	if err != nil {
		t.Fatalf("gCode() error = %v", err)
	}
	if got != 0 {
		t.Fatalf("gCode() = %d, want zero for negative correlation", got)
	}
}

func TestMR122CodeGainRejectsInvalidInputWithoutChangingState(t *testing.T) {
	tests := []struct {
		name string
		code []int16
		xn2  []int16
		y2   []int16
	}{
		{name: "short code", code: make([]int16, subframeSamples-1), xn2: make([]int16, subframeSamples), y2: make([]int16, subframeSamples)},
		{name: "short target", code: make([]int16, subframeSamples), xn2: make([]int16, subframeSamples-1), y2: make([]int16, subframeSamples)},
		{name: "short filter", code: make([]int16, subframeSamples), xn2: make([]int16, subframeSamples), y2: make([]int16, subframeSamples-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state encoderGainState
			state.reset()
			before := state

			if _, err := state.quantizeMR122(tt.code, tt.xn2, tt.y2); err == nil {
				t.Fatal("quantizeMR122() error = nil, want invalid input error")
			}
			if state != before {
				t.Fatal("quantizeMR122() changed gain state after rejecting input")
			}
		})
	}
}

func TestQuantizeJointGainMatchesDecoderGain(t *testing.T) {
	var enc encoderGainState
	enc.reset()
	dec := newGainPredState()

	code := make([]int16, subframeSamples)
	xn := make([]int16, subframeSamples)
	xn2 := make([]int16, subframeSamples)
	y1 := make([]int16, subframeSamples)
	y2 := make([]int16, subframeSamples)
	code[0] = 8191
	code[5] = -8192
	xn[0] = 2200
	xn[5] = -1900
	xn2[0] = 1700
	xn2[5] = -1500
	y1[0] = 1300
	y1[5] = -1100
	y2[0] = 900
	y2[5] = -800
	gCoeff := []int16{12000, 4, 9000, 3}
	got := enc.quantizeJoint(jointGainInput{
		mode:    Mode1020,
		xn:      xn,
		xn2:     xn2,
		y1:      y1,
		y2:      y2,
		gCoeff:  gCoeff,
		gpLimit: gpClip,
		code:    code,
	})
	decodedPit, decodedCode := decGain(&dec, Mode1020, got.index, code, 1)

	if got.index < 0 || got.index >= int16(len(tableGainHighrates)/4) {
		t.Fatalf("index = %d, want high-rate table range", got.index)
	}
	if decodedPit != got.pitchGain {
		t.Fatalf("decoded pitch gain = %d, want encoder gain %d", decodedPit, got.pitchGain)
	}
	if decodedCode != got.gain {
		t.Fatalf("decoded code gain = %d, want encoder gain %d", decodedCode, got.gain)
	}
	if enc.pred.pastQuaEn[0] != dec.pastQuaEn[0] {
		t.Fatalf("predictor energy = %d, want decoder %d", enc.pred.pastQuaEn[0], dec.pastQuaEn[0])
	}
}

func TestQuantizeMR475PairGainMatchesDecoderGain(t *testing.T) {
	var enc encoderGainState
	enc.reset()
	dec := newGainPredState()

	code0 := make([]int16, subframeSamples)
	code1 := make([]int16, subframeSamples)
	xn0 := make([]int16, subframeSamples)
	xn1 := make([]int16, subframeSamples)
	xn20 := make([]int16, subframeSamples)
	xn21 := make([]int16, subframeSamples)
	y10 := make([]int16, subframeSamples)
	y11 := make([]int16, subframeSamples)
	y20 := make([]int16, subframeSamples)
	y21 := make([]int16, subframeSamples)
	code0[0] = 8191
	code0[5] = -8192
	code1[1] = 8191
	code1[6] = -8192
	xn0[0] = 2100
	xn0[5] = -1700
	xn1[1] = 1900
	xn1[6] = -1600
	xn20[0] = 1500
	xn20[5] = -1200
	xn21[1] = 1400
	xn21[6] = -1100
	y10[0] = 1000
	y10[5] = -900
	y11[1] = 950
	y11[6] = -850
	y20[0] = 780
	y20[5] = -640
	y21[1] = 720
	y21[6] = -600
	gCoeff := []int16{10500, 4, 8200, 3}

	enc.prepareMR475Even(mr475SubframeGainInput{
		xn:     xn0,
		xn2:    xn20,
		y1:     y10,
		y2:     y20,
		gCoeff: gCoeff,
		code:   code0,
	})
	got := enc.quantizeMR475Odd(mr475SubframeGainInput{
		xn:     xn1,
		xn2:    xn21,
		y1:     y11,
		y2:     y21,
		gCoeff: gCoeff,
		code:   code1,
	}, gpClip)

	decodedPit0, decodedCode0 := decGain(&dec, Mode475, got.index, code0, 1)
	decodedPit1, decodedCode1 := decGain(&dec, Mode475, got.index, code1, 0)

	if got.index < 0 || got.index >= int16(len(tableGainMR475)/4) {
		t.Fatalf("index = %d, want MR475 table range", got.index)
	}
	if decodedPit0 != got.sf0GainPit || decodedCode0 != got.sf0GainCode {
		t.Fatalf(
			"decoded sf0 gains = %d/%d, want %d/%d",
			decodedPit0,
			decodedCode0,
			got.sf0GainPit,
			got.sf0GainCode,
		)
	}
	if decodedPit1 != got.sf1GainPit || decodedCode1 != got.sf1GainCode {
		t.Fatalf(
			"decoded sf1 gains = %d/%d, want %d/%d",
			decodedPit1,
			decodedCode1,
			got.sf1GainPit,
			got.sf1GainCode,
		)
	}
	if enc.pred.pastQuaEn[0] != dec.pastQuaEn[0] {
		t.Fatalf("predictor energy = %d, want decoder %d", enc.pred.pastQuaEn[0], dec.pastQuaEn[0])
	}
}

func TestQuantizeMR795GainMatchesDecoderGain(t *testing.T) {
	var enc encoderGainState
	enc.reset()
	dec := newGainPredState()

	code := make([]int16, subframeSamples)
	res := make([]int16, subframeSamples)
	exc := make([]int16, subframeSamples)
	xn := make([]int16, subframeSamples)
	xn2 := make([]int16, subframeSamples)
	y1 := make([]int16, subframeSamples)
	y2 := make([]int16, subframeSamples)
	code[0] = 8191
	code[6] = -8192
	res[0] = 1800
	res[6] = -1300
	exc[0] = 1200
	exc[6] = -900
	xn[0] = 2300
	xn[6] = -1800
	xn2[0] = 1600
	xn2[6] = -1400
	y1[0] = 1200
	y1[6] = -1000
	y2[0] = 850
	y2[6] = -700
	gCoeff := []int16{11000, 4, 8500, 3}
	gainPit := int16(12000)

	got := enc.quantizeMR795(mr795GainInput{
		res:     res,
		exc:     exc,
		xn:      xn,
		xn2:     xn2,
		y1:      y1,
		y2:      y2,
		gCoeff:  gCoeff,
		gpLimit: gpClip,
		gainPit: gainPit,
		code:    code,
	})
	decodedPit := dGainPitch(Mode795, got.pitchIndex)
	decodedCode := dGainCode(&dec, Mode795, got.index, code)

	if !got.hasPitchIndex {
		t.Fatal("MR795 pitch index was not set")
	}
	if decodedPit != got.pitchGain {
		t.Fatalf("decoded pitch gain = %d, want encoder gain %d", decodedPit, got.pitchGain)
	}
	if decodedCode != got.gain {
		t.Fatalf("decoded code gain = %d, want encoder gain %d", decodedCode, got.gain)
	}
	if enc.pred.pastQuaEn[0] != dec.pastQuaEn[0] {
		t.Fatalf("predictor energy = %d, want decoder %d", enc.pred.pastQuaEn[0], dec.pastQuaEn[0])
	}
}

func TestGainAdaptProducesPositiveAlphaForLowLTPGain(t *testing.T) {
	var state gainAdaptState
	state.reset()

	alpha := state.adapt(1000, 100)

	if alpha <= 0 {
		t.Fatalf("alpha = %d, want positive adaptation factor", alpha)
	}
	if state.prevGC != 100 {
		t.Fatalf("prevGC = %d, want 100", state.prevGC)
	}
}

func TestMR795GainCodeQuantModProducesValidIndex(t *testing.T) {
	fracEn := [4]int16{12000, 9000, 2000, 15000}
	expEn := [4]int16{4, 3, -1, -2}

	index, quaEnerMR122, quaEner, gainCode := mr795GainCodeQuantMod(
		12000,
		3,
		16000,
		fracEn,
		expEn,
		8192,
		400,
		900,
	)

	if index < 0 || index > 31 {
		t.Fatalf("index = %d, want 0..31", index)
	}
	if gainCode < 0 {
		t.Fatalf("gainCode = %d, want non-negative", gainCode)
	}
	if quaEnerMR122 != quaGainCode[index*3+1] || quaEner != quaGainCode[index*3+2] {
		t.Fatalf("quantized energies = %d/%d, want table values", quaEnerMR122, quaEner)
	}
}
