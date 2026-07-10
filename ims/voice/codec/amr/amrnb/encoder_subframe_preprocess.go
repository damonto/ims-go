/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This encoder subframe pre-processing is ported from enc/src/spreproc.cpp.
 */

package amrnb

import (
	"fmt"
)

type encoderSubframeAnalysis struct {
	aiZero   [lpcCoeffCount]int16
	exc      [subframeSamples]int16
	h1       [subframeSamples]int16
	xn       [subframeSamples]int16
	res      [subframeSamples]int16
	error    [subframeSamples]int16
	pitch    encoderPitchAnalysis
	hasPitch bool
	fixed    encoderFixedCodebookAnalysis
	hasFixed bool
}

type encoderFixedCodebookAnalysis struct {
	index       int16
	sign        int16
	params      [11]int16
	paramCount  int
	code        [subframeSamples]int16
	codeNoSharp [subframeSamples]int16
	y2          [subframeSamples]int16
	gainCode    encoderCodeGainAnalysis
}

type encoderCodeGainAnalysis struct {
	index         int16
	gain          int16
	pitchIndex    int16
	pitchGain     int16
	hasPitchIndex bool
}

type subframePreprocessInput struct {
	mode        Mode
	lpc         []int16
	quantLPC    []int16
	speech      []int16
	frameOffset int
	memErr      []int16
	memW0       []int16
}

func subframePreprocessEncode(in subframePreprocessInput) (encoderSubframeAnalysis, error) {
	var out encoderSubframeAnalysis
	if in.frameOffset < 0 || in.frameOffset+subframeSamples > FrameSamples {
		return out, fmt.Errorf("preprocessing AMR-NB subframe: frame offset %d outside frame samples %d", in.frameOffset, FrameSamples)
	}
	if len(in.lpc) < lpcCoeffCount {
		return out, fmt.Errorf("preprocessing AMR-NB subframe: LPC coefficient count %d, want at least %d", len(in.lpc), lpcCoeffCount)
	}
	if len(in.quantLPC) < lpcCoeffCount {
		return out, fmt.Errorf("preprocessing AMR-NB subframe: quantized LPC coefficient count %d, want at least %d", len(in.quantLPC), lpcCoeffCount)
	}
	if len(in.speech) < lpcLookaheadSamples+FrameSamples {
		return out, fmt.Errorf("preprocessing AMR-NB subframe: speech sample count %d, want at least %d", len(in.speech), lpcLookaheadSamples+FrameSamples)
	}
	if len(in.memErr) < lpcOrder {
		return out, fmt.Errorf("preprocessing AMR-NB subframe: error memory count %d, want at least %d", len(in.memErr), lpcOrder)
	}
	if len(in.memW0) < lpcOrder {
		return out, fmt.Errorf("preprocessing AMR-NB subframe: weighting memory count %d, want at least %d", len(in.memW0), lpcOrder)
	}
	hasHistory := len(in.speech) >= lpcOrder+lpcLookaheadSamples+FrameSamples

	gamma1 := encoderGamma1[:]
	if in.mode == Mode1220 || in.mode == Mode1020 {
		gamma1 = encoderGamma1MR122[:]
	}

	ap1, err := weightLPC(in.lpc, gamma1)
	if err != nil {
		return out, err
	}
	ap2, err := weightLPC(in.lpc, encoderGamma2[:])
	if err != nil {
		return out, err
	}
	copy(out.aiZero[:], ap1[:])

	var impulse [subframeSamples]int16
	copy(impulse[:], ap1[:])
	var zeroMem [lpcOrder]int16
	synthesisFilter(in.quantLPC, impulse[:], out.h1[:], zeroMem[:])
	synthesisFilter(ap2[:], out.h1[:], out.h1[:], zeroMem[:])

	speechStart := lpcLookaheadSamples + in.frameOffset - lpcOrder
	if hasHistory {
		speechStart = in.frameOffset
	}
	residual(in.quantLPC, in.speech[speechStart:], out.res[:])
	copy(out.exc[:], out.res[:])

	synthesisFilter(in.quantLPC, out.exc[:], out.error[:], in.memErr)

	var errorHistory [lpcOrder + subframeSamples]int16
	copy(errorHistory[:lpcOrder], in.memErr[:lpcOrder])
	copy(errorHistory[lpcOrder:], out.error[:])
	residual(ap1[:], errorHistory[:], out.xn[:])
	synthesisFilter(ap2[:], out.xn[:], out.xn[:], in.memW0)
	return out, nil
}
