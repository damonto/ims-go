/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This encoder subframe post-processing is ported from enc/src/spstproc.cpp.
 */

package amrnb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type subframePostprocessInput struct {
	mode       Mode
	offset     int
	gainPit    int16
	gainCode   int16
	quantLPC   []int16
	speech     []int16
	synth      []int16
	sub        *encoderSubframeAnalysis
	memSyn     []int16
	memErr     []int16
	memW0      []int16
	excitation []int16
}

func subframePostprocessEncode(in subframePostprocessInput) (int16, error) {
	if in.sub == nil {
		return 0, errors.New("postprocessing AMR-NB subframe: missing analysis input")
	}
	if in.offset < 0 || in.offset+subframeSamples > FrameSamples {
		return 0, fmt.Errorf("postprocessing AMR-NB subframe: frame offset %d outside frame samples %d", in.offset, FrameSamples)
	}
	needFrame := in.offset + subframeSamples
	if len(in.quantLPC) < lpcCoeffCount {
		return 0, fmt.Errorf("postprocessing AMR-NB subframe: quantized LPC coefficient count %d, want at least %d", len(in.quantLPC), lpcCoeffCount)
	}
	if len(in.speech) < needFrame {
		return 0, fmt.Errorf("postprocessing AMR-NB subframe: speech sample count %d, want at least %d", len(in.speech), needFrame)
	}
	if len(in.synth) < needFrame {
		return 0, fmt.Errorf("postprocessing AMR-NB subframe: synthesis sample count %d, want at least %d", len(in.synth), needFrame)
	}
	if len(in.memSyn) < lpcOrder {
		return 0, fmt.Errorf("postprocessing AMR-NB subframe: synthesis memory count %d, want at least %d", len(in.memSyn), lpcOrder)
	}
	if len(in.memErr) < lpcOrder {
		return 0, fmt.Errorf("postprocessing AMR-NB subframe: error memory count %d, want at least %d", len(in.memErr), lpcOrder)
	}
	if len(in.memW0) < lpcOrder {
		return 0, fmt.Errorf("postprocessing AMR-NB subframe: weighting memory count %d, want at least %d", len(in.memW0), lpcOrder)
	}
	if len(in.excitation) < needFrame {
		return 0, fmt.Errorf("postprocessing AMR-NB subframe: excitation sample count %d, want at least %d", len(in.excitation), needFrame)
	}

	tempShift := int16(1)
	kShift := int16(2)
	pitchFactor := in.gainPit
	if in.mode == Mode1220 {
		tempShift = 2
		kShift = 4
		pitchFactor = fxp.Shr16(in.gainPit, 1)
	}

	sharp := in.gainPit
	if fxp.Sub16(sharp, sharpMax) > 0 {
		sharp = sharpMax
	}
	for i := range subframeSamples {
		total := fxp.LMult(in.excitation[in.offset+i], pitchFactor)
		total = fxp.LMac(total, in.sub.fixed.code[i], in.gainCode)
		in.excitation[in.offset+i] = fxp.Round(fxp.Shl32(total, tempShift))
	}

	nextMemSyn := synthesisFilter(
		in.quantLPC,
		in.excitation[in.offset:in.offset+subframeSamples],
		in.synth[in.offset:in.offset+subframeSamples],
		in.memSyn,
	)
	copy(in.memSyn, nextMemSyn[:])

	for i, j := subframeSamples-lpcOrder, 0; i < subframeSamples; i, j = i+1, j+1 {
		in.memErr[j] = fxp.Sub16(in.speech[in.offset+i], in.synth[in.offset+i])
		temp := fxp.ExtractH(fxp.Shl32(fxp.LMult(in.sub.pitch.yl[i], in.gainPit), 1))
		k := fxp.ExtractH(fxp.Shl32(fxp.LMult(in.sub.fixed.y2[i], in.gainCode), kShift))
		in.memW0[j] = fxp.Sub16(in.sub.xn[i], fxp.Add16(temp, k))
	}
	return sharp, nil
}
