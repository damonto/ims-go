/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This weighted-speech pre-processing is ported from enc/src/pre_big.cpp.
 */

package amrnb

import "fmt"

var encoderGamma1 = [...]int16{
	30802, 28954, 27217, 25584, 24049,
	22606, 21250, 19975, 18777, 17650,
}

var encoderGamma1MR122 = [...]int16{
	29491, 26542, 23888, 21499, 19349,
	17414, 15672, 14105, 12694, 11425,
}

var encoderGamma2 = [...]int16{
	19661, 11797, 7078, 4247, 2548,
	1529, 917, 550, 330, 198,
}

type weightedSpeechBlock struct {
	samples [FrameSamples / 2]int16
	memW    [lpcOrder]int16
}

func preBig(
	mode Mode,
	az [azFrameCount]int16,
	frameOffset int,
	speech []int16,
	memW [lpcOrder]int16,
) (weightedSpeechBlock, error) {
	var out weightedSpeechBlock
	if mode < Mode475 || mode > ModeDTX {
		return out, fmt.Errorf("preparing AMR-NB weighted speech: invalid mode %d", mode)
	}
	if frameOffset != 0 && frameOffset != FrameSamples/2 {
		return out, fmt.Errorf("preparing AMR-NB weighted speech: invalid frame offset %d", frameOffset)
	}
	if len(speech) < lpcLookaheadSamples+FrameSamples {
		return out, fmt.Errorf(
			"preparing AMR-NB weighted speech: speech sample count %d, want at least %d",
			len(speech),
			lpcLookaheadSamples+FrameSamples,
		)
	}

	out.memW = memW
	hasHistory := len(speech) >= lpcOrder+lpcLookaheadSamples+FrameSamples
	gamma1 := encoderGamma1[:]
	if mode > Mode795 {
		gamma1 = encoderGamma1MR122[:]
	}

	aOffset := 0
	if frameOffset > 0 {
		aOffset = 2 * lpcCoeffCount
	}
	for blockOffset := 0; blockOffset < len(out.samples); blockOffset += subframeSamples {
		ap1, err := weightLPC(az[aOffset:aOffset+lpcCoeffCount], gamma1)
		if err != nil {
			return weightedSpeechBlock{}, err
		}
		ap2, err := weightLPC(az[aOffset:aOffset+lpcCoeffCount], encoderGamma2[:])
		if err != nil {
			return weightedSpeechBlock{}, err
		}

		absoluteOffset := frameOffset + blockOffset
		speechStart := lpcLookaheadSamples + absoluteOffset - lpcOrder
		if hasHistory {
			speechStart = absoluteOffset
		}
		weighted := out.samples[blockOffset : blockOffset+subframeSamples]
		residual(ap1[:], speech[speechStart:], weighted)
		out.memW = synthesisFilter(ap2[:], weighted, weighted, out.memW[:])
		aOffset += lpcCoeffCount
	}
	return out, nil
}
