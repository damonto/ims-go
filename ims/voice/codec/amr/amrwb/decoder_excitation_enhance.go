/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This logic follows the AMR-WB decoder noise and pitch enhancer in
 * amr_wb/dec/src/pvamrwbdecoder.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

func enhanceCodeGain(threshold int32, gainCode int32, voiceFac int16, stability int16) (gain int32, nextThreshold int32) {
	unvoiced := fxp.Sub16(16384, voiceFac>>1)
	factor := fxp.Mult(stability, unvoiced)
	target := gainCode
	if target < threshold {
		target = fxp.Add32(target, mpy32By16Value(gainCode, 6226))
		if target > threshold {
			target = threshold
		}
	} else {
		target = mpy32By16Value(gainCode, 27536)
		if target < threshold {
			target = threshold
		}
	}

	out := mpy32By16Value(gainCode, fxp.Sub16(fxp.Max16, factor))
	out = fxp.Add32(out, mpy32By16Value(target, factor))
	return out, target
}

func mpy32By16Value(value int32, factor int16) int32 {
	hi, lo := fxp.LExtract(value)
	return fxp.LMac(fxp.LMult(hi, factor), fxp.Mult(lo, factor), 1)
}

type enhancedExcitation struct {
	excitation     [subframeSamples]int16
	scaledGainCode int16
}

func buildEnhancedExcitation(
	excitation [subframeSamples]int16,
	code [subframeSamples]int16,
	gainPit int16,
	gainCode int32,
	qNew int16,
	voiceFac int16,
) enhancedExcitation {
	out := enhancedExcitation{excitation: excitation}

	pitchFilter := fxp.Add16(voiceFac>>3, 4096)
	out.scaledGainCode = fxp.Round(fxp.Shl32(gainCode, qNew))
	for i := range subframeSamples {
		filtered := int32(code[i]) << 16
		switch {
		case i == 0:
			filtered = fxp.Sub32(filtered, fxp.LMult(code[1], pitchFilter))
		case i == subframeSamples-1:
			filtered = fxp.Sub32(filtered, fxp.LMult(code[i-1], pitchFilter))
		default:
			filtered = fxp.LMsu(filtered, code[i+1], pitchFilter)
			filtered = fxp.LMsu(filtered, code[i-1], pitchFilter)
		}
		code2 := fxp.Round(filtered)
		acc := fxp.LMult(code2, out.scaledGainCode)
		acc = fxp.Shl32(acc, 5)
		acc = fxp.Add32(acc, fxp.LMult(out.excitation[i], gainPit))
		acc = fxp.Shl32(acc, 1)
		out.excitation[i] = fxp.Round(acc)
	}
	return out
}
