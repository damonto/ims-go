/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/voice_factor.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

func voiceFactor(
	excitation [subframeSamples]int16,
	qExc int16,
	gainPit int16,
	code [subframeSamples]int16,
	gainCode int16,
) int16 {
	energy, exp1 := dotProduct12(excitation[:], excitation[:], subframeSamples)
	energy1 := fxp.ExtractH(energy)
	exp1 = fxp.Sub16(exp1, qExc<<1)

	gainPitchSquared := fxp.LMult(gainPit, gainPit)
	exp := normalizeAMRWB(gainPitchSquared)
	tmp := fxp.ExtractH(fxp.Shl32(gainPitchSquared, exp))
	energy1 = fxp.Mult(energy1, tmp)
	exp1 -= exp + 10

	energy, exp2 := dotProduct12(code[:], code[:], subframeSamples)
	energy2 := fxp.ExtractH(energy)
	exp = fxp.NormS(gainCode)
	tmp = fxp.Shl16(gainCode, exp)
	tmp = fxp.Mult(tmp, tmp)
	energy2 = fxp.Mult(energy2, tmp)
	exp2 -= exp << 1

	deltaExp := exp1 - exp2
	if deltaExp >= 0 {
		energy1 = fxp.Shr16(energy1, 1)
		energy2 = fxp.Shr16(energy2, deltaExp+1)
	} else {
		energy1 = fxp.Shr16(energy1, 1-deltaExp)
		energy2 = fxp.Shr16(energy2, 1)
	}

	diff := fxp.Sub16(energy1, energy2)
	total := fxp.Add16(fxp.Add16(energy1, energy2), 1)
	if diff >= 0 {
		return fxp.DivS(diff, total)
	}
	return fxp.Neg16(fxp.DivS(fxp.Neg16(diff), total))
}
