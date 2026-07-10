/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/a_refl.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

func reflectionCoefficients(a []int16) [lpcOrder]int16 {
	var aState [lpcOrder]int16
	var bState [lpcOrder]int16
	copy(aState[:], a[:lpcOrder])

	var refl [lpcOrder]int16
	for i := lpcOrder - 1; i >= 0; i-- {
		if fxp.Abs16(aState[i]) >= 4096 {
			return [lpcOrder]int16{}
		}

		refl[i] = fxp.Shl16(aState[i], 3)
		acc := fxp.Sub32(fxp.Max32, fxp.LMult(refl[i], refl[i]))
		normShift := fxp.NormL(acc)
		scale := fxp.Sub16(15, normShift)
		normProd := fxp.Round(fxp.Shl32(acc, normShift))
		mult := fxp.DivS(16384, normProd)
		for j := range i {
			acc = int32(aState[j]) << 16
			acc = fxp.Sub32(acc, fxp.LMult(refl[i], aState[i-j-1]))
			temp := fxp.Round(acc)
			next := fxp.LMult(mult, temp)
			next = fxp.ShrRound32(next, scale)
			if fxp.Abs32(next) > int32(fxp.Max16) {
				return [lpcOrder]int16{}
			}
			bState[j] = fxp.ExtractL(next)
		}

		copy(aState[:i], bState[:i])
	}
	return refl
}
