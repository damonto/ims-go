/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/agc2_amr_wb.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

func agc2AMRWB(reference [subframeSamples]int16, signal [subframeSamples]int16) [subframeSamples]int16 {
	energyOut := agc2EnergyWB(signal[:])
	if energyOut == 0 {
		return signal
	}
	exp := normalizeAMRWB(energyOut) - 1
	gainOut := fxp.Round(fxp.Shl32(energyOut, exp))

	energyIn := agc2EnergyWB(reference[:])
	var g0 int16
	if energyIn == 0 {
		g0 = 0
	} else {
		inExp := normalizeAMRWB(energyIn)
		gainIn := fxp.Round(fxp.Shl32(energyIn, inExp))
		exp -= inExp

		scale := int32(fxp.DivS(gainOut, gainIn))
		scale = fxp.Shl32(scale, 7)
		scale = fxp.Shr32(scale, exp)
		scale = oneOverSqrtWB(scale)
		g0 = fxp.Round(fxp.Shl32(scale, 9))
	}
	for i := range signal {
		signal[i] = fxp.ExtractH(fxp.Shl32(fxp.LMult(signal[i], g0), 2))
	}
	return signal
}

func agc2EnergyWB(signal []int16) int32 {
	if len(signal) == 0 {
		return 0
	}
	temp := signal[0] >> 2
	sum := fxp.LMult(temp, temp)
	for i := 1; i < len(signal); i++ {
		temp = signal[i] >> 2
		sum = fxp.Add32(sum, fxp.LMult(temp, temp))
	}
	return sum
}

func oneOverSqrtWB(value int32) int32 {
	if value <= 0 {
		return fxp.Max32
	}
	exp := normalizeAMRWB(value)
	value = fxp.Shl32(value, exp)
	exp = 31 - exp
	value, exp = oneOverSqrtNorm(value, exp)
	return fxp.Shl32(value, exp)
}
