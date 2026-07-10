/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/agc.cpp and
 * common/src/inv_sqrt.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

var invSqrtTable = [...]int16{
	32767, 31790, 30894, 30070, 29309, 28602, 27945, 27330, 26755, 26214,
	25705, 25225, 24770, 24339, 23930, 23541, 23170, 22817, 22479, 22155,
	21845, 21548, 21263, 20988, 20724, 20470, 20225, 19988, 19760, 19539,
	19326, 19119, 18919, 18725, 18536, 18354, 18176, 18004, 17837, 17674,
	17515, 17361, 17211, 17064, 16921, 16782, 16646, 16514, 16384,
}

func agc2(reference []int16, signal []int16) {
	energyOut := agcEnergyNew(signal)
	if energyOut == 0 {
		return
	}
	exp := fxp.NormL(energyOut) - 1
	gainOut := fxp.Round(fxp.Shl32(energyOut, exp))

	energyIn := agcEnergyNew(reference)
	var g0 int16
	if energyIn == 0 {
		g0 = 0
	} else {
		inExp := fxp.NormL(energyIn)
		gainIn := fxp.Round(fxp.Shl32(energyIn, inExp))
		exp -= inExp

		scale := int32(fxp.DivS(gainOut, gainIn))
		scale = fxp.Shl32(scale, 7)
		scale = fxp.Shr32(scale, exp)
		scale = invSqrt(scale)
		g0 = fxp.Round(fxp.Shl32(scale, 9))
	}

	for i := range signal {
		acc := fxp.LMult(signal[i], g0)
		if acc > 0x0fffffff {
			signal[i] = fxp.Max16
		} else if acc < -0x10000000 {
			signal[i] = fxp.Min16
		} else {
			signal[i] = int16(acc >> 13)
		}
	}
}

func agcEnergyNew(in []int16) int32 {
	sum := int32(0)
	for i := range in {
		next := fxp.Add32(sum, fxp.LMult(in[i], in[i]))
		sum = next
		if sum == fxp.Max32 {
			return agcEnergyOld(in)
		}
	}
	return fxp.Shr32(sum, 4)
}

func agcEnergyOld(in []int16) int32 {
	sum := int32(0)
	for _, sample := range in {
		scaled := sample >> 2
		sum = fxp.Add32(sum, fxp.LMult(scaled, scaled))
	}
	return sum
}

func invSqrt(x int32) int32 {
	if x <= 0 {
		return 0x3fffffff
	}

	exp := fxp.NormL(x)
	x <<= exp
	exp = 30 - exp
	if exp&1 == 0 {
		x >>= 1
	}
	exp >>= 1
	exp++

	x >>= 9
	index := int16(x >> 16)
	frac := int16(x >> 1)
	frac &= 0x7fff
	index -= 16

	index = max(index, 0)

	if int(index) >= len(invSqrtTable)-1 {
		index = int16(len(invSqrtTable) - 2)
	}

	y := int32(invSqrtTable[index]) << 16
	delta := int32(invSqrtTable[index] - invSqrtTable[index+1])
	y -= (delta * int32(frac)) << 1
	return y >> exp
}
