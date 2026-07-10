/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/isf_extrapolation.cpp.
 */

package amrwb

import (
	"errors"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const invLengthISFExtrapolation int16 = 2731

func isfExtrapolation(isf []int16) ([lpcOrder16k]int16, error) {
	var hfISF [lpcOrder16k]int16
	if len(isf) < lpcOrder {
		return hfISF, errors.New("extrapolate ISF: input buffer is too short")
	}
	copy(hfISF[:lpcOrder], isf[:lpcOrder])
	var diff [lpcOrder - 2]int16
	var corr [3]int32

	hfISF[lpcOrder16k-1] = hfISF[lpcOrder-1]
	for i := 1; i < lpcOrder-1; i++ {
		diff[i-1] = fxp.Sub16(hfISF[i], hfISF[i-1])
	}

	var acc int32
	for i := 3; i < lpcOrder-1; i++ {
		acc = fxp.Add32(acc, fxp.LMult(diff[i-1], invLengthISFExtrapolation))
	}
	mean := fxp.Round(acc)

	maxDiff := int16(0)
	for i := range lpcOrder - 2 {
		maxDiff = max(maxDiff, diff[i])
	}
	exp := fxp.NormS(maxDiff)
	for i := range lpcOrder - 2 {
		diff[i] = fxp.Shl16(diff[i], exp)
	}
	mean = fxp.Shl16(mean, exp)

	for lag := 2; lag <= 4; lag++ {
		var sum int32
		for i := 7; i < lpcOrder-2; i++ {
			tmp2 := fxp.Sub16(diff[i], mean)
			tmp3 := fxp.Sub16(diff[i-lag], mean)
			product := fxp.LMult(tmp2, tmp3)
			hi, lo := fxp.LExtract(product)
			sum = fxp.Add32(sum, fxp.Mpy32(hi, lo, hi, lo))
		}
		corr[lag-2] = sum
	}

	maxCorr := 0
	if corr[1] >= corr[0] {
		maxCorr = 1
	}
	if corr[2] > corr[maxCorr] {
		maxCorr = 2
	}
	maxCorr++

	for i := lpcOrder - 1; i < lpcOrder16k-1; i++ {
		delta := fxp.Sub16(hfISF[i-1-maxCorr], hfISF[i-2-maxCorr])
		hfISF[i] = fxp.Add16(hfISF[i-1], delta)
	}

	tmp := fxp.Add16(hfISF[4], hfISF[3])
	tmp = fxp.Sub16(hfISF[2], tmp)
	tmp = fxp.Mult(tmp, 5461)
	tmp = fxp.Add16(tmp, 20390)
	tmp = min(tmp, 19456)
	tmp = fxp.Sub16(tmp, hfISF[lpcOrder-2])
	tmp2 := fxp.Sub16(hfISF[lpcOrder16k-2], hfISF[lpcOrder-2])
	if tmp <= 0 || tmp2 <= 0 {
		return isfToISPOrder(hfISF[:], lpcOrder16k)
	}

	exp2 := fxp.NormS(tmp2)
	exp = fxp.Sub16(fxp.NormS(tmp), 1)
	scaledTmp := fxp.Shl16(tmp, exp)
	scaledTmp2 := fxp.Shl16(tmp2, exp2)
	coeff := fxp.DivS(scaledTmp, scaledTmp2)
	exp = exp2 - exp

	for i := lpcOrder - 1; i < lpcOrder16k-1; i++ {
		delta := fxp.Sub16(hfISF[i], hfISF[i-1])
		diff[i-(lpcOrder-1)] = fxp.Shl16(fxp.Mult(delta, coeff), exp)
	}

	for i := lpcOrder; i < lpcOrder16k-1; i++ {
		sum := fxp.Add16(diff[i-(lpcOrder-1)], diff[i-lpcOrder])
		if fxp.Sub16(sum, 1280) < 0 {
			if diff[i-(lpcOrder-1)] > diff[i-lpcOrder] {
				diff[i-lpcOrder] = fxp.Sub16(1280, diff[i-(lpcOrder-1)])
			} else {
				diff[i-(lpcOrder-1)] = fxp.Sub16(1280, diff[i-lpcOrder])
			}
		}
	}

	for i := lpcOrder - 1; i < lpcOrder16k-1; i++ {
		hfISF[i] = fxp.Add16(hfISF[i-1], diff[i-(lpcOrder-1)])
	}
	for i := range lpcOrder16k - 1 {
		hfISF[i] = fxp.Mult(hfISF[i], 26214)
	}
	return isfToISPOrder(hfISF[:], lpcOrder16k)
}
