/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_nb/common/src/lsp_lsf.cpp,
 * lsp_az.cpp, int_lpc.cpp, and amr_nb/dec/src/lsp_avg.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	lpcCoeffCount = lpcOrder + 1
	azFrameCount  = 4 * lpcCoeffCount
	lspAvgExp     = 5243
)

var lspCosTable = [...]int16{
	32767, 32729, 32610, 32413, 32138, 31786, 31357, 30853,
	30274, 29622, 28899, 28106, 27246, 26320, 25330, 24279,
	23170, 22006, 20788, 19520, 18205, 16846, 15447, 14010,
	12540, 11039, 9512, 7962, 6393, 4808, 3212, 1608,
	0, -1608, -3212, -4808, -6393, -7962, -9512, -11039,
	-12540, -14010, -15447, -16846, -18205, -19520, -20788, -22006,
	-23170, -24279, -25330, -26320, -27246, -28106, -28899, -29622,
	-30274, -30853, -31357, -31786, -32138, -32413, -32610, -32729,
	-32768,
}

var lspSlope = [...]int16{
	-26887, -8812, -5323, -3813, -2979, -2444, -2081, -1811,
	-1608, -1450, -1322, -1219, -1132, -1059, -998, -946,
	-901, -861, -827, -797, -772, -750, -730, -713,
	-699, -687, -677, -668, -662, -657, -654, -652,
	-652, -654, -657, -662, -668, -677, -687, -699,
	-713, -730, -750, -772, -797, -827, -861, -901,
	-946, -998, -1059, -1132, -1219, -1322, -1450, -1608,
	-1811, -2081, -2444, -2979, -3813, -5323, -8812, -26887,
}

var meanLSF5 = [...]int16{1384, 2077, 3420, 5108, 6742, 8122, 9863, 11092, 12714, 13701}

type lspAvgState struct {
	meanSave [lpcOrder]int16
}

func newLSPAvgState() lspAvgState {
	var state lspAvgState
	state.reset()
	return state
}

func (s *lspAvgState) reset() {
	copy(s.meanSave[:], meanLSF5[:])
}

func (s *lspAvgState) update(lsp []int16) {
	for i := range lpcOrder {
		acc := int32(s.meanSave[i]) << 16
		acc = fxp.Sub32(acc, fxp.LMult(lspAvgExp, s.meanSave[i]))
		acc = fxp.Add32(acc, fxp.LMult(lspAvgExp, lsp[i]))
		s.meanSave[i] = fxp.Round(acc)
	}
}

func lsfToLsp(lsf []int16) [lpcOrder]int16 {
	var lsp [lpcOrder]int16
	for i := range lpcOrder {
		index := int(lsf[i] >> 8)
		if index < 0 {
			index = 0
		} else if index >= len(lspCosTable)-1 {
			index = len(lspCosTable) - 2
		}
		offset := int16(lsf[i] & 0x00ff)
		delta := int32(lspCosTable[index+1]-lspCosTable[index]) * int32(offset)
		lsp[i] = lspCosTable[index] + int16(delta>>8)
	}
	return lsp
}

func lspToLsf(lsp []int16) [lpcOrder]int16 {
	var lsf [lpcOrder]int16
	index := 63
	for i := lpcOrder - 1; i >= 0; i-- {
		value := lsp[i]
		for index > 0 && lspCosTable[index] < value {
			index--
		}
		interp := (int32(value-lspCosTable[index])*int32(lspSlope[index]) + 0x800) >> 12
		lsf[i] = int16(interp) + int16(index<<8)
	}
	return lsf
}

func lspToAz(lsp []int16) [lpcCoeffCount]int16 {
	f1 := lspPolynomial(lsp[0:])
	f2 := lspPolynomial(lsp[1:])

	for i := 5; i > 0; i-- {
		f1[i] += f1[i-1]
		f2[i] -= f2[i-1]
	}

	var a [lpcCoeffCount]int16
	a[0] = 4096
	for i, j := 1, 10; i <= 5; i, j = i+1, j-1 {
		sum := f1[i] + f2[i] + (1 << 12)
		diff := f1[i] - f2[i] + (1 << 12)
		a[i] = int16(sum >> 13)
		a[j] = int16(diff >> 13)
	}
	return a
}

func interpolateLPC1To3(lspOld, lspNew []int16) [azFrameCount]int16 {
	var az [azFrameCount]int16
	var lsp [lpcOrder]int16
	for i := range lpcOrder {
		temp := lspOld[i] - (lspOld[i] >> 2)
		lsp[i] = temp + (lspNew[i] >> 2)
	}
	coeff := lspToAz(lsp[:])
	copy(az[0:lpcCoeffCount], coeff[:])
	for i := range lpcOrder {
		lsp[i] = (lspNew[i] >> 1) + (lspOld[i] >> 1)
	}
	coeff = lspToAz(lsp[:])
	copy(az[lpcCoeffCount:2*lpcCoeffCount], coeff[:])
	for i := range lpcOrder {
		temp := lspNew[i] - (lspNew[i] >> 2)
		lsp[i] = temp + (lspOld[i] >> 2)
	}
	coeff = lspToAz(lsp[:])
	copy(az[2*lpcCoeffCount:3*lpcCoeffCount], coeff[:])

	coeff = lspToAz(lspNew)
	copy(az[3*lpcCoeffCount:4*lpcCoeffCount], coeff[:])
	return az
}

func interpolateLPC1And3(lspOld, lspMid, lspNew []int16) [azFrameCount]int16 {
	var az [azFrameCount]int16
	var lsp [lpcOrder]int16
	for i := range lpcOrder {
		lsp[i] = (lspOld[i] >> 1) + (lspMid[i] >> 1)
	}
	coeff := lspToAz(lsp[:])
	copy(az[0:lpcCoeffCount], coeff[:])
	coeff = lspToAz(lspMid)
	copy(az[lpcCoeffCount:2*lpcCoeffCount], coeff[:])
	for i := range lpcOrder {
		lsp[i] = (lspMid[i] >> 1) + (lspNew[i] >> 1)
	}
	coeff = lspToAz(lsp[:])
	copy(az[2*lpcCoeffCount:3*lpcCoeffCount], coeff[:])
	coeff = lspToAz(lspNew)
	copy(az[3*lpcCoeffCount:4*lpcCoeffCount], coeff[:])
	return az
}

func interpolateLPC1And3Partial(lspOld, lspMid, lspNew []int16) [2][lpcCoeffCount]int16 {
	var az [2][lpcCoeffCount]int16
	var lsp [lpcOrder]int16
	for i := range lpcOrder {
		lsp[i] = (lspOld[i] >> 1) + (lspMid[i] >> 1)
	}
	az[0] = lspToAz(lsp[:])
	for i := range lpcOrder {
		lsp[i] = (lspMid[i] >> 1) + (lspNew[i] >> 1)
	}
	az[1] = lspToAz(lsp[:])
	return az
}

func interpolateLPC1To3Partial(lspOld, lspNew []int16) [3][lpcCoeffCount]int16 {
	var az [3][lpcCoeffCount]int16
	var lsp [lpcOrder]int16
	for i := range lpcOrder {
		temp := lspOld[i] - (lspOld[i] >> 2)
		lsp[i] = temp + (lspNew[i] >> 2)
	}
	az[0] = lspToAz(lsp[:])
	for i := range lpcOrder {
		lsp[i] = (lspNew[i] >> 1) + (lspOld[i] >> 1)
	}
	az[1] = lspToAz(lsp[:])
	for i := range lpcOrder {
		temp := lspNew[i] - (lspNew[i] >> 2)
		lsp[i] = temp + (lspOld[i] >> 2)
	}
	az[2] = lspToAz(lsp[:])
	return az
}

func lspPolynomial(lsp []int16) [6]int32 {
	var f [6]int32
	f[0] = 0x01000000
	f[1] = -int32(lsp[0]) << 10
	lspIndex := 2
	fIndex := 2

	for i := 2; i <= 5; i++ {
		f[fIndex] = f[fIndex-2]
		for j := 1; j < i; j++ {
			prev := f[fIndex-1]
			hi := int16(prev >> 16)
			lo := int16((prev >> 1) - (int32(hi) << 15))
			product := int32(hi)*int32(lsp[lspIndex]) + ((int32(lo) * int32(lsp[lspIndex])) >> 15)
			f[fIndex] += f[fIndex-2]
			f[fIndex] -= product << 2
			fIndex--
		}
		f[fIndex] -= int32(lsp[lspIndex]) << 10
		fIndex += i
		lspIndex += 2
	}
	return f
}
