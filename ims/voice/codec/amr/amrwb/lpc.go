/*
 * Copyright (C) 1998-2010 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_wb/dec/src/isp_isf.cpp,
 * isp_az.cpp, and interpolate_isp.cpp.
 */

package amrwb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const lpcCoeffCount = lpcOrder + 1

var interpolFrac = [...]int16{14746, 26214, 31457, 32767}

var ispCosTable = [...]int16{
	32767,
	32758, 32729, 32679, 32610, 32522, 32413, 32286, 32138,
	31972, 31786, 31581, 31357, 31114, 30853, 30572, 30274,
	29957, 29622, 29269, 28899, 28511, 28106, 27684, 27246,
	26791, 26320, 25833, 25330, 24812, 24279, 23732, 23170,
	22595, 22006, 21403, 20788, 20160, 19520, 18868, 18205,
	17531, 16846, 16151, 15447, 14733, 14010, 13279, 12540,
	11793, 11039, 10279, 9512, 8740, 7962, 7180, 6393,
	5602, 4808, 4011, 3212, 2411, 1608, 804, 0,
	-804, -1608, -2411, -3212, -4011, -4808, -5602, -6393,
	-7180, -7962, -8740, -9512, -10279, -11039, -11793, -12540,
	-13279, -14010, -14733, -15447, -16151, -16846, -17531, -18205,
	-18868, -19520, -20160, -20788, -21403, -22006, -22595, -23170,
	-23732, -24279, -24812, -25330, -25833, -26320, -26791, -27246,
	-27684, -28106, -28511, -28899, -29269, -29622, -29957, -30274,
	-30572, -30853, -31114, -31357, -31581, -31786, -31972, -32138,
	-32286, -32413, -32522, -32610, -32679, -32729, -32758, -32768,
}

func isfToISP(isf []int16) ([lpcOrder]int16, error) {
	var out [lpcOrder]int16
	isp, err := isfToISPOrder(isf, lpcOrder)
	if err != nil {
		return out, err
	}
	copy(out[:], isp[:lpcOrder])
	return out, nil
}

func isfToISPOrder(isf []int16, order int) ([lpcOrder16k]int16, error) {
	var isp [lpcOrder16k]int16
	if order <= 0 || order > lpcOrder16k || len(isf) < order {
		return isp, fmt.Errorf("convert ISF to ISP: order %d with %d input values is invalid", order, len(isf))
	}
	for i := range order {
		value := isf[i]
		if i == order-1 {
			value = fxp.Shl16(value, 1)
		}
		index := int(value >> 7)
		if index < 0 {
			index = 0
		} else if index >= len(ispCosTable)-1 {
			index = len(ispCosTable) - 2
		}
		offset := int16(value & 0x007f)
		delta := int32(ispCosTable[index+1]-ispCosTable[index]) * int32(offset)
		isp[i] = fxp.Add16(ispCosTable[index], int16(delta>>7))
	}
	return isp, nil
}

func interpolateISP(ispOld, ispNew []int16) ([4 * lpcCoeffCount]int16, error) {
	var az [4 * lpcCoeffCount]int16
	if len(ispOld) < lpcOrder || len(ispNew) < lpcOrder {
		return az, fmt.Errorf("interpolate ISP: input lengths %d/%d, want at least %d", len(ispOld), len(ispNew), lpcOrder)
	}
	var isp [lpcOrder]int16
	for subframe := range 3 {
		facNew := interpolFrac[subframe]
		facOld := fxp.Add16(fxp.Sub16(fxp.Max16, facNew), 1)
		for i := range lpcOrder {
			acc := int32(ispOld[i]) * int32(facOld)
			acc += int32(ispNew[i]) * int32(facNew)
			isp[i] = fxp.Round(acc << 1)
		}
		coefficients, err := ispToAz(isp[:], false)
		if err != nil {
			return az, fmt.Errorf("interpolate ISP: subframe %d: %w", subframe, err)
		}
		copy(az[subframe*lpcCoeffCount:(subframe+1)*lpcCoeffCount], coefficients[:])
	}
	coefficients, err := ispToAz(ispNew, false)
	if err != nil {
		return az, fmt.Errorf("interpolate ISP: final subframe: %w", err)
	}
	copy(az[3*lpcCoeffCount:4*lpcCoeffCount], coefficients[:])
	return az, nil
}

func weightLPC(a []int16, gamma int16) ([lpcCoeffCount]int16, error) {
	var out [lpcCoeffCount]int16
	weighted, err := weightLPCOrder(a, gamma, lpcOrder)
	if err != nil {
		return out, err
	}
	copy(out[:], weighted[:lpcCoeffCount])
	return out, nil
}

func weightLPCOrder(a []int16, gamma int16, order int) ([lpcOrder16k + 1]int16, error) {
	var weighted [lpcOrder16k + 1]int16
	if order <= 0 || order > lpcOrder16k || len(a) <= order {
		return weighted, fmt.Errorf("weight LPC: order %d with %d coefficients is invalid", order, len(a))
	}

	weighted[0] = a[0]
	factor := gamma
	for i := 1; i <= order; i++ {
		weighted[i] = int16((int32(a[i])*int32(factor) + 0x4000) >> 15)
		factor = int16((int32(factor)*int32(gamma) + 0x4000) >> 15)
	}
	return weighted, nil
}

func reorderISF(isf [lpcOrder]int16, minDistance int16) [lpcOrder]int16 {
	isfMin := minDistance
	for i := range lpcOrder - 1 {
		isf[i] = max(isf[i], isfMin)
		isfMin = fxp.Add16(isf[i], minDistance)
	}
	return isf
}

func median5(values []int16) int16 {
	x1 := values[0]
	x2 := values[1]
	x3 := values[2]
	x4 := values[3]
	x5 := values[4]

	if x2 < x1 {
		x1, x2 = x2, x1
	}
	if x3 < x1 {
		x1, x3 = x3, x1
	}
	if x4 < x1 {
		x1, x4 = x4, x1
	}

	x5 = max(x5, x1)

	if x3 < x2 {
		x2, x3 = x3, x2
	}
	if x4 < x2 {
		x2, x4 = x4, x2
	}

	x5 = max(x5, x2)
	x3 = min(x3, x4)
	x3 = min(x3, x5)

	return x3
}

func ispToAz(isp []int16, adaptiveScaling bool) ([lpcCoeffCount]int16, error) {
	var out [lpcCoeffCount]int16
	coefficients, err := ispToAzOrder(isp, lpcOrder, adaptiveScaling)
	if err != nil {
		return out, err
	}
	copy(out[:], coefficients[:lpcCoeffCount])
	return out, nil
}

func ispToAzOrder(isp []int16, order int, adaptiveScaling bool) ([lpcOrder16k + 1]int16, error) {
	var a [lpcOrder16k + 1]int16
	if order <= 0 || order > lpcOrder16k || order%2 != 0 || len(isp) < order {
		return a, fmt.Errorf("convert ISP to Az: order %d with %d ISP values is invalid", order, len(isp))
	}
	var f1 [lpcOrder16k/2 + 1]int32
	var f2 [lpcOrder16k/2 + 1]int32
	nc := order / 2

	if nc > lpcOrder/2 {
		f1 = ispPolynomial16k(isp, nc)
		for i := 0; i <= nc; i++ {
			f1[i] = fxp.Shl32(f1[i], 2)
		}
		f2 = ispPolynomial16k(isp[1:], nc-1)
		for i := 0; i <= nc-1; i++ {
			f2[i] = fxp.Shl32(f2[i], 2)
		}
	} else {
		f1 = ispPolynomial(isp, nc)
		f2 = ispPolynomial(isp[1:], nc-1)
	}
	for i := nc - 1; i > 1; i-- {
		f2[i] -= f2[i-2]
	}
	for i := range nc {
		t0 := fxpMul32By16(f1[i], isp[order-1]) << 1
		t1 := fxpMul32By16(f2[i], isp[order-1]) << 1
		f1[i] += t0
		f2[i] -= t1
	}

	a[0] = 4096
	tmax := int32(1)
	j := order - 1
	for i := 1; i < nc; i++ {
		t0 := f1[i] + f2[i]
		tmax |= fxp.Abs32(t0)
		a[i] = int16((t0 >> 12) + ((t0 >> 11) & 1))

		t0 = f1[i] - f2[i]
		tmax |= fxp.Abs32(t0)
		a[j] = int16((t0 >> 12) + ((t0 >> 11) & 1))
		j--
	}

	q := int16(0)
	if adaptiveScaling {
		q = 4 - normalizeAMRWB(tmax)
	}
	qSug := int16(12)
	if q > 0 {
		qSug = 12 + q
		for i, j := 1, order-1; i < nc; i, j = i+1, j-1 {
			t0 := f1[i] + f2[i]
			a[i] = int16((t0 >> qSug) + ((t0 >> (qSug - 1)) & 1))

			t0 = f1[i] - f2[i]
			a[j] = int16((t0 >> qSug) + ((t0 >> (qSug - 1)) & 1))
		}
		a[0] >>= q
	} else {
		q = 0
	}

	t0 := fxpMul32By16(f1[nc], isp[order-1]) << 1
	t0 += f1[nc]
	a[nc] = int16((t0 >> qSug) + ((t0 >> (qSug - 1)) & 1))
	a[order] = fxp.ShrRound16(isp[order-1], 3+q)
	return a, nil
}

func ispPolynomial(isp []int16, n int) [lpcOrder16k/2 + 1]int32 {
	var f [lpcOrder16k/2 + 1]int32
	f[0] = 0x00800000
	f[1] = -int32(isp[0]) << 9
	fIndex := 2
	ispIndex := 2

	for i := 2; i <= n; i++ {
		f[fIndex] = f[fIndex-2]
		for j := 1; j < i; j++ {
			t0 := fxpMul32By16(f[fIndex-1], isp[ispIndex])
			t0 = fxp.Shl32(t0, 2)
			f[fIndex] -= t0
			f[fIndex] += f[fIndex-2]
			fIndex--
		}
		f[fIndex] -= int32(isp[ispIndex]) << 9
		fIndex += i
		ispIndex += 2
	}
	return f
}

func ispPolynomial16k(isp []int16, n int) [lpcOrder16k/2 + 1]int32 {
	var f [lpcOrder16k/2 + 1]int32
	f[0] = 0x00200000
	f[1] = -int32(isp[0]) << 7
	fIndex := 2
	ispIndex := 2

	for i := 2; i <= n; i++ {
		f[fIndex] = f[fIndex-2]
		for j := 1; j < i; j++ {
			t0 := fxpMul32By16(f[fIndex-1], isp[ispIndex])
			t0 = fxp.Shl32(t0, 2)
			f[fIndex] -= t0
			f[fIndex] += f[fIndex-2]
			fIndex--
		}
		f[fIndex] -= int32(isp[ispIndex]) << 7
		fIndex += i
		ispIndex += 2
	}
	return f
}

func fxpMul32By16(value int32, factor int16) int32 {
	return int32((int64(value) * int64(int32(factor)<<16)) >> 32)
}

func normalizeAMRWB(value int32) int16 {
	return fxp.NormL(value)
}
