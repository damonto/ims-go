/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This A(z) to ISP conversion is ported from amrwbenc/src/az_isp.c.
 */

package amrwb

import (
	"errors"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

var encoderISPGrid = [...]int16{
	32767, 32751, 32703, 32622, 32509, 32364,
	32187, 31978, 31738, 31466, 31164, 30830,
	30466, 30072, 29649, 29196, 28714, 28204,
	27666, 27101, 26509, 25891, 25248, 24579,
	23886, 23170, 22431, 21669, 20887, 20083,
	19260, 18418, 17557, 16680, 15786, 14876,
	13951, 13013, 12062, 11099, 10125, 9141,
	8149, 7148, 6140, 5126, 4106, 3083,
	2057, 1029, 0, -1029, -2057, -3083,
	-4106, -5126, -6140, -7148, -8149, -9141,
	-10125, -11099, -12062, -13013, -13951, -14876,
	-15786, -16680, -17557, -18418, -19260, -20083,
	-20887, -21669, -22431, -23170, -23886, -24579,
	-25248, -25891, -26509, -27101, -27666, -28204,
	-28714, -29196, -29649, -30072, -30466, -30830,
	-31164, -31466, -31738, -31978, -32187, -32364,
	-32509, -32622, -32703, -32751, -32760,
}

func encoderAzToISP(a []int16, oldISP []int16) ([lpcOrder]int16, error) {
	var isp [lpcOrder]int16
	if len(a) < lpcOrder+1 || len(oldISP) < lpcOrder {
		return isp, errors.New("convert A(z) to ISP: buffers are too short")
	}

	var f1 [lpcOrder/2 + 1]int16
	var f2 [lpcOrder / 2]int16
	for i := range lpcOrder / 2 {
		t0 := int32(a[i]) << 15
		f1[i] = fxp.Round(fxp.Add32(t0, int32(a[lpcOrder-i])<<15))
		f2[i] = fxp.Round(fxp.Sub32(t0, int32(a[lpcOrder-i])<<15))
	}
	f1[lpcOrder/2] = a[lpcOrder/2]
	for i := 2; i < lpcOrder/2; i++ {
		f2[i] = fxp.Add16(f2[i], f2[i-2])
	}

	found := 0
	useF1 := true
	coef := f1[:]
	order := lpcOrder / 2
	xlow := encoderISPGrid[0]
	ylow := encoderChebps2(xlow, coef, order)
	for j := 0; found < lpcOrder-1 && j < len(encoderISPGrid)-1; {
		j++
		xhigh := xlow
		yhigh := ylow
		xlow = encoderISPGrid[j]
		ylow = encoderChebps2(xlow, coef, order)
		if int32(ylow)*int32(yhigh) > 0 {
			continue
		}

		for range 2 {
			xmid := fxp.Shr16(xlow, 1) + fxp.Shr16(xhigh, 1)
			ymid := encoderChebps2(xmid, coef, order)
			if int32(ylow)*int32(ymid) <= 0 {
				yhigh = ymid
				xhigh = xmid
			} else {
				ylow = ymid
				xlow = xmid
			}
		}

		xint := xlow
		x := fxp.Sub16(xhigh, xlow)
		y := fxp.Sub16(yhigh, ylow)
		if y != 0 {
			sign := y
			y = fxp.Abs16(y)
			exp := fxp.NormS(y)
			y = fxp.Shl16(y, exp)
			y = fxp.DivS(16383, y)
			t0 := int32(x) * int32(y)
			t0 = fxp.Shr32(t0, 19-exp)
			y = fxp.ExtractL(t0)
			if sign < 0 {
				y = fxp.Neg16(y)
			}
			t0 = int32(ylow) * int32(y)
			t0 = fxp.Shr32(t0, 10)
			xint = fxp.Sub16(xlow, fxp.ExtractL(t0))
		}

		isp[found] = xint
		xlow = xint
		found++
		if useF1 {
			useF1 = false
			coef = f2[:]
			order = lpcOrder/2 - 1
		} else {
			useF1 = true
			coef = f1[:]
			order = lpcOrder / 2
		}
		ylow = encoderChebps2(xlow, coef, order)
	}

	if found < lpcOrder-1 {
		copy(isp[:lpcOrder], oldISP[:lpcOrder])
		return isp, nil
	}
	isp[lpcOrder-1] = fxp.Shl16(a[lpcOrder], 3)
	return isp, nil
}

func encoderChebps2(x int16, f []int16, n int) int16 {
	t0 := int32(f[0]) << 13
	b2h, b2l := fxp.LExtract(t0)

	t0 = (int32(b2h) * int32(x) << 1) + ((int32(b2l) * int32(x) >> 15) << 1)
	t0 <<= 1
	t0 += int32(f[1]) << 13
	b1h, b1l := fxp.LExtract(t0)

	for i := 2; i < n; i++ {
		t0 = (int32(b1h) * int32(x) << 1) + ((int32(b1l) * int32(x) >> 15) << 1)
		t0 += int32(b2h) * -16384 << 1
		t0 += int32(f[i]) << 12
		t0 <<= 1
		t0 -= int32(b2l) << 1

		b0h, b0l := fxp.LExtract(t0)
		b2h, b2l = b1h, b1l
		b1h, b1l = b0h, b0l
	}

	t0 = (int32(b1h) * int32(x) << 1) + ((int32(b1l) * int32(x) >> 15) << 1)
	t0 += int32(b2h) * -32768 << 1
	t0 -= int32(b2l) << 1
	t0 += int32(f[n]) << 12
	t0 = fxp.Shl32(t0, 6)
	cheb := fxp.ExtractH(t0)
	if cheb == fxp.Min16 {
		return -32767
	}
	return cheb
}
