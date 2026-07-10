/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This Az-to-LSP conversion is ported from amr_nb/common/src/az_lsp.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

var lspGrid = [...]int16{
	32760, 32723, 32588, 32364, 32051, 31651,
	31164, 30591, 29935, 29196, 28377, 27481,
	26509, 25465, 24351, 23170, 21926, 20621,
	19260, 17846, 16384, 14876, 13327, 11743,
	10125, 8480, 6812, 5126, 3425, 1714,
	0, -1714, -3425, -5126, -6812, -8480,
	-10125, -11743, -13327, -14876, -16384, -17846,
	-19260, -20621, -21926, -23170, -24351, -25465,
	-26509, -27481, -28377, -29196, -29935, -30591,
	-31164, -31651, -32051, -32364, -32588, -32723,
	-32760,
}

func azToLSP(a []int16, oldLSP []int16) ([lpcOrder]int16, error) {
	var lsp [lpcOrder]int16
	if len(a) < lpcCoeffCount || len(oldLSP) < lpcOrder {
		return lsp, fmt.Errorf(
			"converting AMR-NB LPC to LSP: coefficient counts %d/%d, want at least %d/%d",
			len(a),
			len(oldLSP),
			lpcCoeffCount,
			lpcOrder,
		)
	}
	var f1 [lpcOrder/2 + 1]int16
	var f2 [lpcOrder/2 + 1]int16
	f1[0] = 1024
	f2[0] = 1024
	for i := range lpcOrder / 2 {
		x := int16((int32(a[i+1]) + int32(a[lpcOrder-i])) >> 2)
		y := int16((int32(a[i+1]) - int32(a[lpcOrder-i])) >> 2)
		f1[i+1] = fxp.Sub16(x, f1[i])
		f2[i+1] = fxp.Add16(y, f2[i])
	}

	found := 0
	useF2 := false
	coef := f1[:]
	xlow := lspGrid[0]
	ylow := chebyshev(xlow, coef, lpcOrder/2)

	for j := 1; found < lpcOrder && j < len(lspGrid); j++ {
		xhigh := xlow
		yhigh := ylow
		xlow = lspGrid[j]
		ylow = chebyshev(xlow, coef, lpcOrder/2)
		if int32(ylow)*int32(yhigh) > 0 {
			continue
		}

		for range 4 {
			xmid := (xlow >> 1) + (xhigh >> 1)
			ymid := chebyshev(xmid, coef, lpcOrder/2)
			if int32(ylow)*int32(ymid) <= 0 {
				yhigh = ymid
				xhigh = xmid
			} else {
				ylow = ymid
				xlow = xmid
			}
		}

		x := fxp.Sub16(xhigh, xlow)
		y := fxp.Sub16(yhigh, ylow)
		xint := xlow
		if y != 0 {
			sign := y
			y = fxp.Abs16(y)
			exp := fxp.NormS(y)
			y = fxp.Shl16(y, exp)
			y = fxp.DivS(16383, y)
			y = int16((int32(x) * int32(y)) >> (19 - exp))
			if sign < 0 {
				y = fxp.Neg16(y)
			}
			xint = fxp.Sub16(xlow, int16((int32(ylow)*int32(y))>>10))
		}

		lsp[found] = xint
		xlow = xint
		found++
		if useF2 {
			useF2 = false
			coef = f1[:]
		} else {
			useF2 = true
			coef = f2[:]
		}
		ylow = chebyshev(xlow, coef, lpcOrder/2)
	}

	if found < lpcOrder {
		copy(lsp[:lpcOrder], oldLSP[:lpcOrder])
	}
	return lsp, nil
}

func chebyshev(x int16, f []int16, n int) int16 {
	if len(f) <= n || n < 2 {
		return 0
	}
	prev := int32(0x01000000)
	t0 := (int32(x) << 10) + (int32(f[1]) << 14)
	b1h, b1l := fxp.LExtract(t0)

	for i := 2; i < n; i++ {
		t0 = int32(b1h)*int32(x) + ((int32(b1l) * int32(x)) >> 15)
		t0 <<= 2
		t0 -= prev
		t0 += int32(f[i]) << 14
		prev = (int32(b1h) << 16) + (int32(b1l) << 1)
		b1h, b1l = fxp.LExtract(t0)
	}

	t0 = int32(b1h)*int32(x) + ((int32(b1l) * int32(x)) >> 15)
	t0 <<= 1
	t0 -= prev
	t0 += int32(f[n]) << 13

	if uint32(t0+33554432) < 67108863 {
		return int16(t0 >> 10)
	}
	if t0 > 0x01ffffff {
		return fxp.Max16
	}
	return fxp.Min16
}
