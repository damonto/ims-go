/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This Levinson-Durbin LPC recursion is ported from amr_nb/enc/src/levinson.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type levinsonState struct {
	oldA [lpcCoeffCount]int16
}

type levinsonResult struct {
	a  [lpcCoeffCount]int16
	rc [4]int16
}

func newLevinsonState() levinsonState {
	var state levinsonState
	state.reset()
	return state
}

func (s *levinsonState) reset() {
	clear(s.oldA[:])
	s.oldA[0] = 4096
}

func (s *levinsonState) levinson(rh []int16, rl []int16) (levinsonResult, error) {
	var out levinsonResult
	if len(rh) < lpcCoeffCount || len(rl) < lpcCoeffCount {
		return out, fmt.Errorf(
			"calculating AMR-NB Levinson recursion: autocorrelation counts %d/%d, want at least %d",
			len(rh),
			len(rl),
			lpcCoeffCount,
		)
	}

	var ah [lpcCoeffCount]int16
	var al [lpcCoeffCount]int16
	var anh [lpcCoeffCount]int16
	var anl [lpcCoeffCount]int16

	t1 := (int32(rh[1]) << 16) + (int32(rl[1]) << 1)
	t2 := fxp.Abs32(t1)
	t0 := fxp.Div32(t2, rh[0], rl[0])
	if t1 > 0 {
		t0 = fxp.Neg32(t0)
	}
	kh, kl := fxp.LExtract(t0)
	out.rc[0] = fxp.Round(t0)

	t0 >>= 4
	ah[1], al[1] = fxp.LExtract(t0)

	t0 = fxp.Mpy32(kh, kl, kh, kl)
	t0 = fxp.Abs32(t0)
	t0 = fxp.Sub32(fxp.Max32, t0)
	hi, lo := fxp.LExtract(t0)
	t0 = fxp.Mpy32(rh[0], rl[0], hi, lo)

	alpExp := fxp.NormL(t0)
	t0 = fxp.Shl32(t0, alpExp)
	alpH, alpL := fxp.LExtract(t0)

	for i := 2; i <= lpcOrder; i++ {
		var sum int32
		for j := 1; j < i; j++ {
			sum += (int32(rh[j]) * int32(al[i-j])) >> 15
			sum += (int32(rl[j]) * int32(ah[i-j])) >> 15
			sum += int32(rh[j]) * int32(ah[i-j])
		}
		sum <<= 5
		sum += (int32(rh[i]) << 16) + (int32(rl[i]) << 1)

		tmp := fxp.Div32(fxp.Abs32(sum), alpH, alpL)
		if sum > 0 {
			tmp = fxp.Neg32(tmp)
		}
		tmp = fxp.Shl32(tmp, alpExp)
		kh, kl = fxp.LExtract(tmp)
		if i < 5 {
			out.rc[i-1] = fxp.Round(tmp)
		}
		if fxp.Abs16(kh) > 32750 {
			out.a = s.oldA
			clear(out.rc[:])
			return out, nil
		}

		for j := 1; j < i; j++ {
			acc := (int32(kh) * int32(al[i-j])) >> 15
			acc += (int32(kl) * int32(ah[i-j])) >> 15
			acc += int32(kh) * int32(ah[i-j])
			acc += (int32(ah[j]) << 15) + int32(al[j])
			anh[j] = int16(acc >> 15)
			anl[j] = int16(acc - (int32(anh[j]) << 15))
		}
		anh[i] = int16(tmp >> 20)
		anl[i] = int16((tmp >> 5) - (int32(anh[i]) << 15))

		tmp = fxp.Mpy32(kh, kl, kh, kl)
		tmp = fxp.Abs32(tmp)
		tmp = fxp.Sub32(fxp.Max32, tmp)
		hi, lo = fxp.LExtract(tmp)
		tmp = fxp.Mpy32(alpH, alpL, hi, lo)
		shift := fxp.NormL(tmp)
		tmp = fxp.Shl32(tmp, shift)
		alpH, alpL = fxp.LExtract(tmp)
		alpExp = fxp.Add16(alpExp, shift)

		copy(ah[1:i+1], anh[1:i+1])
		copy(al[1:i+1], anl[1:i+1])
	}

	out.a[0] = 4096
	for i := 1; i <= lpcOrder; i++ {
		tmp := (int32(ah[i]) << 15) + int32(al[i])
		out.a[i] = int16((tmp + 0x2000) >> 14)
	}
	s.oldA = out.a
	return out, nil
}
