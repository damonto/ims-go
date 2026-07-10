/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This Levinson-Durbin LPC recursion is ported from amrwbenc/src/levinson.c.
 */

package amrwb

import (
	"errors"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type encoderLevinsonState struct {
	oldA  [lpcOrder]int16
	oldRC [2]int16
}

type encoderLevinsonResult struct {
	a  [lpcCoeffCount]int16
	rc [lpcOrder]int16
}

func newEncoderLevinsonState() encoderLevinsonState {
	return encoderLevinsonState{}
}

func (s *encoderLevinsonState) reset() {
	clear(s.oldA[:])
	clear(s.oldRC[:])
}

func (s *encoderLevinsonState) levinson(rh []int16, rl []int16) (encoderLevinsonResult, error) {
	var out encoderLevinsonResult
	if len(rh) < lpcOrder+1 || len(rl) < lpcOrder+1 {
		return out, errors.New("run Levinson-Durbin recursion: buffers are too short")
	}

	var ah [lpcOrder + 1]int16
	var al [lpcOrder + 1]int16
	var anh [lpcOrder + 1]int16
	var anl [lpcOrder + 1]int16

	t1 := fxp.LComp(rh[1], rl[1])
	t2 := fxp.Abs32(t1)
	t0 := fxp.Div32(t2, rh[0], rl[0])
	if t1 > 0 {
		t0 = fxp.Neg32(t0)
	}

	kh, kl := fxp.LExtract(t0)
	out.rc[0] = kh
	t0 = fxp.Shr32(t0, 4)
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
		t0 = 0
		for j := 1; j < i; j++ {
			t0 = fxp.Add32(t0, fxp.Mpy32(rh[j], rl[j], ah[i-j], al[i-j]))
		}
		t0 = fxp.Shl32(t0, 4)
		t1 = fxp.LComp(rh[i], rl[i])
		t0 = fxp.Add32(t0, t1)

		t1 = fxp.Abs32(t0)
		t2 = fxp.Div32(t1, alpH, alpL)
		if t0 > 0 {
			t2 = fxp.Neg32(t2)
		}
		t2 = fxp.Shl32(t2, alpExp)

		kh, kl = fxp.LExtract(t2)
		out.rc[i-1] = kh
		if fxp.Abs16(kh) > 32750 {
			out.a[0] = 4096
			copy(out.a[1:lpcOrder+1], s.oldA[:])
			out.rc[0] = s.oldRC[0]
			out.rc[1] = s.oldRC[1]
			return out, nil
		}

		for j := 1; j < i; j++ {
			t0 = fxp.Mpy32(kh, kl, ah[i-j], al[i-j])
			t0 = fxp.Add32(t0, fxp.LComp(ah[j], al[j]))
			anh[j], anl[j] = fxp.LExtract(t0)
		}
		t2 = fxp.Shr32(t2, 4)
		anh[i], anl[i] = fxp.LExtract(t2)

		t0 = fxp.Mpy32(kh, kl, kh, kl)
		t0 = fxp.Abs32(t0)
		t0 = fxp.Sub32(fxp.Max32, t0)
		hi, lo = fxp.LExtract(t0)
		t0 = fxp.Mpy32(alpH, alpL, hi, lo)

		shift := fxp.NormL(t0)
		t0 = fxp.Shl32(t0, shift)
		alpH, alpL = fxp.LExtract(t0)
		alpExp = fxp.Add16(alpExp, shift)

		for j := 1; j <= i; j++ {
			ah[j] = anh[j]
			al[j] = anl[j]
		}
	}

	out.a[0] = 4096
	for i := 1; i <= lpcOrder; i++ {
		t0 = fxp.LComp(ah[i], al[i])
		out.a[i] = fxp.Round(fxp.Shl32(t0, 1))
		s.oldA[i-1] = out.a[i]
	}
	s.oldRC[0] = out.rc[0]
	s.oldRC[1] = out.rc[1]
	return out, nil
}
