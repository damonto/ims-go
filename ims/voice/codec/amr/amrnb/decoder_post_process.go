/*
 * Copyright (C) 1998-2010 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/post_pro.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	postProcessA1 int16 = 15836
	postProcessA2 int16 = -7667
	postProcessB0 int16 = 7699
	postProcessB1 int16 = -15398
	postProcessB2 int16 = 7699
)

type postProcessState struct {
	y2Hi int16
	y2Lo int16
	y1Hi int16
	y1Lo int16
	x0   int16
	x1   int16
}

func (s *postProcessState) reset() {
	*s = postProcessState{}
}

func (s *postProcessState) process(signal []int16) {
	for i := range signal {
		x2 := s.x1
		s.x1 = s.x0
		s.x0 = signal[i]

		acc := mpy32x16(s.y1Hi, s.y1Lo, postProcessA1)
		acc = fxp.Add32(acc, mpy32x16(s.y2Hi, s.y2Lo, postProcessA2))
		acc = fxp.Add32(acc, fxp.LMult(s.x0, postProcessB0))
		acc = fxp.Add32(acc, fxp.LMult(s.x1, postProcessB1))
		acc = fxp.Add32(acc, fxp.LMult(x2, postProcessB2))
		acc = fxp.Shl32(acc, 2)

		signal[i] = fxp.Round(fxp.Shl32(acc, 1))

		s.y2Hi = s.y1Hi
		s.y2Lo = s.y1Lo
		s.y1Hi, s.y1Lo = fxp.LExtract(acc)
	}
}

func mpy32x16(hi int16, lo int16, n int16) int32 {
	acc := fxp.LMult(hi, n)
	return fxp.Add32(acc, fxp.LMult(fxp.Mult(lo, n), 1))
}
