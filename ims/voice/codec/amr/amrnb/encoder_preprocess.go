/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This high-pass input filter is ported from amr_nb/enc/src/pre_proc.cpp.
 */

package amrnb

type encoderPreprocessState struct {
	y2Hi int16
	y2Lo int16
	y1Hi int16
	y1Lo int16
	x0   int16
	x1   int16
}

func (s *encoderPreprocessState) reset() {
	*s = encoderPreprocessState{}
}

func (s *encoderPreprocessState) process(signal []int16) {
	x2 := s.x1
	x1 := s.x0
	for i := range signal {
		acc := int32(s.y1Hi) * 7807
		acc += (int32(s.y1Lo) * 7807) >> 15
		acc += int32(s.y2Hi) * -3733
		s.y2Hi = s.y1Hi
		acc += (int32(s.y2Lo) * -3733) >> 15
		s.y2Lo = s.y1Lo

		acc += int32(x2) * 1899
		x2 = x1
		acc += int32(x1) * -3798
		x1 = signal[i]
		acc += int32(x1) * 1899

		signal[i] = int16((acc + 0x0800) >> 12)
		s.y1Hi = int16(acc >> 12)
		s.y1Lo = int16((acc << 3) - (int32(s.y1Hi) << 15))
	}
	s.x1 = x2
	s.x0 = x1
}
