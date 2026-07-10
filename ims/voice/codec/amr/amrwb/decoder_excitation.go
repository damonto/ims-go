/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_wb/dec/src/preemph_amrwb_dec.cpp,
 * pit_shrp.cpp, and noise_gen_amrwb.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const pitSharp = 27853

func preemphasis(signal []int16, mu int16) {
	limit := len(signal)
	for i := limit - 1; i > 0; i-- {
		acc := fxp.LMsu(fxp.LDepositH(signal[i]), signal[i-1], mu)
		signal[i] = fxp.Round(acc)
	}
}

func sharpenPitch(signal []int16, pitchLag int16, sharp int16) {
	for i := int(pitchLag); i < len(signal); i++ {
		acc := fxp.LMac(fxp.LDepositH(signal[i]), signal[i-int(pitchLag)], sharp)
		signal[i] = fxp.Round(acc)
	}
}

func nextNoise(seed int16) int16 {
	next := int32(seed)*31821 + 13849
	return int16(next)
}
