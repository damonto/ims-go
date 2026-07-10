/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_nb/common/src/log2.cpp,
 * log2_norm.cpp, log2_tbl.cpp, pow2.cpp, and pow2_tbl.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

var log2Tbl = [...]int16{
	0, 1455, 2866, 4236, 5568, 6863, 8124, 9352, 10549, 11716,
	12855, 13967, 15054, 16117, 17156, 18172, 19167, 20142, 21097, 22033,
	22951, 23852, 24735, 25603, 26455, 27291, 28113, 28922, 29716, 30497,
	31266, 32023, 32767,
}

var pow2Tbl = [...]int16{
	16384, 16743, 17109, 17484, 17867, 18258, 18658, 19066, 19484, 19911,
	20347, 20792, 21247, 21713, 22188, 22674, 23170, 23678, 24196, 24726,
	25268, 25821, 26386, 26964, 27554, 28158, 28774, 29405, 30048, 30706,
	31379, 32066, 32767,
}

func log2Value(value int32) (exponent, fraction int16) {
	exp := fxp.NormL(value)
	return log2Norm(value<<exp, exp)
}

func log2Norm(value int32, normExp int16) (exponent, fraction int16) {
	if value <= 0 {
		return 0, 0
	}

	exponent = 30 - normExp
	shifted := value >> 10
	index := int((shifted >> 15) - 32)
	if index < 0 {
		index = 0
	} else if index >= len(log2Tbl)-1 {
		index = len(log2Tbl) - 2
	}
	interp := int16(shifted & 0x7fff)
	delta := log2Tbl[index] - log2Tbl[index+1]
	fraction = fxp.ExtractH(fxp.LMsu(int32(log2Tbl[index])<<16, delta, interp))
	return exponent, fraction
}

func pow2Value(exponent, fraction int16) int32 {
	product := fxp.LMult(fraction, 32)
	index := int((product >> 16) & 31)
	interp := int16((product >> 1) & 0x7fff)

	out := int32(pow2Tbl[index]) << 16
	delta := pow2Tbl[index] - pow2Tbl[index+1]
	out = fxp.Sub32(out, fxp.LMult(delta, interp))
	return fxp.ShrRound32(out, 30-exponent)
}
