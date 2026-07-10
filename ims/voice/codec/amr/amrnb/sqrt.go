/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/common/src/sqrt_l.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

var sqrtTable = [...]int16{
	16384, 16888, 17378, 17854, 18318, 18770, 19212, 19644, 20066, 20480,
	20886, 21283, 21674, 22058, 22435, 22806, 23170, 23530, 23884, 24232,
	24576, 24915, 25249, 25580, 25905, 26227, 26545, 26859, 27170, 27477,
	27780, 28081, 28378, 28672, 28963, 29251, 29537, 29819, 30099, 30377,
	30652, 30924, 31194, 31462, 31727, 31991, 32252, 32511, 32767, 32767,
}

func sqrtLExp(x int32) (int32, int16) {
	if x <= 0 {
		return 0, 0
	}

	exp := fxp.NormL(x) & ^int16(1)
	x = fxp.Shl32(x, exp)
	x >>= 10
	index := int16(x>>15) & 63
	frac := int16(x) & 0x7fff
	if index > 15 {
		index -= 16
	} else {
		index = 0
	}
	if int(index) >= len(sqrtTable)-1 {
		index = int16(len(sqrtTable) - 2)
	}

	y := int32(sqrtTable[index]) << 16
	delta := int32(sqrtTable[index] - sqrtTable[index+1])
	y = fxp.Sub32(y, fxp.LMult(int16(delta), frac))
	return y, exp
}
