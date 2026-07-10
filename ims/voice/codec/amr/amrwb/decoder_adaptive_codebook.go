/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/pred_lt4.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	upSample     = 4
	interpolLen2 = 16
)

var inter4_2 = [...][2 * interpolLen2]int16{
	{
		0, -2, 4, -2, -10, 38, -88, 165,
		-275, 424, -619, 871, -1207, 1699, -2598, 5531,
		14031, -2147, 780, -249, -16, 153, -213, 226,
		-209, 175, -133, 91, -55, 28, -10, 2,
	},
	{
		1, -7, 19, -33, 47, -52, 43, -9,
		-60, 175, -355, 626, -1044, 1749, -3267, 10359,
		10359, -3267, 1749, -1044, 626, -355, 175, -60,
		-9, 43, -52, 47, -33, 19, -7, 1,
	},
	{
		2, -10, 28, -55, 91, -133, 175, -209,
		226, -213, 153, -16, -249, 780, -2147, 14031,
		5531, -2598, 1699, -1207, 871, -619, 424, -275,
		165, -88, 38, -10, -2, 4, -2, 0,
	},
	{
		1, -7, 22, -49, 92, -153, 231, -325,
		431, -544, 656, -762, 853, -923, 968, 15401,
		968, -923, 853, -762, 656, -544, 431, -325,
		231, -153, 92, -49, 22, -7, 1, 0,
	},
}

func predictAdaptiveCodebook(excitation []int16, offset int, t0 int16, frac int16, length int) {
	past := offset - int(t0)
	frac = -frac
	if frac < 0 {
		frac += upSample
		past--
	}
	past -= interpolLen2 - 1
	filter := inter4_2[upSample-1-int(frac)]
	for n := range length {
		var sum int32
		for i := range 2 * interpolLen2 {
			sum = fxp.LMac(sum, excitation[past+n+i], filter[i])
		}
		excitation[offset+n] = fxp.Round(fxp.Shl32(sum, 1))
	}
}
