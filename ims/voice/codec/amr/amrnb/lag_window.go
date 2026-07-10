/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This LPC lag windowing step is ported from amr_nb/enc/src/lag_wind.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

var lagWindowH = [...]int16{
	32728, 32619, 32438, 32187, 31867,
	31480, 31029, 30517, 29946, 29321,
}

var lagWindowL = [...]int16{
	11904, 17280, 30720, 25856, 24192,
	28992, 24384, 7360, 19520, 14784,
}

func lagWindow(rh, rl [lpcCoeffCount]int16) ([lpcCoeffCount]int16, [lpcCoeffCount]int16) {
	for i := 1; i <= lpcOrder; i++ {
		value := fxp.Mpy32(rh[i], rl[i], lagWindowH[i-1], lagWindowL[i-1])
		rh[i], rl[i] = fxp.LExtract(value)
	}
	return rh, rl
}
