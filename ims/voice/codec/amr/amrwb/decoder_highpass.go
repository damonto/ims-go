/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_wb/dec/src/highpass_50Hz_at_12k8.cpp
 * and highpass_400Hz_at_12k8.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

func highpass50HzAt12k8(signal []int16, memory [6]int16) [6]int16 {
	y2Hi := memory[0]
	y2Lo := memory[1]
	y1Hi := memory[2]
	y1Lo := memory[3]
	x0 := memory[4]
	x1 := memory[5]

	for i := range signal {
		x2 := x1
		x1 = x0
		x0 = signal[i]

		tmp := int32(16384)
		tmp = fxp.LMac(tmp, y1Lo, 16211)
		tmp = fxp.LMac(tmp, y2Lo, -8021)
		tmp = fxp.Shr32(tmp, 15)
		tmp = fxp.LMac(tmp, y1Hi, 16211)
		tmp = fxp.LMac(tmp, y2Hi, -8021)
		tmp = fxp.LMac(tmp, x0, 4053)
		tmp = fxp.LMac(tmp, x1, -8106)
		tmp = fxp.LMac(tmp, x2, 4053)
		tmp = fxp.Shl32(tmp, 2)

		y2Hi = y1Hi
		y2Lo = y1Lo
		y1Hi, y1Lo = fxp.LExtract(tmp)
		signal[i] = fxp.Round(fxp.Shl32(tmp, 1))
	}

	return [6]int16{y2Hi, y2Lo, y1Hi, y1Lo, x0, x1}
}

func highpass400HzAt12k8(signal []int16, memory [6]int16) [6]int16 {
	y2Hi := memory[0]
	y2Lo := memory[1]
	y1Hi := memory[2]
	y1Lo := memory[3]
	x0 := memory[4]
	x1 := memory[5]

	for i := range signal {
		x2 := x1
		x1 = x0
		x0 = signal[i]

		tmp := int32(16384)
		tmp = fxp.LMac(tmp, y1Lo, 29280)
		tmp = fxp.LMac(tmp, y2Lo, -14160)
		tmp = fxp.Shr32(tmp, 15)
		tmp = fxp.LMac(tmp, y1Hi, 29280)
		tmp = fxp.LMac(tmp, y2Hi, -14160)
		tmp = fxp.LMac(tmp, x0, 915)
		tmp = fxp.LMac(tmp, x1, -1830)
		tmp = fxp.LMac(tmp, x2, 915)
		tmp = fxp.Shl32(tmp, 1)

		y2Hi = y1Hi
		y2Lo = y1Lo
		y1Hi, y1Lo = fxp.LExtract(tmp)
		signal[i] = fxp.Round(tmp)
	}

	return [6]int16{y2Hi, y2Lo, y1Hi, y1Lo, x0, x1}
}

func amrWBShl1Round(value int32) int16 {
	if (value<<1)>>1 == value {
		return int16((value + 0x00004000) >> 15)
	}
	if value < 0 {
		return fxp.Min16
	}
	return fxp.Max16
}
