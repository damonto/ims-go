/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/oversamp_12k8_to_16k.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	oversampleMemory = 24
	oversampleDelay  = 12
)

var firUp12k8To16k = [...][24]int16{
	{
		-1, 12, -33, 68, -119, 191,
		-291, 430, -634, 963, -1616, 3792,
		15317, -2496, 1288, -809, 542, -369,
		247, -160, 96, -52, 23, -6,
	},
	{
		-4, 24, -62, 124, -213, 338,
		-510, 752, -1111, 1708, -2974, 8219,
		12368, -3432, 1881, -1204, 812, -552,
		368, -235, 139, -73, 30, -7,
	},
	{
		-7, 30, -73, 139, -235, 368,
		-552, 812, -1204, 1881, -3432, 12368,
		8219, -2974, 1708, -1111, 752, -510,
		338, -213, 124, -62, 24, -4,
	},
	{
		-6, 23, -52, 96, -160, 247,
		-369, 542, -809, 1288, -2496, 15317,
		3792, -1616, 963, -634, 430, -291,
		191, -119, 68, -33, 12, -1,
	},
}

type oversampleResult struct {
	signal [subframeSamples16k]int16
	memory [oversampleMemory]int16
}

func oversample12k8To16k(signal [subframeSamples]int16, memory [oversampleMemory]int16) oversampleResult {
	var buffer [oversampleMemory + subframeSamples]int16
	copy(buffer[:oversampleMemory], memory[:])
	copy(buffer[oversampleMemory:], signal[:])
	out := oversampleResult{signal: upSample12k8To16k(buffer[:])}
	copy(out.memory[:], buffer[subframeSamples:subframeSamples+oversampleMemory])
	return out
}

func upSample12k8To16k(sigD []int16) [subframeSamples16k]int16 {
	var sigU [subframeSamples16k]int16
	frac := int16(1)
	for j := range sigU {
		i := int((int32(j) * 6554) >> 13)
		frac--
		if frac != 0 {
			sigU[j] = interpolate12k8To16k(sigD, oversampleDelay+i, firUp12k8To16k[4-frac][:])
			continue
		}
		sigU[j] = sigD[oversampleDelay+i]
		frac = 5
	}
	return sigU
}

func interpolate12k8To16k(sigD []int16, center int, fir []int16) int16 {
	start := center - oversampleDelay + 1
	var sum int32
	for i, coeff := range fir {
		index := start + i
		if index < 0 || index >= len(sigD) {
			continue
		}
		sum = fxp.LMac(sum, sigD[index], coeff)
	}
	return fxp.Round(fxp.Shl32(sum, 1))
}
