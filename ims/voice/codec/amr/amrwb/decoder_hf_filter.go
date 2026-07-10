/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_wb/dec/src/band_pass_6k_7k.cpp
 * and low_pass_filt_7k.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const hfFIRMemory = 30

var fir6k7k = [...]int16{
	-32, 47, 32, -27, -369, 1122, -1421, 0,
	3798, -8880, 12349, -10984, 3548, 7766, -18001,
	22118, -18001, 7766, 3548, -10984, 12349, -8880,
	3798, 0, -1421, 1122, -369, -27, 32, 47,
	-32,
}

var fir7k = [...]int16{
	-21, 47, -89, 146, -203, 229, -177, 0,
	335, -839, 1485, -2211, 2931, -3542, 3953,
	28682, 3953, -3542, 2931, -2211, 1485, -839,
	335, 0, -177, 229, -203, 146, -89, 47,
	-21,
}

type hfFilterResult struct {
	signal [subframeSamples16k]int16
	memory [hfFIRMemory]int16
}

func bandPass6k7k(signal [subframeSamples16k]int16, memory [hfFIRMemory]int16) hfFilterResult {
	var out hfFilterResult
	var x [hfFIRMemory + subframeSamples16k]int16
	copy(x[:], memory[:])
	for i := range signal {
		x[hfFIRMemory+i] = signal[i] >> 2
	}
	for i := range signal {
		var acc int32
		for j := 0; j <= hfFIRMemory; j++ {
			acc = fxp.LMac(acc, x[i+j], fir6k7k[j])
		}
		out.signal[i] = fxp.Round(acc)
	}
	copy(out.memory[:], x[subframeSamples16k:subframeSamples16k+hfFIRMemory])
	return out
}

func lowPass7k(signal [subframeSamples16k]int16, memory [hfFIRMemory]int16) hfFilterResult {
	var out hfFilterResult
	var x [hfFIRMemory + subframeSamples16k]int16
	copy(x[:], memory[:])
	copy(x[hfFIRMemory:], signal[:])
	for i := range signal {
		var acc int32
		for j := 0; j <= hfFIRMemory; j++ {
			acc = fxp.LMac(acc, x[i+j], fir7k[j])
		}
		out.signal[i] = fxp.Round(acc)
	}
	copy(out.memory[:], x[subframeSamples16k:subframeSamples16k+hfFIRMemory])
	return out
}
