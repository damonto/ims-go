/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/phase_dispersion.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	phasePitch06 int16 = 9830
	phasePitch09 int16 = 14746
)

var phaseImpulseLowWB = [...]int16{
	20182, 9693, 3270, -3437, 2864, -5240, 1589, -1357,
	600, 3893, -1497, -698, 1203, -5249, 1199, 5371,
	-1488, -705, -2887, 1976, 898, 721, -3876, 4227,
	-5112, 6400, -1032, -4725, 4093, -4352, 3205, 2130,
	-1996, -1835, 2648, -1786, -406, 573, 2484, -3608,
	3139, -1363, -2566, 3808, -639, -2051, -541, 2376,
	3932, -6262, 1432, -3601, 4889, 370, 567, -1163,
	-2854, 1914, 39, -2418, 3454, 2975, -4021, 3431,
}

var phaseImpulseMidWB = [...]int16{
	24098, 10460, -5263, -763, 2048, -927, 1753, -3323,
	2212, 652, -2146, 2487, -3539, 4109, -2107, -374,
	-626, 4270, -5485, 2235, 1858, -2769, 744, 1140,
	-763, -1615, 4060, -4574, 2982, -1163, 731, -1098,
	803, 167, -714, 606, -560, 639, 43, -1766,
	3228, -2782, 665, 763, 233, -2002, 1291, 1871,
	-3470, 1032, 2710, -4040, 3624, -4214, 5292, -4270,
	1563, 108, -580, 1642, -2458, 957, 544, 2540,
}

type phaseDispersionResult struct {
	code   [subframeSamples]int16
	memory [8]int16
}

func phaseDispersion(
	gainCode int16,
	gainPit int16,
	code [subframeSamples]int16,
	mode int16,
	memory [8]int16,
) phaseDispersionResult {
	out := phaseDispersionResult{code: code, memory: memory}
	prevState := &out.memory[0]
	prevGainCode := &out.memory[1]
	prevGainPit := out.memory[2:8]

	state := int16(2)
	if gainPit < phasePitch06 {
		state = 0
	} else if gainPit < phasePitch09 {
		state = 1
	}

	for i := 5; i > 0; i-- {
		prevGainPit[i] = prevGainPit[i-1]
	}
	prevGainPit[0] = gainPit

	if fxp.Sub16(gainCode, *prevGainCode) > fxp.Shl16(*prevGainCode, 1) {
		if state < 2 {
			state++
		}
	} else {
		lowCount := int16(0)
		for i := range 6 {
			if prevGainPit[i] < phasePitch06 {
				lowCount++
			}
		}
		if lowCount > 2 {
			state = 0
		}
		if state > *prevState+1 {
			state--
		}
	}

	*prevGainCode = gainCode
	*prevState = state

	dispersion := state + mode
	if dispersion >= 2 {
		return out
	}

	var code2 [2 * subframeSamples]int16
	impulse := phaseImpulseLowWB[:]
	if dispersion == 1 {
		impulse = phaseImpulseMidWB[:]
	}
	for i := range subframeSamples {
		if out.code[i] == 0 {
			continue
		}
		for j := range subframeSamples {
			code2[i+j] = fxp.Add16(code2[i+j], fxp.MultRound(out.code[i], impulse[j]))
		}
	}
	for i := range subframeSamples {
		out.code[i] = fxp.Add16(code2[i], code2[i+subframeSamples])
	}
	return out
}

func phaseDispersionMode(mode Mode) int16 {
	switch {
	case mode <= Mode660:
		return 0
	case mode <= Mode885:
		return 1
	default:
		return 2
	}
}
