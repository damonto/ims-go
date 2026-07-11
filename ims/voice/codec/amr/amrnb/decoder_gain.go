/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_nb/dec/src/d_gain_p.cpp,
 * d_gain_c.cpp, and amr_nb/common/src/gains_tbl.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

var quaGainPitch = [...]int16{
	0, 3277, 6556, 8192, 9830, 11469, 12288, 13107,
	13926, 14746, 15565, 16384, 17203, 18022, 18842, 19661,
}

var quaGainCode = [...]int16{
	159, -3776, -22731,
	206, -3394, -20428,
	268, -3005, -18088,
	349, -2615, -15739,
	419, -2345, -14113,
	482, -2138, -12867,
	554, -1932, -11629,
	637, -1726, -10387,
	733, -1518, -9139,
	842, -1314, -7906,
	969, -1106, -6656,
	1114, -900, -5416,
	1281, -694, -4173,
	1473, -487, -2931,
	1694, -281, -1688,
	1948, -75, -445,
	2241, 133, 801,
	2577, 339, 2044,
	2963, 545, 3285,
	3408, 752, 4530,
	3919, 958, 5772,
	4507, 1165, 7016,
	5183, 1371, 8259,
	5960, 1577, 9501,
	6855, 1784, 10745,
	7883, 1991, 11988,
	9065, 2197, 13231,
	10425, 2404, 14474,
	12510, 2673, 16096,
	16263, 3060, 18429,
	21142, 3448, 20763,
	27485, 3836, 23097,
	27485, 3836, 23097,
}

func dGainPitch(mode Mode, index int16) int16 {
	gain := quaGainPitch[index]
	if mode == Mode1220 {
		gain &^= 3
	}
	return gain
}

func dGainCode(state *gainPredState, mode Mode, index int16, code []int16) int16 {
	prediction := state.predict(mode, code)
	exp, frac := prediction.exponent, prediction.fraction
	index &= 31
	offset := index * 3
	gainFactor := quaGainCode[offset]

	var gainCode int16
	if mode == Mode1220 {
		gcode0 := fxp.Shl16(int16(pow2Value(exp, frac)), 4)
		gainCode = fxp.Shl16(fxp.Mult(gcode0, gainFactor), 1)
	} else {
		gcode0 := int16(pow2Value(14, frac))
		product := fxp.LMult(gainFactor, gcode0)
		product = fxp.Shr32(product, 9-exp)
		gainCode = fxp.ExtractH(product)
	}

	state.update(quaGainCode[offset+1], quaGainCode[offset+2])
	return gainCode
}

func decGain(state *gainPredState, mode Mode, index int16, code []int16, evenSubfr int16) (gainPit, gainCode int16) {
	offset := int(fxp.Shl16(index, 2))
	var gCode, quaEnerMR122, quaEner int16

	switch mode {
	case Mode1020, Mode740, Mode670:
		entry := readGainEntry(tableGainHighrates[:], offset)
		gainPit, gCode, quaEnerMR122, quaEner = entry.pitch, entry.code, entry.energyMR122, entry.energy
	case Mode475:
		offset += int((1 ^ evenSubfr) << 1)
		offset = min(offset, len(tableGainMR475)-2)
		gainPit = tableGainMR475[offset]
		gCode = tableGainMR475[offset+1]

		exp, frac := log2Value(int32(gCode))
		exp -= 12
		quaEnerMR122 = fxp.Add16(fxp.ShrRound16(frac, 5), fxp.Shl16(exp, 10))
		quaEner = fxp.Round(fxp.Shl32(fxp.Mpy32By16(exp, frac, 24660), 13))
	default:
		entry := readGainEntry(tableGainLowrates[:], offset)
		gainPit, gCode, quaEnerMR122, quaEner = entry.pitch, entry.code, entry.energyMR122, entry.energy
	}

	prediction := state.predict(mode, code)
	exp, frac := prediction.exponent, prediction.fraction
	gcode0 := int16(pow2Value(14, frac))
	product := fxp.LMult(gCode, gcode0)
	product = fxp.Shr32(product, 10-exp)
	gainCode = fxp.ExtractH(product)

	state.update(quaEnerMR122, quaEner)
	return gainPit, gainCode
}

type gainTableEntry struct {
	pitch       int16
	code        int16
	energyMR122 int16
	energy      int16
}

func readGainEntry(table []int16, offset int) gainTableEntry {
	return gainTableEntry{
		pitch:       table[offset],
		code:        table[offset+1],
		energyMR122: table[offset+2],
		energy:      table[offset+3],
	}
}
