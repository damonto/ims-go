/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This encoder gain-quantizer state follows amrwbenc/src/q_gain2.c.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

type encoderGainQuantState struct {
	pastQuaEn [gainPredOrder]int16
}

type encodedSubframeGain struct {
	index     int16
	pitch     int16
	code      int32
	codeTable int16
	nbits     int16
}

func (s *encoderGainQuantState) reset() {
	for i := range s.pastQuaEn {
		s.pastQuaEn[i] = -14336
	}
}

func (s *encoderGainQuantState) quantize(mode Mode, sf *encoderSubframePitch, clipGain bool) encodedSubframeGain {
	nbits := int16(7)
	table := gainTable7Bit[:]
	if mode <= Mode885 {
		nbits = 6
		table = gainTable6Bit[:]
	}

	gcode0, expGcode0 := s.predictedCodeGain(sf.code[:])
	index := s.search(table, sf, gcode0, expGcode0, clipGain)
	offset := int(index) << 1
	pitch := table[offset]
	codeTable := table[offset+1]
	code := fxp.Shl32(fxp.LMult(codeTable, gcode0), expGcode0+4)
	s.update(codeTable)
	return encodedSubframeGain{
		index:     index,
		pitch:     pitch,
		code:      code,
		codeTable: codeTable,
		nbits:     nbits,
	}
}

func (s *encoderGainQuantState) predictedCodeGain(code []int16) (int16, int16) {
	energy := s.innovationEnergyOffset(code)
	predicted := fxp.Shl32(energy, 10)
	for i := range gainPredOrder {
		predicted = fxp.Add32(predicted, fxp.LMult(gainPred[i], s.pastQuaEn[i]))
	}
	gcode0 := fxp.ExtractH(predicted)
	scaled := int32(gcode0) * 5443 >> 7
	expGcode0, frac := fxp.LExtract(scaled)
	gcode0 = int16(powerOf2WB(14, frac))
	expGcode0 -= 14
	return gcode0, expGcode0
}

func (s *encoderGainQuantState) innovationEnergyOffset(code []int16) int32 {
	energy, expCode := dotProduct12(code, code, subframeSamples)
	expCode -= 18 + 6 + 31
	exp, frac := log2WB(energy)
	exp += expCode
	out := fxp.Mpy32By16(exp, frac, -24660)
	return fxp.Add32(out, int32(gainMeanEnergy*8192)<<1)
}

func (s *encoderGainQuantState) update(codeTable int16) {
	s.pastQuaEn[3] = s.pastQuaEn[2]
	s.pastQuaEn[2] = s.pastQuaEn[1]
	s.pastQuaEn[1] = s.pastQuaEn[0]
	exp, frac := log2WB(int32(codeTable))
	exp -= 11
	s.pastQuaEn[0] = int16(fxp.Mpy32By16(exp, frac, 24660) >> 3)
}

func (s *encoderGainQuantState) search(
	table []int16,
	sf *encoderSubframePitch,
	gcode0 int16,
	expGcode0 int16,
	clipGain bool,
) int16 {
	rawCoeff, rawExp := gainSearchRawCoefficients(sf)
	coeff := alignGainSearchCoefficients(rawCoeff, rawExp, expGcode0)
	start, size := gainSearchRange(table, sf.gain, clipGain)
	best := start
	bestDist := fxp.Max32
	for i := range size {
		index := start + i
		dist := gainSearchDistance(table[index*2], table[index*2+1], gcode0, coeff)
		if dist < bestDist {
			bestDist = dist
			best = index
		}
	}
	return int16(best)
}

type gainSearchCoeff struct {
	hi [5]int16
	lo [5]int16
}

func gainSearchRawCoefficients(sf *encoderSubframePitch) ([5]int16, [5]int16) {
	var coeff [5]int16
	var expCoeff [5]int16
	coeff[0] = sf.gCoeff[0]
	expCoeff[0] = sf.gCoeff[1]
	coeff[1] = fxp.Neg16(sf.gCoeff[2])
	expCoeff[1] = sf.gCoeff[3] + 1

	product, exp := dotProduct12(sf.codeFiltered[:], sf.codeFiltered[:], subframeSamples)
	coeff[2] = fxp.ExtractH(product)
	expCoeff[2] = exp - 18 + (sf.qxn << 1)
	product, exp = dotProduct12(sf.target[:], sf.codeFiltered[:], subframeSamples)
	coeff[3] = fxp.ExtractH(fxp.Neg32(product))
	expCoeff[3] = exp - 8 + sf.qxn
	product, exp = dotProduct12(sf.filtered[:], sf.codeFiltered[:], subframeSamples)
	coeff[4] = fxp.ExtractH(product)
	expCoeff[4] = exp - 8 + sf.qxn

	return coeff, expCoeff
}

func alignGainSearchCoefficients(
	coeff [5]int16,
	expCoeff [5]int16,
	expGcode0 int16,
) gainSearchCoeff {
	expCode := expGcode0 + 4
	expMax := [5]int16{
		expCoeff[0] - 13,
		expCoeff[1] - 14,
		expCoeff[2] + 15 + (expCode << 1),
		expCoeff[3] + expCode,
		expCoeff[4] + 1 + expCode,
	}
	eMax := expMax[0]
	for i := 1; i < len(expMax); i++ {
		eMax = max(eMax, expMax[i])
	}

	var out gainSearchCoeff
	for i := range coeff {
		shift := eMax - expMax[i] + 2
		value := fxp.Shr32(int32(coeff[i])<<16, shift)
		out.hi[i], out.lo[i] = fxp.LExtract(value)
		out.lo[i] >>= 3
	}
	return out
}

func gainSearchRange(table []int16, pitch int16, clipGain bool) (int, int) {
	size := len(table) / 2
	if size <= 64 {
		if clipGain && size > 16 {
			return 0, size - 16
		}
		return 0, size
	}
	start := 0
	probe := 64
	limit := size - 64
	if clipGain {
		limit -= 27
	}
	for probe+1 < len(table) && start < limit {
		if pitch > table[probe] {
			start++
		}
		probe += 2
	}
	return start, 64
}

func gainSearchDistance(pitch int16, codeTable int16, gcode0 int16, coeff gainSearchCoeff) int32 {
	code := fxp.MultRound(codeTable, gcode0)
	pitch2 := fxp.MultRound(pitch, pitch)
	pitchCode := fxp.MultRound(code, pitch)
	code2Hi, code2Lo := fxp.LExtract(fxp.LMult(code, code))

	dist := fxp.LMult(coeff.hi[2], code2Lo)
	dist = fxp.Shr32(dist, 3)
	dist = fxp.LMac(dist, coeff.lo[0], pitch2)
	dist = fxp.LMac(dist, coeff.lo[1], pitch)
	dist = fxp.LMac(dist, coeff.lo[2], code2Hi)
	dist = fxp.LMac(dist, coeff.lo[3], code)
	dist = fxp.LMac(dist, coeff.lo[4], pitchCode)
	dist = fxp.Shr32(dist, 12)
	dist = fxp.LMac(dist, coeff.hi[0], pitch2)
	dist = fxp.LMac(dist, coeff.hi[1], pitch)
	dist = fxp.LMac(dist, coeff.hi[2], code2Hi)
	dist = fxp.LMac(dist, coeff.hi[3], code)
	dist = fxp.LMac(dist, coeff.hi[4], pitchCode)
	return dist
}

func gainParameterIndex(mode Mode, pitchParamIndex int) int {
	switch {
	case mode == Mode660:
		return pitchParamIndex + 2
	case mode == Mode885:
		return pitchParamIndex + 5
	case mode >= Mode1265 && mode <= Mode1585:
		return pitchParamIndex + 6
	case mode >= Mode1825 && mode <= Mode2385:
		return pitchParamIndex + 10
	default:
		return -1
	}
}
