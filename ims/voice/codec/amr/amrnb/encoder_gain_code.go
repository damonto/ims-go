/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These encoder-side code-gain primitives are ported from enc/src/g_code.cpp
 * and enc/src/q_gain_c.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type encoderGainState struct {
	pred    gainPredState
	unqPred gainPredState
	adapt   gainAdaptState
	mr475   mr475PairState
}

func (s *encoderGainState) reset() {
	s.pred.reset()
	s.unqPred.reset()
	s.adapt.reset()
	s.mr475 = mr475PairState{}
}

type mr475PairState struct {
	active       bool
	expGCode0    int16
	fracGCode0   int16
	fracCoeff    [5]int16
	expCoeff     [5]int16
	expTargetEn  int16
	fracTargetEn int16
}

type mr475SubframeGainInput struct {
	xn     []int16
	xn2    []int16
	y1     []int16
	y2     []int16
	gCoeff []int16
	code   []int16
}

type jointGainInput struct {
	mode    Mode
	xn      []int16
	xn2     []int16
	y1      []int16
	y2      []int16
	gCoeff  []int16
	gpLimit int16
	code    []int16
}

type mr795GainInput struct {
	res     []int16
	exc     []int16
	xn      []int16
	xn2     []int16
	y1      []int16
	y2      []int16
	gCoeff  []int16
	gpLimit int16
	gainPit int16
	code    []int16
}

type mr475PairGainResult struct {
	index       int16
	sf0GainPit  int16
	sf0GainCode int16
	sf1GainPit  int16
	sf1GainCode int16
}

type filteredGainEnergies struct {
	fracCoeff   [5]int16
	expCoeff    [5]int16
	codGainFrac int16
	codGainExp  int16
}

type mr795CodeGainPrediction struct {
	expGCode0  int16
	expCodeEn  int16
	fracCodeEn int16
	gcode0     int16
}

type mr795PitchCandidates struct {
	gain  [3]int16
	index [3]int16
}

func (s *encoderGainState) quantizeMR122(code []int16, xn2 []int16, y2 []int16) (encoderCodeGainAnalysis, error) {
	var out encoderCodeGainAnalysis
	if len(code) < subframeSamples || len(xn2) < subframeSamples || len(y2) < subframeSamples {
		return out, fmt.Errorf(
			"quantizing AMR-NB MR122 code gain: code/target/filter sample counts %d/%d/%d, want at least %d",
			len(code),
			len(xn2),
			len(y2),
			subframeSamples,
		)
	}
	expGCode0, fracGCode0, _, _ := s.pred.predict(Mode1220, code)
	gainCode, err := gCode(xn2, y2)
	if err != nil {
		return out, err
	}
	result := qGainCodeScalar(Mode1220, expGCode0, fracGCode0, gainCode)
	s.pred.update(result.quaEnerMR122, result.quaEner)
	return encoderCodeGainAnalysis{index: result.index, gain: result.gain}, nil
}

func (s *encoderGainState) quantizeJoint(in jointGainInput) encoderCodeGainAnalysis {
	expGCode0, fracGCode0, _, _ := s.pred.predict(in.mode, in.code)
	energies := calcFilteredGainEnergies(in.mode, in.xn, in.xn2, in.y1, in.y2, in.gCoeff)
	result := quaGain(
		in.mode,
		expGCode0,
		fracGCode0,
		energies.fracCoeff,
		energies.expCoeff,
		in.gpLimit,
	)
	s.pred.update(result.quaEnerMR122, result.quaEner)
	return encoderCodeGainAnalysis{
		index:     result.index,
		gain:      result.gainCode,
		pitchGain: result.gainPit,
	}
}

func (s *encoderGainState) quantizeMR795(in mr795GainInput) encoderCodeGainAnalysis {
	prediction := s.predictMR795CodeGain(in.code)
	energies := calcFilteredGainEnergies(Mode795, in.xn, in.xn2, in.y1, in.y2, in.gCoeff)
	candidates := in.pitchCandidates()
	result := mr795GainCodeQuant3(
		prediction.expGCode0,
		prediction.gcode0,
		candidates.gain,
		candidates.index,
		energies.fracCoeff,
		energies.expCoeff,
	)
	result = s.refineMR795CodeGain(in, prediction, energies, result)
	s.pred.update(result.quaEnerMR122, result.quaEner)
	return result.analysis
}

func (s *encoderGainState) predictMR795CodeGain(code []int16) mr795CodeGainPrediction {
	expGCode0, fracGCode0, expCodeEn, fracCodeEn := s.pred.predict(Mode795, code)
	return mr795CodeGainPrediction{
		expGCode0:  expGCode0,
		expCodeEn:  expCodeEn,
		fracCodeEn: fracCodeEn,
		gcode0:     int16(pow2Value(14, fracGCode0)),
	}
}

func (in mr795GainInput) pitchCandidates() mr795PitchCandidates {
	quantized := quantizePitchGain(Mode795, in.gpLimit, in.gainPit)
	return mr795PitchCandidates{
		gain:  quantized.candidates,
		index: quantized.candidateIndices,
	}
}

func (s *encoderGainState) refineMR795CodeGain(
	in mr795GainInput,
	prediction mr795CodeGainPrediction,
	energies filteredGainEnergies,
	result mr795GainQuant3Result,
) mr795GainQuant3Result {
	fracEn, expEn, ltpg := calcUnfiltEnergies(in.res, in.exc, in.code, result.pitchGain)
	alpha := s.adapt.adapt(ltpg, result.analysis.gain)
	if fracEn[0] != 0 && alpha > 0 {
		fracEn[3] = prediction.fracCodeEn
		expEn[3] = prediction.expCodeEn
		exp := energies.codGainExp - prediction.expGCode0 + 10
		gainCodUnq := fxp.Shl16(energies.codGainFrac, exp)
		index, quaEnerMR122, quaEner, gainCode := mr795GainCodeQuantMod(
			result.pitchGain,
			prediction.expGCode0,
			prediction.gcode0,
			fracEn,
			expEn,
			alpha,
			gainCodUnq,
			result.analysis.gain,
		)
		result.analysis.index = index
		result.analysis.gain = gainCode
		result.quaEnerMR122 = quaEnerMR122
		result.quaEner = quaEner
	}
	return result
}

func (s *encoderGainState) prepareMR475Even(in mr475SubframeGainInput) encoderCodeGainAnalysis {
	s.unqPred = s.pred
	state, codGainFrac, codGainExp := in.analyzeMR475Subframe(&s.unqPred)
	mr475UpdateUnquantizedPredictor(
		&s.unqPred,
		state.expGCode0,
		state.fracGCode0,
		codGainExp,
		codGainFrac,
	)
	s.mr475 = state
	return encoderCodeGainAnalysis{gain: fxp.Shl16(codGainFrac, codGainExp+1)}
}

func (s *encoderGainState) quantizeMR475Odd(in mr475SubframeGainInput, gpLimit int16) mr475PairGainResult {
	if !s.mr475.active {
		s.prepareMR475Even(in)
	}
	state, _, _ := in.analyzeMR475Subframe(&s.unqPred)
	result := mr475GainQuant(
		&s.pred,
		s.mr475,
		state,
		in.code,
		gpLimit,
	)
	s.mr475 = mr475PairState{}
	return result
}

func (in mr475SubframeGainInput) analyzeMR475Subframe(pred *gainPredState) (mr475PairState, int16, int16) {
	expGCode0, fracGCode0, _, _ := pred.predict(Mode475, in.code)
	energies := calcFilteredGainEnergies(Mode475, in.xn, in.xn2, in.y1, in.y2, in.gCoeff)
	expTargetEn, fracTargetEn := calcTargetEnergy(in.xn)
	return mr475PairState{
		active:       true,
		expGCode0:    expGCode0,
		fracGCode0:   fracGCode0,
		fracCoeff:    energies.fracCoeff,
		expCoeff:     energies.expCoeff,
		expTargetEn:  expTargetEn,
		fracTargetEn: fracTargetEn,
	}, energies.codGainFrac, energies.codGainExp
}

func gCode(xn2 []int16, y2 []int16) (int16, error) {
	if len(xn2) < subframeSamples || len(y2) < subframeSamples {
		return 0, fmt.Errorf(
			"calculating AMR-NB code gain: target/filter sample counts %d/%d, want at least %d",
			len(xn2),
			len(y2),
			subframeSamples,
		)
	}

	sumXY := int32(0)
	for i := range subframeSamples {
		sumXY += int32(xn2[i]) * int32(y2[i]>>1)
	}
	sumXY <<= 1
	expXY := fxp.NormL(sumXY + 1)
	var xy int16
	if expXY < 17 {
		xy = int16(sumXY >> (17 - expXY))
	} else {
		xy = int16(sumXY << (expXY - 17))
	}
	if xy <= 0 {
		return 0, nil
	}

	sumYY := int32(0)
	for i := range subframeSamples {
		scaled := y2[i] >> 1
		sumYY += (int32(scaled) * int32(scaled)) >> 2
	}
	sumYY <<= 3
	expYY := fxp.NormL(sumYY)
	var yy int16
	if expYY < 16 {
		yy = int16(sumYY >> (16 - expYY))
	} else {
		yy = int16(sumYY << (expYY - 16))
	}
	if yy <= 0 {
		return 0, nil
	}

	gain := fxp.DivS(xy, yy)
	shift := expXY + 5 - expYY
	if shift > 1 {
		return gain >> (shift - 1), nil
	}
	return int16(gain << (1 - shift)), nil
}

type scalarCodeGainQuantization struct {
	index        int16
	gain         int16
	quaEnerMR122 int16
	quaEner      int16
}

func qGainCodeScalar(mode Mode, expGCode0 int16, fracGCode0 int16, gain int16) scalarCodeGainQuantization {
	gQ0 := gain
	if mode == Mode1220 {
		gQ0 = fxp.Shr16(gain, 1)
	}

	gcode0 := int16(pow2Value(expGCode0, fracGCode0))
	if mode == Mode1220 {
		gcode0 = fxp.Shl16(gcode0, 4)
	} else {
		gcode0 = fxp.Shl16(gcode0, 5)
	}

	errMin := fxp.Abs16(fxp.Sub16(gQ0, fxp.Mult(gcode0, quaGainCode[0])))
	index := int16(0)
	for i := int16(1); i < 32; i++ {
		offset := i * 3
		err := fxp.Abs16(fxp.Sub16(gQ0, fxp.Mult(gcode0, quaGainCode[offset])))
		if err < errMin {
			errMin = err
			index = i
		}
	}

	offset := index * 3
	temp := fxp.Mult(gcode0, quaGainCode[offset])
	if mode == Mode1220 {
		gain = fxp.Shl16(temp, 1)
	} else {
		gain = temp
	}
	return scalarCodeGainQuantization{
		index:        index,
		gain:         gain,
		quaEnerMR122: quaGainCode[offset+1],
		quaEner:      quaGainCode[offset+2],
	}
}

func calcFiltEnergies(
	mode Mode,
	xn []int16,
	xn2 []int16,
	y1 []int16,
	y2 []int16,
	gCoeff []int16,
) ([5]int16, [5]int16, int16, int16) {
	var fracCoeff [5]int16
	var expCoeff [5]int16
	var codGainFrac int16
	var codGainExp int16
	if len(gCoeff) >= 4 {
		fracCoeff[0] = gCoeff[0]
		expCoeff[0] = gCoeff[1]
		fracCoeff[1] = fxp.Neg16(gCoeff[2])
		expCoeff[1] = fxp.Add16(gCoeff[3], 1)
	}

	enerInit := int32(1)
	if mode == Mode795 || mode == Mode475 {
		enerInit = 0
	}

	var scaledY2 [subframeSamples]int16
	s1 := enerInit
	s2 := enerInit
	s3 := enerInit
	for i := range subframeSamples {
		tmp := int16(0)
		if i < len(y2) {
			tmp = fxp.Shr16(y2[i], 3)
		}
		scaledY2[i] = tmp

		s1 = fxp.Add32(s1, fxp.LMult(tmp, tmp))
		if i < len(xn) {
			s2 = fxp.Add32(s2, fxp.LMult(xn[i], tmp))
		}
		if i < len(y1) {
			s3 = fxp.Add32(s3, fxp.LMult(y1[i], tmp))
		}
	}

	exp := fxp.NormL(s1)
	fracCoeff[2] = fxp.ExtractH(fxp.Shl32(s1, exp))
	expCoeff[2] = -3 - exp

	exp = fxp.NormL(s2)
	fracCoeff[3] = fxp.Neg16(fxp.ExtractH(fxp.Shl32(s2, exp)))
	expCoeff[3] = 7 - exp

	exp = fxp.NormL(s3)
	fracCoeff[4] = fxp.ExtractH(fxp.Shl32(s3, exp))
	expCoeff[4] = 7 - exp

	if mode == Mode795 || mode == Mode475 {
		sum := int32(0)
		for i := range subframeSamples {
			if i < len(xn2) {
				sum = fxp.Add32(sum, fxp.LMult(xn2[i], scaledY2[i]))
			}
		}
		exp = fxp.NormL(sum)
		frac := fxp.ExtractH(fxp.Shl32(sum, exp))
		exp = 6 - exp
		if frac > 0 && fracCoeff[2] > 0 {
			codGainFrac = fxp.DivS(fxp.Shr16(frac, 1), fracCoeff[2])
			codGainExp = exp - expCoeff[2] - 14
		}
	}
	return fracCoeff, expCoeff, codGainFrac, codGainExp
}

func calcFilteredGainEnergies(
	mode Mode,
	xn []int16,
	xn2 []int16,
	y1 []int16,
	y2 []int16,
	gCoeff []int16,
) filteredGainEnergies {
	fracCoeff, expCoeff, codGainFrac, codGainExp := calcFiltEnergies(mode, xn, xn2, y1, y2, gCoeff)
	return filteredGainEnergies{
		fracCoeff:   fracCoeff,
		expCoeff:    expCoeff,
		codGainFrac: codGainFrac,
		codGainExp:  codGainExp,
	}
}

func calcTargetEnergy(xn []int16) (expEn, fracEn int16) {
	sum := int32(0)
	for i := range subframeSamples {
		var sample int16
		if i < len(xn) {
			sample = xn[i]
		}
		sum = fxp.Add32(sum, fxp.LMult(sample, sample))
	}
	exp := fxp.NormL(sum)
	fracEn = fxp.ExtractH(fxp.Shl32(sum, exp))
	expEn = 16 - exp
	return expEn, fracEn
}

type jointGainQuantization struct {
	index        int16
	gainPit      int16
	gainCode     int16
	quaEnerMR122 int16
	quaEner      int16
}

func quaGain(
	mode Mode,
	expGCode0 int16,
	fracGCode0 int16,
	fracCoeff [5]int16,
	expCoeff [5]int16,
	gpLimit int16,
) jointGainQuantization {
	table := tableGainLowrates[:]
	if mode == Mode1020 || mode == Mode740 || mode == Mode670 {
		table = tableGainHighrates[:]
	}

	gcode0 := int16(pow2Value(14, fracGCode0))
	expCode := expGCode0 - 11

	expMax := [5]int16{
		expCoeff[0] - 13,
		expCoeff[1] - 14,
		expCoeff[2] + fxp.Shl16(expCode, 1) + 15,
		expCoeff[3] + expCode,
		expCoeff[4] + expCode + 1,
	}
	eMax := expMax[0]
	for i := 1; i < len(expMax); i++ {
		eMax = max(eMax, expMax[i])
	}
	eMax++

	var coeff [5]int16
	var coeffLo [5]int16
	for i := range 5 {
		scaled := fxp.Shr32(int32(fracCoeff[i])<<16, eMax-expMax[i])
		coeff[i], coeffLo[i] = fxp.LExtract(scaled)
	}

	distMin := fxp.Max32
	index := int16(0)
	for i := range len(table) / 4 {
		offset := i * 4
		gPitch := table[offset]
		if gPitch > gpLimit {
			continue
		}
		gCode := fxp.Mult(table[offset+1], gcode0)
		g2Pitch := fxp.Mult(gPitch, gPitch)
		g2Code := fxp.Mult(gCode, gCode)
		gPitCod := fxp.Mult(gCode, gPitch)

		dist := fxp.Mpy32By16(coeff[0], coeffLo[0], g2Pitch)
		dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[1], coeffLo[1], gPitch))
		dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[2], coeffLo[2], g2Code))
		dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[3], coeffLo[3], gCode))
		dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[4], coeffLo[4], gPitCod))
		if dist < distMin {
			distMin = dist
			index = int16(i)
		}
	}
	offset := int(index) * 4
	gCode := table[offset+1]
	product := fxp.LMult(gCode, gcode0)
	product = fxp.Shr32(product, 10-expGCode0)
	return jointGainQuantization{
		index:        index,
		gainPit:      table[offset],
		gainCode:     fxp.ExtractH(product),
		quaEnerMR122: table[offset+2],
		quaEner:      table[offset+3],
	}
}

const (
	minQuaEnerMR475      int16 = -5443
	minQuaEnerMR122MR475 int16 = -32768
	maxQuaEnerMR475      int16 = 3037
	maxQuaEnerMR122MR475 int16 = 18284
)

func mr475UpdateUnquantizedPredictor(
	pred *gainPredState,
	expGCode0 int16,
	fracGCode0 int16,
	codGainExp int16,
	codGainFrac int16,
) {
	quaEner := minQuaEnerMR475
	quaEnerMR122 := minQuaEnerMR122MR475
	if codGainFrac > 0 {
		gcode0 := int16(pow2Value(14, fracGCode0))
		if codGainFrac >= gcode0 {
			codGainFrac = fxp.Shr16(codGainFrac, 1)
			codGainExp = fxp.Add16(codGainExp, 1)
		}
		frac := fxp.DivS(codGainFrac, gcode0)
		tmp := fxp.Sub16(fxp.Sub16(codGainExp, expGCode0), 1)
		exp, logFrac := log2Value(int32(frac))
		exp = fxp.Add16(exp, tmp)
		quaEnerMR122 = fxp.Add16(fxp.ShrRound16(logFrac, 5), fxp.Shl16(exp, 10))
		switch {
		case quaEnerMR122 < minQuaEnerMR122MR475:
			quaEner = minQuaEnerMR475
			quaEnerMR122 = minQuaEnerMR122MR475
		case quaEnerMR122 > maxQuaEnerMR122MR475:
			quaEner = maxQuaEnerMR475
			quaEnerMR122 = maxQuaEnerMR122MR475
		default:
			quaEner = fxp.Round(fxp.Shl32(fxp.Mpy32By16(exp, logFrac, 24660), 13))
		}
	}
	pred.update(quaEnerMR122, quaEner)
}

func mr475GainQuant(
	pred *gainPredState,
	sf0 mr475PairState,
	sf1 mr475PairState,
	sf1CodeNoSharp []int16,
	gpLimit int16,
) mr475PairGainResult {
	sf0GCode0 := int16(pow2Value(14, sf0.fracGCode0))
	sf1GCode0 := int16(pow2Value(14, sf1.fracGCode0))

	var expMax [10]int16
	firstExpMax := mr475ExpMax(sf0.expCoeff, sf0.expGCode0)
	secondExpMax := mr475ExpMax(sf1.expCoeff, sf1.expGCode0)
	copy(expMax[:5], firstExpMax[:])
	copy(expMax[5:], secondExpMax[:])

	diff := fxp.Sub16(sf0.expTargetEn, sf1.expTargetEn)
	sf0Target := sf0.fracTargetEn
	sf1Target := sf1.fracTargetEn
	if diff > 0 {
		sf1Target = fxp.Shr16(sf1Target, diff)
	} else {
		sf0Target = fxp.Shr16(sf0Target, -diff)
	}

	scale := int16(0)
	if fxp.ShrRound16(sf1Target, 1) > sf0Target {
		scale = 1
	} else if fxp.Shr16(fxp.Add16(sf0Target, 3), 2) > sf1Target {
		scale = -1
	}
	for i := range 5 {
		expMax[i] = fxp.Add16(expMax[i], scale)
	}

	exp := expMax[0]
	for i := 1; i < len(expMax); i++ {

		exp = max(exp, expMax[i])

	}
	exp++

	var coeff [10]int16
	var coeffLo [10]int16
	for i := range 5 {
		scaled := fxp.Shr32(int32(sf0.fracCoeff[i])<<16, exp-expMax[i])
		coeff[i], coeffLo[i] = fxp.LExtract(scaled)
	}
	for i := range 5 {
		scaled := fxp.Shr32(int32(sf1.fracCoeff[i])<<16, exp-expMax[i+5])
		coeff[i+5], coeffLo[i+5] = fxp.LExtract(scaled)
	}

	distMin := fxp.Max32
	index := int16(0)
	for i := range len(tableGainMR475) / 4 {
		offset := i * 4
		gPitch0 := tableGainMR475[offset]
		gCode0 := fxp.Mult(tableGainMR475[offset+1], sf0GCode0)
		dist := mr475Dist(coeff[:5], coeffLo[:5], gPitch0, gCode0)
		gPitch1 := tableGainMR475[offset+2]
		if gPitch0 > gpLimit || gPitch1 > gpLimit {
			continue
		}
		gCode1 := fxp.Mult(tableGainMR475[offset+3], sf1GCode0)
		dist = fxp.Add32(dist, mr475Dist(coeff[5:], coeffLo[5:], gPitch1, gCode1))
		if dist < distMin {
			distMin = dist
			index = int16(i)
		}
	}
	offset := int(index) * 4
	sf0Pitch, sf0Code := mr475StoreResults(
		pred,
		tableGainMR475[offset],
		tableGainMR475[offset+1],
		sf0GCode0,
		sf0.expGCode0,
	)
	sf1ExpGCode0, sf1FracGCode0, _, _ := pred.predict(Mode475, sf1CodeNoSharp)
	sf1GCode0 = int16(pow2Value(14, sf1FracGCode0))
	sf1Pitch, sf1Code := mr475StoreResults(
		pred,
		tableGainMR475[offset+2],
		tableGainMR475[offset+3],
		sf1GCode0,
		sf1ExpGCode0,
	)

	return mr475PairGainResult{
		index:       index,
		sf0GainPit:  sf0Pitch,
		sf0GainCode: sf0Code,
		sf1GainPit:  sf1Pitch,
		sf1GainCode: sf1Code,
	}
}

func mr475ExpMax(expCoeff [5]int16, expGCode0 int16) [5]int16 {
	var out [5]int16
	expCode := expGCode0 - 11
	out[0] = expCoeff[0] - 13
	out[1] = expCoeff[1] - 14
	out[2] = expCoeff[2] + fxp.Shl16(expCode, 1) + 15
	out[3] = expCoeff[3] + expCode
	out[4] = expCoeff[4] + expCode + 1
	return out
}

func mr475Dist(coeff []int16, coeffLo []int16, gainPitch int16, gainCode int16) int32 {
	g2Pitch := fxp.Mult(gainPitch, gainPitch)
	g2Code := fxp.Mult(gainCode, gainCode)
	gPitCod := fxp.Mult(gainCode, gainPitch)
	dist := fxp.Mpy32By16(coeff[0], coeffLo[0], g2Pitch)
	dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[1], coeffLo[1], gainPitch))
	dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[2], coeffLo[2], g2Code))
	dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[3], coeffLo[3], gainCode))
	dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[4], coeffLo[4], gPitCod))
	return dist
}

func mr475StoreResults(
	pred *gainPredState,
	gainPitch int16,
	tableGainCode int16,
	gcode0 int16,
	expGCode0 int16,
) (int16, int16) {
	product := fxp.LMult(tableGainCode, gcode0)
	product = fxp.Shr32(product, 10-expGCode0)
	gainCode := fxp.ExtractH(product)

	exp, frac := log2Value(int32(tableGainCode))
	exp -= 12
	quaEnerMR122 := fxp.Add16(fxp.ShrRound16(frac, 5), fxp.Shl16(exp, 10))
	quaEner := fxp.Round(fxp.Shl32(fxp.Mpy32By16(exp, frac, 24660), 13))
	pred.update(quaEnerMR122, quaEner)
	return gainPitch, gainCode
}

type mr795GainQuant3Result struct {
	analysis       encoderCodeGainAnalysis
	quaEnerMR122   int16
	quaEner        int16
	pitchGain      int16
	pitchGainIndex int16
}

func mr795GainCodeQuant3(
	expGCode0 int16,
	gcode0 int16,
	gainPitchCand [3]int16,
	gainPitchIndex [3]int16,
	fracCoeff [5]int16,
	expCoeff [5]int16,
) mr795GainQuant3Result {
	expCode := expGCode0 - 10
	expMax := [5]int16{
		expCoeff[0] - 13,
		expCoeff[1] - 14,
		expCoeff[2] + fxp.Shl16(expCode, 1) + 15,
		expCoeff[3] + expCode,
		expCoeff[4] + expCode + 1,
	}
	eMax := expMax[0]
	for i := 1; i < len(expMax); i++ {

		eMax = max(eMax, expMax[i])

	}
	eMax++

	var coeff [5]int16
	var coeffLo [5]int16
	for i := range 5 {
		scaled := fxp.Shr32(int32(fracCoeff[i])<<16, eMax-expMax[i])
		coeff[i], coeffLo[i] = fxp.LExtract(scaled)
	}

	distMin := fxp.Max32
	codeIndex := int16(0)
	pitchSlot := 0
	for slot := range 3 {
		gPitch := gainPitchCand[slot]
		g2Pitch := fxp.Mult(gPitch, gPitch)
		base := fxp.Mpy32By16(coeff[0], coeffLo[0], g2Pitch)
		base = fxp.Add32(base, fxp.Mpy32By16(coeff[1], coeffLo[1], gPitch))

		for i := int16(0); i < 32; i++ {
			offset := i * 3
			gCode := fxp.Mult(quaGainCode[offset], gcode0)
			g2Code := fxp.LMult(gCode, gCode)
			g2CodeH, g2CodeL := fxp.LExtract(g2Code)
			gPitCode := fxp.LMult(gCode, gPitch)
			gPitCodeH, gPitCodeL := fxp.LExtract(gPitCode)

			dist := fxp.Add32(base, fxp.Mpy32(coeff[2], coeffLo[2], g2CodeH, g2CodeL))
			dist = fxp.Add32(dist, fxp.Mpy32By16(coeff[3], coeffLo[3], gCode))
			dist = fxp.Add32(dist, fxp.Mpy32(coeff[4], coeffLo[4], gPitCodeH, gPitCodeL))
			if dist < distMin {
				distMin = dist
				codeIndex = i
				pitchSlot = slot
			}
		}
	}

	offset := codeIndex * 3
	gainCode := fxp.LMult(quaGainCode[offset], gcode0)
	gainCode = fxp.Shr32(gainCode, 9-expGCode0)
	pitchIndex := gainPitchIndex[pitchSlot]
	pitchGain := gainPitchCand[pitchSlot]
	return mr795GainQuant3Result{
		analysis: encoderCodeGainAnalysis{
			index:         codeIndex,
			gain:          fxp.ExtractH(gainCode),
			pitchIndex:    pitchIndex,
			pitchGain:     pitchGain,
			hasPitchIndex: true,
		},
		quaEnerMR122:   quaGainCode[offset+1],
		quaEner:        quaGainCode[offset+2],
		pitchGain:      pitchGain,
		pitchGainIndex: pitchIndex,
	}
}

const (
	ltpGainThr1 = 2721
	ltpGainThr2 = 5443
	ltpgMemSize = 5
)

type gainAdaptState struct {
	onset     int16
	prevAlpha int16
	prevGC    int16
	ltpgMem   [ltpgMemSize]int16
}

func (s *gainAdaptState) reset() {
	s.onset = 0
	s.prevAlpha = 0
	s.prevGC = 0
	clear(s.ltpgMem[:])
}

func (s *gainAdaptState) adapt(ltpg int16, gainCode int16) int16 {
	adapt := int16(0)
	if ltpg > ltpGainThr2 {
		adapt = 2
	} else if ltpg > ltpGainThr1 {
		adapt = 1
	}

	if fxp.ShrRound16(gainCode, 1) > s.prevGC && gainCode > 200 {
		s.onset = 8
	} else if s.onset != 0 {
		s.onset--
	}
	if s.onset != 0 && adapt < 2 {
		adapt++
	}

	s.ltpgMem[0] = ltpg
	filtered := median5(s.ltpgMem)
	result := int16(0)
	if adapt == 0 {
		switch {
		case filtered > ltpGainThr2:
			result = 0
		case filtered < 0:
			result = 16384
		default:
			result = fxp.Sub16(16384, fxp.Mult(24660, fxp.Shl16(filtered, 2)))
		}
	}
	if s.prevAlpha == 0 {
		result = fxp.Shr16(result, 1)
	}

	s.prevAlpha = result
	s.prevGC = gainCode
	for i := ltpgMemSize - 1; i > 0; i-- {
		s.ltpgMem[i] = s.ltpgMem[i-1]
	}
	return result
}

func median5(values [ltpgMemSize]int16) int16 {
	sorted := values
	for i := 1; i < len(sorted); i++ {
		value := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j] > value {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = value
	}
	return sorted[len(sorted)/2]
}

func calcUnfiltEnergies(res []int16, exc []int16, code []int16, gainPit int16) ([4]int16, [4]int16, int16) {
	var fracEn [4]int16
	var expEn [4]int16

	s1 := int32(0)
	s2 := int32(0)
	s3 := int32(0)
	s4 := int32(0)
	for i := range subframeSamples {
		var residual, excitation, innovation int16
		if i < len(res) {
			residual = res[i]
		}
		if i < len(exc) {
			excitation = exc[i]
		}
		if i < len(code) {
			innovation = code[i]
		}

		s1 = fxp.Add32(s1, int32(residual)*int32(residual))
		s2 = fxp.Add32(s2, int32(excitation)*int32(excitation))
		s3 = fxp.Add32(s3, int32(excitation)*int32(innovation))
		pitch := fxp.Round(fxp.Shl32(fxp.LMult(excitation, gainPit), 1))
		ltpResidual := fxp.Sub16(residual, pitch)
		s4 = fxp.Add32(s4, fxp.LMult(ltpResidual, ltpResidual))
	}
	s1 = fxp.Shl32(s1, 1)
	s2 = fxp.Shl32(s2, 1)
	s3 = fxp.Shl32(s3, 1)

	if s1 < 400 {
		fracEn[0] = 0
		expEn[0] = -15
	} else {
		exp := fxp.NormL(s1)
		fracEn[0] = fxp.ExtractH(fxp.Shl32(s1, exp))
		expEn[0] = 15 - exp
	}

	exp := fxp.NormL(s2)
	fracEn[1] = fxp.ExtractH(fxp.Shl32(s2, exp))
	expEn[1] = 15 - exp

	exp = fxp.NormL(s3)
	fracEn[2] = fxp.ExtractH(fxp.Shl32(s3, exp))
	expEn[2] = 2 - exp

	exp = fxp.NormL(s4)
	ltpResEn := fxp.ExtractH(fxp.Shl32(s4, exp))
	exp = 15 - exp
	fracEn[3] = ltpResEn
	expEn[3] = exp

	ltpg := int16(0)
	if ltpResEn > 0 && fracEn[0] != 0 {
		predGain := fxp.DivS(fxp.Shr16(fracEn[0], 1), ltpResEn)
		expDiff := exp - expEn[0]
		value := fxp.Shr32(int32(predGain)<<16, expDiff+3)
		ltpgExp, ltpgFrac := log2Value(value)
		level := fxp.LComp(ltpgExp-27, ltpgFrac)
		ltpg = fxp.Round(fxp.Shl32(level, 13))
	}
	return fracEn, expEn, ltpg
}

func mr795GainCodeQuantMod(
	gainPit int16,
	expGCode0 int16,
	gcode0 int16,
	fracEn [4]int16,
	expEn [4]int16,
	alpha int16,
	gainCodUnq int16,
	currentGainCode int16,
) (index int16, quaEnerMR122 int16, quaEner int16, gainCode int16) {
	gainCodeLimit := fxp.Shl16(currentGainCode, 10-expGCode0)
	g2Pitch := fxp.Mult(gainPit, gainPit)
	oneAlpha := fxp.Add16(32767-alpha, 1)

	t1 := fxp.Shl32(fxp.LMult(alpha, fracEn[1]), 1)
	tmp := fxp.ExtractH(t1)
	lT1 := fxp.LMult(tmp, g2Pitch)
	expCoeff1 := expEn[1] - 15

	tmp = fxp.ExtractH(fxp.Shl32(fxp.LMult(alpha, fracEn[2]), 1))
	coeff2 := fxp.Mult(tmp, gainPit)
	expCoeff2 := expEn[2] + expGCode0 - 10

	coeff3 := fxp.ExtractH(fxp.Shl32(fxp.LMult(alpha, fracEn[3]), 1))
	expCoeff3 := expEn[3] + fxp.Shl16(expGCode0, 1) - 7

	coeff4 := fxp.Mult(oneAlpha, fracEn[3])
	expCoeff4 := expCoeff3 + 1

	rootInput := fxp.LMult(alpha, fracEn[0])
	lT0, exp0 := sqrtLExp(rootInput)
	exp0 += 47
	expCoeff0 := expEn[0] - exp0

	eMax := expCoeff0 + 31
	for _, expValue := range []int16{expCoeff1, expCoeff2, expCoeff3, expCoeff4} {

		eMax = max(eMax, expValue)

	}

	lT1 = fxp.Shr32(lT1, eMax-expCoeff1)
	var coeff [5]int16
	var coeffLo [5]int16
	for i, in := range []struct {
		frac int16
		exp  int16
	}{
		{coeff2, expCoeff2},
		{coeff3, expCoeff3},
		{coeff4, expCoeff4},
	} {
		scaled := fxp.Shr32(int32(in.frac)<<16, eMax-in.exp)
		coeff[i+2], coeffLo[i+2] = fxp.LExtract(scaled)
	}

	newExp := eMax - 31
	shift := newExp - expCoeff0
	lT0 = fxp.Shr32(lT0, fxp.Shr16(shift, 1))
	if shift&1 != 0 {
		coeff[0], coeffLo[0] = fxp.LExtract(lT0)
		lT0 = fxp.Mpy32By16(coeff[0], coeffLo[0], 23170)
	}

	distMin := fxp.Max32
	for i := int16(0); i < 32; i++ {
		offset := i * 3
		gCode := fxp.Mult(quaGainCode[offset], gcode0)
		if gCode >= gainCodeLimit {
			break
		}

		g2Code := fxp.LMult(gCode, gCode)
		g2CodeH, g2CodeL := fxp.LExtract(g2Code)
		diff := fxp.Sub16(gCode, gainCodUnq)
		d2Code := fxp.LMult(diff, diff)
		d2CodeH, d2CodeL := fxp.LExtract(d2Code)

		dist := fxp.Add32(lT1, fxp.Mpy32By16(coeff[2], coeffLo[2], gCode))
		dist = fxp.Add32(dist, fxp.Mpy32(coeff[3], coeffLo[3], g2CodeH, g2CodeL))

		root, rootExp := sqrtLExp(dist)
		root = fxp.Shr32(root, fxp.Shr16(rootExp, 1))
		rootDiff := fxp.Round(fxp.Sub32(root, lT0))
		dist = fxp.LMult(rootDiff, rootDiff)
		dist = fxp.Add32(dist, fxp.Mpy32(coeff[4], coeffLo[4], d2CodeH, d2CodeL))
		if dist < distMin {
			distMin = dist
			index = i
		}
	}

	offset := index * 3
	product := fxp.LMult(quaGainCode[offset], gcode0)
	product = fxp.Shr32(product, 9-expGCode0)
	return index, quaGainCode[offset+1], quaGainCode[offset+2], fxp.ExtractH(product)
}
