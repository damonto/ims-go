/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/common/src/gc_pred.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	gainPredTaps       = 4
	meanEnergyMR122    = 783741
	minEnergy          = -14336
	minEnergyMR122     = -2381
	codeGainMeanLow    = 16678
	codeGainMeanMR67   = 32268
	codeGainMeanMR74   = 32588
	codeGainMeanMR795  = 17062
	log10OverLog2Q13   = -24660
	codeGainFactorMR74 = 5439
	codeGainFactor     = 5443
)

var gainPred = [...]int16{5571, 4751, 2785, 1556}
var gainPredMR122 = [...]int16{44, 37, 22, 12}

type gainPredState struct {
	pastQuaEn      [gainPredTaps]int16
	pastQuaEnMR122 [gainPredTaps]int16
}

func newGainPredState() gainPredState {
	var state gainPredState
	state.reset()
	return state
}

func (s *gainPredState) reset() {
	for i := range gainPredTaps {
		s.pastQuaEn[i] = minEnergy
		s.pastQuaEnMR122[i] = minEnergyMR122
	}
}

func (s *gainPredState) predict(mode Mode, code []int16) (expGCode0, fracGCode0, expEn, fracEn int16) {
	energy := innovationEnergy(code)
	if mode == Mode1220 {
		energy = int32(fxp.Round(energy)) * 26214 << 1
		exp, frac := log2Value(energy)
		logEnergy := fxp.LComp(exp-30, frac)

		predicted := int32(meanEnergyMR122)
		for i := range gainPredTaps {
			predicted = fxp.Add32(predicted, fxp.LMult(s.pastQuaEnMR122[i], gainPredMR122[i]))
		}

		diff := fxp.Shr32(fxp.Sub32(predicted, logEnergy), 1)
		expGCode0, fracGCode0 = fxp.LExtract(diff)
		return expGCode0, fracGCode0, 0, 0
	}

	expCode := fxp.NormL(energy)
	energy = fxp.Shl32(energy, expCode)
	exp, frac := log2Norm(energy, expCode)
	level := fxp.Mpy32By16(exp, frac, log10OverLog2Q13)

	switch mode {
	case Mode1020:
		level = fxp.Add32(level, int32(codeGainMeanLow)<<7)
	case Mode795:
		fracEn = fxp.ExtractH(energy)
		expEn = -11 - expCode
		level = fxp.Add32(level, int32(codeGainMeanMR795)<<7)
	case Mode740:
		level = fxp.Add32(level, int32(codeGainMeanMR74)<<6)
	case Mode670:
		level = fxp.Add32(level, int32(codeGainMeanMR67)<<6)
	default:
		level = fxp.Add32(level, int32(codeGainMeanLow)<<7)
	}

	level = fxp.Shl32(level, 10)
	for i := range gainPredTaps {
		level = fxp.Add32(level, fxp.LMult(gainPred[i], s.pastQuaEn[i]))
	}
	gcode0 := fxp.ExtractH(level)

	factor := int16(codeGainFactor)
	if mode == Mode740 {
		factor = codeGainFactorMR74
	}
	level = fxp.Shr32(fxp.LMult(gcode0, factor), 8)
	expGCode0, fracGCode0 = fxp.LExtract(level)
	return expGCode0, fracGCode0, expEn, fracEn
}

func (s *gainPredState) update(quaEnerMR122, quaEner int16) {
	for i := gainPredTaps - 1; i > 0; i-- {
		s.pastQuaEn[i] = s.pastQuaEn[i-1]
		s.pastQuaEnMR122[i] = s.pastQuaEnMR122[i-1]
	}
	s.pastQuaEnMR122[0] = quaEnerMR122
	s.pastQuaEn[0] = quaEner
}

func (s *gainPredState) averageLimited() (enerAvgMR122, enerAvg int16) {
	for i := range gainPredTaps {
		enerAvgMR122 = fxp.Add16(enerAvgMR122, s.pastQuaEnMR122[i])
	}
	enerAvgMR122 = fxp.Shr16(enerAvgMR122, 2)

	enerAvgMR122 = max(enerAvgMR122, minEnergyMR122)
	for i := range gainPredTaps {
		enerAvg = fxp.Add16(enerAvg, s.pastQuaEn[i])
	}
	enerAvg = fxp.Shr16(enerAvg, 2)

	enerAvg = max(enerAvg, minEnergy)

	return enerAvgMR122, enerAvg
}

func innovationEnergy(code []int16) int32 {
	energy := int32(0)
	for i := range subframeSamples {
		energy = fxp.LMac(energy, code[i], code[i])
	}
	return energy
}
