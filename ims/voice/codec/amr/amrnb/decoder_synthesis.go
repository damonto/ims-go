/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_nb/common/src/syn_filt.cpp,
 * residu.cpp, and the AMR-NB decoder excitation combine loop.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

func synthesisFilter(a, x, y, memory []int16) [lpcOrder]int16 {
	var history [lpcOrder + subframeSamples]int16
	copy(history[:lpcOrder], memory[:lpcOrder])

	for i := range len(x) {
		sum := fxp.LMult(x[i], a[0])
		for j := 1; j <= lpcOrder; j++ {
			sum = fxp.LMsu(sum, a[j], history[lpcOrder+i-j])
		}
		out := fxp.Round(fxp.Shl32(sum, 3))
		history[lpcOrder+i] = out
		y[i] = out
	}

	var nextMemory [lpcOrder]int16
	copy(nextMemory[:], history[len(x):len(x)+lpcOrder])
	return nextMemory
}

func residual(a []int16, x []int16, y []int16) {
	for i := range len(y) {
		base := i + lpcOrder
		sum := fxp.LMult(x[base], a[0])
		for j := 1; j <= lpcOrder; j++ {
			sum = fxp.LMac(sum, a[j], x[base-j])
		}
		y[i] = fxp.Round(fxp.Shl32(sum, 3))
	}
}

func addPitchContribution(code []int16, t0 int16, pitSharp int16) {
	for i := int(t0); i < subframeSamples; i++ {
		code[i] = fxp.Add16(code[i], fxp.Mult(code[i-int(t0)], pitSharp))
	}
}

func (s *decoderCoreState) currentExcitation() []int16 {
	return s.oldExc[s.excOffset : s.excOffset+subframeSamples]
}

func (s *decoderCoreState) synthesizeCurrentSubframe(
	subframe int,
	code []int16,
	gainPit int16,
	gainCode int16,
	gainCodeMix int16,
	mode Mode,
	dst []int16,
) []int16 {
	if cap(dst) < subframeSamples {
		dst = make([]int16, subframeSamples)
	} else {
		dst = dst[:subframeSamples]
	}

	exc := s.currentExcitation()
	var synthesisExcitation [subframeSamples]int16
	copy(synthesisExcitation[:], exc)

	pitSharp := gainPit
	if mode != Mode1220 && pitSharp > sharpMax {
		pitSharp = sharpMax
	}
	if mode == Mode1020 && s.oldT0 > subframeSamples+5 {
		pitSharp = fxp.Shr16(pitSharp, 2)
	}
	pitSharp = fxp.Shl16(pitSharp, 1)
	var pitchEnhanced [subframeSamples]int16
	usePitchEnhancement := pitSharp > 16384
	if usePitchEnhancement {
		for i := range subframeSamples {
			temp := fxp.Mult(exc[i], pitSharp)
			acc := fxp.LMult(temp, gainPit)
			if mode == Mode1220 {
				acc = fxp.Shr32(acc, 1)
			}
			pitchEnhanced[i] = fxp.Round(acc)
		}
	}

	pitchFactor := gainPit
	shift := int16(1)
	if mode == Mode1220 {
		pitchFactor = fxp.Shr16(gainPit, 1)
		shift = 2
	}
	combineExcitation(exc, code, pitchFactor, gainCode, shift)
	s.phaseDisp.apply(mode, synthesisExcitation[:], gainCodeMix, gainPit, code, pitchFactor, shift)
	s.updateExcitationEnergyHistory(excitationEnergy(synthesisExcitation[:]))
	synthExcitation := synthesisExcitation[:]
	if usePitchEnhancement {
		for i := range subframeSamples {
			pitchEnhanced[i] = fxp.Add16(pitchEnhanced[i], synthesisExcitation[i])
		}
		agc2(synthesisExcitation[:], pitchEnhanced[:])
		synthExcitation = pitchEnhanced[:]
	}
	azOffset := subframe * lpcCoeffCount
	s.memSyn = synthesisFilter(s.az[azOffset:azOffset+lpcCoeffCount], synthExcitation, dst, s.memSyn[:])
	s.advanceExcitation()
	return dst
}

func (s *decoderCoreState) advanceExcitation() {
	copy(s.oldExc[:pitchMax+interpolationLen], s.oldExc[subframeSamples:])
}

func (s *decoderCoreState) updateExcitationEnergyHistory(energy int16) {
	if s.inBackgroundNoise && s.prevBF && s.state < 4 {
		return
	}
	copy(s.excEnergyHist[:excitationHistoryLen-1], s.excEnergyHist[1:])
	s.excEnergyHist[excitationHistoryLen-1] = energy
}

func excitationEnergy(excitation []int16) int16 {
	sum := int32(0)
	for i := range subframeSamples {
		sum = fxp.Add32(sum, fxp.LMult(excitation[i], excitation[i]))
	}
	sum = fxp.Shr32(sum, 1)
	root, exp := sqrtLExp(sum)
	root = fxp.Shr32(root, fxp.Add16(fxp.Shr16(exp, 1), 15))
	return int16(fxp.Shr32(root, 2))
}
