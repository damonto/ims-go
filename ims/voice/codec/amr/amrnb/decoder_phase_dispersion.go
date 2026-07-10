/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This file ports the AMR-NB decoder phase dispersion logic from
 * opencore-amr amr_nb/dec/src/ph_disp.cpp and common/src/ph_disp_tab.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	phaseGainMemSize = 5
	phaseThr1LTP     = 9830
	phaseThr2LTP     = 14746
	phaseOnFactPlus1 = 16384
	phaseOnLength    = 2
)

var phaseImpLowMR795 = [...]int16{
	26777, 801, 2505, -683, -1382, 582, 604, -1274, 3511, -5894,
	4534, -499, -1940, 3011, -5058, 5614, -1990, -1061, -1459, 4442,
	-700, -5335, 4609, 452, -589, -3352, 2953, 1267, -1212, -2590,
	1731, 3670, -4475, -975, 4391, -2537, 949, -1363, -979, 5734,
}

var phaseImpMidMR795 = [...]int16{
	30274, 3831, -4036, 2972, -1048, -1002, 2477, -3043, 2815, -2231,
	1753, -1611, 1714, -1775, 1543, -1008, 429, -169, 472, -1264,
	2176, -2706, 2523, -1621, 344, 826, -1529, 1724, -1657, 1701,
	-2063, 2644, -3060, 2897, -1978, 557, 780, -1369, 842, 655,
}

var phaseImpLow = [...]int16{
	14690, 11518, 1268, -2761, -5671, 7514, -35, -2807, -3040, 4823,
	2952, -8424, 3785, 1455, 2179, -8637, 8051, -2103, -1454, 777,
	1108, -2385, 2254, -363, -674, -2103, 6046, -5681, 1072, 3123,
	-5058, 5312, -2329, -3728, 6924, -3889, 675, -1775, 29, 10145,
}

var phaseImpMid = [...]int16{
	30274, 3831, -4036, 2972, -1048, -1002, 2477, -3043, 2815, -2231,
	1753, -1611, 1714, -1775, 1543, -1008, 429, -169, 472, -1264,
	2176, -2706, 2523, -1621, 344, 826, -1529, 1724, -1657, 1701,
	-2063, 2644, -3060, 2897, -1978, 557, 780, -1369, 842, 655,
}

type phaseDispersionState struct {
	gainMem    [phaseGainMemSize]int16
	prevState  int16
	prevCbGain int16
	lockFull   int16
	onset      int16
}

func (s *phaseDispersionState) reset() {
	clear(s.gainMem[:])
	s.prevState = 0
	s.prevCbGain = 0
	s.lockFull = 0
	s.onset = 0
}

func (s *phaseDispersionState) lock() {
	s.lockFull = 1
}

func (s *phaseDispersionState) release() {
	s.lockFull = 0
}

func (s *phaseDispersionState) apply(
	mode Mode,
	excitation []int16,
	cbGain int16,
	ltpGain int16,
	innovation []int16,
	pitchFactor int16,
	shift int16,
) {
	impNr := s.selectFilter(cbGain, ltpGain)
	if shouldPhaseDisperse(mode, impNr) {
		s.disperseInnovation(mode, impNr, innovation)
	}
	combineExcitation(excitation, innovation, pitchFactor, cbGain, shift)
}

func (s *phaseDispersionState) selectFilter(cbGain, ltpGain int16) int16 {
	copy(s.gainMem[1:], s.gainMem[:phaseGainMemSize-1])
	s.gainMem[0] = ltpGain

	impNr := int16(2)
	if ltpGain < phaseThr2LTP {
		if ltpGain > phaseThr1LTP {
			impNr = 1
		} else {
			impNr = 0
		}
	}

	threshold := fxp.Round(fxp.Shl32(fxp.LMult(s.prevCbGain, phaseOnFactPlus1), 2))
	if cbGain > threshold {
		s.onset = phaseOnLength
	} else if s.onset > 0 {
		s.onset--
	}

	if s.onset == 0 {
		lowGainCount := int16(0)
		for _, gain := range s.gainMem {
			if gain < phaseThr1LTP {
				lowGainCount++
			}
		}
		if lowGainCount > 2 {
			impNr = 0
		}
	}

	if impNr > s.prevState+1 && s.onset == 0 {
		impNr--
	}
	if impNr < 2 && s.onset > 0 {
		impNr++
	}
	if cbGain < 10 {
		impNr = 2
	}
	if s.lockFull == 1 {
		impNr = 0
	}

	s.prevState = impNr
	s.prevCbGain = cbGain
	return impNr
}

func shouldPhaseDisperse(mode Mode, impNr int16) bool {
	return mode != Mode1220 && mode != Mode1020 && mode != Mode740 && impNr < 2
}

func (s *phaseDispersionState) disperseInnovation(mode Mode, impNr int16, innovation []int16) {
	limit := subframeSamples
	limit = min(limit, len(innovation))

	var saved [subframeSamples]int16
	var positions [subframeSamples]int16
	nze := 0
	for i := range limit {
		if innovation[i] != 0 {
			positions[nze] = int16(i)
			nze++
		}
		saved[i] = innovation[i]
		innovation[i] = 0
	}

	impulse := phaseImpulse(mode, impNr)
	for pulse := range nze {
		ppos := int(positions[pulse])
		value := saved[ppos]
		tap := 0
		for i := ppos; i < limit; i++ {
			innovation[i] = fxp.Add16(innovation[i], fxp.Mult(value, impulse[tap]))
			tap++
		}
		for i := range ppos {
			innovation[i] = fxp.Add16(innovation[i], fxp.Mult(value, impulse[tap]))
			tap++
		}
	}
}

func phaseImpulse(mode Mode, impNr int16) []int16 {
	if mode == Mode795 {
		if impNr == 0 {
			return phaseImpLowMR795[:]
		}
		return phaseImpMidMR795[:]
	}
	if impNr == 0 {
		return phaseImpLow[:]
	}
	return phaseImpMid[:]
}

func combineExcitationWithMode(excitation []int16, code []int16, gainPit int16, gainCode int16, mode Mode) {
	pitchFactor := gainPit
	shift := int16(1)
	if mode == Mode1220 {
		pitchFactor = fxp.Shr16(gainPit, 1)
		shift = 2
	}
	combineExcitation(excitation, code, pitchFactor, gainCode, shift)
}

func combineExcitation(excitation []int16, code []int16, pitchFactor int16, gainCode int16, shift int16) {
	limit := subframeSamples
	limit = min(limit, len(excitation))
	limit = min(limit, len(code))
	for i := range limit {
		acc := fxp.LMult(excitation[i], pitchFactor)
		acc = fxp.Add32(acc, fxp.LMult(code[i], gainCode))
		acc = fxp.Shl32(acc, shift)
		excitation[i] = fxp.Round(acc)
	}
}
