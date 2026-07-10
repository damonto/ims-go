/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/c_g_aver.cpp and
 * int_lsf.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const cbGainHistoryLen = 7

type cbGainAverageState struct {
	history   [cbGainHistoryLen]int16
	hangVar   int16
	hangCount int16
}

func (s *cbGainAverageState) reset() {
	*s = cbGainAverageState{}
}

type cbGainAverageInput struct {
	mode              Mode
	gainCode          int16
	lsf               []int16
	lsfAverage        []int16
	badFrame          bool
	previousBadFrame  bool
	potentialDegrade  bool
	previousDegrade   bool
	inBackgroundNoise bool
	voicedHangover    int16
}

func (s *cbGainAverageState) average(in cbGainAverageInput) int16 {
	gainMix := in.gainCode
	copy(s.history[:cbGainHistoryLen-1], s.history[1:])
	s.history[cbGainHistoryLen-1] = in.gainCode

	diff := lsfDifference(in.lsf, in.lsfAverage)
	if diff > 5325 {
		s.hangVar = fxp.Add16(s.hangVar, 1)
	} else {
		s.hangVar = 0
	}
	if s.hangVar > 10 {
		s.hangCount = 0
	}

	if !modeUsesCBGainMix(in.mode) {
		s.hangCount = fxp.Add16(s.hangCount, 1)
		return gainMix
	}

	bgMix := int16(8192)
	tmpDiff := fxp.Sub16(diff, 3277)
	if ((in.potentialDegrade && in.previousDegrade) || in.badFrame || in.previousBadFrame) &&
		in.voicedHangover > 1 &&
		in.inBackgroundNoise &&
		(in.mode == Mode475 || in.mode == Mode515 || in.mode == Mode590) {
		tmpDiff = fxp.Sub16(diff, 4506)
	}

	tmp := tmpDiff

	tmp = max(tmp, 0)

	if tmp <= 2048 {
		bgMix = fxp.Shl16(tmp, 2)
	}

	if s.hangCount < 40 || diff > 5325 {
		bgMix = 8192
	}

	gainMean := s.gainMean(false)
	if (in.badFrame || in.previousBadFrame) &&
		in.inBackgroundNoise &&
		(in.mode == Mode475 || in.mode == Mode515 || in.mode == Mode590) {
		gainMean = s.gainMean(true)
	}

	acc := fxp.LMult(bgMix, gainMix)
	acc = fxp.Add32(acc, fxp.LMult(8192, gainMean))
	acc = fxp.Sub32(acc, fxp.LMult(bgMix, gainMean))
	gainMix = fxp.Round(fxp.Shl32(acc, 2))

	s.hangCount = fxp.Add16(s.hangCount, 1)
	return gainMix
}

func (s *cbGainAverageState) gainMean(useFullHistory bool) int16 {
	weight := int16(6554)
	start := 2
	if useFullHistory {
		weight = 4681
		start = 0
	}
	acc := fxp.LMult(weight, s.history[start])
	for i := start + 1; i < cbGainHistoryLen; i++ {
		acc = fxp.Add32(acc, fxp.LMult(weight, s.history[i]))
	}
	return fxp.Round(acc)
}

func modeUsesCBGainMix(mode Mode) bool {
	return mode <= Mode670 || mode == Mode1020
}

func lsfDifference(lsf, average []int16) int16 {
	var diff int16
	for i := range lpcOrder {
		delta := fxp.Abs16(fxp.Sub16(average[i], lsf[i]))
		shift1 := fxp.Sub16(fxp.NormS(delta), 1)
		scaledDelta := fxp.Shl16(delta, shift1)
		shift2 := fxp.NormS(average[i])
		scaledAverage := fxp.Shl16(average[i], shift2)
		ratio := fxp.DivS(scaledDelta, scaledAverage)
		shift := fxp.Sub16(fxp.Add16(2, shift1), shift2)
		if shift >= 0 {
			ratio = fxp.Shr16(ratio, shift)
		} else {
			ratio = fxp.Shl16(ratio, fxp.Neg16(shift))
		}
		diff = fxp.Add16(diff, ratio)
	}
	return diff
}

func interpolateLSF(oldLSF, newLSF []int16, subframe int) ([lpcOrder]int16, error) {
	var out [lpcOrder]int16
	if len(oldLSF) < lpcOrder || len(newLSF) < lpcOrder {
		return out, fmt.Errorf(
			"interpolating AMR-NB LSF: old/new coefficient counts %d/%d, want at least %d",
			len(oldLSF),
			len(newLSF),
			lpcOrder,
		)
	}
	if subframe < 0 || subframe >= FrameSamples/subframeSamples {
		return out, fmt.Errorf("interpolating AMR-NB LSF: invalid subframe %d", subframe)
	}

	switch subframe {
	case 0:
		for i := range lpcOrder {
			out[i] = fxp.Add16(
				fxp.Sub16(oldLSF[i], fxp.Shr16(oldLSF[i], 2)),
				fxp.Shr16(newLSF[i], 2),
			)
		}
	case 1:
		for i := range lpcOrder {
			out[i] = fxp.Shr16(oldLSF[i], 1) + fxp.Shr16(newLSF[i], 1)
		}
	case 2:
		for i := range lpcOrder {
			out[i] = fxp.Add16(
				fxp.Shr16(oldLSF[i], 2),
				fxp.Sub16(newLSF[i], fxp.Shr16(newLSF[i], 2)),
			)
		}
	case 3:
		copy(out[:], newLSF[:lpcOrder])
	}
	return out, nil
}
