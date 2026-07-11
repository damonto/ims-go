/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This open-loop pitch search is ported from enc/src/ol_ltp.cpp,
 * enc/src/pitch_ol.cpp, and enc/src/calc_cor.cpp for the non-DTX path.
 */

package amrnb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	pitchMin       = 20
	pitchMinMR122  = 18
	pitchThreshold = 27853
)

func openLoopPitch(mode Mode, wspHistory []int16) ([2]int16, error) {
	return openLoopPitchWithState(openLoopPitchInput{
		mode:       mode,
		wspHistory: wspHistory,
	})
}

type openLoopPitchInput struct {
	mode       Mode
	wspHistory []int16
	weighted   *pitchOLWeightState
	oldLags    []int16
	olGainFlag []int16
	vad        *encoderVADState
	vad2       *encoderVAD2State
}

func openLoopPitchWithState(in openLoopPitchInput) ([2]int16, error) {
	var tOp [2]int16
	if in.mode < Mode475 || in.mode > ModeDTX {
		return tOp, fmt.Errorf("estimating AMR-NB open-loop pitch: invalid mode %d", in.mode)
	}
	if len(in.wspHistory) < pitchMax+FrameSamples {
		return tOp, fmt.Errorf(
			"estimating AMR-NB open-loop pitch: weighted speech sample count %d, want at least %d",
			len(in.wspHistory),
			pitchMax+FrameSamples,
		)
	}
	if in.mode == Mode1020 {
		if in.weighted == nil {
			return tOp, errors.New("estimating AMR-NB open-loop pitch: weighted pitch state is required for mode 1020")
		}
		if len(in.oldLags) < 5 {
			return tOp, fmt.Errorf(
				"estimating AMR-NB open-loop pitch: old lag count %d, want at least 5",
				len(in.oldLags),
			)
		}
		if len(in.olGainFlag) < 2 {
			return tOp, fmt.Errorf(
				"estimating AMR-NB open-loop pitch: open-loop gain flag count %d, want at least 2",
				len(in.olGainFlag),
			)
		}
	}
	if in.mode != Mode1020 && len(in.olGainFlag) >= 2 {
		clear(in.olGainFlag[:2])
	}

	switch in.mode {
	case Mode475, Mode515:
		lag, err := pitchOlWithVAD(pitchOLSearchInput{
			signal:        in.wspHistory,
			start:         pitchMax,
			pitMin:        pitchMin,
			pitMax:        pitchMax,
			frameLen:      FrameSamples,
			mode:          in.mode,
			vad:           in.vad,
			vad2:          in.vad2,
			updateComplex: true,
		})
		if err != nil {
			return tOp, err
		}
		tOp[0], tOp[1] = lag, lag
		return tOp, nil
	case Mode1020:
		weighted := pitchOLWeightInput{
			signal:     in.wspHistory,
			start:      pitchMax,
			pitMin:     pitchMin,
			pitMax:     pitchMax,
			frameLen:   FrameSamples / 2,
			oldLags:    in.oldLags,
			olGainFlag: in.olGainFlag,
			vad:        in.vad,
			vad2:       in.vad2,
		}
		var err error
		tOp[0], err = in.weighted.pitch(weighted)
		if err != nil {
			return [2]int16{}, err
		}
		weighted.start = pitchMax + FrameSamples/2
		weighted.index = 1
		tOp[1], err = in.weighted.pitch(weighted)
		if err != nil {
			return [2]int16{}, err
		}
		return tOp, nil
	default:
		pitMin := pitchMin
		if in.mode == Mode1220 {
			pitMin = pitchMinMR122
		}
		first := pitchOLSearchInput{
			signal:   in.wspHistory,
			start:    pitchMax,
			pitMin:   pitMin,
			pitMax:   pitchMax,
			frameLen: FrameSamples / 2,
			mode:     in.mode,
			vad:      in.vad,
			vad2:     in.vad2,
		}
		var err error
		tOp[0], err = pitchOlWithVAD(first)
		if err != nil {
			return [2]int16{}, err
		}
		first.start = pitchMax + FrameSamples/2
		first.updateComplex = true
		tOp[1], err = pitchOlWithVAD(first)
		if err != nil {
			return [2]int16{}, err
		}
		return tOp, nil
	}
}

type pitchOLSearchInput struct {
	signal        []int16
	start         int
	pitMin        int
	pitMax        int
	frameLen      int
	mode          Mode
	vad           *encoderVADState
	vad2          *encoderVAD2State
	updateComplex bool
}

func pitchOlWithVAD(in pitchOLSearchInput) (int16, error) {
	if in.mode < Mode475 || in.mode > ModeDTX {
		return 0, fmt.Errorf("searching AMR-NB open-loop pitch: invalid mode %d", in.mode)
	}
	if in.pitMin <= 0 || in.pitMax < in.pitMin || in.pitMax > pitchMax || in.frameLen <= 0 || in.frameLen > FrameSamples {
		return 0, fmt.Errorf(
			"searching AMR-NB open-loop pitch: invalid lag/frame range %d..%d/%d",
			in.pitMin,
			in.pitMax,
			in.frameLen,
		)
	}
	if in.start-in.pitMax < 0 || in.start+in.frameLen > len(in.signal) {
		return 0, fmt.Errorf(
			"searching AMR-NB open-loop pitch: signal range %d..%d exceeds %d samples",
			in.start-in.pitMax,
			in.start+in.frameLen,
			len(in.signal),
		)
	}

	var scaled [pitchMax + FrameSamples]int16
	if in.vad != nil {
		in.vad.toneDetectionUpdate(in.mode == Mode475 || in.mode == Mode515)
	}

	energy := int32(0)
	for _, sample := range in.signal[in.start-in.pitMax : in.start+in.frameLen] {
		energy = fxp.Add32(energy, fxp.LMult(sample, sample))
	}

	scalFac := int16(0)
	source := in.signal[in.start-in.pitMax : in.start+in.frameLen]
	switch {
	case energy == fxp.Max32:
		for i, sample := range source {
			scaled[i] = fxp.Shr16(sample, 3)
		}
		scalFac = 3
	case energy < 1<<20:
		for i, sample := range source {
			scaled[i] = fxp.Shl16(sample, 3)
		}
		scalFac = -3
	default:
		copy(scaled[:], source)
	}

	corr := computePitchCorrelations(scaled[:], in.pitMin, in.pitMax, in.frameLen)
	if in.vad != nil && in.updateComplex {
		in.vad.complexDetectionUpdate(hpMax(corr[:], scaled[:], in.frameLen, in.pitMax, in.pitMin))
	}
	scalFlag := in.mode == Mode1220

	lag1Max := in.pitMin << 2
	lagIn := lagMaxInput{
		corr:     corr[:],
		scaled:   scaled[:],
		scalFac:  scalFac,
		scalFlag: scalFlag,
		frameLen: in.frameLen,
		vad:      in.vad,
	}
	lagIn.lagMaxValue, lagIn.lagMinValue = in.pitMax, lag1Max
	first := lagMax(lagIn)
	lagIn.lagMaxValue, lagIn.lagMinValue = lag1Max-1, in.pitMin<<1
	second := lagMax(lagIn)
	lagIn.lagMaxValue, lagIn.lagMinValue = (in.pitMin<<1)-1, in.pitMin
	third := lagMax(lagIn)
	maxLag1, corr1, rawCorr1, rawEnergy1 := first.lag, first.correlation, first.rawCorrelation, first.energy
	maxLag2, corr2, rawCorr2, rawEnergy2 := second.lag, second.correlation, second.rawCorrelation, second.energy
	maxLag3, corr3, rawCorr3, rawEnergy3 := third.lag, third.correlation, third.rawCorrelation, third.energy

	if fxp.Mult(corr1, pitchThreshold) < corr2 {
		corr1 = corr2
		maxLag1 = maxLag2
		rawCorr1 = rawCorr2
		rawEnergy1 = rawEnergy2
	}
	if fxp.Mult(corr1, pitchThreshold) < corr3 {
		maxLag1 = maxLag3
		rawCorr1 = rawCorr3
		rawEnergy1 = rawEnergy3
	}
	if in.vad2 != nil {
		in.vad2.addPitchCorrelation(rawCorr1, rawEnergy1)
	}

	return maxLag1, nil
}

func hpMax(corr []int32, scaled []int16, frameLen int, lagMaxValue int, lagMinValue int) int16 {
	maxValue := fxp.Min32
	for lag := lagMaxValue - 1; lag > lagMinValue; lag-- {
		filtered := fxp.Sub32(fxp.Shl32(corr[lag], 1), corr[lag+1])
		filtered = fxp.Sub32(filtered, corr[lag-1])
		if filtered < 0 {
			filtered = fxp.Abs32(filtered)
		}
		if filtered >= maxValue {
			maxValue = filtered
		}
	}

	var energy int32
	for i := range frameLen {
		energy = fxp.LMac(energy, scaled[pitchMax+i], scaled[pitchMax+i])
	}
	var lag1Energy int32
	for i := range frameLen {
		lag1Energy = fxp.LMac(lag1Energy, scaled[pitchMax+i], scaled[pitchMax+i-1])
	}
	energy = fxp.Sub32(fxp.Shl32(energy, 1), fxp.Shl32(lag1Energy, 1))
	if energy < 0 {
		energy = fxp.Abs32(energy)
	}

	shift1 := fxp.Sub16(fxp.NormL(maxValue), 1)
	max16 := fxp.ExtractH(fxp.Shl32(maxValue, shift1))
	shift2 := fxp.NormL(energy)
	energy16 := fxp.ExtractH(fxp.Shl32(energy, shift2))

	correlation := int16(0)
	if energy16 != 0 {
		correlation = fxp.DivS(max16, energy16)
	}
	shift := fxp.Sub16(shift1, shift2)
	if shift >= 0 {
		return fxp.Shr16(correlation, shift)
	}
	return fxp.Shl16(correlation, -shift)
}

func computePitchCorrelations(scaled []int16, pitMin int, pitMax int, frameLen int) [pitchMax + 1]int32 {
	var corr [pitchMax + 1]int32
	current := pitchMax
	for lag := pitMin; lag <= pitMax; lag++ {
		acc := int32(0)
		for i := range frameLen {
			acc = fxp.Add32(acc, fxp.LMult(scaled[current+i], scaled[current+i-lag]))
		}
		corr[lag] = acc
	}
	return corr
}

type lagMaxInput struct {
	corr        []int32
	scaled      []int16
	scalFac     int16
	scalFlag    bool
	frameLen    int
	lagMaxValue int
	lagMinValue int
	vad         *encoderVADState
}

type lagSearchResult struct {
	lag            int16
	correlation    int16
	rawCorrelation int32
	energy         int32
}

func lagMax(in lagMaxInput) lagSearchResult {
	maxCorr := fxp.Min32
	bestLag := in.lagMaxValue
	for lag := in.lagMaxValue; lag >= in.lagMinValue; lag-- {
		if in.corr[lag] >= maxCorr {
			maxCorr = in.corr[lag]
			bestLag = lag
		}
	}

	energy := int32(0)
	for i := range in.frameLen {
		sample := in.scaled[pitchMax+i-bestLag]
		energy = fxp.Add32(energy, fxp.LMult(sample, sample))
	}
	if in.vad != nil {
		in.vad.toneDetection(maxCorr, energy)
	}

	root := invSqrt(energy)
	if in.scalFlag {
		if root > 0x3fffffff {
			root = fxp.Max32
		} else {
			root <<= 1
		}
	}

	maxHi, maxLo := fxp.LExtract(maxCorr)
	rootHi, rootLo := fxp.LExtract(root)
	normalized := fxp.Mpy32(maxHi, maxLo, rootHi, rootLo)
	if in.scalFlag {
		normalized = fxp.Shr32(normalized, in.scalFac)
		if normalized > 0x0000ffff {
			return lagSearchResult{int16(bestLag), fxp.Max16, maxCorr, energy}
		}
		if normalized < -65536 {
			return lagSearchResult{int16(bestLag), fxp.Min16, maxCorr, energy}
		}
		return lagSearchResult{int16(bestLag), int16(normalized >> 1), maxCorr, energy}
	}

	return lagSearchResult{int16(bestLag), int16(normalized), maxCorr, energy}
}
