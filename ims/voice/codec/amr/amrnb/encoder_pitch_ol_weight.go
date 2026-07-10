/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This weighted open-loop pitch search is ported from enc/src/p_ol_wgh.cpp
 * and common/corrwght.tab for AMR-NB MR102.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type pitchOLWeightState struct {
	oldT0Med int16
	adaW     int16
	wghtFlag int16
}

func (s *pitchOLWeightState) reset() {
	s.oldT0Med = 40
	s.adaW = 0
	s.wghtFlag = 0
}

var corrWeight = [...]int16{
	20473, 20506, 20539, 20572, 20605, 20644, 20677,
	20716, 20749, 20788, 20821, 20860, 20893, 20932,
	20972, 21011, 21050, 21089, 21129, 21168, 21207,
	21247, 21286, 21332, 21371, 21417, 21456, 21502,
	21542, 21588, 21633, 21679, 21725, 21771, 21817,
	21863, 21909, 21961, 22007, 22059, 22105, 22158,
	22210, 22263, 22315, 22367, 22420, 22472, 22531,
	22584, 22643, 22702, 22761, 22820, 22879, 22938,
	23003, 23062, 23128, 23193, 23252, 23324, 23390,
	23455, 23527, 23600, 23665, 23744, 23816, 23888,
	23967, 24045, 24124, 24202, 24288, 24366, 24451,
	24537, 24628, 24714, 24805, 24904, 24995, 25094,
	25192, 25297, 25395, 25500, 25611, 25723, 25834,
	25952, 26070, 26188, 26313, 26444, 26575, 26706,
	26844, 26988, 27132, 27283, 27440, 27597, 27761,
	27931, 28108, 28285, 28475, 28665, 28869, 29078,
	29295, 29524, 29760, 30002, 30258, 30527, 30808,
	31457, 32767, 32767, 32767, 32767, 32767,
	32767, 32767, 31457, 30808, 30527, 30258, 30002,
	29760, 29524, 29295, 29078, 28869, 28665, 28475,
	28285, 28108, 27931, 27761, 27597, 27440, 27283,
	27132, 26988, 26844, 26706, 26575, 26444, 26313,
	26188, 26070, 25952, 25834, 25723, 25611, 25500,
	25395, 25297, 25192, 25094, 24995, 24904, 24805,
	24714, 24628, 24537, 24451, 24366, 24288, 24202,
	24124, 24045, 23967, 23888, 23816, 23744, 23665,
	23600, 23527, 23455, 23390, 23324, 23252, 23193,
	23128, 23062, 23003, 22938, 22879, 22820, 22761,
	22702, 22643, 22584, 22531, 22472, 22420, 22367,
	22315, 22263, 22210, 22158, 22105, 22059, 22007,
	21961, 21909, 21863, 21817, 21771, 21725, 21679,
	21633, 21588, 21542, 21502, 21456, 21417, 21371,
	21332, 21286, 21247, 21207, 21168, 21129, 21089,
	21050, 21011, 20972, 20932, 20893, 20860, 20821,
	20788, 20749, 20716, 20677, 20644, 20605, 20572,
	20539, 20506, 20473, 20434, 20401, 20369, 20336,
}

type pitchOLWeightInput struct {
	signal     []int16
	start      int
	pitMin     int
	pitMax     int
	frameLen   int
	oldLags    []int16
	olGainFlag []int16
	index      int
	vad        *encoderVADState
	vad2       *encoderVAD2State
}

func (s *pitchOLWeightState) pitch(in pitchOLWeightInput) (int16, error) {
	if in.start-in.pitMax < 0 ||
		in.start+in.frameLen > len(in.signal) ||
		in.frameLen > FrameSamples ||
		len(in.oldLags) < 5 ||
		len(in.olGainFlag) <= in.index ||
		in.index < 0 {
		return 0, fmt.Errorf("searching AMR-NB weighted open-loop pitch: invalid search buffers or range")
	}

	var scaled [pitchMax + FrameSamples]int16
	energy := int32(0)
	source := in.signal[in.start-in.pitMax : in.start+in.frameLen]
	for _, sample := range source {
		energy = fxp.Add32(energy, fxp.LMult(sample, sample))
	}

	switch {
	case energy == fxp.Max32:
		for i, sample := range source {
			scaled[i] = fxp.Shr16(sample, 3)
		}
	case energy < 1<<20:
		for i, sample := range source {
			scaled[i] = fxp.Shl16(sample, 3)
		}
	default:
		copy(scaled[:], source)
	}

	corr := computePitchCorrelations(scaled[:], in.pitMin, in.pitMax, in.frameLen)
	if in.vad != nil && in.index == 1 {
		in.vad.complexDetectionUpdate(hpMax(corr[:], scaled[:], in.frameLen, in.pitMax, in.pitMin))
	}
	if in.vad != nil {
		in.vad.toneDetectionUpdate(false)
	}
	pMax, gainFlag := s.lagMax(pitchOLWeightLagInput{
		corr:        corr[:],
		scaled:      scaled[:],
		frameLen:    in.frameLen,
		lagMaxValue: in.pitMax,
		lagMinValue: in.pitMin,
		vad:         in.vad,
		vad2:        in.vad2,
	})
	in.olGainFlag[in.index] = gainFlag

	if in.olGainFlag[in.index] > 0 {
		copy(in.oldLags[1:5], in.oldLags[:4])
		in.oldLags[0] = pMax
		s.oldT0Med = gmedN(in.oldLags[:5])
		s.adaW = fxp.Max16
	} else {
		s.oldT0Med = pMax
		s.adaW = fxp.Mult(s.adaW, 29491)
	}

	if s.adaW < 9830 {
		s.wghtFlag = 0
	} else {
		s.wghtFlag = 1
	}

	return pMax, nil
}

type pitchOLWeightLagInput struct {
	corr        []int32
	scaled      []int16
	frameLen    int
	lagMaxValue int
	lagMinValue int
	vad         *encoderVADState
	vad2        *encoderVAD2State
}

func (s *pitchOLWeightState) lagMax(in pitchOLWeightLagInput) (int16, int16) {
	maxCorr := fxp.Min32
	bestLag := in.lagMaxValue
	weightIndex := 250
	nearOldIndex := 123 + in.lagMaxValue - int(s.oldT0Med)

	for lag := in.lagMaxValue; lag >= in.lagMinValue; lag-- {
		corrHi, corrLo := fxp.LExtract(in.corr[lag])
		weighted := fxp.Mpy32By16(corrHi, corrLo, corrWeight[weightIndex])
		weightIndex--
		if s.wghtFlag > 0 {
			weightedHi, weightedLo := fxp.LExtract(weighted)
			weighted = fxp.Mpy32By16(weightedHi, weightedLo, corrWeight[nearOldIndex])
			nearOldIndex--
		}
		if weighted >= maxCorr {
			maxCorr = weighted
			bestLag = lag
		}
	}

	var correlation int32
	var energy int32
	for i := range in.frameLen {
		current := in.scaled[pitchMax+i]
		delayed := in.scaled[pitchMax+i-bestLag]
		correlation = fxp.LMac(correlation, current, delayed)
		energy = fxp.LMac(energy, delayed, delayed)
	}
	if in.vad != nil {
		in.vad.toneDetection(correlation, energy)
	}
	if in.vad2 != nil {
		in.vad2.addPitchCorrelation(correlation, energy)
	}

	gainFlag := fxp.Round(fxp.LMsu(correlation, fxp.Round(energy), 13107))
	return int16(bestLag), gainFlag
}
