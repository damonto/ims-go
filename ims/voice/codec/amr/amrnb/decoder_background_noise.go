/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/bgnscd.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	energyHistoryLen = 60
	lowerNoiseLimit  = 20
	upperNoiseLimit  = 1953
	frameEnergyLimit = 17578
)

type backgroundNoiseState struct {
	frameEnergyHist [energyHistoryLen]int16
	bgHangover      int16
}

func (s *backgroundNoiseState) reset() {
	*s = backgroundNoiseState{}
}

func (s *backgroundNoiseState) detect(ltpGainHist []int16, speech []int16, voicedHangover int16) (bool, int16) {
	currEnergy := frameEnergy(speech)
	frameEnergyMin := int16(32767)
	for _, energy := range s.frameEnergyHist {
		frameEnergyMin = min(frameEnergyMin, energy)
	}
	noiseFloor := fxp.Saturate16(int32(frameEnergyMin) << 4)

	maxEnergy := s.frameEnergyHist[0]
	for i := 1; i < energyHistoryLen-4; i++ {
		maxEnergy = max(maxEnergy, s.frameEnergyHist[i])
	}

	maxEnergyLastPart := s.frameEnergyHist[2*energyHistoryLen/3]
	for i := 2*energyHistoryLen/3 + 1; i < energyHistoryLen; i++ {
		maxEnergyLastPart = max(maxEnergyLastPart, s.frameEnergyHist[i])
	}

	if maxEnergy > lowerNoiseLimit &&
		currEnergy < frameEnergyLimit &&
		currEnergy > lowerNoiseLimit &&
		(currEnergy < noiseFloor || maxEnergyLastPart < upperNoiseLimit) {
		s.bgHangover = fxp.Add16(s.bgHangover, 1)
		s.bgHangover = min(s.bgHangover, 30)
	} else {
		s.bgHangover = 0
	}

	inBackgroundNoise := s.bgHangover > 1

	copy(s.frameEnergyHist[:energyHistoryLen-1], s.frameEnergyHist[1:])
	s.frameEnergyHist[energyHistoryLen-1] = currEnergy

	ltpLimit := int16(13926)
	if s.bgHangover > 15 {
		ltpLimit = 16383
	} else if s.bgHangover > 8 {
		ltpLimit = 15565
	}

	prevVoiced := false
	if len(ltpGainHist) >= ltpGainHistoryLen && gmedN(ltpGainHist[4:9]) > ltpLimit {
		prevVoiced = true
	}
	if s.bgHangover > 20 && len(ltpGainHist) >= ltpGainHistoryLen {
		prevVoiced = gmedN(ltpGainHist[:ltpGainHistoryLen]) > ltpLimit
	}

	if prevVoiced {
		return inBackgroundNoise, 0
	}

	voicedHangover = fxp.Add16(voicedHangover, 1)
	if voicedHangover > 10 {
		voicedHangover = 10
	}
	return inBackgroundNoise, voicedHangover
}

func frameEnergy(speech []int16) int16 {
	sum := int32(0)
	for i := range FrameSamples {
		sum = fxp.Add32(sum, fxp.LMult(speech[i], speech[i]))
	}
	if sum > 0x1fffffff {
		return fxp.Max16
	}
	return int16(sum >> 14)
}
