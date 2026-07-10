/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This VAD feature extraction is ported from amrwbenc/src/wb_vad.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
	amrvad "github.com/damonto/ims-go/ims/voice/codec/amr/vad"
)

const (
	vadFrameLen = frameSamples12k8
	vadBands    = 12

	vadUnityShift int16 = 7

	vadSpeechEstimateCount    int16 = 80
	vadSpeechActivityCount    int16 = 25
	vadAlphaSpeechUp          int16 = 4915
	vadAlphaSpeechDown        int16 = 4915
	vadSpeechLevelInit        int16 = 2050
	vadMinSpeechLevel1        int16 = 129
	vadMinSpeechLevel2        int16 = 410
	vadMinSpeechSNR           int16 = 4096
	vadAlphaUp1               int16 = 1638
	vadAlphaDown1             int16 = 2097
	vadAlphaUp2               int16 = 491
	vadAlphaDown2             int16 = 1867
	vadAlpha3                 int16 = 1638
	vadAlpha4                 int16 = 3276
	vadAlpha5                 int16 = 16383
	vadThresholdMin           int16 = 204
	vadThresholdHigh          int16 = 768
	vadThresholdLow           int16 = 217
	vadNoisePoint1            int16 = 31744
	vadNoiseSlope             int16 = 1509
	vadSpeechChangeMin        int16 = -96
	vadSpeechChangeMax        int16 = 96
	vadSpeechPoint1           int16 = 22527
	vadSpeechSlope            int16 = -1340
	vadHangHigh               int16 = 12
	vadHangLow                int16 = 2
	vadHangPoint1             int16 = vadThresholdLow
	vadHangSlope              int16 = -1110
	vadBurstHigh              int16 = 8
	vadBurstPoint1            int16 = vadThresholdHigh
	vadBurstSlope             int16 = 297
	vadStationaryCount        int16 = 20
	vadStationaryThresholdLev int16 = 184
	vadStationaryThreshold    int16 = 1000
	vadNoiseMin               int16 = 40
	vadNoiseMax               int16 = 20000
	vadNoiseInit              int16 = 150
	vadPowerLow               int32 = 30000
	vadPowerToneThreshold     int32 = 686080
	vadToneThreshold          int16 = 21298
	vadCoeff3                 int16 = 13363
	vadCoeff51                int16 = 21955
	vadCoeff52                int16 = 6390
)

var vadLevelBands = [...]amrvad.LevelBand{
	{TailStart: 2, TailEnd: 8, Step: 32, Offset: 0, Scale: 17},
	{TailStart: 2, TailEnd: 8, Step: 32, Offset: 16, Scale: 17},
	{TailStart: 2, TailEnd: 8, Step: 32, Offset: 24, Scale: 17},
	{TailStart: 2, TailEnd: 8, Step: 32, Offset: 8, Scale: 17},
	{TailStart: 4, TailEnd: 16, Step: 16, Offset: 12, Scale: 16},
	{TailStart: 4, TailEnd: 16, Step: 16, Offset: 4, Scale: 16},
	{TailStart: 4, TailEnd: 16, Step: 16, Offset: 6, Scale: 16},
	{TailStart: 4, TailEnd: 16, Step: 16, Offset: 14, Scale: 16},
	{TailStart: 8, TailEnd: 32, Step: 8, Offset: 2, Scale: 15},
	{TailStart: 8, TailEnd: 32, Step: 8, Offset: 3, Scale: 15},
	{TailStart: 8, TailEnd: 32, Step: 8, Offset: 7, Scale: 15},
	{TailStart: 16, TailEnd: 64, Step: 4, Offset: 1, Scale: 14},
}

type encoderVADState struct {
	background [vadBands]int16
	average    [vadBands]int16
	oldLevel   [vadBands]int16
	subLevel   [vadBands]int16
	data5      [5][2]int16
	data3      [6]int16

	burstCount int16
	hangCount  int16
	statCount  int16
	vadReg     int16
	toneFlag   int16

	speechEstimateCount int16
	speechMax           int16
	speechMaxCount      int16
	speechLevel         int16
	prevPowerSum        int32
}

func (s *encoderVADState) reset() {
	*s = encoderVADState{}
	for i := range vadBands {
		s.background[i] = vadNoiseInit
		s.oldLevel[i] = vadNoiseInit
		s.average[i] = vadNoiseInit
	}
	s.speechLevel = vadSpeechLevelInit
}

func (s *encoderVADState) filterBank(input []int16) ([vadBands]int16, error) {
	var level [vadBands]int16
	if len(input) < vadFrameLen {
		return level, errors.New("filter VAD bands: input buffer is too short")
	}
	var tmp [vadFrameLen]int16
	for i := range vadFrameLen {
		tmp[i] = fxp.Shr16(input[i], 1)
	}
	for i := range 128 {
		filtered := filter5(tmp[2*i], tmp[2*i+1], s.data5[0])
		tmp[2*i], tmp[2*i+1] = filtered.low, filtered.high
		s.data5[0] = filtered.memory
	}
	for i := range 64 {
		filtered := filter5(tmp[4*i], tmp[4*i+2], s.data5[1])
		tmp[4*i], tmp[4*i+2] = filtered.low, filtered.high
		s.data5[1] = filtered.memory
		filtered = filter5(tmp[4*i+1], tmp[4*i+3], s.data5[2])
		tmp[4*i+1], tmp[4*i+3] = filtered.low, filtered.high
		s.data5[2] = filtered.memory
	}
	for i := range 32 {
		filtered := filter5(tmp[8*i], tmp[8*i+4], s.data5[3])
		tmp[8*i], tmp[8*i+4] = filtered.low, filtered.high
		s.data5[3] = filtered.memory
		filtered = filter5(tmp[8*i+2], tmp[8*i+6], s.data5[4])
		tmp[8*i+2], tmp[8*i+6] = filtered.low, filtered.high
		s.data5[4] = filtered.memory
		tmp[8*i+3], tmp[8*i+7], s.data3[0] = filter3(tmp[8*i+3], tmp[8*i+7], s.data3[0])
	}
	for i := range 16 {
		tmp[16*i], tmp[16*i+8], s.data3[1] = filter3(tmp[16*i], tmp[16*i+8], s.data3[1])
		tmp[16*i+4], tmp[16*i+12], s.data3[2] = filter3(tmp[16*i+4], tmp[16*i+12], s.data3[2])
		tmp[16*i+6], tmp[16*i+14], s.data3[3] = filter3(tmp[16*i+6], tmp[16*i+14], s.data3[3])
	}
	for i := range 8 {
		tmp[32*i], tmp[32*i+16], s.data3[4] = filter3(tmp[32*i], tmp[32*i+16], s.data3[4])
		tmp[32*i+8], tmp[32*i+24], s.data3[5] = filter3(tmp[32*i+8], tmp[32*i+24], s.data3[5])
	}

	for i, band := range vadLevelBands {
		level[i], s.subLevel[i] = band.Calculate(tmp[:], s.subLevel[i])
	}
	return level, nil
}

func (s *encoderVADState) decide(input []int16) (bool, error) {
	if len(input) < vadFrameLen {
		return false, errors.New("run VAD: input buffer is too short")
	}
	var power int32
	for i := range vadFrameLen {
		power = fxp.Add32(power, fxp.LMult(input[i], input[i]))
	}
	powerSum := fxp.Add32(power, s.prevPowerSum)
	s.prevPowerSum = power
	if powerSum < vadPowerToneThreshold {
		s.toneFlag &= 0x1fff
	}
	level, err := s.filterBank(input)
	if err != nil {
		return false, fmt.Errorf("run VAD: %w", err)
	}
	vad := s.vadDecision(level[:], powerSum)
	var inputLevel int32
	for i := 1; i < vadBands; i++ {
		inputLevel = fxp.Add32(inputLevel, int32(level[i]))
	}
	s.estimateSpeech(extractHighSaturating(int64(inputLevel) << 12))
	return vad, nil
}

func (s *encoderVADState) vadDecision(level []int16, powerSum int32) bool {
	var snrSum int32
	for i := range vadBands {
		exp := norm16(s.background[i])
		denom := fxp.Shl16(s.background[i], exp)
		temp := fxp.DivS(fxp.Shr16(level[i], 1), denom)
		temp = fxp.Shl16(temp, fxp.Sub16(exp, vadUnityShift-1))
		snrSum = fxp.Add32(snrSum, fxp.LMult(temp, temp))
	}

	var noiseSum int32
	for i := 1; i < vadBands; i++ {
		noiseSum = fxp.Add32(noiseSum, int32(s.background[i]))
	}
	noiseLevel := extractHighSaturating(int64(noiseSum) << 12)
	temp := fxp.Shl16(fxp.Mult(noiseLevel, vadMinSpeechSNR), 3)

	s.speechLevel = max(s.speechLevel, temp)

	noiseLog := vadILog2(noiseLevel)
	speechLog := vadILog2(fxp.Sub16(s.speechLevel, temp))

	threshold := fxp.Add16(fxp.Mult(vadNoiseSlope, fxp.Sub16(noiseLog, vadNoisePoint1)), vadThresholdHigh)
	speechChange := fxp.Add16(vadSpeechChangeMin, fxp.Mult(vadSpeechSlope, fxp.Sub16(speechLog, vadSpeechPoint1)))
	speechChange = max(speechChange, vadSpeechChangeMin)
	speechChange = min(speechChange, vadSpeechChangeMax)
	threshold = fxp.Add16(threshold, speechChange)
	threshold = max(threshold, vadThresholdMin)

	s.vadReg >>= 1
	if snrSum > fxp.LMult(threshold, 512*vadBands) {
		s.vadReg |= 0x4000
	}
	lowPower := powerSum < vadPowerLow
	s.noiseEstimateUpdate(level)

	hangLen := max(fxp.Add16(fxp.Mult(vadHangSlope, fxp.Sub16(threshold, vadHangPoint1)), vadHangHigh), vadHangLow)
	burstLen := fxp.Add16(fxp.Mult(vadBurstSlope, fxp.Sub16(threshold, vadBurstPoint1)), vadBurstHigh)
	return s.hangoverAddition(lowPower, hangLen, burstLen)
}

func (s *encoderVADState) updateControl(level []int16) {
	if fxp.Sub16(s.toneFlag&0x7c00, 0x7c00) == 0 || (s.vadReg&0x7f80) == 0 {
		s.statCount = vadStationaryCount
	} else {
		var statRatio int16
		for i := range vadBands {
			num := level[i]
			denom := s.average[i]
			if num < denom {
				num, denom = denom, num
			}

			num = max(num, vadStationaryThresholdLev)

			denom = max(denom, vadStationaryThresholdLev)

			exp := norm16(denom)
			denom = fxp.Shl16(denom, exp)
			temp := fxp.DivS(fxp.Shr16(num, 1), denom)
			statRatio = fxp.Add16(statRatio, fxp.Shr16(temp, fxp.Sub16(8, exp)))
		}
		if statRatio > vadStationaryThreshold {
			s.statCount = vadStationaryCount
		} else if (s.vadReg&0x4000) != 0 && s.statCount != 0 {
			s.statCount--
		}
	}

	alpha := vadAlpha4
	if s.statCount == vadStationaryCount {
		alpha = fxp.Max16
	} else if (s.vadReg & 0x4000) == 0 {
		alpha = vadAlpha5
	}
	for i := range vadBands {
		s.average[i] = fxp.Add16(s.average[i], fxp.MultRound(alpha, fxp.Sub16(level[i], s.average[i])))
	}
}

func (s *encoderVADState) noiseEstimateUpdate(level []int16) {
	s.updateControl(level)
	alphaUp := vadAlphaUp1
	alphaDown := vadAlphaDown1
	backgroundAdd := int16(2)
	if (0x7800 & s.vadReg) != 0 {
		if s.statCount == 0 {
			alphaUp = vadAlphaUp2
			alphaDown = vadAlphaDown2
		} else {
			alphaUp = 0
			alphaDown = vadAlpha3
			backgroundAdd = 0
		}
	}
	for i := range vadBands {
		diff := s.oldLevel[i] - s.background[i]
		if diff < 0 {
			s.background[i] = max(fxp.Add16(-2, fxp.Add16(s.background[i], fxp.MultRound(alphaDown, diff))), vadNoiseMin)
		} else {
			s.background[i] = min(fxp.Add16(backgroundAdd, fxp.Add16(s.background[i], fxp.MultRound(alphaUp, diff))), vadNoiseMax)
		}
		s.oldLevel[i] = level[i]
	}
}

func (s *encoderVADState) hangoverAddition(lowPower bool, hangLen int16, burstLen int16) bool {
	if lowPower {
		s.burstCount = 0
		s.hangCount = 0
		return false
	}
	if (s.vadReg & 0x4000) != 0 {
		s.burstCount++
		if s.burstCount >= burstLen {
			s.hangCount = hangLen
		}
		return true
	}
	s.burstCount = 0
	if s.hangCount > 0 {
		s.hangCount--
		return true
	}
	return false
}

func (s *encoderVADState) estimateSpeech(inputLevel int16) {
	if fxp.Sub16(s.speechEstimateCount, s.speechMaxCount) > fxp.Sub16(vadSpeechEstimateCount, vadSpeechActivityCount) {
		s.speechEstimateCount = 0
		s.speechMax = 0
		s.speechMaxCount = 0
	}
	s.speechEstimateCount++
	if ((s.vadReg&0x4000) != 0 || inputLevel > s.speechLevel) && inputLevel > vadMinSpeechLevel1 {

		s.speechMax = max(s.speechMax, inputLevel)

		s.speechMaxCount++
		if s.speechMaxCount >= vadSpeechActivityCount {
			estimate := fxp.Shr16(s.speechMax, 1)
			alpha := vadAlphaSpeechDown
			if estimate > s.speechLevel {
				alpha = vadAlphaSpeechUp
			}
			if estimate > vadMinSpeechLevel2 {
				s.speechLevel = fxp.Add16(s.speechLevel, fxp.MultRound(alpha, fxp.Sub16(estimate, s.speechLevel)))
			}
			s.speechMax = 0
			s.speechMaxCount = 0
			s.speechEstimateCount = 0
		}
	}
}

func (s *encoderVADState) toneDetection(pitchGain int16) {
	s.toneFlag = fxp.Shr16(s.toneFlag, 1)
	if fxp.Sub16(pitchGain, vadToneThreshold) > 0 {
		s.toneFlag |= 0x4000
	}
}

type filter5Result struct {
	low    int16
	high   int16
	memory [2]int16
}

func filter5(in0 int16, in1 int16, memory [2]int16) filter5Result {
	temp0 := fxp.Sub16(in0, fxp.Mult(vadCoeff51, memory[0]))
	temp1 := fxp.Add16(memory[0], fxp.Mult(vadCoeff51, temp0))
	memory[0] = temp0

	temp0 = fxp.Sub16(in1, fxp.Mult(vadCoeff52, memory[1]))
	temp2 := fxp.Add16(memory[1], fxp.Mult(vadCoeff52, temp0))
	memory[1] = temp0

	return filter5Result{low: halfAdd(temp1, temp2), high: halfSub(temp1, temp2), memory: memory}
}

func filter3(in0 int16, in1 int16, data int16) (int16, int16, int16) {
	temp1 := fxp.Sub16(in1, fxp.Mult(vadCoeff3, data))
	temp2 := fxp.Add16(data, fxp.Mult(vadCoeff3, temp1))
	return halfAdd(in0, temp2), halfSub(in0, temp2), temp1
}

func halfAdd(a int16, b int16) int16 {
	return fxp.Saturate16((int32(a) + int32(b)) >> 1)
}

func halfSub(a int16, b int16) int16 {
	return fxp.Saturate16((int32(a) - int32(b)) >> 1)
}

func extractHighSaturating(value int64) int16 {
	if value > int64(fxp.Max32) {
		return fxp.Max16
	}
	if value < int64(fxp.Min32) {
		return fxp.Min16
	}
	return int16(int32(value) >> 16)
}

func norm16(value int16) int16 {
	return fxp.NormS(value)
}

func vadILog2(mant int16) int16 {
	if mant <= 0 {
		mant = 1
	}
	ex := fxp.NormS(mant)
	mant = fxp.Shl16(mant, ex)

	for range 3 {
		mant = fxp.Mult(mant, mant)
	}
	temp := fxp.LMult(mant, mant)

	ex2 := fxp.NormL(temp)
	mant = fxp.ExtractH(fxp.Shl32(temp, ex2))

	res := fxp.Shl16(fxp.Add16(ex, 16), 10)
	res = fxp.Add16(res, fxp.Shl16(ex2, 6))
	res = fxp.Sub16(fxp.Add16(res, 127), fxp.Shr16(mant, 8))
	return res
}
