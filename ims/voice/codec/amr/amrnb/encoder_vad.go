/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This VAD path is ported from the AMR-NB common/src/vad1.cpp filter bank,
 * background estimate, and hangover decision.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
	amrvad "github.com/damonto/ims-go/ims/voice/codec/amr/vad"
)

const (
	vad1Bands        = 9
	vad1InvBands     = 3641
	vad1UnityShift   = 6
	vad1NoiseInit    = 150
	vad1NoiseMin     = 40
	vad1NoiseMax     = 16000
	vad1AlphaUp1     = 1638
	vad1AlphaDown1   = 2097
	vad1AlphaUp2     = 491
	vad1AlphaDown2   = 1867
	vad1Alpha3       = 1638
	vad1Alpha4       = 3276
	vad1Alpha5       = 16383
	vad1ThresholdHi  = 1260
	vad1ThresholdLo  = 720
	vad1Slope        = -2810
	vad1StatCount    = 20
	vad1StatLevel    = 184
	vad1StatThresh   = 1000
	vad1ToneThresh   = 21298
	vad1HangNoise    = 100
	vad1BurstHi      = 4
	vad1HangHi       = 7
	vad1BurstLo      = 5
	vad1HangLo       = 4
	vad1PowerLow     = 15000
	vad1PowerPitch   = 343040
	vad1PowerComplex = 15000
	vad1Coeff3       = 13363
	vad1Coeff51      = 21955
	vad1Coeff52      = 6390
	vad1CADMinStat   = 5

	vad1ComplexAdaptHigh       = 19660
	vad1ComplexAdaptLow        = 16383
	vad1ComplexInNoise         = 21298
	vad1ComplexHangThreshold   = 22936
	vad1ComplexHangLimit       = 100
	vad1ComplexHangLength      = 250
	vad1ComplexLowPowerReset   = 13106
	vad1ComplexMinCorrelation  = 13106
	vad1ComplexAdaptSlow       = 655
	vad1ComplexAdaptFast       = 2621
	vad1ComplexAdaptReallyFast = 6553
)

var vad1LevelBands = [...]amrvad.LevelBand{
	{TailStart: FrameSamples/16 - 2, TailEnd: FrameSamples / 16, Step: 16, Offset: 0, Scale: 16},
	{TailStart: FrameSamples/16 - 2, TailEnd: FrameSamples / 16, Step: 16, Offset: 8, Scale: 16},
	{TailStart: FrameSamples/16 - 2, TailEnd: FrameSamples / 16, Step: 16, Offset: 12, Scale: 16},
	{TailStart: FrameSamples/16 - 2, TailEnd: FrameSamples / 16, Step: 16, Offset: 4, Scale: 16},
	{TailStart: FrameSamples/8 - 4, TailEnd: FrameSamples / 8, Step: 8, Offset: 6, Scale: 16},
	{TailStart: FrameSamples/8 - 4, TailEnd: FrameSamples / 8, Step: 8, Offset: 2, Scale: 16},
	{TailStart: FrameSamples/8 - 4, TailEnd: FrameSamples / 8, Step: 8, Offset: 3, Scale: 16},
	{TailStart: FrameSamples/8 - 4, TailEnd: FrameSamples / 8, Step: 8, Offset: 7, Scale: 16},
	{TailStart: FrameSamples/4 - 8, TailEnd: FrameSamples / 4, Step: 4, Offset: 1, Scale: 15},
}

type encoderVADState struct {
	background [vad1Bands]int16
	average    [vad1Bands]int16
	oldLevel   [vad1Bands]int16
	subLevel   [vad1Bands]int16
	data5      [3][2]int16
	data3      [5]int16

	burstCount  int16
	hangCount   int16
	statCount   int16
	vadReg      int16
	pitch       int16
	tone        int16
	oldLag      int16
	oldLagCount int16

	complexHigh      int16
	complexLow       int16
	complexHangCount int16
	complexHangTimer int16
	bestCorrHP       int16
	corrHPFast       int16
	complexWarning   int16
}

func (s *encoderVADState) reset() {
	*s = encoderVADState{}
	for i := range vad1Bands {
		s.background[i] = vad1NoiseInit
		s.average[i] = vad1NoiseInit
		s.oldLevel[i] = vad1NoiseInit
	}
	s.bestCorrHP = vad1ComplexLowPowerReset
	s.corrHPFast = vad1ComplexLowPowerReset
}

func (s *encoderVADState) activeWithPower(pcm []int16, powerPCM []int16) (bool, error) {
	if len(pcm) != FrameSamples {
		return false, fmt.Errorf(
			"detecting AMR-NB voice activity: pcm sample count %d, want %d",
			len(pcm),
			FrameSamples,
		)
	}
	if len(powerPCM) != FrameSamples {
		return false, fmt.Errorf(
			"detecting AMR-NB voice activity: power sample count %d, want %d",
			len(powerPCM),
			FrameSamples,
		)
	}

	var power int32
	for i := range FrameSamples {
		power = fxp.LMac(power, powerPCM[i], powerPCM[i])
	}
	if power < vad1PowerPitch {
		s.pitch &= 0x3fff
	}
	if power < vad1PowerComplex {
		s.complexLow &= 0x3fff
	}

	var level [vad1Bands]int16
	s.filterBank(pcm, level[:])
	return s.decision(level[:], power), nil
}

func (s *encoderVADState) filterBank(input []int16, level []int16) {
	tmp, firstStageState := vad1FirstFilterStage(input, s.data5[0])
	s.data5[0] = firstStageState
	for i := range FrameSamples / 4 {
		tmp[4*i], tmp[4*i+2] = vad1Filter5(tmp[4*i], tmp[4*i+2], s.data5[1][:])
		tmp[4*i+1], tmp[4*i+3] = vad1Filter5(tmp[4*i+1], tmp[4*i+3], s.data5[2][:])
	}
	for i := range FrameSamples / 8 {
		tmp[8*i], tmp[8*i+4], s.data3[0] = vad1Filter3(tmp[8*i], tmp[8*i+4], s.data3[0])
		tmp[8*i+2], tmp[8*i+6], s.data3[1] = vad1Filter3(tmp[8*i+2], tmp[8*i+6], s.data3[1])
		tmp[8*i+3], tmp[8*i+7], s.data3[4] = vad1Filter3(tmp[8*i+3], tmp[8*i+7], s.data3[4])
	}
	for i := range FrameSamples / 16 {
		tmp[16*i], tmp[16*i+8], s.data3[2] = vad1Filter3(tmp[16*i], tmp[16*i+8], s.data3[2])
		tmp[16*i+4], tmp[16*i+12], s.data3[3] = vad1Filter3(tmp[16*i+4], tmp[16*i+12], s.data3[3])
	}

	for i, band := range vad1LevelBands {
		level[i], s.subLevel[i] = band.Calculate(tmp[:], s.subLevel[i])
	}
}

func vad1FirstFilterStage(input []int16, data [2]int16) ([FrameSamples]int16, [2]int16) {
	var out [FrameSamples]int16
	data0 := data[0]
	data1 := data[1]
	for i := range FrameSamples / 4 {
		temp0 := fxp.Sub16(fxp.Shr16(input[4*i], 2), fxp.Mult(vad1Coeff51, data0))
		temp1 := fxp.Add16(data0, fxp.Mult(vad1Coeff51, temp0))

		temp3 := fxp.Sub16(fxp.Shr16(input[4*i+1], 2), fxp.Mult(vad1Coeff52, data1))
		temp2 := fxp.Add16(data1, fxp.Mult(vad1Coeff52, temp3))

		out[4*i] = fxp.Add16(temp1, temp2)
		out[4*i+1] = fxp.Sub16(temp1, temp2)

		data0 = fxp.Sub16(fxp.Shr16(input[4*i+2], 2), fxp.Mult(vad1Coeff51, temp0))
		temp1 = fxp.Add16(temp0, fxp.Mult(vad1Coeff51, data0))

		data1 = fxp.Sub16(fxp.Shr16(input[4*i+3], 2), fxp.Mult(vad1Coeff52, temp3))
		temp2 = fxp.Add16(temp3, fxp.Mult(vad1Coeff52, data1))

		out[4*i+2] = fxp.Add16(temp1, temp2)
		out[4*i+3] = fxp.Sub16(temp1, temp2)
	}
	return out, [2]int16{data0, data1}
}

func (s *encoderVADState) decision(level []int16, power int32) bool {
	var snrEnergy int32
	for i := range vad1Bands {
		exp := fxp.NormS(s.background[i])
		denom := fxp.Shl16(s.background[i], exp)
		temp := fxp.DivS(fxp.Shr16(level[i], 1), denom)
		temp = fxp.Shl16(temp, fxp.Sub16(exp, vad1UnityShift-1))
		snrEnergy = fxp.LMac(snrEnergy, temp, temp)
	}
	snrSum := fxp.Mult(fxp.ExtractH(fxp.Shl32(snrEnergy, 6)), vad1InvBands)

	var noiseSum int32
	for i := range vad1Bands {
		noiseSum = fxp.Add32(noiseSum, int32(s.background[i]))
	}
	noiseLevel := fxp.ExtractH(fxp.Shl32(noiseSum, 13))

	threshold := fxp.Add16(fxp.Mult(vad1Slope, noiseLevel), vad1ThresholdHi)

	threshold = max(threshold, vad1ThresholdLo)

	s.vadReg = fxp.Shr16(s.vadReg, 1)
	if snrSum > threshold {
		s.vadReg |= 0x4000
	}

	lowPower := power < vad1PowerLow
	s.complexEstimateAdapt(lowPower)
	s.complexWarning = s.complexVAD(lowPower)
	s.noiseEstimateUpdate(level)
	return s.hangoverAddition(noiseLevel, lowPower)
}

func (s *encoderVADState) updateControl(level []int16) {
	if s.complexWarning != 0 && s.statCount < vad1CADMinStat {
		s.statCount = vad1CADMinStat
	}
	if (s.pitch&0x6000) == 0x6000 || (s.tone&0x7c00) == 0x7c00 || (s.vadReg&0x7f80) == 0 {
		s.statCount = vad1StatCount
	} else {
		var statRatio int16
		for i := range vad1Bands {
			num := level[i]
			denom := s.average[i]
			if num < denom {
				num, denom = denom, num
			}

			num = max(num, vad1StatLevel)

			denom = max(denom, vad1StatLevel)

			exp := fxp.NormS(denom)
			denom = fxp.Shl16(denom, exp)
			temp := fxp.DivS(fxp.Shr16(num, 1), denom)
			statRatio = fxp.Add16(statRatio, fxp.Shr16(temp, fxp.Sub16(8, exp)))
		}
		if statRatio > vad1StatThresh {
			s.statCount = vad1StatCount
		} else if (s.vadReg&0x4000) != 0 && s.statCount != 0 {
			s.statCount--
		}
	}

	alpha := int16(vad1Alpha4)
	if s.statCount == vad1StatCount {
		alpha = fxp.Max16
	} else if (s.vadReg & 0x4000) == 0 {
		alpha = vad1Alpha5
	}
	for i := range vad1Bands {
		s.average[i] = fxp.Add16(s.average[i], fxp.MultRound(alpha, fxp.Sub16(level[i], s.average[i])))
	}
}

func (s *encoderVADState) noiseEstimateUpdate(level []int16) {
	s.updateControl(level)

	alphaUp := int16(vad1AlphaUp1)
	alphaDown := int16(vad1AlphaDown1)
	backgroundAdd := int16(2)
	if (s.vadReg&0x7800) == 0 && (s.pitch&0x7800) == 0 && s.complexHangCount == 0 {
		alphaUp = vad1AlphaUp1
		alphaDown = vad1AlphaDown1
	} else {
		if s.statCount == 0 && s.complexHangCount == 0 {
			alphaUp = vad1AlphaUp2
			alphaDown = vad1AlphaDown2
		} else {
			alphaUp = 0
			alphaDown = vad1Alpha3
			backgroundAdd = 0
		}
	}
	for i := range vad1Bands {
		diff := fxp.Sub16(s.oldLevel[i], s.background[i])
		if diff < 0 {
			next := fxp.Add16(s.background[i], fxp.MultRound(alphaDown, diff))
			s.background[i] = fxp.Add16(-2, next)
			s.background[i] = max(s.background[i], vad1NoiseMin)
		} else {
			next := fxp.Add16(s.background[i], fxp.MultRound(alphaUp, diff))
			s.background[i] = fxp.Add16(backgroundAdd, next)
			s.background[i] = min(s.background[i], vad1NoiseMax)
		}
		s.oldLevel[i] = level[i]
	}
}

func (s *encoderVADState) hangoverAddition(noiseLevel int16, lowPower bool) bool {
	burstLen := int16(vad1BurstLo)
	hangLen := int16(vad1HangLo)
	if noiseLevel > vad1HangNoise {
		burstLen = vad1BurstHi
		hangLen = vad1HangHi
	}

	if lowPower {
		s.burstCount = 0
		s.hangCount = 0
		s.complexHangCount = 0
		s.complexHangTimer = 0
		return false
	}
	if s.complexHangTimer > vad1ComplexHangLimit && s.complexHangCount < vad1ComplexHangLength {
		s.complexHangCount = vad1ComplexHangLength
	}
	if s.complexHangCount != 0 {
		s.burstCount = vad1BurstHi
		s.complexHangCount--
		return true
	}
	if (s.vadReg&0x3ff0) == 0 && s.corrHPFast > vad1ComplexInNoise {
		return true
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

func (s *encoderVADState) pitchDetection(lags []int16) {
	var lagCount int16
	for i := 0; i < 2 && i < len(lags); i++ {
		if fxp.Abs16(fxp.Sub16(s.oldLag, lags[i])) < 4 {
			lagCount++
		}
		s.oldLag = lags[i]
	}

	s.pitch = fxp.Shr16(s.pitch, 1)
	if fxp.Add16(s.oldLagCount, lagCount) >= 4 {
		s.pitch |= 0x4000
	}
	s.oldLagCount = lagCount
}

func (s *encoderVADState) toneDetectionUpdate(oneLagPerFrame bool) {
	s.tone = fxp.Shr16(s.tone, 1)
	if oneLagPerFrame {
		s.tone = fxp.Shr16(s.tone, 1)
		s.tone |= 0x2000
	}
}

func (s *encoderVADState) toneDetection(correlation int32, energy int32) {
	energyRounded := fxp.Round(energy)
	if energyRounded > 0 && fxp.LMsu(correlation, energyRounded, vad1ToneThresh) > 0 {
		s.tone |= 0x4000
	}
}

func (s *encoderVADState) complexDetectionUpdate(bestCorrHP int16) {
	s.bestCorrHP = bestCorrHP
}

func (s *encoderVADState) complexEstimateAdapt(lowPower bool) {
	alpha := int16(vad1ComplexAdaptFast)
	if s.bestCorrHP < s.corrHPFast {
		if s.corrHPFast >= vad1ComplexAdaptHigh {
			alpha = vad1ComplexAdaptReallyFast
		}
	} else if s.corrHPFast >= vad1ComplexAdaptHigh {
		alpha = vad1ComplexAdaptSlow
	}

	acc := fxp.Shl32(int32(s.corrHPFast), 16)
	acc = fxp.LMsu(acc, alpha, s.corrHPFast)
	acc = fxp.LMac(acc, alpha, s.bestCorrHP)
	s.corrHPFast = fxp.Round(acc)

	s.corrHPFast = max(s.corrHPFast, vad1ComplexMinCorrelation)

	if lowPower {
		s.corrHPFast = vad1ComplexMinCorrelation
	}
}

func (s *encoderVADState) complexVAD(lowPower bool) int16 {
	s.complexHigh = fxp.Shr16(s.complexHigh, 1)
	s.complexLow = fxp.Shr16(s.complexLow, 1)
	if !lowPower {
		if s.corrHPFast > vad1ComplexAdaptHigh {
			s.complexHigh |= 0x4000
		}
		if s.corrHPFast > vad1ComplexAdaptLow {
			s.complexLow |= 0x4000
		}
	}
	if s.corrHPFast > vad1ComplexHangThreshold {
		s.complexHangTimer++
	} else {
		s.complexHangTimer = 0
	}
	if (s.complexHigh&0x7f80) == 0x7f80 || (s.complexLow&0x7fff) == 0x7fff {
		return 1
	}
	return 0
}

func vad1Filter5(in0 int16, in1 int16, data []int16) (int16, int16) {
	temp0 := fxp.Sub16(in0, fxp.Mult(vad1Coeff51, data[0]))
	temp1 := fxp.Add16(data[0], fxp.Mult(vad1Coeff51, temp0))
	data[0] = temp0

	temp0 = fxp.Sub16(in1, fxp.Mult(vad1Coeff52, data[1]))
	temp2 := fxp.Add16(data[1], fxp.Mult(vad1Coeff52, temp0))
	data[1] = temp0

	return vad1HalfAdd(temp1, temp2), vad1HalfSub(temp1, temp2)
}

func vad1Filter3(in0 int16, in1 int16, data int16) (int16, int16, int16) {
	temp1 := fxp.Sub16(in1, fxp.Mult(vad1Coeff3, data))
	temp2 := fxp.Add16(data, fxp.Mult(vad1Coeff3, temp1))
	return vad1HalfAdd(in0, temp2), vad1HalfSub(in0, temp2), temp1
}

func vad1HalfAdd(a int16, b int16) int16 {
	return fxp.Saturate16((int32(a) + int32(b)) >> 1)
}

func vad1HalfSub(a int16, b int16) int16 {
	return fxp.Saturate16((int32(a) - int32(b)) >> 1)
}
