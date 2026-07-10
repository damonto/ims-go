/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This VAD option 2 path is ported from amr_nb/common/src/vad2.cpp and
 * common/src/r_fft.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	vad2FrameLen = 80
	vad2Delay    = 24
	vad2FFTLen   = 128
	vad2Channels = 16

	vad2UpdateThreshold    = 35
	vad2HysterCountThresh  = 6
	vad2UpdateCountThresh  = 50
	vad2NoiseFloorChan0    = 512
	vad2MinChanEnergy0     = 32
	vad2MinNoiseEnergy0    = 32
	vad2InitialNoise0      = 8192
	vad2FractionalBits0    = 9
	vad2NoiseFloorChan1    = 16
	vad2MinChanEnergy1     = 1
	vad2InitialNoise1      = 256
	vad2FractionalBits1    = 4
	vad2HighAlpha          = 29491
	vad2LowAlpha           = 22938
	vad2AlphaRange         = vad2HighAlpha - vad2LowAlpha
	vad2DeviationThreshold = 7168
	vad2PreEmphasis        = -26214
	vad2EnergySmooth       = 18022
	vad2OneMinusEnergy     = 14746
	vad2NoiseSmooth        = 3277
	vad2OneMinusNoise      = 29491
	vad2FFTHeadroom        = 2
)

var vad2ChannelTable = [vad2Channels][2]int16{
	{2, 3}, {4, 5}, {6, 7}, {8, 9},
	{10, 11}, {12, 13}, {14, 16}, {17, 19},
	{20, 22}, {23, 26}, {27, 30}, {31, 35},
	{36, 41}, {42, 48}, {49, 55}, {56, 63},
}

var vad2ChannelScale = [vad2Channels]int16{
	16384, 16384, 16384, 16384, 16384, 16384, 10923, 10923,
	10923, 8192, 8192, 6554, 5461, 4681, 4681, 4096,
}

var vad2VoiceMetric = [...]int16{
	2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
	2, 3, 3, 3, 3, 3, 4, 4, 4, 5,
	5, 5, 6, 6, 7, 7, 7, 8, 8, 9,
	9, 10, 10, 11, 12, 12, 13, 13, 14, 15,
	15, 16, 17, 17, 18, 19, 20, 20, 21, 22,
	23, 24, 24, 25, 26, 27, 28, 28, 29, 30,
	31, 32, 33, 34, 35, 36, 37, 37, 38, 39,
	40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
	50, 50, 50, 50, 50, 50, 50, 50, 50, 50,
}

var vad2HangoverTable = [...]int16{
	30, 30, 30, 30, 30, 30, 28, 26, 24, 22,
	20, 18, 16, 14, 12, 10, 8, 8, 8, 8,
}

var vad2BurstcountTable = [...]int16{
	8, 8, 8, 8, 8, 8, 8, 8, 7, 6,
	5, 4, 4, 4, 4, 4, 4, 4, 4, 4,
}

var vad2ThresholdTable = [...]int16{
	34, 34, 34, 34, 34, 34, 34, 34, 34, 34,
	34, 40, 51, 71, 100, 139, 191, 257, 337, 432,
}

var vad2PhaseTable = [...]int16{
	32767, 0, 32729, -1608, 32610, -3212, 32413, -4808,
	32138, -6393, 31786, -7962, 31357, -9512, 30853, -11039,
	30274, -12540, 29622, -14010, 28899, -15447, 28106, -16846,
	27246, -18205, 26320, -19520, 25330, -20788, 24279, -22006,
	23170, -23170, 22006, -24279, 20788, -25330, 19520, -26320,
	18205, -27246, 16846, -28106, 15447, -28899, 14010, -29622,
	12540, -30274, 11039, -30853, 9512, -31357, 7962, -31786,
	6393, -32138, 4808, -32413, 3212, -32610, 1608, -32729,
	0, -32768, -1608, -32729, -3212, -32610, -4808, -32413,
	-6393, -32138, -7962, -31786, -9512, -31357, -11039, -30853,
	-12540, -30274, -14010, -29622, -15447, -28899, -16846, -28106,
	-18205, -27246, -19520, -26320, -20788, -25330, -22006, -24279,
	-23170, -23170, -24279, -22006, -25330, -20788, -26320, -19520,
	-27246, -18205, -28106, -16846, -28899, -15447, -29622, -14010,
	-30274, -12540, -30853, -11039, -31357, -9512, -31786, -7962,
	-32138, -6393, -32413, -4808, -32610, -3212, -32729, -1608,
}

var vad2IITable = [...]int16{64, 32, 16, 8, 4, 2}

type encoderVAD2State struct {
	preEmpMem      int16
	updateCount    int16
	hysterCount    int16
	lastUpdate     int16
	chEnergyLongDB [vad2Channels]int16
	frameCount     int32
	chEnergy       [vad2Channels]int32
	chNoise        [vad2Channels]int32
	lastNormShift  int16
	tsnr           int16
	hangover       int16
	burstCount     int16
	forceUpdate    int16
	negSNRVar      int16
	negSNRBias     int16
	shiftState     int16
	r0             int32
	rmax           int32
	ltpFlag        int16
}

func (s *encoderVAD2State) reset() {
	*s = encoderVAD2State{}
}

func (s *encoderVAD2State) active(pcm []int16) (bool, error) {
	if len(pcm) != FrameSamples {
		return false, fmt.Errorf(
			"detecting AMR-NB voice activity with VAD2: pcm sample count %d, want %d",
			len(pcm),
			FrameSamples,
		)
	}
	first := s.activeHalf(pcm[:vad2FrameLen])
	second := s.activeHalf(pcm[vad2FrameLen:FrameSamples])
	return first || second, nil
}

func (s *encoderVAD2State) activeHalf(input []int16) bool {
	noiseFloor := [2]int32{vad2NoiseFloorChan0, vad2NoiseFloorChan1}
	minChanEnergy := [2]int32{vad2MinChanEnergy0, vad2MinChanEnergy1}
	initialNoise := [2]int32{vad2InitialNoise0, vad2InitialNoise1}
	fbits := [2]int16{vad2FractionalBits0, vad2FractionalBits1}
	stateShift := [2]int16{vad2FractionalBits1 - vad2FractionalBits0, vad2FractionalBits0 - vad2FractionalBits1}
	energyNormShift := [2]int16{vad2FractionalBits0 - 1 + 2, vad2FractionalBits1 - 1 + 2}

	s.frameCount = fxp.Add32(s.frameCount, 1)

	normalized, normShift := vad2BlockNorm(input, vad2FFTHeadroom)

	var data [vad2FFTLen]int16
	s.preEmpMem = fxp.ShrRound16(s.preEmpMem, fxp.Sub16(s.lastNormShift, normShift))
	s.lastNormShift = normShift
	data[vad2Delay] = fxp.Add16(normalized[0], fxp.Mult(vad2PreEmphasis, s.preEmpMem))
	for i, j := vad2Delay+1, 1; i < vad2Delay+vad2FrameLen; i, j = i+1, j+1 {
		data[i] = fxp.Add16(normalized[j], fxp.Mult(vad2PreEmphasis, normalized[j-1]))
	}
	s.preEmpMem = normalized[vad2FrameLen-1]

	vad2RFFT(data[:])

	stateChange := false
	if s.shiftState == 0 {
		if normShift <= -vad2FFTHeadroom+2 {
			stateChange = true
			s.shiftState = 1
		}
	} else if normShift >= -vad2FFTHeadroom+5 {
		stateChange = true
		s.shiftState = 0
	}
	if stateChange {
		for i := range vad2Channels {
			s.chEnergy[i] = fxp.Shr32(s.chEnergy[i], stateShift[s.shiftState])
		}
	}

	alpha := int16(vad2EnergySmooth)
	oneMinusAlpha := int16(vad2OneMinusEnergy)
	if s.frameCount == 1 {
		alpha = fxp.Max16
		oneMinusAlpha = 0
	}
	for i := range vad2Channels {
		var energy int32
		for j := vad2ChannelTable[i][0]; j <= vad2ChannelTable[i][1]; j++ {
			energy = fxp.LMac(energy, data[2*j], data[2*j])
			energy = fxp.LMac(energy, data[2*j+1], data[2*j+1])
		}
		shift := fxp.Sub16(fxp.Shl16(normShift, 1), energyNormShift[s.shiftState])
		energy = fxp.ShrRound32(energy, shift)

		tmp := fxp.Mult(alpha, vad2ChannelScale[i])
		hi, lo := fxp.LExtract(energy)
		cur := fxp.Mpy32By16(hi, lo, tmp)
		hi, lo = fxp.LExtract(s.chEnergy[i])
		prev := fxp.Mpy32By16(hi, lo, oneMinusAlpha)
		s.chEnergy[i] = fxp.Add32(cur, prev)
		s.chEnergy[i] = max(s.chEnergy[i], minChanEnergy[s.shiftState])
	}

	var totalEnergy int32
	for i := range vad2Channels {
		totalEnergy = fxp.Add32(totalEnergy, s.chEnergy[i])
	}

	var peak int32
	for i := 2; i < vad2Channels; i++ {
		if fxp.Sub32(s.chEnergy[i], peak) > 0 {
			peak = s.chEnergy[i]
		}
	}
	hi, lo := fxp.LExtract(totalEnergy)
	p2aFlag := fxp.Sub32(peak, fxp.Mpy32By16(hi, lo, 20480)) > 0

	if s.frameCount <= 4 {
		for i := range vad2Channels {
			switch {
			case p2aFlag:
				s.chNoise[i] = vad2InitialNoise0
			case s.chEnergy[i] < initialNoise[s.shiftState]:
				s.chNoise[i] = vad2InitialNoise0
			case s.shiftState == 1:
				s.chNoise[i] = fxp.Shr32(s.chEnergy[i], stateShift[0])
			default:
				s.chNoise[i] = s.chEnergy[i]
			}
		}
	}

	var chSNR [vad2Channels]int16
	var chEnergyDB [vad2Channels]int16
	var vmSum int16
	for i := range vad2Channels {
		chEnergyDB[i] = vad2Log10(s.chEnergy[i], fbits[s.shiftState])
		noiseDB := vad2Log10(s.chNoise[i], vad2FractionalBits0)
		chSNR[i] = fxp.Sub16(chEnergyDB[i], noiseDB)
		tmp := fxp.Mult(21845, chSNR[i])
		snrq := fxp.ShrRound16(tmp, 6)
		index := int16(0)
		if snrq < 89 {
			if snrq > 0 {
				index = snrq
			}
		} else {
			index = 89
		}
		vmSum = fxp.Add16(vmSum, vad2VoiceMetric[index])
	}

	var xt int16
	if s.frameCount <= 4 || s.forceUpdate != 0 {
		tceDB := int16(14320)
		s.negSNRVar = 0
		s.negSNRBias = 0
		var totalNoise int32
		for i := range vad2Channels {
			totalNoise = fxp.Add32(totalNoise, s.chNoise[i])
		}
		noiseDB := vad2Log10(totalNoise, vad2FractionalBits0)
		xt = fxp.Sub16(tceDB, noiseDB)
		s.tsnr = xt
	} else {
		var sum int32
		for i := range vad2Channels {
			power := fxp.LMult(chSNR[i], 10885)
			power = fxp.Shr32(power, 8)
			hi, lo := fxp.LExtract(power)
			hi = fxp.Add16(hi, 3)
			sum = fxp.Add32(sum, pow2Value(hi, lo))
		}
		xt = vad2Log10(sum, 7)
		if xt > s.tsnr {
			a := fxp.LMult(29491, s.tsnr)
			b := fxp.LMult(3277, xt)
			s.tsnr = fxp.Round(fxp.Add32(a, b))
		} else {
			tmp := fxp.Sub16(xt, fxp.Mult(20480, s.tsnr))
			if tmp > 0 {
				a := fxp.LMult(32702, s.tsnr)
				b := fxp.LMult(66, xt)
				s.tsnr = fxp.Round(fxp.Add32(a, b))
			}
		}
	}

	tsnrq := fxp.Shr16(fxp.Mult(s.tsnr, 10923), 8)
	tsnrq = min(max(tsnrq, 0), 19)

	if xt < 0 {
		tmp32 := fxp.LMult(xt, xt)
		tmp32 = fxp.Shl32(tmp32, 7)
		tmp := fxp.Round(tmp32)
		a := fxp.LMult(32440, s.negSNRVar)
		b := fxp.LMult(328, tmp)
		s.negSNRVar = fxp.Round(fxp.Add32(a, b))

		s.negSNRVar = min(s.negSNRVar, 1024)

		tmp = fxp.Sub16(s.negSNRVar, 166)
		tmp = fxp.Shl16(tmp, 4)
		tmp = fxp.MultRound(tmp, 24576)
		if tmp < 0 {
			s.negSNRBias = 0
		} else {
			s.negSNRBias = fxp.Shr16(tmp, 8)
		}
	}

	threshold := fxp.Add16(vad2ThresholdTable[tsnrq], s.negSNRBias)
	active := false
	if vmSum > threshold {
		active = true
		s.burstCount = fxp.Add16(s.burstCount, 1)
		if s.burstCount > vad2BurstcountTable[tsnrq] {
			s.hangover = vad2HangoverTable[tsnrq]
		}
	} else {
		s.burstCount = 0
		s.hangover = fxp.Sub16(s.hangover, 1)
		if s.hangover <= 0 {
			s.hangover = 0
		} else {
			active = true
		}
	}

	var energyDeviation int16
	if s.frameCount == 1 {
		copy(s.chEnergyLongDB[:], chEnergyDB[:])
	} else {
		for i := range vad2Channels {
			diff := fxp.Abs16(fxp.Sub16(s.chEnergyLongDB[i], chEnergyDB[i]))
			energyDeviation = fxp.Add16(energyDeviation, diff)
		}
	}

	tmp := fxp.Sub16(s.tsnr, xt)
	switch {
	case tmp <= 0 || s.tsnr <= 0:
		alpha = vad2HighAlpha
		oneMinusAlpha = 32768 - vad2HighAlpha
	case tmp > s.tsnr:
		alpha = vad2LowAlpha
		oneMinusAlpha = 32768 - vad2LowAlpha
	default:
		tmp = fxp.DivS(tmp, s.tsnr)
		tmp = fxp.Mult(vad2AlphaRange, tmp)
		alpha = fxp.Sub16(vad2HighAlpha, tmp)
		oneMinusAlpha = fxp.Sub16(fxp.Max16, alpha)
	}
	for i := range vad2Channels {
		a := fxp.LMult(oneMinusAlpha, chEnergyDB[i])
		b := fxp.LMult(alpha, s.chEnergyLongDB[i])
		s.chEnergyLongDB[i] = fxp.Round(fxp.Add32(a, b))
	}

	update := false
	s.forceUpdate = 0
	if vmSum <= vad2UpdateThreshold {
		if s.burstCount == 0 {
			update = true
			s.updateCount = 0
		}
	} else if fxp.Sub32(totalEnergy, noiseFloor[s.shiftState]) > 0 {
		if energyDeviation < vad2DeviationThreshold && !p2aFlag && s.ltpFlag == 0 {
			s.updateCount = fxp.Add16(s.updateCount, 1)
			if s.updateCount >= vad2UpdateCountThresh {
				update = true
				s.forceUpdate = 1
			}
		}
	}
	if s.updateCount == s.lastUpdate {
		s.hysterCount = fxp.Add16(s.hysterCount, 1)
	} else {
		s.hysterCount = 0
	}
	s.lastUpdate = s.updateCount
	if s.hysterCount > vad2HysterCountThresh {
		s.updateCount = 0
	}

	if update {
		shift := int16(0)
		if s.shiftState == 1 {
			shift = stateShift[0]
		}
		for i := range vad2Channels {
			energy := fxp.Shr32(s.chEnergy[i], shift)
			hi, lo := fxp.LExtract(energy)
			cur := fxp.Mpy32By16(hi, lo, vad2NoiseSmooth)
			hi, lo = fxp.LExtract(s.chNoise[i])
			prev := fxp.Mpy32By16(hi, lo, vad2OneMinusNoise)
			s.chNoise[i] = fxp.Add32(cur, prev)
			if s.chNoise[i] <= vad2MinNoiseEnergy0 {
				s.chNoise[i] = vad2MinNoiseEnergy0
			}
		}
	}

	return active
}

func (s *encoderVAD2State) resetPitchCorrelation() {
	s.rmax = 0
	s.r0 = 0
}

func (s *encoderVAD2State) addPitchCorrelation(correlation, energy int32) {
	s.rmax = fxp.Add32(s.rmax, correlation)
	s.r0 = fxp.Add32(s.r0, energy)
}

func (s *encoderVAD2State) updateLTPFlag(mode Mode) {
	thresh := int16(21299)
	switch mode {
	case Mode475, Mode515:
		thresh = 18022
	case Mode1020:
		thresh = 19660
	}
	hi, lo := fxp.LExtract(s.r0)
	limit := fxp.Mpy32By16(hi, lo, thresh)
	if s.rmax > limit {
		s.ltpFlag = 1
	} else {
		s.ltpFlag = 0
	}
}

func vad2Log10(input int32, fractionalBits int16) int16 {
	integer, fraction := log2Value(input)
	integer = fxp.Sub16(integer, fractionalBits)
	out := fxp.Mpy32By16(integer, fraction, 24660)
	return int16(fxp.ShrRound32(out, 6))
}

func vad2BlockNorm(input []int16, headroom int16) ([vad2FrameLen]int16, int16) {
	var output [vad2FrameLen]int16
	maxAbs := fxp.Abs16(input[0])
	for i := 1; i < vad2FrameLen; i++ {
		if abs := fxp.Abs16(input[i]); abs > maxAbs {
			maxAbs = abs
		}
	}
	var shift int16
	if maxAbs != 0 {
		shift = fxp.Sub16(fxp.NormS(maxAbs), headroom)
		for i := range vad2FrameLen {
			output[i] = fxp.Shl16(input[i], shift)
		}
	} else {
		shift = fxp.Sub16(16, headroom)
	}
	return output, shift
}

func vad2CFFT(data []int16) {
	for i, j := int16(0), int16(0); i < vad2FFTLen-2; i += 2 {
		if j > i {
			data[i], data[j] = data[j], data[i]
			data[i+1], data[j+1] = data[j+1], data[i+1]
		}
		k := int16(vad2FFTLen / 2)
		for j >= k {
			j = fxp.Sub16(j, k)
			k = fxp.Shr16(k, 1)
		}
		j = fxp.Add16(j, k)
	}

	for stage := int16(0); stage < 6; stage++ {
		jj := fxp.Shl16(2, stage)
		kk := fxp.Shl16(jj, 1)
		ii := vad2IITable[stage]
		ii2 := fxp.Shl16(ii, 1)
		phase := int16(0)
		for j := int16(0); j < jj; j += 2 {
			for k := j; k < vad2FFTLen; k = fxp.Add16(k, kk) {
				bottom := fxp.Add16(k, jj)
				real := fxp.LMult(data[bottom], vad2PhaseTable[phase])
				real = fxp.LMsu(real, data[bottom+1], vad2PhaseTable[phase+1])
				imag := fxp.LMult(data[bottom+1], vad2PhaseTable[phase])
				imag = fxp.LMac(imag, data[bottom], vad2PhaseTable[phase+1])
				tmpReal := fxp.Round(real)
				tmpImag := fxp.Round(imag)

				tmp := fxp.Sub16(data[k], tmpReal)
				data[bottom] = fxp.Shr16(tmp, 1)
				tmp = fxp.Sub16(data[k+1], tmpImag)
				data[bottom+1] = fxp.Shr16(tmp, 1)
				tmp = fxp.Add16(data[k], tmpReal)
				data[k] = fxp.Shr16(tmp, 1)
				tmp = fxp.Add16(data[k+1], tmpImag)
				data[k+1] = fxp.Shr16(tmp, 1)
			}
			phase = fxp.Add16(phase, ii2)
		}
	}
}

func vad2RFFT(data []int16) {
	vad2CFFT(data)

	firstReal := data[0]
	secondReal := data[1]
	data[0] = fxp.Add16(firstReal, secondReal)
	data[1] = fxp.Sub16(firstReal, secondReal)

	for i, j := int16(2), int16(vad2FFTLen-2); i <= vad2FFTLen/2; i, j = i+2, vad2FFTLen-(i+2) {
		real1 := fxp.Add16(data[i], data[j])
		imag1 := fxp.Sub16(data[i+1], data[j+1])
		real2 := fxp.Add16(data[i+1], data[j+1])
		imag2 := fxp.Sub16(data[j], data[i])

		depReal := fxp.LDepositH(real1)
		depImag := fxp.LDepositH(imag1)

		acc := fxp.LMac(depReal, real2, vad2PhaseTable[i])
		acc = fxp.LMsu(acc, imag2, vad2PhaseTable[i+1])
		data[i] = fxp.Round(fxp.Shr32(acc, 1))

		acc = fxp.LMac(depImag, imag2, vad2PhaseTable[i])
		acc = fxp.LMac(acc, real2, vad2PhaseTable[i+1])
		data[i+1] = fxp.Round(fxp.Shr32(acc, 1))

		acc = fxp.LMac(depReal, real2, vad2PhaseTable[j])
		acc = fxp.LMac(acc, imag2, vad2PhaseTable[j+1])
		data[j] = fxp.Round(fxp.Shr32(acc, 1))

		acc = fxp.Neg32(depImag)
		acc = fxp.LMsu(acc, imag2, vad2PhaseTable[j])
		acc = fxp.LMac(acc, real2, vad2PhaseTable[j+1])
		data[j+1] = fxp.Round(fxp.Shr32(acc, 1))
	}
}
