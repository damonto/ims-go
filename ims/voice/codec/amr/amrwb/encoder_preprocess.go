/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * These AMR-WB encoder preprocessing primitives are ported from
 * amrwbenc/src/homing.c and amrwbenc/src/decim54.c.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	decimDelay16k           = 15
	downFactorQ15           = 26215
	lpcLookahead12k8        = 12
	encoderOldSpeechSamples = 128
	preemphasisFactor       = 22282
)

var decimFirDown = [...][30]int16{
	{
		-5, 24, -50, 54, 0, -128, 294, -408, 344, 0,
		-647, 1505, -2379, 3034, 13107, 3034, -2379, 1505, -647, 0,
		344, -408, 294, -128, 0, 54, -50, 24, -5, 0,
	},
	{
		-6, 19, -26, 0, 77, -188, 270, -233, 0, 434,
		-964, 1366, -1293, 0, 12254, 6575, -2746, 1030, 0, -507,
		601, -441, 198, 0, -95, 99, -58, 18, 0, -1,
	},
	{
		-3, 9, 0, -41, 111, -170, 153, 0, -295, 649,
		-888, 770, 0, -1997, 9894, 9894, -1997, 0, 770, -888,
		649, -295, 0, 153, -170, 111, -41, 0, 9, -3,
	},
	{
		-1, 0, 18, -58, 99, -95, 0, 198, -441, 601,
		-507, 0, 1030, -2746, 6575, 12254, 0, -1293, 1366, -964,
		434, 0, -233, 270, -188, 77, 0, -26, 19, -6,
	},
}

type encoderPreprocessState struct {
	decimMem  [2 * decimDelay16k]int16
	hp50Mem   [6]int16
	memPreemp int16
	qOld      int16
	qMax      [2]int16
}

func (s *encoderPreprocessState) reset() {
	clear(s.decimMem[:])
	clear(s.hp50Mem[:])
	s.memPreemp = 0
	s.qOld = 15
	s.qMax[0] = 15
	s.qMax[1] = 15
}

func encoderHomingFrame(pcm []int16) bool {
	if len(pcm) != FrameSamples {
		return false
	}
	for _, sample := range pcm {
		if sample != encoderHomingFrameSample {
			return false
		}
	}
	return true
}

func maskEncoderInput(pcm []int16) {
	for i := range pcm {
		pcm[i] &= ^int16(3)
	}
}

func (s *encoderPreprocessState) decimate16kTo12k8(dst []int16, src []int16) []int16 {
	if len(src) == 0 {
		return dst[:0]
	}
	outLen := (len(src) * downFactorQ15) >> 15
	if cap(dst) < outLen {
		dst = make([]int16, outLen)
	} else {
		dst = dst[:outLen]
	}

	historyLen := len(s.decimMem)
	signal := make([]int16, historyLen+len(src))
	copy(signal, s.decimMem[:])
	copy(signal[historyLen:], src)
	downsample(signal, dst)
	copy(s.decimMem[:], signal[len(src):len(src)+historyLen])
	return dst
}

func downsample(signal []int16, dst []int16) {
	pos := 0
	for j := range dst {
		i := pos >> 2
		frac := pos & 3
		x := signal[i+1:]
		y := decimFirDown[frac][:]
		sum := int32(0)
		for k := range y {
			sum = fxp.LMac(sum, x[k], y[k])
		}
		sum = fxp.Shl32(sum, 1)
		dst[j] = fxp.Round(sum)
		pos += 5
	}
}

func (s *encoderPreprocessState) highpass50Hz(signal []int16) {
	s.hp50Mem = highpass50HzAt12k8(signal, s.hp50Mem)
}

func (s *encoderPreprocessState) processFrame(dst []int16, pcm []int16) []int16 {
	var input [FrameSamples]int16
	copy(input[:], pcm)
	maskEncoderInput(input[:])
	if cap(dst) < frameSamples12k8+lpcLookahead12k8 {
		dst = make([]int16, frameSamples12k8+lpcLookahead12k8)
	} else {
		dst = dst[:frameSamples12k8+lpcLookahead12k8]
	}

	frame := s.decimate16kTo12k8(dst[:0], input[:])
	lookaheadDecimMem := s.decimMem
	var zeros [decimDelay16k]int16
	lookahead := (&encoderPreprocessState{decimMem: lookaheadDecimMem}).
		decimate16kTo12k8(dst[frameSamples12k8:frameSamples12k8], zeros[:])

	s.highpass50Hz(frame)
	lookaheadHP := s.hp50Mem
	lookaheadHP = highpass50HzAt12k8(lookahead, lookaheadHP)
	out := dst[:len(frame)+len(lookahead)]
	s.preemphasisAndScale(out)
	return out
}

func (s *encoderPreprocessState) preemphasisAndScale(signal []int16) int16 {
	if len(signal) == 0 {
		return s.qOld
	}
	mu := int16(preemphasisFactor >> 1)
	maxValue := fxp.Abs32(preemphasisDiff(signal[0], s.memPreemp, mu))
	for i := 1; i < len(signal); i++ {
		value := fxp.Abs32(preemphasisDiff(signal[i], signal[i-1], mu))
		maxValue = max(maxValue, value)
	}

	hi := fxp.ExtractH(maxValue)
	shift := int16(qMax)
	if hi != 0 {
		shift = fxp.NormS(hi) - 1
		shift = max(shift, 0)
		shift = min(shift, qMax)
	}
	qNew := shift
	qNew = min(qNew, s.qMax[0])
	qNew = min(qNew, s.qMax[1])

	s.qOld = qNew
	s.qMax[1] = s.qMax[0]
	s.qMax[0] = shift

	mem := s.memPreemp
	s.memPreemp = signal[frameSamples12k8-1]
	for i := len(signal) - 1; i > 0; i-- {
		signal[i] = fxp.Round(fxp.Shl32(preemphasisDiff(signal[i], signal[i-1], mu), qNew))
	}
	signal[0] = fxp.Round(fxp.Shl32(preemphasisDiff(signal[0], mem, mu), qNew))
	return qNew
}

func preemphasisDiff(current int16, previous int16, mu int16) int32 {
	return fxp.Sub32(int32(current)<<15, int32(previous)*int32(mu)<<1)
}
