/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * These open-loop pitch routines are ported from amrwbenc/src/p_med_ol.c,
 * hp_wsp.c, and math_op.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	openLoopPitchMin = 17
	openLoopPitchMax = 115
)

var openLoopCorrWeight = [...]int16{
	10772, 10794, 10816, 10839, 10862, 10885, 10908, 10932, 10955, 10980,
	11004, 11029, 11054, 11079, 11105, 11131, 11157, 11183, 11210, 11238,
	11265, 11293, 11322, 11350, 11379, 11409, 11439, 11469, 11500, 11531,
	11563, 11595, 11628, 11661, 11694, 11728, 11763, 11798, 11834, 11870,
	11907, 11945, 11983, 12022, 12061, 12101, 12142, 12184, 12226, 12270,
	12314, 12358, 12404, 12451, 12498, 12547, 12596, 12647, 12699, 12751,
	12805, 12861, 12917, 12975, 13034, 13095, 13157, 13221, 13286, 13353,
	13422, 13493, 13566, 13641, 13719, 13798, 13880, 13965, 14053, 14143,
	14237, 14334, 14435, 14539, 14648, 14761, 14879, 15002, 15130, 15265,
	15406, 15554, 15710, 15874, 16056, 16384, 16384, 16384, 16384, 16384,
	16384, 16384, 16056, 15874, 15710, 15554, 15406, 15265, 15130, 15002,
	14879, 14761, 14648, 14539, 14435, 14334, 14237, 14143, 14053, 13965,
	13880, 13798, 13719, 13641, 13566, 13493, 13422, 13353, 13286, 13221,
	13157, 13095, 13034, 12975, 12917, 12861, 12805, 12751, 12699, 12647,
	12596, 12547, 12498, 12451, 12404, 12358, 12314, 12270, 12226, 12184,
	12142, 12101, 12061, 12022, 11983, 11945, 11907, 11870, 11834, 11798,
	11763, 11728, 11694, 11661, 11628, 11595, 11563, 11531, 11500, 11469,
	11439, 11409, 11379, 11350, 11322, 11293, 11265, 11238, 11210, 11183,
	11157, 11131, 11105, 11079, 11054, 11029, 11004, 10980, 10955, 10932,
	10908, 10885, 10862, 10839, 10816, 10794, 10772, 10750, 10728,
}

var inverseSqrtTable = [...]int16{
	32767, 31790, 30894, 30070, 29309, 28602, 27945, 27330, 26755, 26214,
	25705, 25225, 24770, 24339, 23930, 23541, 23170, 22817, 22479, 22155,
	21845, 21548, 21263, 20988, 20724, 20470, 20225, 19988, 19760, 19539,
	19326, 19119, 18919, 18725, 18536, 18354, 18176, 18004, 17837, 17674,
	17515, 17361, 17211, 17064, 16921, 16782, 16646, 16514, 16384,
}

func (e *Encoder) resetOpenLoopPitch() {
	e.oldT0Med = 40
	e.olGain = 0
	e.adaW = 0
	e.olWghtFlg = 0
	for i := range e.oldOLLag {
		e.oldOLLag[i] = 40
	}
}

func inverseSqrtNormalized(frac int32, exp int16) (int32, int16) {
	if frac <= 0 {
		return fxp.Max32, 0
	}
	if exp&1 == 1 {
		frac >>= 1
	}
	exp = fxp.Neg16((exp - 1) >> 1)

	frac >>= 9
	index := int16(frac >> 16)
	frac >>= 1
	alpha := int16(frac) & 0x7fff
	index -= 16
	index = max(index, 0)

	if int(index) >= len(inverseSqrtTable)-1 {
		index = int16(len(inverseSqrtTable) - 2)
	}

	out := int32(inverseSqrtTable[index]) << 16
	delta := fxp.Sub16(inverseSqrtTable[index], inverseSqrtTable[index+1])
	out = fxp.Sub32(out, fxp.LMult(delta, alpha))
	return out, exp
}

func updateOpenLoopLagHistory(prevLag int16, history [5]int16) (int16, [5]int16) {
	for i := len(history) - 1; i > 0; i-- {
		history[i] = history[i-1]
	}
	history[0] = prevLag
	return median5(history[:]), history
}

type highpassWeightedSpeechResult struct {
	signal [frameSamples12k8 / 2]int16
	memory [9]int16
}

func highpassWeightedSpeech(wsp []int16, memory [9]int16) (highpassWeightedSpeechResult, error) {
	var out highpassWeightedSpeechResult
	if len(wsp) > len(out.signal) {
		return out, errors.New("high-pass weighted speech exceeds one half-frame")
	}
	a := [...]int16{8192, 21663, -19258, 5734}
	b := [...]int16{-3432, 10280, -10280, 3432}

	y3h, y3l := memory[0], memory[1]
	y2h, y2l := memory[2], memory[3]
	y1h, y1l := memory[4], memory[5]
	x0, x1, x2 := memory[6], memory[7], memory[8]
	for i, sample := range wsp {
		x3 := x2
		x2 = x1
		x1 = x0
		x0 = sample

		acc := int32(16384)
		acc += int32(y1l) * int32(a[1]) << 1
		acc += int32(y2l) * int32(a[2]) << 1
		acc += int32(y3l) * int32(a[3]) << 1
		acc >>= 15
		acc += int32(y1h) * int32(a[1]) << 1
		acc += int32(y2h) * int32(a[2]) << 1
		acc += int32(y3h) * int32(a[3]) << 1
		acc += int32(x0) * int32(b[0]) << 1
		acc += int32(x1) * int32(b[1]) << 1
		acc += int32(x2) * int32(b[2]) << 1
		acc += int32(x3) * int32(b[3]) << 1
		acc = fxp.Shl32(acc, 2)

		y3h, y3l = y2h, y2l
		y2h, y2l = y1h, y1l
		y1h, y1l = fxp.LExtract(acc)
		out.signal[i] = int16((acc + 0x4000) >> 15)
	}

	out.memory = [9]int16{y3h, y3l, y2h, y2l, y1h, y1l, x0, x1, x2}
	return out, nil
}

func scaleHighpassWeightedSpeechMemory(memory [9]int16, exp int16) [9]int16 {
	for i := 0; i < 6; i += 2 {
		value := fxp.LComp(memory[i], memory[i+1])
		value = fxp.Shl32(value, exp)
		memory[i], memory[i+1] = fxp.LExtract(value)
	}
	scaleSignalRound(memory[6:9], exp)
	return memory
}

func (e *Encoder) estimateOpenLoopPitch(weighted encoderWeightedSpeech) (int16, int16, error) {
	var wsp [oldWspSamples + frameSamples12k8/2]int16
	copy(wsp[:oldWspSamples], e.oldWsp[:])
	copy(wsp[oldWspSamples:], weighted.wsp[:])

	if e.mode == Mode660 {
		t0, err := e.pitchMedOL(wsp[:], oldWspSamples, frameSamples12k8/2)
		if err != nil {
			return 0, 0, fmt.Errorf("estimate open-loop pitch: %w", err)
		}
		e.updateOpenLoopWeighting(t0)
		e.vad.toneDetection(e.olGain)
		t0 *= 2
		copy(e.oldWsp[:], wsp[frameSamples12k8/2:frameSamples12k8/2+oldWspSamples])
		return t0, t0, nil
	}

	t0, err := e.pitchMedOL(wsp[:], oldWspSamples, frameSamples12k8/4)
	if err != nil {
		return 0, 0, fmt.Errorf("estimate first open-loop pitch: %w", err)
	}
	e.updateOpenLoopWeighting(t0)
	e.vad.toneDetection(e.olGain)
	t02, err := e.pitchMedOL(wsp[:], oldWspSamples+frameSamples12k8/4, frameSamples12k8/4)
	if err != nil {
		return 0, 0, fmt.Errorf("estimate second open-loop pitch: %w", err)
	}
	e.updateOpenLoopWeighting(t02)
	e.vad.toneDetection(e.olGain)
	copy(e.oldWsp[:], wsp[frameSamples12k8/2:frameSamples12k8/2+oldWspSamples])
	return t0 * 2, t02 * 2, nil
}

func (e *Encoder) updateOpenLoopWeighting(t0 int16) {
	if e.olGain > 19661 {
		e.oldT0Med, e.oldOLLag = updateOpenLoopLagHistory(t0, e.oldOLLag)
		e.adaW = fxp.Max16
	} else {
		e.adaW = fxp.Mult(e.adaW, 29491)
	}
	if e.adaW < 26214 {
		e.olWghtFlg = 0
		return
	}
	e.olWghtFlg = 1
}

func (e *Encoder) pitchMedOL(wsp []int16, offset int, frameLen int) (int16, error) {
	if offset < openLoopPitchMax || offset+frameLen > len(wsp) || frameLen <= 0 {
		return 0, errors.New("open-loop pitch search range is outside weighted speech")
	}
	l0 := e.oldT0Med
	weightIndex := len(openLoopCorrWeight) - 1
	oldWeightIndex := 98 + openLoopPitchMax - int(l0)
	oldWeightIndex = max(oldWeightIndex, 0)
	if oldWeightIndex >= len(openLoopCorrWeight) {
		oldWeightIndex = len(openLoopCorrWeight) - 1
	}

	best := int32(fxp.Min32)
	tm := int16(0)
	for lag := openLoopPitchMax; lag > openLoopPitchMin; lag-- {
		var corr int32
		for j := range frameLen {
			corr = fxp.Add32(corr, fxp.LMult(wsp[offset+j], wsp[offset+j-lag]))
		}
		hi, lo := fxp.LExtract(corr)
		corr = fxp.Mpy32By16(hi, lo, openLoopCorrWeight[weightIndex])
		weightIndex--
		if l0 > 0 && e.olWghtFlg > 0 {
			hi, lo = fxp.LExtract(corr)
			corr = fxp.Mpy32By16(hi, lo, openLoopCorrWeight[oldWeightIndex])
			oldWeightIndex--

			oldWeightIndex = max(oldWeightIndex, 0)

		}
		if corr >= best {
			best = corr
			tm = int16(lag)
		}
	}

	var hpInput [frameSamples12k8 / 2]int16
	copy(hpInput[:frameLen], wsp[offset:offset+frameLen])
	highpass, err := highpassWeightedSpeech(hpInput[:frameLen], e.hpWspMem)
	if err != nil {
		return 0, fmt.Errorf("estimate open-loop pitch: %w", err)
	}
	e.hpWspMem = highpass.memory
	var hp [oldWspSamples + frameSamples12k8/2]int16
	copy(hp[:oldWspSamples], e.oldHPWsp[:])
	copy(hp[oldWspSamples:], highpass.signal[:frameLen])

	var r0 int32
	r1 := int32(1)
	r2 := int32(1)
	for j := range frameLen {
		x := hp[oldWspSamples+j]
		y := hp[oldWspSamples+j-int(tm)]
		r0 = fxp.LMac(r0, x, y)
		r1 = fxp.LMac(r1, y, y)
		r2 = fxp.LMac(r2, x, x)
	}

	expR0 := fxp.NormL(r0)
	r0 = fxp.Shl32(r0, expR0)
	expR1 := fxp.NormL(r1)
	r1 = fxp.Shl32(r1, expR1)
	expR2 := fxp.NormL(r2)
	r2 = fxp.Shl32(r2, expR2)

	r1 = fxp.LMult(fxp.Round(r1), fxp.Round(r2))
	shift := fxp.NormL(r1)
	r1 = fxp.Shl32(r1, shift)
	expR1 = fxp.Add16(fxp.Add16(expR1, expR2), shift)
	expR1 = fxp.Sub16(62, expR1)
	r1, expR1 = inverseSqrtNormalized(r1, expR1)

	r0 = fxp.LMult(fxp.Round(r0), fxp.Round(r1))
	expR0 = fxp.Sub16(31, expR0)
	expR0 = fxp.Add16(expR0, expR1)
	e.olGain = fxp.Round(fxp.Shl32(r0, expR0))

	copy(e.oldHPWsp[:], hp[frameLen:frameLen+oldWspSamples])
	return tm, nil
}
