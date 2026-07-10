/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * These weighted-speech encoder primitives are ported from amrwbenc/src/residu.c,
 * deemph.c, scale.c, and lp_dec2.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	encoderGamma1  int16 = 30147
	encoderTiltFac int16 = 22282
)

var decim2FIR = [...]int16{4260, 7536, 9175, 7536, 4260}

type encoderWeightedSpeech struct {
	wsp   [frameSamples12k8 / 2]int16
	shift int16
}

func (e *Encoder) buildWeightedSpeech(a []int16) (encoderWeightedSpeech, error) {
	var out encoderWeightedSpeech
	if len(a) < 4*lpcCoeffCount {
		return out, errors.New("weighted speech LPC buffer is too short")
	}
	speech, err := buildEncoderSpeechFrame(e.oldSpeech[:], e.speech12k8[:])
	if err != nil {
		return out, fmt.Errorf("build weighted speech: %w", err)
	}

	var wsp [frameSamples12k8]int16
	for subframe := 0; subframe < frameSamples12k8; subframe += subframeSamples {
		ap, err := weightLPC(a[(subframe/subframeSamples)*lpcCoeffCount:], encoderGamma1)
		if err != nil {
			return out, fmt.Errorf("build weighted speech subframe %d: %w", subframe/subframeSamples, err)
		}
		if err := encoderResidual(ap[:], speech[subframe:subframe+lpcOrder+subframeSamples], wsp[subframe:subframe+subframeSamples]); err != nil {
			return out, fmt.Errorf("build weighted speech subframe %d: %w", subframe/subframeSamples, err)
		}
	}
	e.memWsp = deemphasis2(wsp[:], encoderTiltFac, e.memWsp)

	maxValue := int16(0)
	for _, sample := range wsp {
		abs := fxp.Abs16(sample)

		maxValue = max(maxValue, abs)

	}
	refMax := e.oldWspMax
	refMax = max(refMax, maxValue)

	e.oldWspMax = maxValue

	shift := fxp.Sub16(fxp.NormS(refMax), 3)
	shift = min(shift, 0)

	decimated := decimateWeightedSpeechBy2(wsp, e.memDecim2)
	e.memDecim2 = decimated.memory
	scaleSignalRound(decimated.signal[:], shift)
	historyShift := fxp.Add16(e.scaleExp, fxp.Sub16(shift, e.oldWspShift))
	e.oldWspShift = shift
	scaleSignalRound(e.oldWsp[:], historyShift)
	scaleSignalRound(e.oldHPWsp[:], historyShift)
	e.hpWspMem = scaleHighpassWeightedSpeechMemory(e.hpWspMem, historyShift)
	out.wsp = decimated.signal
	out.shift = shift
	return out, nil
}

func encoderResidual(a []int16, xWithHistory []int16, y []int16) error {
	if len(a) < lpcCoeffCount || len(xWithHistory) < len(y)+lpcOrder {
		return errors.New("encoder residual buffers are too short")
	}
	for i := range y {
		base := lpcOrder + i
		sum := fxp.LMult(xWithHistory[base], a[0])
		for j := 0; j <= lpcOrder; j++ {
			if j == 0 {
				continue
			}
			sum = fxp.LMac(sum, a[j], xWithHistory[base-j])
		}
		sum = fxp.Shl32(sum, 4)
		y[i] = fxp.Round(sum)
	}
	return nil
}

func deemphasis2(x []int16, mu int16, mem int16) int16 {
	if len(x) == 0 {
		return mem
	}
	acc := fxp.LMult(x[0], 16384)
	acc = fxp.LMac(acc, mem, mu)
	x[0] = fxp.Round(acc)
	for i := 1; i < len(x); i++ {
		acc = fxp.LMult(x[i], 16384)
		acc = fxp.LMac(acc, x[i-1], mu)
		x[i] = fxp.Round(acc)
	}
	return x[len(x)-1]
}

func scaleSignalRound(x []int16, exp int16) {
	if exp > 0 {
		for i := len(x) - 1; i >= 0; i-- {
			x[i] = fxp.Round(fxp.Shl32(int32(x[i])<<16, exp))
		}
		return
	}
	shift := -exp
	for i := len(x) - 1; i >= 0; i-- {
		acc := (int32(x[i]) << 16) >> shift
		x[i] = int16((acc + 0x8000) >> 16)
	}
}

type decimatedWeightedSpeech struct {
	signal [frameSamples12k8 / 2]int16
	memory [3]int16
}

func decimateWeightedSpeechBy2(x [frameSamples12k8]int16, memory [3]int16) decimatedWeightedSpeech {
	var out decimatedWeightedSpeech
	var buffer [3 + frameSamples12k8]int16
	copy(buffer[:3], memory[:])
	copy(out.memory[:], x[frameSamples12k8-3:])
	copy(buffer[3:], x[:])
	for i, j := 0, 0; i < len(x); i, j = i+2, j+1 {
		var acc int32
		for k := range len(decim2FIR) {
			acc += int32(buffer[i+k]) * int32(decim2FIR[k])
		}
		out.signal[j] = int16((acc + 0x4000) >> 15)
	}
	return out
}
