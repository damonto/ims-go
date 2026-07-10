/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * The 23.85 kbit/s encoder carries a 4-bit high-band correction gain after
 * each core subframe. This file follows the VisualOn encoder synthesis()
 * path used to derive that index from the original 16 kHz high band.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type encoderHighBandState struct {
	memSynHi  [lpcOrder]int16
	memSynLo  [lpcOrder]int16
	memDeemph int16
	memSigOut [6]int16
	memHP400  [6]int16
	memSynHF  [lpcOrder]int16
	memHF     [hfFIRMemory]int16
	memHF2    [hfFIRMemory]int16
	seed2     int16
	vadHist   int16
	gainAlpha int16
	gcThresh  int32
}

func (s *encoderHighBandState) reset() {
	*s = encoderHighBandState{
		seed2:     randomInitialSeed,
		gainAlpha: fxp.Max16,
	}
}

func (e *Encoder) updateEncoderVADHistory(active bool) {
	if active {
		e.vadActive = true
		e.hb.vadHist = 0
		return
	}
	e.vadActive = false
	e.hb.vadHist = fxp.Add16(e.hb.vadHist, 1)
}

func (e *Encoder) highBandCorrectionIndex(
	aq []int16,
	adaptiveExc []int16,
	sf *encoderSubframePitch,
	qNew int16,
	voiceFac int16,
	stability int16,
	subframe int,
) (int16, error) {
	if len(aq) < lpcCoeffCount || len(adaptiveExc) < subframeSamples {
		return 0, errors.New("compute high-band correction index: buffers are too short")
	}
	if subframe < 0 || subframe >= frameSamples12k8/subframeSamples {
		return 0, fmt.Errorf("compute high-band correction index: invalid subframe %d", subframe)
	}
	var exc2 [subframeSamples]int16
	copy(exc2[:], adaptiveExc[:subframeSamples])

	enhancedGain, gcThresh := enhanceCodeGain(e.hb.gcThresh, sf.gainCode, voiceFac, stability)
	e.hb.gcThresh = gcThresh
	enhanced := buildEnhancedExcitation(exc2, sf.code, sf.gain, enhancedGain, qNew, voiceFac)
	exc2 = enhanced.excitation

	offset := subframe * subframeSamples16k
	return e.hb.correctionIndex(
		aq,
		exc2[:],
		qNew,
		e.speech16k[offset:offset+subframeSamples16k],
		e.dtxState.hangoverCount,
	)
}

func nearestHFGainIndex(gain int16) int16 {
	best := 0
	bestDist := int32(fxp.Max32)
	for i, candidate := range hpGain {
		dist := int32(candidate) - int32(gain)
		if dist < 0 {
			dist = -dist
		}
		if dist < bestDist {
			bestDist = dist
			best = i
		}
	}
	return int16(best)
}

func (s *encoderHighBandState) correctionIndex(
	aq []int16,
	exc []int16,
	qNew int16,
	speech16k []int16,
	hangoverCount int16,
) (int16, error) {
	if len(aq) < lpcCoeffCount || len(exc) < subframeSamples || len(speech16k) < subframeSamples16k {
		return 0, errors.New("compute high-band correction index: buffers are too short")
	}
	filtered, err := synthesisFilter32(aq, exc[:subframeSamples], qNew, s.memSynHi, s.memSynLo)
	if err != nil {
		return 0, fmt.Errorf("compute high-band correction index: %w", err)
	}
	s.memSynHi = filtered.memoryHigh
	s.memSynLo = filtered.memoryLow

	deemphasized := deemphasis32(filtered.high, filtered.low, deemphasisFactor, s.memDeemph)
	synth := deemphasized.signal
	s.memDeemph = deemphasized.memory
	s.memSigOut = highpass50HzAt12k8(synth[:], s.memSigOut)

	hf, seed := generateHFNoise(s.seed2)
	s.seed2 = seed
	hf, err = scaleHFNoiseToExcitation(hf, exc, qNew)
	if err != nil {
		return 0, fmt.Errorf("compute high-band correction index: %w", err)
	}

	tilt := hfGainFromTilt(synth, s.memHP400, s.vadHist)
	s.memHP400 = tilt.memory

	weighted, err := weightLPC(aq, 19661)
	if err != nil {
		return 0, fmt.Errorf("compute high-band correction index: %w", err)
	}
	synthesizedHF, err := wbSynthesisFilter(weighted[:], hf[:], s.memSynHF[:])
	if err != nil {
		return 0, fmt.Errorf("compute high-band correction index: %w", err)
	}
	hf = synthesizedHF.signal
	copy(s.memSynHF[:], synthesizedHF.memory[:lpcOrder])
	filteredHF := bandPass6k7k(hf, s.memHF)
	hf = filteredHF.signal
	s.memHF = filteredHF.memory

	var speechHF [subframeSamples16k]int16
	copy(speechHF[:], speech16k[:subframeSamples16k])
	filteredSpeech := bandPass6k7k(speechHF, s.memHF2)
	speechHF = filteredSpeech.signal
	s.memHF2 = filteredSpeech.memory
	scaleSignal(speechHF[:], -1)

	calculatedGain := highBandCalculatedGain(speechHF[:], hf[:])
	s.updateGainAlpha(hangoverCount)

	estimatedGain := tilt.gain >> 1
	correctionGain := fxp.Add16(
		fxp.Mult(calculatedGain, s.gainAlpha),
		fxp.Mult(fxp.Sub16(fxp.Max16, s.gainAlpha), estimatedGain),
	)
	return nearestHFGainIndexSquared(correctionGain), nil
}

func highBandCalculatedGain(reference []int16, hf []int16) int16 {
	product, expReference := dotProduct12(
		reference,
		reference,
		subframeSamples16k,
	)
	energyReference := fxp.ExtractH(product)
	product, expHF := dotProduct12(hf, hf, subframeSamples16k)
	energyHF := fxp.ExtractH(product)
	if energyHF > energyReference {
		energyHF >>= 1
		expHF++
	}
	scale := int32(fxp.DivS(energyHF, energyReference)) << 16
	expHF = fxp.Sub16(expHF, expReference)
	scale, expHF = oneOverSqrtNorm(scale, expHF)
	scale = fxp.Shl32(scale, expHF)
	return fxp.ExtractH(scale)
}

func (s *encoderHighBandState) updateGainAlpha(hangoverCount int16) {
	factor := fxp.ExtractH(fxp.Shl32(fxp.LMult(hangoverCount, 4681), 15))
	s.gainAlpha = fxp.Mult(s.gainAlpha, factor)
	if hangoverCount > 6 {
		s.gainAlpha = fxp.Max16
	}
}

func nearestHFGainIndexSquared(gain int16) int16 {
	best := int16(0)
	bestDist := int16(fxp.Max16)
	for i, candidate := range hpGain {
		delta := fxp.Sub16(gain, candidate)
		dist := fxp.Mult(delta, delta)
		if bestDist > dist {
			bestDist = dist
			best = int16(i)
		}
	}
	return best
}

func highBandCorrectionParameterIndex(mode Mode, gainParamIndex int) int {
	if mode != Mode2385 {
		return -1
	}
	return gainParamIndex + 1
}
