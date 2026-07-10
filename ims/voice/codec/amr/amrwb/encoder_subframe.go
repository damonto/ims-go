/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * These encoder subframe primitives are ported from amrwbenc/src/syn_filt.c,
 * updt_tar.c, and the impulse-response block in voAMRWBEnc.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func updateTarget(target []int16, filtered []int16, gain int16) ([subframeSamples]int16, error) {
	var out [subframeSamples]int16
	if len(target) < subframeSamples || len(filtered) < subframeSamples {
		return out, errors.New("update target: buffers are too short")
	}
	for i := range subframeSamples {
		acc := fxp.LMult(target[i], 16384)
		acc = fxp.LMsu(acc, filtered[i], gain)
		out[i] = fxp.ExtractH(fxp.Shl32(acc, 1))
	}
	return out, nil
}

type encoderSynthesisResult struct {
	signal [subframeSamples]int16
	memory [lpcOrder]int16
}

func encoderSynthesisFilter(
	coefficients []int16,
	excitation []int16,
	memory []int16,
	samples int,
) (encoderSynthesisResult, error) {
	var result encoderSynthesisResult
	if len(coefficients) < lpcCoeffCount || samples < lpcOrder || samples > subframeSamples ||
		len(excitation) < samples || len(memory) < lpcOrder {
		return result, errors.New("synthesize encoder speech: buffers are too short or sample count is invalid")
	}
	var history [lpcOrder + subframeSamples]int16
	copy(history[:lpcOrder], memory[:lpcOrder])
	shift := fxp.NormS(coefficients[0]) - 2
	a0 := coefficients[0] >> 1
	for i := range samples {
		acc := fxp.LMult(excitation[i], a0)
		for j := 1; j <= lpcOrder; j++ {
			acc = fxp.LMsu(acc, coefficients[j], history[lpcOrder+i-j])
		}
		acc = fxp.Shl32(acc, 3+shift)
		out := fxp.Round(acc)
		history[lpcOrder+i] = out
		result.signal[i] = out
	}
	copy(result.memory[:], result.signal[samples-lpcOrder:samples])
	return result, nil
}

func impulseResponse(unquantizedLPC []int16, quantizedLPC []int16) ([subframeSamples]int16, error) {
	var dst [subframeSamples]int16
	if len(unquantizedLPC) < lpcCoeffCount || len(quantizedLPC) < lpcCoeffCount {
		return dst, errors.New("calculate impulse response: buffers are too short")
	}
	var response [lpcOrder + subframeSamples]int16
	weighted, err := weightLPC(unquantizedLPC, encoderGamma1)
	if err != nil {
		return dst, fmt.Errorf("calculate impulse response: %w", err)
	}
	copy(response[lpcOrder:lpcOrder+lpcCoeffCount], weighted[:])
	for i := range subframeSamples {
		acc := int64(response[lpcOrder+i]) << 14
		for j := 1; j <= lpcOrder; j++ {
			acc -= int64(quantizedLPC[j]) * int64(response[lpcOrder+i-j])
		}
		out := fxp.Round(fxp.Shl32(fxp.Saturate32(acc), 4))
		response[lpcOrder+i] = out
		dst[i] = out
	}
	_ = deemphasis2(dst[:subframeSamples], encoderTiltFac, 0) // Every impulse response starts with zero filter memory.
	return dst, nil
}

func pitchSearchRange(openLoopLag int16) pitchLagState {
	state := pitchLagState{t0Min: openLoopLag - 8}

	state.t0Min = max(state.t0Min, pitchMin)

	state.t0Max = state.t0Min + 15
	if state.t0Max > pitchMax {
		state.t0Max = pitchMax
		state.t0Min = pitchMax - 15
	}
	return state
}

func buildEncoderSpeechFrame(oldSpeech []int16, speech12k8 []int16) ([lpcOrder + frameSamples12k8]int16, error) {
	var speech [lpcOrder + frameSamples12k8]int16
	if len(oldSpeech) < encoderOldSpeechSamples || len(speech12k8) < frameSamples12k8+lpcLookahead12k8 {
		return speech, errors.New("encoder speech history buffers are too short")
	}
	const (
		presentSpeechStart = 64
		historyStart       = presentSpeechStart - lpcOrder
		newSpeechStart     = encoderOldSpeechSamples - lpcLookahead12k8
		oldPartSamples     = newSpeechStart - historyStart
	)
	copy(speech[:oldPartSamples], oldSpeech[historyStart:newSpeechStart])
	copy(speech[oldPartSamples:], speech12k8[:len(speech)-oldPartSamples])
	return speech, nil
}

func residualFrame(aq []int16, speech []int16, excitation []int16) error {
	if len(aq) < 4*lpcCoeffCount || len(speech) < lpcOrder+frameSamples12k8 ||
		len(excitation) < frameSamples12k8 {
		return errors.New("residual frame buffers are too short")
	}
	for subframe := 0; subframe < frameSamples12k8; subframe += subframeSamples {
		aOffset := (subframe / subframeSamples) * lpcCoeffCount
		if err := encoderResidual(
			aq[aOffset:aOffset+lpcCoeffCount],
			speech[subframe:subframe+lpcOrder+subframeSamples],
			excitation[subframe:subframe+subframeSamples],
		); err != nil {
			return fmt.Errorf("calculate residual frame subframe %d: %w", subframe/subframeSamples, err)
		}
	}
	return nil
}
