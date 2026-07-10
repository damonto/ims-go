/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This pitch excitation selection path is ported from the subframe loop in
 * amrwbenc/src/voAMRWBEnc.c.
 */

package amrwb

import (
	"errors"
	"fmt"
)

type selectedPitchPrediction struct {
	excitation [subframeSamples]int16
	filtered   [subframeSamples]int16
	codeSeed   [subframeSamples]int16
	target2    [subframeSamples]int16
	gCoeff     [4]int16
	gain       int16
	selectNoLP int16
}

func selectPitchPrediction(
	mode Mode,
	excWithHistory []int16,
	target []int16,
	h1 []int16,
	clipGain bool,
) (selectedPitchPrediction, error) {
	var out selectedPitchPrediction
	if len(excWithHistory) < subframeSamples+2 || len(target) < subframeSamples || len(h1) < subframeSamples {
		return out, errors.New("select pitch prediction: buffers are too short")
	}

	var filteredNoLP [subframeSamples]int16
	var targetNoLP [subframeSamples]int16
	var noLP pitchGainResult
	if mode > Mode885 {
		var err error
		filteredNoLP, err = convolve(excWithHistory[1:1+subframeSamples], h1[:subframeSamples])
		if err != nil {
			return out, fmt.Errorf("select pitch prediction without low-pass filter: %w", err)
		}
		noLP, err = pitchGain(target, filteredNoLP[:])
		if err != nil {
			return out, fmt.Errorf("select pitch prediction without low-pass filter: %w", err)
		}
		if clipGain && noLP.gain > pitchClipGain {
			noLP.gain = pitchClipGain
		}
		targetNoLP, err = updateTarget(target, filteredNoLP[:], noLP.gain)
		if err != nil {
			return out, fmt.Errorf("select pitch prediction without low-pass filter: %w", err)
		}
	}

	lpExc, err := filterPitchExcitation(excWithHistory)
	if err != nil {
		return out, fmt.Errorf("select low-pass pitch prediction: %w", err)
	}

	filteredLP, err := convolve(lpExc[:], h1[:subframeSamples])
	if err != nil {
		return out, fmt.Errorf("select low-pass pitch prediction: %w", err)
	}
	lp, err := pitchGain(target, filteredLP[:])
	if err != nil {
		return out, fmt.Errorf("select low-pass pitch prediction: %w", err)
	}
	if clipGain && lp.gain > pitchClipGain {
		lp.gain = pitchClipGain
	}

	targetLP, err := updateTarget(target, filteredLP[:], lp.gain)
	if err != nil {
		return out, fmt.Errorf("select low-pass pitch prediction: %w", err)
	}

	selectNoLP := int16(0)
	if mode > Mode885 && targetEnergyDelta(targetNoLP[:], targetLP[:]) <= 0 {
		selectNoLP = 1
	}

	if selectNoLP == 0 {
		copy(out.excitation[:], lpExc[:])
		copy(out.filtered[:], filteredLP[:])
		copy(out.codeSeed[:], filteredLP[:])
		copy(out.target2[:], targetLP[:])
		copy(out.gCoeff[:], lp.coeff[:])
		out.gain = lp.gain
		return out, nil
	}

	copy(out.excitation[:], excWithHistory[1:1+subframeSamples])
	copy(out.filtered[:], filteredNoLP[:])
	copy(out.codeSeed[:], filteredLP[:])
	copy(out.target2[:], targetNoLP[:])
	copy(out.gCoeff[:], noLP.coeff[:])
	out.gain = noLP.gain
	out.selectNoLP = selectNoLP
	return out, nil
}

func filterPitchExcitation(excWithHistory []int16) ([subframeSamples]int16, error) {
	var dst [subframeSamples]int16
	if len(excWithHistory) < subframeSamples+2 {
		return dst, errors.New("filter pitch excitation: buffer is too short")
	}
	for i := range subframeSamples {
		acc := int32(5898)*int32(excWithHistory[i]) +
			int32(20972)*int32(excWithHistory[i+1]) +
			int32(5898)*int32(excWithHistory[i+2])
		dst[i] = int16((acc + 0x4000) >> 15)
	}
	return dst, nil
}

func targetEnergyDelta(noLP []int16, lp []int16) int32 {
	var acc int32
	for i := range subframeSamples {
		acc += int32(noLP[i]) * int32(noLP[i])
		acc -= int32(lp[i]) * int32(lp[i])
	}
	return acc
}
