/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This closed-loop pitch search is ported from amrwbenc/src/pitch_f4.c
 * and convolve.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const closedLoopInterpolationLen = 4

var closedLoopInterpolation = [...][2 * closedLoopInterpolationLen]int16{
	{-12, 420, -1732, 5429, 13418, -1242, 73, 32},
	{-26, 455, -2142, 9910, 9910, -2142, 455, -26},
	{32, 73, -1242, 13418, 5429, -1732, 420, -12},
	{206, -766, 1376, 14746, 1376, -766, 206, 0},
}

func pitchFR4(
	excitation []int16,
	offset int,
	xn []int16,
	h []int16,
	t0Min int16,
	t0Max int16,
	pitFlag int16,
	t0Frac2 int16,
	t0Frac1 int16,
) (int16, int16, error) {
	if len(xn) < subframeSamples || len(h) < subframeSamples ||
		int(t0Min)-closedLoopInterpolationLen < 0 ||
		int(t0Max)+closedLoopInterpolationLen >= offset {
		return 0, 0, errors.New("search closed-loop pitch: invalid buffers or lag range")
	}

	tMin := t0Min - closedLoopInterpolationLen
	tMax := t0Max + closedLoopInterpolationLen
	corr := make([]int16, int(tMax-tMin)+1)
	if err := normalizedPitchCorrelation(excitation, offset, xn, h, tMin, tMax, corr); err != nil {
		return 0, 0, fmt.Errorf("search closed-loop pitch: %w", err)
	}

	t0 := t0Min
	maxCorr := corr[int(t0Min-tMin)]
	for lag := t0Min + 1; lag <= t0Max; lag++ {
		value := corr[int(lag-tMin)]
		if value >= maxCorr {
			maxCorr = value
			t0 = lag
		}
	}
	if pitFlag == 0 && t0 >= t0Frac1 {
		return t0, 0, nil
	}

	step := int16(1)
	fraction := int16(-3)
	if t0Frac2 == pitchMin || (pitFlag == 0 && t0 >= t0Frac2) {
		step = 2
		fraction = -2
	}
	if t0 == t0Min {
		fraction = 0
	}

	center := int(t0 - tMin)
	best, err := interpolatePitchCorrelation(corr, center, fraction)
	if err != nil {
		return 0, 0, fmt.Errorf("search closed-loop pitch: %w", err)
	}
	for frac := fraction + step; frac <= 3; frac += step {
		value, err := interpolatePitchCorrelation(corr, center, frac)
		if err != nil {
			return 0, 0, fmt.Errorf("search closed-loop pitch: %w", err)
		}
		if value > best {
			best = value
			fraction = frac
		}
	}
	if fraction < 0 {
		fraction += upSample
		t0--
	}
	return t0, fraction, nil
}

func normalizedPitchCorrelation(
	excitation []int16,
	offset int,
	xn []int16,
	h []int16,
	tMin int16,
	tMax int16,
	corr []int16,
) error {
	if len(xn) < subframeSamples || len(h) < subframeSamples ||
		len(corr) < int(tMax-tMin)+1 {
		return errors.New("calculate normalized pitch correlation: buffers are too short")
	}

	energyXN := int32(1)
	for i := range subframeSamples {
		energyXN = fxp.LMac(energyXN, xn[i], xn[i])
	}
	exp := fxp.NormL(energyXN)
	exp = fxp.Sub16(30, exp)
	exp = fxp.Add16(exp, 2)
	scale := fxp.Neg16(fxp.Shr16(exp, 1))

	start := offset - int(tMin)
	if start < 0 || start+subframeSamples > len(excitation) {
		return errors.New("calculate normalized pitch correlation: excitation range is invalid")
	}
	excf, err := convolve(excitation[start:start+subframeSamples], h[:subframeSamples])
	if err != nil {
		return fmt.Errorf("calculate normalized pitch correlation: %w", err)
	}

	for lag := tMin; lag <= tMax; lag++ {
		cross := int32(1)
		energyY := int32(1)
		for i := range subframeSamples {
			cross = fxp.LMac(cross, xn[i], excf[i])
			energyY = fxp.LMac(energyY, excf[i], excf[i])
		}

		expCorr := fxp.NormL(cross)
		cross = fxp.Shl32(cross, expCorr)
		expCorr = fxp.Sub16(30, expCorr)
		corrHi := fxp.ExtractH(cross)

		expNorm := fxp.NormL(energyY)
		energyY = fxp.Shl32(energyY, expNorm)
		expNorm = fxp.Sub16(30, expNorm)
		energyY, expNorm = inverseSqrtNormalized(energyY, expNorm)
		normHi := fxp.ExtractH(energyY)

		value := fxp.LMult(corrHi, normHi)
		shift := fxp.Add16(fxp.Add16(expCorr, expNorm), scale)
		value = fxp.Shl32(value, shift)
		corr[int(lag-tMin)] = fxp.Round(value)

		if lag == tMax {
			continue
		}
		tmpIndex := offset - int(lag+1)
		if tmpIndex < 0 || tmpIndex >= len(excitation) {
			return errors.New("calculate normalized pitch correlation: excitation history is too short")
		}
		tmp := excitation[tmpIndex]
		for i := subframeSamples - 1; i > 0; i-- {
			excf[i] = fxp.Add16(fxp.Mult(tmp, h[i]), excf[i-1])
		}
		excf[0] = fxp.Mult(tmp, h[0])
	}
	return nil
}

func interpolatePitchCorrelation(corr []int16, center int, frac int16) (int16, error) {
	if frac < 0 {
		frac += upSample
		center--
	}
	start := center - closedLoopInterpolationLen + 1
	if start < 0 || start+2*closedLoopInterpolationLen > len(corr) {
		return 0, errors.New("interpolate pitch correlation: window is outside correlation buffer")
	}
	if frac < 0 || frac >= upSample {
		return 0, fmt.Errorf("interpolate pitch correlation: invalid fraction %d", frac)
	}
	filter := closedLoopInterpolation[upSample-1-int(frac)]
	var sum int32
	for i := range 2 * closedLoopInterpolationLen {
		sum = fxp.LMac(sum, corr[start+i], filter[i])
	}
	return fxp.Round(fxp.Shl32(sum, 1)), nil
}

func convolve(x []int16, h []int16) ([subframeSamples]int16, error) {
	var y [subframeSamples]int16
	if len(x) < subframeSamples || len(h) < subframeSamples {
		return y, errors.New("convolve signals: buffers are too short")
	}
	for n := range y {
		var sum int32
		for i := 0; i <= n; i++ {
			sum = fxp.LMac(sum, x[i], h[n-i])
		}
		y[n] = fxp.Round(sum)
	}
	return y, nil
}
