/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This pitch gain estimator is ported from amrwbenc/src/g_pitch.c.
 */

package amrwb

import (
	"errors"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type pitchGainResult struct {
	gain  int16
	coeff [4]int16
}

func pitchGain(xn []int16, y1 []int16) (pitchGainResult, error) {
	var out pitchGainResult
	if len(xn) < subframeSamples || len(y1) < subframeSamples {
		return out, errors.New("calculate AMR-WB pitch gain: buffers are too short")
	}
	product, expXY := dotProduct12(xn, y1, subframeSamples)
	xy := fxp.ExtractH(product)
	product, expYY := dotProduct12(y1, y1, subframeSamples)
	yy := fxp.ExtractH(product)

	out.coeff[0] = yy
	out.coeff[1] = expYY
	out.coeff[2] = xy
	out.coeff[3] = expXY

	if xy < 0 || yy <= 0 {
		return out, nil
	}

	out.gain = fxp.DivS(xy>>1, yy)
	out.gain = fxp.Shl16(out.gain, expXY-expYY)
	if out.gain > 19661 {
		out.gain = 19661
	}
	return out, nil
}
