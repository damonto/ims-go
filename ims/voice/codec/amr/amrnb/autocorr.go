/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This LPC autocorrelation step is ported from amr_nb/enc/src/autocorr.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type autocorrelationResult struct {
	rh   [lpcCoeffCount]int16
	rl   [lpcCoeffCount]int16
	norm int16
}

func autocorrelation(x []int16, window []int16) (autocorrelationResult, error) {
	var out autocorrelationResult
	if len(window) == 0 || len(x) < len(window) {
		return out, fmt.Errorf(
			"calculating AMR-NB autocorrelation: input/window sample counts %d/%d require a non-empty full window",
			len(x),
			len(window),
		)
	}

	y := make([]int16, len(window))
	for i := range window {
		y[i] = fxp.MultRound(x[i], window[i])
	}

	var overflowShift int16
	sum := autocorrEnergy(y)
	for sum > int64(fxp.Max32) {
		overflowShift = fxp.Add16(overflowShift, 4)
		for i := range y {
			y[i] >>= 2
		}
		sum = autocorrEnergy(y)
	}
	sum++

	norm := fxp.NormL(int32(sum))
	normalized := fxp.Shl32(int32(sum), norm)
	out.rh[0], out.rl[0] = fxp.LExtract(normalized)

	for lag := 1; lag <= lpcOrder; lag++ {
		corr := autocorrLag(y, lag)
		corr = int64(fxp.Shl32(int32(corr), norm))
		out.rh[lag], out.rl[lag] = fxp.LExtract(int32(corr))
	}

	out.norm = fxp.Sub16(norm, overflowShift)
	return out, nil
}

func autocorrEnergy(y []int16) int64 {
	var sum int64
	for _, sample := range y {
		sum += int64(sample) * int64(sample) * 2
	}
	return sum
}

func autocorrLag(y []int16, lag int) int64 {
	var sum int64
	for i := 0; i+lag < len(y); i++ {
		sum += int64(y[i]) * int64(y[i+lag]) * 2
	}
	if sum > int64(fxp.Max32) {
		return int64(fxp.Max32)
	}
	if sum < int64(fxp.Min32) {
		return int64(fxp.Min32)
	}
	return sum
}
