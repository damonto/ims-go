/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This innovation-target preparation is ported from the subframe loop in
 * amrwbenc/src/voAMRWBEnc.c and preemph.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func innovationSearchTarget(
	quantizedLPC []int16,
	weightedLPC []int16,
	target []int16,
	residual []int16,
) ([subframeSamples]int16, error) {
	var dst [subframeSamples]int16
	if len(quantizedLPC) < lpcCoeffCount || len(weightedLPC) < lpcCoeffCount ||
		len(target) < subframeSamples || len(residual) < subframeSamples {
		return dst, errors.New("prepare innovation search target: buffers are too short")
	}

	var work [lpcOrder + subframeSamples/2]int16
	copy(work[lpcOrder:], target[:subframeSamples/2])
	_ = preemphasis2(work[lpcOrder:], encoderTiltFac, 0) // This temporary target has no history across calls.
	synthesized, err := encoderSynthesisFilter(
		weightedLPC,
		work[lpcOrder:],
		work[:lpcOrder],
		subframeSamples/2,
	)
	if err != nil {
		return dst, fmt.Errorf("prepare innovation search target: %w", err)
	}
	copy(work[lpcOrder:], synthesized.signal[:subframeSamples/2])
	if err := encoderResidual(quantizedLPC, work[:], dst[:subframeSamples/2]); err != nil {
		return dst, fmt.Errorf("prepare innovation search target: %w", err)
	}
	copy(dst[subframeSamples/2:subframeSamples], residual[subframeSamples/2:subframeSamples])
	return dst, nil
}

func preemphasis2(x []int16, mu int16, mem int16) int16 {
	if len(x) == 0 {
		return mem
	}
	temp := x[len(x)-1]
	for i := len(x) - 1; i > 0; i-- {
		acc := fxp.LDepositH(x[i])
		acc = fxp.LMsu(acc, x[i-1], mu)
		acc = fxp.Shl32(acc, 1)
		x[i] = fxp.Round(acc)
	}
	acc := fxp.LDepositH(x[0])
	acc = fxp.LMsu(acc, mem, mu)
	acc = fxp.Shl32(acc, 1)
	x[0] = fxp.Round(acc)
	return temp
}
