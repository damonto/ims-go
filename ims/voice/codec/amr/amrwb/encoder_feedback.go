/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This subframe feedback path follows the post-gain section of
 * amrwbenc/src/voAMRWBEnc.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func (e *Encoder) updateSubframeFeedback(ctx encoderSubframeContext, sf *encoderSubframePitch) error {
	aq := ctx.quantLPC()
	exc := ctx.excitationFrame()
	iSubframe := ctx.offset()
	shift := ctx.analysis.weighted.shift
	if len(aq) < lpcCoeffCount || len(exc) < iSubframe+subframeSamples {
		return errors.New("update subframe feedback: buffers are too short")
	}

	gainCode := fxp.Round(fxp.Shl32(sf.gainCode, e.preprocess.qOld))

	var exc2 [subframeSamples]int16
	copy(exc2[:], exc[iSubframe:iSubframe+subframeSamples])
	scaleSignalRound(exc2[:], shift)
	voiceFac := voiceFactor(exc2, shift, sf.gain, sf.code, gainCode)
	e.tiltCode = fxp.Add16(voiceFac>>2, 8192)

	last := subframeSamples - 1
	acc := int32(gainCode) * int32(sf.codeFiltered[last]) << 1
	acc = fxp.Shl32(acc, 5+shift)
	acc = fxp.Neg32(acc)
	acc += int32(sf.target[last]) * int32(16384) << 1
	acc -= int32(sf.filtered[last]) * int32(sf.gain) << 1
	acc = fxp.Shl32(acc, 1-shift)
	e.memW0 = fxp.Round(acc)
	for i := range subframeSamples {
		acc := int32(sf.code[i]) * int32(gainCode) << 1
		acc <<= 5
		acc += int32(exc[iSubframe+i]) * int32(sf.gain) << 1
		acc = fxp.Shl32(acc, 1)
		exc[iSubframe+i] = fxp.Round(acc)
	}

	synthesized, err := encoderSynthesisFilter(
		aq,
		exc[iSubframe:iSubframe+subframeSamples],
		e.memSyn[:],
		subframeSamples,
	)
	if err != nil {
		return fmt.Errorf("update subframe feedback: %w", err)
	}
	e.memSyn = synthesized.memory
	return nil
}
