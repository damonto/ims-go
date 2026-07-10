/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/ex_ctrl.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func controlExcitation(
	excitation []int16,
	excEnergy int16,
	energyHist []int16,
	voicedHangover int16,
	prevBFI int16,
	carefulFlag int16,
) ([subframeSamples]int16, error) {
	var out [subframeSamples]int16
	if len(excitation) < subframeSamples {
		return out, fmt.Errorf(
			"controlling AMR-NB excitation: sample count %d, want at least %d",
			len(excitation),
			subframeSamples,
		)
	}
	if len(energyHist) < excitationHistoryLen {
		return out, fmt.Errorf(
			"controlling AMR-NB excitation: energy history count %d, want at least %d",
			len(energyHist),
			excitationHistoryLen,
		)
	}
	copy(out[:], excitation[:subframeSamples])

	avgEnergy := gmedN(energyHist[:excitationHistoryLen])
	prevEnergy := int16((int32(energyHist[7]) + int32(energyHist[8])) >> 1)
	prevEnergy = min(prevEnergy, energyHist[8])

	if excEnergy >= avgEnergy || excEnergy <= 5 {
		return out, nil
	}

	testEnergy := fxp.Shl16(prevEnergy, 2)
	if voicedHangover < 7 || prevBFI != 0 {
		testEnergy = fxp.Sub16(testEnergy, prevEnergy)
	}

	avgEnergy = min(avgEnergy, testEnergy)

	exp := fxp.NormS(excEnergy)
	normalizedEnergy := fxp.Shl16(excEnergy, exp)
	reciprocal := fxp.DivS(16383, normalizedEnergy)
	acc := fxp.LMult(avgEnergy, reciprocal)
	acc = fxp.Shr32(acc, fxp.Sub16(20, exp))

	acc = min(acc, int32(fxp.Max16))

	scaleFactor := int16(acc)
	if carefulFlag != 0 && scaleFactor > 3072 {
		scaleFactor = 3072
	}

	for i := range out {
		sample := fxp.LMult(scaleFactor, out[i])
		out[i] = int16(fxp.Shr32(sample, 11))
	}
	return out, nil
}
