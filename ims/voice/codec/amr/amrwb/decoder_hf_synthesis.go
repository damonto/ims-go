/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This HF noise gain flow follows amr_wb/dec/src/synthesis_amr_wb.cpp.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

var hpGain = [...]int16{
	3624, 4673, 5597, 6479, 7425, 8378, 9324, 10264,
	11210, 12206, 13391, 14844, 16770, 19655, 24289, 32728,
}

func generateHFNoise(seed int16) ([subframeSamples16k]int16, int16) {
	var hf [subframeSamples16k]int16
	for i := range hf {
		seed = nextNoise(seed)
		hf[i] = seed >> 3
	}
	return hf, seed
}

func scaleHFNoiseToExcitation(
	hf [subframeSamples16k]int16,
	exc []int16,
	qNew int16,
) ([subframeSamples16k]int16, error) {
	if len(exc) < subframeSamples {
		return hf, errors.New("scale high-frequency noise: excitation buffer is too short")
	}
	var scaledExc [subframeSamples]int16
	for i := range subframeSamples {
		scaledExc[i] = exc[i]
	}
	scaleSignalExact(scaledExc[:], -3)
	qAdjusted := qNew - 3

	energy, expEner := dotProduct12(scaledExc[:], scaledExc[:], subframeSamples)
	ener := fxp.ExtractH(energy)
	expEner -= qAdjusted << 1
	if ener <= 0 {
		return hf, nil
	}

	hfEnergy, exp := dotProduct12(hf[:subframeSamples16k], hf[:subframeSamples16k], subframeSamples16k)
	hfEner := fxp.ExtractH(hfEnergy)
	if hfEner <= 0 {
		return hf, nil
	}
	if hfEner > ener {
		hfEner >>= 1
		exp++
	}
	scale := int32(fxp.DivS(hfEner, ener)) << 16
	exp -= expEner
	scale, exp = oneOverSqrtNorm(scale, exp)
	scale = fxp.Shl32(scale, exp+1)
	gain := int16(scale >> 16)
	for i := range subframeSamples16k {
		hf[i] = fxp.Mult(hf[i], gain)
	}
	return hf, nil
}

type hfTiltResult struct {
	gain   int16
	memory [6]int16
}

func hfGainFromTilt(synth [subframeSamples]int16, memory [6]int16, vadHistory int16) hfTiltResult {
	memory = highpass400HzAt12k8(synth[:], memory)

	corr0 := int32(1)
	corr1 := int32(1)
	corr0 = fxp.Add32(corr0, fxp.LMult(synth[0], synth[0]))
	for i := 1; i < subframeSamples; i++ {
		corr0 = fxp.Add32(corr0, fxp.LMult(synth[i], synth[i]))
		corr1 = fxp.Add32(corr1, fxp.LMult(synth[i], synth[i-1]))
	}

	exp := normalizeAMRWB(corr0)
	ener := int16(fxp.Shl32(corr0, exp) >> 16)
	tmp := int16(fxp.Shl32(corr1, exp) >> 16)

	fac := int16(0)
	if tmp > 0 {
		fac = fxp.DivS(tmp, ener)
	}
	gain1 := fxp.Sub16(fxp.Max16, fac)
	gain2 := fxp.Shl16(fxp.Mult(gain1, 20480), 1)

	if vadHistory > 0 {
		tmp = gain2 - 1
	} else {
		tmp = gain1 - 1
	}
	if tmp != 0 {
		tmp++
	}
	tmp = max(tmp, 3277)
	return hfTiltResult{gain: tmp, memory: memory}
}

func applyHFGain(hf []int16, gain int16) {
	for i := range hf {
		hf[i] = fxp.Mult(hf[i], gain)
	}
}

func applyHFCorrectionGain(hf []int16, index int16) error {
	if len(hf) < subframeSamples16k {
		return errors.New("apply high-frequency correction gain: buffer is too short")
	}
	if index < 0 || int(index) >= len(hpGain) {
		return fmt.Errorf("apply high-frequency correction gain: index %d is outside table", index)
	}
	gain := hpGain[index]
	for i := range subframeSamples16k {
		hf[i] = fxp.Shl16(fxp.Mult(hf[i], gain), 1)
	}
	return nil
}
