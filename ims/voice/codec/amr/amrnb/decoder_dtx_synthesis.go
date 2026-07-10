/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This comfort-noise synthesis path is ported from amr_nb/dec/src/dtx_dec.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

func (s *decoderCoreState) synthesizeComfortNoise(dst []int16) []int16 {
	if cap(dst) < FrameSamples {
		dst = make([]int16, 0, FrameSamples)
	} else {
		dst = dst[:0]
	}

	var lspInt [lpcOrder]int16
	var lspIntVariab [lpcOrder]int16
	var lsfIntVariab [lpcOrder]int16
	var excitation [subframeSamples]int16
	dtx := &s.dtx

	intFac := fxp.Shl16(fxp.Add16(dtx.sinceLastSID, 1), 10)
	intFac = fxp.Mult(intFac, dtx.trueSIDPeriodInv)
	switch {
	case intFac > 1024:
		intFac = 16384
	case intFac < -2048:
		intFac = fxp.Min16
	default:
		intFac = fxp.Shl16(intFac, 4)
	}

	logEnergyInt := fxp.LMult(intFac, dtx.logEnergy)
	for i := range lpcOrder {
		lspInt[i] = fxp.Mult(intFac, dtx.lsp[i])
	}

	invIntFac := fxp.Sub16(16384, intFac)
	logEnergyInt = fxp.Add32(logEnergyInt, fxp.LMult(invIntFac, dtx.oldLogEnergy))
	for i := range lpcOrder {
		lspInt[i] = fxp.Add16(lspInt[i], fxp.Mult(invIntFac, dtx.lspOld[i]))
		lspInt[i] = fxp.Shl16(lspInt[i], 1)
	}

	lsfVariabFactor := fxp.Sub16(dtx.logPGMean, 2457)
	lsfVariabFactor = fxp.Sub16(4096, fxp.Mult(lsfVariabFactor, 9830))
	if lsfVariabFactor > 4095 {
		lsfVariabFactor = fxp.Max16
	} else if lsfVariabFactor < 0 {
		lsfVariabFactor = 0
	} else {
		lsfVariabFactor = fxp.Shl16(lsfVariabFactor, 3)
	}

	lsfVariabIndex, nextSeed := pseudoNoise(dtx.pnSeedRX, 3)
	dtx.pnSeedRX = nextSeed
	lsfInt := lspToLsf(lspInt[:])
	copy(lsfIntVariab[:], lsfInt[:])
	for i := range lpcOrder {
		offset := int(lsfVariabIndex)*lpcOrder + i
		lsfIntVariab[i] = fxp.Add16(
			lsfIntVariab[i],
			fxp.Mult(lsfVariabFactor, dtx.lsfHistMean[offset]),
		)
	}

	reorderLSF(lsfInt[:], lsfGap)
	reorderLSF(lsfIntVariab[:], lsfGap)
	copy(s.lsfState.pastLSFQ[:], lsfInt[:])
	lspInt = lsfToLsp(lsfInt[:])
	lspIntVariab = lsfToLsp(lsfIntVariab[:])

	acoeff := lspToAz(lspInt[:])
	acoeffVariab := lspToAz(lspIntVariab[:])
	for i := range 4 {
		copy(s.az[i*lpcCoeffCount:(i+1)*lpcCoeffCount], acoeff[:])
	}

	refl := reflectionCoefficients(acoeff[1:])
	predErr := int16(fxp.Max16)
	for i := range lpcOrder {
		predErr = fxp.Mult(predErr, fxp.Sub16(fxp.Max16, fxp.Mult(refl[i], refl[i])))
	}

	logPGE, logPGM := log2Value(int32(predErr))
	logPG := fxp.Shl16(fxp.Sub16(logPGE, 15), 12)
	logPG = fxp.Shr16(
		fxp.Sub16(0, fxp.Add16(logPG, fxp.Shr16(logPGM, 3))),
		1,
	)
	dtx.logPGMean = fxp.Add16(
		fxp.Mult(29491, dtx.logPGMean),
		fxp.Mult(3277, logPG),
	)

	logEnergyInt = fxp.Shr32(logEnergyInt, 10)
	logEnergyInt = fxp.Add32(logEnergyInt, 4*65536)
	logEnergyInt = fxp.Sub32(logEnergyInt, fxp.Shl32(int32(logPG), 4))
	logEnergyInt = fxp.Add32(logEnergyInt, fxp.Shl32(int32(dtx.logEnergyAdjust), 5))

	logEnergyE := fxp.ExtractH(logEnergyInt)
	logEnergyM := fxp.ExtractL(
		fxp.Shr32(fxp.Sub32(logEnergyInt, int32(logEnergyE)<<16), 1),
	)
	level := int16(pow2Value(logEnergyE, logEnergyM))
	for range 4 {
		_, dtx.pnSeedRX = buildCNCode(dtx.pnSeedRX, excitation[:])
		for j := range subframeSamples {
			excitation[j] = fxp.Mult(level, excitation[j])
		}
		var subframe [subframeSamples]int16
		s.memSyn = synthesisFilter(acoeffVariab[:], excitation[:], subframe[:], s.memSyn[:])
		dst = append(dst, subframe[:]...)
	}

	s.cbGainAvg.hangVar = 20
	s.cbGainAvg.hangCount = 0
	if s.lastDTXState == dtxStateMute {
		dtx.muteComfortNoise()
	}
	return dst
}
