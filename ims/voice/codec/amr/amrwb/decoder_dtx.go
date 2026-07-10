/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This comfort-noise path follows amr_wb/dec/src/dtx_decoder_amr_wb.cpp.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	dtxISFGap        int16 = 128
	dtxISFDitherGap  int16 = 448
	dtxISFFactorLow  int16 = 256
	dtxISFFactorStep int16 = 2
	dtxGainFactor    int16 = 75
)

type dtxSIDData struct {
	isf            [lpcOrder]int16
	logEnergyIndex int16
	dither         bool
}

type comfortNoiseFrame struct {
	isf        [lpcOrder]int16
	excitation [frameSamples12k8]int16
}

func (s *decoderCoreState) decodeComfortNoise(
	dst []int16,
	mode Mode,
	dtxState dtxStateType,
	sid dtxSIDData,
	badFrame bool,
) ([]int16, error) {
	if len(dst) < FrameSamples {
		return nil, errors.New("decode comfort noise: output buffer is too short")
	}
	noise := s.dtx.decodeComfortNoise(dtxState, sid)

	isp, err := isfToISP(noise.isf[:])
	if err != nil {
		return nil, fmt.Errorf("decode comfort noise: %w", err)
	}
	aq, err := ispToAz(isp[:], true)
	if err != nil {
		return nil, fmt.Errorf("decode comfort noise: %w", err)
	}

	oldISF := s.isfOld
	for iSubframe := 0; iSubframe < frameSamples12k8; iSubframe += subframeSamples {
		hfISF, err := interpolateISFForSubframe(oldISF[:], noise.isf[:], iSubframe/subframeSamples)
		if err != nil {
			return nil, fmt.Errorf("decode comfort noise: %w", err)
		}
		outOffset := iSubframe + (iSubframe >> 2)
		if _, err := s.synthesize(
			aq[:],
			noise.excitation[iSubframe:iSubframe+subframeSamples],
			0,
			dst[outOffset:outOffset+subframeSamples16k],
			1,
			hfISF[:],
			mode,
			dtxState,
			badFrame,
		); err != nil {
			return nil, fmt.Errorf("decode comfort noise: subframe %d: %w", iSubframe/subframeSamples, err)
		}
	}

	s.reset(false)
	copy(s.isfOld[:], noise.isf[:])
	s.dtx.globalState = dtxState
	return dst, nil
}

func (s *dtxDecState) decodeComfortNoise(
	newState dtxStateType,
	sid dtxSIDData,
) comfortNoiseFrame {
	var out comfortNoiseFrame
	if s.dtxHangoverAdded && s.sidFrame {
		ptr := int(s.histPtr) + 1
		if ptr == 8 {
			ptr = 0
		}
		copy(s.isfHist[ptr*lpcOrder:(ptr+1)*lpcOrder], s.isfHist[int(s.histPtr)*lpcOrder:int(s.histPtr+1)*lpcOrder])
		s.logEnergyHist[ptr] = s.logEnergyHist[s.histPtr]

		s.logEnergy = 0
		var sumISF [lpcOrder]int32
		for i := range 8 {
			s.logEnergy = fxp.Add16(s.logEnergy, s.logEnergyHist[i])
			for j := range lpcOrder {
				sumISF[j] = fxp.Add32(sumISF[j], int32(s.isfHist[i*lpcOrder+j]))
			}
		}
		s.logEnergy >>= 1
		s.logEnergy = fxp.Add16(s.logEnergy, 1024)

		s.logEnergy = max(s.logEnergy, 0)
		for j := range lpcOrder {
			s.isf[j] = int16(sumISF[j] >> 3)
		}
	}

	if s.sidFrame {
		copy(s.isfOld[:], s.isf[:])
		s.oldLogEnergy = s.logEnergy
		if s.validData {
			length := s.sinceLastSID
			length = min(length, 32)

			if length >= 2 {
				s.trueSIDPeriodInv = fxp.DivS(1<<10, fxp.Shl16(length, 10))
			} else {
				s.trueSIDPeriodInv = 1 << 14
			}
			copy(s.isf[:], sid.isf[:])
			s.cnDither = sid.dither
			s.logEnergy = fxp.Shl16(sid.logEnergyIndex, 15-6)
			s.logEnergy = fxp.Mult(s.logEnergy, 12483)
			if !s.dataUpdated || s.globalState == dtxStateSpeech {
				copy(s.isfOld[:], s.isf[:])
				s.oldLogEnergy = s.logEnergy
			}
		}
	}
	if s.sidFrame && s.validData {
		s.sinceLastSID = 0
	}

	interpolation := fxp.Shl16(s.sinceLastSID, 10)
	interpolation = fxp.Mult(interpolation, s.trueSIDPeriodInv)
	interpolation = min(interpolation, 1024)
	interpolation = fxp.Shl16(interpolation, 4)

	logEnergyInt := int32(interpolation) * int32(s.logEnergy) * 2
	for i := range lpcOrder {
		out.isf[i] = fxp.Mult(interpolation, s.isf[i])
	}

	inverse := fxp.Sub16(16384, interpolation)
	logEnergyInt = fxp.Add32(logEnergyInt, int32(inverse)*int32(s.oldLogEnergy)*2)
	for i := range lpcOrder {
		out.isf[i] = fxp.Add16(out.isf[i], fxp.Mult(inverse, s.isfOld[i]))
		out.isf[i] = fxp.Shl16(out.isf[i], 1)
	}

	if s.cnDither {
		dithered := cnDithering(out.isf, logEnergyInt, s.ditherSeed)
		out.isf = dithered.isf
		logEnergyInt = dithered.logEnergy
		s.ditherSeed = dithered.seed
	}

	logEnergyInt >>= 9
	logEnergyExp := fxp.ExtractH(logEnergyInt)
	logEnergyFrac := int16(fxp.Sub32(logEnergyInt, int32(logEnergyExp)<<16) >> 1)
	logEnergyExp += 15
	level32 := powerOf2WB(logEnergyExp, logEnergyFrac)
	exp0 := normalizeAMRWB(level32)
	level32 = fxp.Shl32(level32, exp0)
	exp0 = 15 - exp0
	level := int16(level32 >> 16)
	for i := range frameSamples12k8 {
		s.cngSeed = nextNoise(s.cngSeed)
		out.excitation[i] = s.cngSeed >> 4
	}
	energy, exp := dotProduct12(out.excitation[:], out.excitation[:], frameSamples12k8)
	energy, exp = oneOverSqrtNorm(energy, exp)
	gain := fxp.Mult(level, fxp.ExtractH(energy))
	exp += exp0 + 4
	for i := range frameSamples12k8 {
		out.excitation[i] = fxp.Shl16(fxp.Mult(out.excitation[i], gain), exp)
	}

	if newState == dtxStateMute {
		length := s.sinceLastSID

		length = min(length, 32)

		s.trueSIDPeriodInv = fxp.DivS(1<<10, fxp.Shl16(length, 10))
		s.sinceLastSID = 0
		s.oldLogEnergy = s.logEnergy
		s.logEnergy -= 64

		s.logEnergy = max(s.logEnergy, 0)

	}

	if s.sidFrame && (s.validData || (!s.validData && s.dtxHangoverAdded)) {
		s.sinceLastSID = 0
		s.dataUpdated = true
	}
	return out
}

func parseDTXSID(params []int16) (dtxSIDData, error) {
	var out dtxSIDData
	if len(params) < 7 {
		return out, errors.New("parse DTX SID: parameter buffer is too short")
	}
	isf, err := decodeISFNoise(params[:5])
	if err != nil {
		return out, fmt.Errorf("parse DTX SID: %w", err)
	}
	out.isf = isf
	out.logEnergyIndex = params[5]
	out.dither = params[6]&1 != 0
	return out, nil
}

func decodeISFNoise(indices []int16) ([lpcOrder]int16, error) {
	var isf [lpcOrder]int16
	if len(indices) < 5 {
		return isf, errors.New("decode noise ISF: index buffer is too short")
	}
	tables := [...]struct {
		values []int16
		width  int
	}{
		{values: dico1ISFNoise[:], width: 2},
		{values: dico2ISFNoise[:], width: 3},
		{values: dico3ISFNoise[:], width: 3},
		{values: dico4ISFNoise[:], width: 4},
		{values: dico5ISFNoise[:], width: 4},
	}
	for i, table := range tables {
		index := int(indices[i])
		if index < 0 || index >= len(table.values)/table.width {
			return isf, fmt.Errorf("decode noise ISF: index %d value %d is outside codebook", i, index)
		}
	}

	copy(isf[0:2], dico1ISFNoise[int(indices[0])*2:])
	copy(isf[2:5], dico2ISFNoise[int(indices[1])*3:])
	copy(isf[5:8], dico3ISFNoise[int(indices[2])*3:])
	copy(isf[8:12], dico4ISFNoise[int(indices[3])*4:])
	copy(isf[12:16], dico5ISFNoise[int(indices[4])*4:])
	for i := range lpcOrder {
		isf[i] = fxp.Add16(isf[i], meanISFNoise[i])
	}
	isf = reorderISF(isf, dtxISFGap)
	return isf, nil
}

type cnDitherResult struct {
	isf       [lpcOrder]int16
	logEnergy int32
	seed      int16
}

func cnDithering(isf [lpcOrder]int16, logEnergy int32, seed int16) cnDitherResult {
	seed = nextNoise(seed)
	first := seed
	seed = nextNoise(seed)
	second := seed
	randDith := (first >> 1) + (second >> 1)
	logEnergy = fxp.Add32(logEnergy, fxp.LMult(randDith, dtxGainFactor))
	if logEnergy < 0 {
		logEnergy = 0
	}

	ditherFactor := dtxISFFactorLow
	seed = nextNoise(seed)
	first = seed
	seed = nextNoise(seed)
	second = seed
	randDith = (first >> 1) + (second >> 1)
	temp := fxp.Add16(isf[0], fxp.MultRound(randDith, ditherFactor))
	if temp < dtxISFGap {
		isf[0] = dtxISFGap
	} else {
		isf[0] = temp
	}
	for i := 1; i < lpcOrder-1; i++ {
		ditherFactor = fxp.Add16(ditherFactor, dtxISFFactorStep)
		seed = nextNoise(seed)
		first = seed
		seed = nextNoise(seed)
		second = seed
		randDith = (first >> 1) + (second >> 1)
		temp = fxp.Add16(isf[i], fxp.MultRound(randDith, ditherFactor))
		if fxp.Sub16(temp, isf[i-1]) < dtxISFDitherGap {
			isf[i] = fxp.Add16(isf[i-1], dtxISFDitherGap)
		} else {
			isf[i] = temp
		}
	}

	isf[lpcOrder-2] = min(isf[lpcOrder-2], 16384)
	return cnDitherResult{isf: isf, logEnergy: logEnergy, seed: seed}
}

func (s *dtxDecState) activityUpdate(isf [lpcOrder]int16, exc [frameSamples12k8]int16) {
	s.histPtr++
	if s.histPtr == 8 {
		s.histPtr = 0
	}
	copy(s.isfHist[int(s.histPtr)*lpcOrder:int(s.histPtr+1)*lpcOrder], isf[:])

	var frameEnergy int32
	for i := range exc {
		frameEnergy = fxp.Add32(frameEnergy, fxp.LMult(exc[i], exc[i]))
	}
	frameEnergy >>= 1
	exp, frac := log2WB(frameEnergy)
	logEnergy := fxp.Shl16(exp, 7)
	logEnergy = fxp.Add16(logEnergy, frac>>8)
	logEnergy = fxp.Sub16(logEnergy, 1024)
	s.logEnergyHist[s.histPtr] = logEnergy
}
