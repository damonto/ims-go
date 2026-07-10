/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This encoder-side PLSF quantization is ported from common/src/q_plsf_3.cpp
 * and common/src/q_plsf_5.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type quantizedPLSF3 struct {
	lsp      [lpcOrder]int16
	indices  [3]int16
	predInit int16
}

type quantizedPLSF5 struct {
	lsp1    [lpcOrder]int16
	lsp2    [lpcOrder]int16
	indices [5]int16
}

func lsfWeight(lsf []int16) ([lpcOrder]int16, error) {
	var wf [lpcOrder]int16
	if len(lsf) < lpcOrder {
		return wf, fmt.Errorf("weighting AMR-NB LSF: coefficient count %d, want at least %d", len(lsf), lpcOrder)
	}

	wf[0] = lsf[1]
	for i := 1; i < lpcOrder-1; i++ {
		wf[i] = lsf[i+1] - lsf[i-1]
	}
	wf[lpcOrder-1] = 16384 - lsf[lpcOrder-2]
	for i := range lpcOrder {
		wgt := wf[i]
		if temp := wgt - 1843; temp > 0 {
			wgt = 1843 - int16((int32(temp)*6242)>>15)
		} else {
			wgt = 3427 - int16((int32(wgt)*28160)>>15)
		}
		wf[i] = wgt << 3
	}
	return wf, nil
}

func (s *dPLSFState) quantize3(mode Mode, lsp []int16) (quantizedPLSF3, error) {
	var out quantizedPLSF3
	if err := validatePLSF3Mode(mode); err != nil {
		return out, fmt.Errorf("quantizing AMR-NB PLSF3: %w", err)
	}
	if len(lsp) < lpcOrder {
		return out, fmt.Errorf("quantizing AMR-NB PLSF3: LSP coefficient count %d, want at least %d", len(lsp), lpcOrder)
	}

	lsf := lspToLsf(lsp)
	var wf, lsfP, lsfR, lsfQ [lpcOrder]int16
	var err error
	wf, err = lsfWeight(lsf[:])
	if err != nil {
		return out, err
	}

	if mode == ModeDTX {
		out.predInit, lsfP, lsfR = selectInitVector(lsf)
	} else {
		for i := range lpcOrder {
			lsfP[i] = fxp.Add16(meanLSF3[i], fxp.Mult(s.pastRQ[i], predFac3[i]))
			lsfR[i] = fxp.Sub16(lsf[i], lsfP[i])
		}
	}

	switch mode {
	case Mode475, Mode515:
		out.indices[0] = vqSubvec3(lsfR[0:3], dico1LSF3[:], wf[0:3], 256, false)
		out.indices[1] = vqSubvec3(lsfR[3:6], dico2LSF3[:], wf[3:6], 256, true)
		out.indices[2] = vqSubvec4(lsfR[6:10], mr5153LSF[:], wf[6:10], 128)
	case Mode795:
		out.indices[0] = vqSubvec3(lsfR[0:3], mr7951LSF[:], wf[0:3], 512, false)
		out.indices[1] = vqSubvec3(lsfR[3:6], dico2LSF3[:], wf[3:6], 512, false)
		out.indices[2] = vqSubvec4(lsfR[6:10], dico3LSF3[:], wf[6:10], 512)
	default:
		out.indices[0] = vqSubvec3(lsfR[0:3], dico1LSF3[:], wf[0:3], 256, false)
		out.indices[1] = vqSubvec3(lsfR[3:6], dico2LSF3[:], wf[3:6], 512, false)
		out.indices[2] = vqSubvec4(lsfR[6:10], dico3LSF3[:], wf[6:10], 512)
	}
	for i := range lpcOrder {
		lsfQ[i] = fxp.Add16(lsfR[i], lsfP[i])
	}
	reorderLSF(lsfQ[:], lsfGap)
	out.lsp = lsfToLsp(lsfQ[:])
	s.pastRQ = lsfR
	s.pastLSFQ = lsfQ
	return out, nil
}

func selectInitVector(lsf [lpcOrder]int16) (int16, [lpcOrder]int16, [lpcOrder]int16) {
	var best int16
	bestErr := int64(fxp.Max32)
	var bestP, bestR, tempP, tempR [lpcOrder]int16
	for j := range 8 {
		err := int64(0)
		for i := range lpcOrder {
			tempP[i] = fxp.Add16(meanLSF3[i], pastRQInit[j*lpcOrder+i])
			tempR[i] = fxp.Sub16(lsf[i], tempP[i])
			err += int64(tempR[i]) * int64(tempR[i]) * 2
		}
		if err < bestErr {
			bestErr = err
			best = int16(j)
			bestP = tempP
			bestR = tempR
		}
	}

	return best, bestP, bestR
}

func (s *dPLSFState) quantize5(lsp1, lsp2 []int16) (quantizedPLSF5, error) {
	var out quantizedPLSF5
	if len(lsp1) < lpcOrder || len(lsp2) < lpcOrder {
		return out, fmt.Errorf(
			"quantizing AMR-NB PLSF5: LSP coefficient counts %d/%d, want at least %d",
			len(lsp1),
			len(lsp2),
			lpcOrder,
		)
	}

	lsf1 := lspToLsf(lsp1)
	lsf2 := lspToLsf(lsp2)
	var wf1, wf2 [lpcOrder]int16
	var lsfP, lsfR1, lsfR2 [lpcOrder]int16
	var lsf1Q, lsf2Q [lpcOrder]int16

	var err error
	wf1, err = lsfWeight(lsf1[:])
	if err != nil {
		return out, err
	}
	wf2, err = lsfWeight(lsf2[:])
	if err != nil {
		return out, err
	}
	for i := range lpcOrder {
		lsfP[i] = fxp.Add16(meanLSF5[i], fxp.Mult(s.pastRQ[i], lspPredFacMR122))
		lsfR1[i] = fxp.Sub16(lsf1[i], lsfP[i])
		lsfR2[i] = fxp.Sub16(lsf2[i], lsfP[i])
	}

	out.indices[0] = vqSubvec(lsfR1[0:2], lsfR2[0:2], dico1LSF5[:], wf1[0:2], wf2[0:2], 128)
	out.indices[1] = vqSubvec(lsfR1[2:4], lsfR2[2:4], dico2LSF5[:], wf1[2:4], wf2[2:4], 256)
	out.indices[2] = vqSubvecSigned(lsfR1[4:6], lsfR2[4:6], dico3LSF5[:], wf1[4:6], wf2[4:6], 256)
	out.indices[3] = vqSubvec(lsfR1[6:8], lsfR2[6:8], dico4LSF5[:], wf1[6:8], wf2[6:8], 256)
	out.indices[4] = vqSubvec(lsfR1[8:10], lsfR2[8:10], dico5LSF5[:], wf1[8:10], wf2[8:10], 64)
	for i := range lpcOrder {
		lsf1Q[i] = fxp.Add16(lsfR1[i], lsfP[i])
		lsf2Q[i] = fxp.Add16(lsfR2[i], lsfP[i])
	}

	reorderLSF(lsf1Q[:], lsfGap)
	reorderLSF(lsf2Q[:], lsfGap)
	out.lsp1 = lsfToLsp(lsf1Q[:])
	out.lsp2 = lsfToLsp(lsf2Q[:])
	s.pastRQ = lsfR2
	s.pastLSFQ = lsf2Q
	return out, nil
}

func vqSubvec4(lsfR []int16, dico []int16, wf []int16, size int) int16 {
	index := 0
	distMin := int64(fxp.Max32)
	for i := range size {
		offset := i * 4
		dist := int64(0)
		for j := range 4 {
			temp := int16((int32(wf[j]) * int32(lsfR[j]-dico[offset+j])) >> 15)
			dist += int64(temp) * int64(temp)
		}
		if dist < distMin {
			distMin = dist
			index = i
		}
	}
	copy(lsfR[:4], dico[index*4:index*4+4])
	return int16(index)
}

func vqSubvec3(lsfR []int16, dico []int16, wf []int16, size int, useHalf bool) int16 {
	index := 0
	distMin := int64(fxp.Max32)
	step := 3
	if useHalf {
		step = 6
	}
	for i := range size {
		offset := i * step
		dist := int64(0)
		for j := range 3 {
			temp := int16((int32(wf[j]) * int32(lsfR[j]-dico[offset+j])) >> 15)
			dist += int64(temp) * int64(temp)
		}
		if dist < distMin {
			distMin = dist
			index = i
		}
	}
	offset := index * step
	copy(lsfR[:3], dico[offset:offset+3])
	return int16(index)
}

func vqSubvec(lsfR1 []int16, lsfR2 []int16, dico []int16, wf1 []int16, wf2 []int16, size int) int16 {
	index := 0
	distMin := int64(fxp.Max32)
	for i := range size {
		offset := i * 4
		dist := vqPairDist(lsfR1, lsfR2, dico[offset:offset+4], wf1, wf2, false)
		if dist < distMin {
			distMin = dist
			index = i
		}
	}
	offset := index * 4
	lsfR1[0], lsfR1[1] = dico[offset], dico[offset+1]
	lsfR2[0], lsfR2[1] = dico[offset+2], dico[offset+3]
	return int16(index)
}

func vqSubvecSigned(lsfR1 []int16, lsfR2 []int16, dico []int16, wf1 []int16, wf2 []int16, size int) int16 {
	index := 0
	sign := int16(0)
	distMin := int64(fxp.Max32)
	for i := range size {
		offset := i * 4
		if dist := vqPairDist(lsfR1, lsfR2, dico[offset:offset+4], wf1, wf2, false); dist < distMin {
			distMin = dist
			index = i
			sign = 0
		}
		if dist := vqPairDist(lsfR1, lsfR2, dico[offset:offset+4], wf1, wf2, true); dist < distMin {
			distMin = dist
			index = i
			sign = 1
		}
	}

	offset := index * 4
	for i := range 2 {
		value := dico[offset+i]
		value2 := dico[offset+2+i]
		if sign != 0 {
			value = fxp.Neg16(value)
			value2 = fxp.Neg16(value2)
		}
		lsfR1[i] = value
		lsfR2[i] = value2
	}

	return int16(index*2) + sign
}

func vqPairDist(lsfR1 []int16, lsfR2 []int16, vector []int16, wf1 []int16, wf2 []int16, negate bool) int64 {
	dist := int64(0)
	for i := range 2 {
		value1 := vector[i]
		value2 := vector[i+2]
		if negate {
			value1 = fxp.Neg16(value1)
			value2 = fxp.Neg16(value2)
		}
		temp := int16((int32(wf1[i]) * int32(lsfR1[i]-value1)) >> 15)
		dist += int64(temp) * int64(temp)
		temp = int16((int32(wf2[i]) * int32(lsfR2[i]-value2)) >> 15)
		dist += int64(temp) * int64(temp)
	}
	return dist
}
