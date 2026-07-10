/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * These encoder ISF conversion and quantization routines are ported from
 * amrwbenc/src/isp_isf.c and amrwbenc/src/qpisf_2s.c.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type encoderISFQuantState struct {
	pastISFQ [lpcOrder]int16
	ispOldQ  [lpcOrder]int16
	isfOld   [lpcOrder]int16
	first    bool
}

func (s *encoderISFQuantState) reset() {
	clear(s.pastISFQ[:])
	copy(s.ispOldQ[:], initialISP[:])
	copy(s.isfOld[:], initialISF[:])
	s.first = true
}

type encoderQuantizedLPC struct {
	isf        [lpcOrder]int16
	isfQ       [lpcOrder]int16
	ispQ       [lpcOrder]int16
	aq         [4 * lpcCoeffCount]int16
	stability  int16
	indices    [7]int16
	indexCount int
}

func ispToISF(isp []int16) ([lpcOrder]int16, error) {
	var isf [lpcOrder]int16
	if len(isp) < lpcOrder {
		return isf, errors.New("convert ISP to ISF: buffer is too short")
	}
	index := len(ispCosTable) - 2
	for i := lpcOrder - 1; i >= 0; i-- {
		if i >= lpcOrder-2 {
			index = len(ispCosTable) - 2
		}
		for index > 0 && ispCosTable[index] < isp[i] {
			index--
		}
		diff := fxp.Sub16(isp[i], ispCosTable[index])
		acc := fxp.LMult(diff, ispToISFSlope[index])
		isf[i] = fxp.Round(fxp.Shl32(acc, 4))
		isf[i] = fxp.Add16(isf[i], int16(index<<7))
	}
	isf[lpcOrder-1] = fxp.Shr16(isf[lpcOrder-1], 1)
	return isf, nil
}

type quantizedISF struct {
	isf        [lpcOrder]int16
	indices    [7]int16
	indexCount int
}

func (s *encoderISFQuantState) quantize(mode Mode, isf []int16) (quantizedISF, error) {
	if mode == Mode660 {
		return s.quantize36(isf)
	}
	return s.quantize46(isf)
}

func (s *encoderISFQuantState) quantizeLPC(mode Mode, isp []int16) (encoderQuantizedLPC, error) {
	var out encoderQuantizedLPC
	if len(isp) < lpcOrder {
		return out, errors.New("quantize LPC: ISP buffer is too short")
	}
	var err error
	out.isf, err = ispToISF(isp)
	if err != nil {
		return out, fmt.Errorf("quantize LPC: %w", err)
	}
	quantized, err := s.quantize(mode, out.isf[:])
	if err != nil {
		return out, fmt.Errorf("quantize LPC: %w", err)
	}
	out.isfQ = quantized.isf
	out.indices = quantized.indices
	out.indexCount = quantized.indexCount
	out.stability = isfStability(out.isfQ[:], s.isfOld[:])
	copy(s.isfOld[:], out.isfQ[:])
	out.ispQ, err = isfToISP(out.isfQ[:])
	if err != nil {
		return out, fmt.Errorf("quantize LPC: %w", err)
	}
	if s.first {
		s.first = false
		copy(s.ispOldQ[:], out.ispQ[:])
	}
	out.aq, err = interpolateISP(s.ispOldQ[:], out.ispQ[:])
	if err != nil {
		return out, fmt.Errorf("quantize LPC: %w", err)
	}
	copy(s.ispOldQ[:], out.ispQ[:])
	return out, nil
}

func (s *encoderISFQuantState) quantize46(isfIn []int16) (quantizedISF, error) {
	var out quantizedISF
	out.indexCount = 7
	if len(isfIn) < lpcOrder {
		return out, errors.New("46-bit ISF quantization buffer is too short")
	}
	var isf [lpcOrder]int16
	var isfStage2 [lpcOrder]int16
	for i := range lpcOrder {
		isf[i] = fxp.Sub16(isfIn[i], meanIsf[i])
		isf[i] = fxp.Sub16(isf[i], fxp.Mult(isfMu, s.pastISFQ[i]))
	}

	survivors := vqStage1(isf[:9], dico1Isf[:], 9, 4)
	bestDistance := fxp.Max32
	var tmp [5]int16
	for _, survivor := range survivors {
		for i := range 9 {
			isfStage2[i] = fxp.Sub16(isf[i], codebookValue(dico1Isf[:], int(survivor), 9, i))
		}
		idx0, dist := subVQ(isfStage2[:3], dico21Isf[:], 3)
		tmpDistance := dist
		idx1, dist := subVQ(isfStage2[3:6], dico22Isf[:], 3)
		tmpDistance = fxp.Add32(tmpDistance, dist)
		idx2, dist := subVQ(isfStage2[6:9], dico23Isf[:], 3)
		tmpDistance = fxp.Add32(tmpDistance, dist)
		if tmpDistance < bestDistance {
			bestDistance = tmpDistance
			out.indices[0] = survivor
			tmp[0] = idx0
			tmp[1] = idx1
			tmp[2] = idx2
		}
	}
	copy(out.indices[2:5], tmp[:3])

	survivors = vqStage1(isf[9:], dico2Isf[:], 7, 4)
	bestDistance = fxp.Max32
	for _, survivor := range survivors {
		for i := range 7 {
			isfStage2[i] = fxp.Sub16(isf[9+i], codebookValue(dico2Isf[:], int(survivor), 7, i))
		}
		idx0, dist := subVQ(isfStage2[:3], dico24Isf[:], 3)
		tmpDistance := dist
		idx1, dist := subVQ(isfStage2[3:7], dico25Isf[:], 4)
		tmpDistance = fxp.Add32(tmpDistance, dist)
		if tmpDistance < bestDistance {
			bestDistance = tmpDistance
			out.indices[1] = survivor
			tmp[0] = idx0
			tmp[1] = idx1
		}
	}
	out.indices[5] = tmp[0]
	out.indices[6] = tmp[1]

	decoder := isfDecodeState{pastResidual: s.pastISFQ[:]}
	decoded, err := decoder.decode46(out.indices[:7])
	if err != nil {
		return out, fmt.Errorf("quantize 46-bit ISF: reconstruct ISF: %w", err)
	}
	out.isf = decoded
	return out, nil
}

func (s *encoderISFQuantState) quantize36(isfIn []int16) (quantizedISF, error) {
	var out quantizedISF
	out.indexCount = 5
	if len(isfIn) < lpcOrder {
		return out, errors.New("36-bit ISF quantization buffer is too short")
	}
	var isf [lpcOrder]int16
	var isfStage2 [lpcOrder]int16
	for i := range lpcOrder {
		isf[i] = fxp.Sub16(isfIn[i], meanIsf[i])
		isf[i] = fxp.Sub16(isf[i], fxp.Mult(isfMu, s.pastISFQ[i]))
	}

	survivors := vqStage1(isf[:9], dico1Isf[:], 9, 4)
	bestDistance := fxp.Max32
	var tmp [5]int16
	for _, survivor := range survivors {
		for i := range 9 {
			isfStage2[i] = fxp.Sub16(isf[i], codebookValue(dico1Isf[:], int(survivor), 9, i))
		}
		idx0, dist := subVQ(isfStage2[:5], dico21Isf36b[:], 5)
		tmpDistance := dist
		idx1, dist := subVQ(isfStage2[5:9], dico22Isf36b[:], 4)
		tmpDistance = fxp.Add32(tmpDistance, dist)
		if tmpDistance < bestDistance {
			bestDistance = tmpDistance
			out.indices[0] = survivor
			tmp[0] = idx0
			tmp[1] = idx1
		}
	}
	out.indices[2] = tmp[0]
	out.indices[3] = tmp[1]

	survivors = vqStage1(isf[9:], dico2Isf[:], 7, 4)
	bestDistance = fxp.Max32
	for _, survivor := range survivors {
		for i := range 7 {
			isfStage2[i] = fxp.Sub16(isf[9+i], codebookValue(dico2Isf[:], int(survivor), 7, i))
		}
		idx0, dist := subVQ(isfStage2[:7], dico23Isf36b[:], 7)
		if dist < bestDistance {
			bestDistance = dist
			out.indices[1] = survivor
			out.indices[4] = idx0
		}
	}

	decoder := isfDecodeState{pastResidual: s.pastISFQ[:]}
	decoded, err := decoder.decode36(out.indices[:5])
	if err != nil {
		return out, fmt.Errorf("quantize 36-bit ISF: reconstruct ISF: %w", err)
	}
	out.isf = decoded
	return out, nil
}

func subVQ(x []int16, codebook []int16, width int) (int16, int32) {
	size := len(codebook) / width
	bestIndex := 0
	bestDistance := fxp.Max32
	for i := range size {
		var distance int32
		for j := range width {
			diff := int32(x[j]) - int32(codebook[i*width+j])
			distance += (diff * diff) << 1
		}
		if distance < bestDistance {
			bestDistance = distance
			bestIndex = i
		}
	}
	copy(x[:width], codebook[bestIndex*width:bestIndex*width+width])
	return int16(bestIndex), bestDistance
}

func vqStage1(x []int16, codebook []int16, width int, survivorCount int) []int16 {

	survivorCount = min(survivorCount, 4)

	distances := [4]int32{fxp.Max32, fxp.Max32, fxp.Max32, fxp.Max32}
	indices := [4]int16{0, 1, 2, 3}
	size := len(codebook) / width
	for i := range size {
		var distance int32
		for j := range width {
			diff := int32(x[j]) - int32(codebook[i*width+j])
			distance += (diff * diff) << 1
		}
		for k := range survivorCount {
			if distance >= distances[k] {
				continue
			}
			for l := survivorCount - 1; l > k; l-- {
				distances[l] = distances[l-1]
				indices[l] = indices[l-1]
			}
			distances[k] = distance
			indices[k] = int16(i)
			break
		}
	}
	return indices[:survivorCount]
}

var ispToISFSlope = [...]int16{
	-26214, -9039, -5243, -3799, -2979, -2405, -2064, -1771,
	-1579, -1409, -1279, -1170, -1079, -1004, -933, -880,
	-827, -783, -743, -708, -676, -647, -621, -599,
	-576, -557, -538, -521, -506, -492, -479, -466,
	-456, -445, -435, -426, -417, -410, -402, -395,
	-389, -383, -377, -372, -367, -363, -359, -355,
	-351, -348, -345, -342, -340, -337, -335, -333,
	-331, -330, -329, -328, -327, -326, -326, -326,
	-326, -326, -326, -327, -328, -329, -330, -331,
	-333, -335, -337, -340, -342, -345, -348, -351,
	-355, -359, -363, -367, -372, -377, -383, -389,
	-395, -402, -410, -417, -426, -435, -445, -456,
	-466, -479, -492, -506, -521, -538, -557, -576,
	-599, -621, -647, -676, -708, -743, -783, -827,
	-880, -933, -1004, -1079, -1170, -1279, -1409, -1579,
	-1771, -2064, -2405, -2979, -3799, -5243, -9039, -26214,
}
