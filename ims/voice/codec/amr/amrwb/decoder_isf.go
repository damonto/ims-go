/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/qpisf_2s.cpp.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	isfMu       int16 = 10923
	isfAlpha    int16 = 29491
	isfOneAlpha int16 = 3277
	isfGap      int16 = 128
)

type isfDecodeState struct {
	pastResidual []int16
	history      []int16
}

type isfCodebook struct {
	name   string
	values []int16
	width  int
}

func (s isfDecodeState) decode46(indices []int16) ([lpcOrder]int16, error) {
	var dst [lpcOrder]int16
	codebooks := [...]isfCodebook{
		{name: "stage 1-1", values: dico1Isf[:], width: 9},
		{name: "stage 1-2", values: dico2Isf[:], width: 7},
		{name: "stage 2-1", values: dico21Isf[:], width: 3},
		{name: "stage 2-2", values: dico22Isf[:], width: 3},
		{name: "stage 2-3", values: dico23Isf[:], width: 3},
		{name: "stage 2-4", values: dico24Isf[:], width: 3},
		{name: "stage 2-5", values: dico25Isf[:], width: 4},
	}
	if err := s.validateGoodFrame(indices, codebooks[:]); err != nil {
		return dst, err
	}

	copy(dst[:9], codebookVector(dico1Isf[:], int(indices[0]), 9))
	copy(dst[9:16], codebookVector(dico2Isf[:], int(indices[1]), 7))
	for i := range 3 {
		dst[i] = fxp.Add16(dst[i], codebookValue(dico21Isf[:], int(indices[2]), 3, i))
		dst[i+3] = fxp.Add16(dst[i+3], codebookValue(dico22Isf[:], int(indices[3]), 3, i))
		dst[i+6] = fxp.Add16(dst[i+6], codebookValue(dico23Isf[:], int(indices[4]), 3, i))
		dst[i+9] = fxp.Add16(dst[i+9], codebookValue(dico24Isf[:], int(indices[5]), 3, i))
		dst[i+12] = fxp.Add16(dst[i+12], codebookValue(dico25Isf[:], int(indices[6]), 4, i))
	}
	dst[15] = fxp.Add16(dst[15], codebookValue(dico25Isf[:], int(indices[6]), 4, 3))

	dst = s.finishGoodFrame(dst)
	dst = reorderISF(dst, isfGap)
	return dst, nil
}

func (s isfDecodeState) decode36(indices []int16) ([lpcOrder]int16, error) {
	var dst [lpcOrder]int16
	codebooks := [...]isfCodebook{
		{name: "stage 1-1", values: dico1Isf[:], width: 9},
		{name: "stage 1-2", values: dico2Isf[:], width: 7},
		{name: "stage 2-1", values: dico21Isf36b[:], width: 5},
		{name: "stage 2-2", values: dico22Isf36b[:], width: 4},
		{name: "stage 2-3", values: dico23Isf36b[:], width: 7},
	}
	if err := s.validateGoodFrame(indices, codebooks[:]); err != nil {
		return dst, err
	}

	copy(dst[:9], codebookVector(dico1Isf[:], int(indices[0]), 9))
	for i := range 7 {
		dst[i+9] = fxp.Add16(
			codebookValue(dico2Isf[:], int(indices[1]), 7, i),
			codebookValue(dico23Isf36b[:], int(indices[4]), 7, i),
		)
	}
	for i := range 5 {
		dst[i] = fxp.Add16(dst[i], codebookValue(dico21Isf36b[:], int(indices[2]), 5, i))
	}
	for i := range 4 {
		dst[i+5] = fxp.Add16(dst[i+5], codebookValue(dico22Isf36b[:], int(indices[3]), 4, i))
	}

	dst = s.finishGoodFrame(dst)
	dst = reorderISF(dst, isfGap)
	return dst, nil
}

func (s isfDecodeState) validateGoodFrame(indices []int16, codebooks []isfCodebook) error {
	if len(s.pastResidual) < lpcOrder {
		return errors.New("decode ISF: residual history buffer is too short")
	}
	if len(indices) < len(codebooks) {
		return errors.New("decode ISF: index buffer is too short")
	}
	if s.history != nil && len(s.history) < meanISFBufferSize*lpcOrder {
		return errors.New("decode ISF: history buffer is too short")
	}
	for i, codebook := range codebooks {
		index := int(indices[i])
		if index < 0 || index >= len(codebook.values)/codebook.width {
			return fmt.Errorf("decode ISF: %s index %d is outside codebook", codebook.name, index)
		}
	}
	return nil
}

func (s isfDecodeState) finishGoodFrame(dst [lpcOrder]int16) [lpcOrder]int16 {
	for i := range lpcOrder {
		residual := dst[i]
		dst[i] = fxp.Add16(dst[i], meanIsf[i])
		dst[i] = fxp.Add16(dst[i], fxp.Mult(isfMu, s.pastResidual[i]))
		s.pastResidual[i] = residual
	}
	if s.history != nil {
		updateISFBuffer(s.history, dst[:])
	}
	return dst
}

func (s isfDecodeState) conceal(previous []int16) ([lpcOrder]int16, error) {
	var dst [lpcOrder]int16
	if len(previous) < lpcOrder || len(s.pastResidual) < lpcOrder ||
		len(s.history) < meanISFBufferSize*lpcOrder {
		return dst, errors.New("conceal ISF: buffers are too short")
	}
	var refISF [lpcOrder]int16
	for i := range lpcOrder {
		acc := fxp.LMult(meanIsf[i], 8192)
		for j := range meanISFBufferSize {
			acc = fxp.Add32(acc, fxp.LMult(s.history[j*lpcOrder+i], 8192))
		}
		refISF[i] = fxp.Round(acc)
	}
	for i := range lpcOrder {
		dst[i] = fxp.Add16(fxp.Mult(isfAlpha, previous[i]), fxp.Mult(isfOneAlpha, refISF[i]))
	}
	for i := range lpcOrder {
		predicted := fxp.Add16(refISF[i], fxp.Mult(s.pastResidual[i], isfMu))
		s.pastResidual[i] = fxp.Shr16(fxp.Sub16(dst[i], predicted), 1)
	}
	dst = reorderISF(dst, isfGap)
	return dst, nil
}

func updateISFBuffer(isfBuf []int16, isfQ []int16) {
	for i := range lpcOrder {
		for j := meanISFBufferSize - 1; j > 0; j-- {
			isfBuf[j*lpcOrder+i] = isfBuf[(j-1)*lpcOrder+i]
		}
		isfBuf[i] = isfQ[i]
	}
}

func codebookVector(table []int16, index int, width int) []int16 {
	offset := index * width
	return table[offset : offset+width]
}

func codebookValue(table []int16, index int, width int, element int) int16 {
	return table[index*width+element]
}
