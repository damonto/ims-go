/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/d_plsf_3.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	plsf3BadFrameAlpha    int16 = 29491
	plsf3BadFrameOneAlpha int16 = 3277
)

func (s *dPLSFState) decode3(mode Mode, indices []int16) ([lpcOrder]int16, error) {
	lsfR, err := decode3Residuals(mode, indices)
	if err != nil {
		return [lpcOrder]int16{}, err
	}

	var lsfQ [lpcOrder]int16
	for i := range lpcOrder {
		predicted := meanLSF3[i]
		if mode != ModeDTX {
			predicted = fxp.Add16(predicted, fxp.Mult(s.pastRQ[i], predFac3[i]))
		} else {
			predicted = fxp.Add16(predicted, s.pastRQ[i])
		}
		lsfQ[i] = fxp.Add16(lsfR[i], predicted)
	}

	reorderLSF(lsfQ[:], lsfGap)
	lspQ := lsfToLsp(lsfQ[:])
	s.pastRQ = lsfR
	s.pastLSFQ = lsfQ
	return lspQ, nil
}

func (s *dPLSFState) conceal3(mode Mode) ([lpcOrder]int16, error) {
	if err := validatePLSF3Mode(mode); err != nil {
		return [lpcOrder]int16{}, err
	}

	var lsfQ, nextPastRQ [lpcOrder]int16
	for i := range lpcOrder {
		lsfQ[i] = fxp.Add16(
			fxp.Mult(s.pastLSFQ[i], plsf3BadFrameAlpha),
			fxp.Mult(meanLSF3[i], plsf3BadFrameOneAlpha),
		)
	}
	for i := range lpcOrder {
		predicted := meanLSF3[i]
		if mode != ModeDTX {
			predicted = fxp.Add16(predicted, fxp.Mult(s.pastRQ[i], predFac3[i]))
		} else {
			predicted = fxp.Add16(predicted, s.pastRQ[i])
		}
		nextPastRQ[i] = fxp.Sub16(lsfQ[i], predicted)
	}

	reorderLSF(lsfQ[:], lsfGap)
	lspQ := lsfToLsp(lsfQ[:])
	s.pastRQ = nextPastRQ
	s.pastLSFQ = lsfQ
	return lspQ, nil
}

func decode3Residuals(mode Mode, indices []int16) ([lpcOrder]int16, error) {
	var lsfR [lpcOrder]int16
	if err := validatePLSF3Indices(mode, indices); err != nil {
		return lsfR, err
	}

	cb1 := dico1LSF3[:]
	cb3 := dico3LSF3[:]
	if mode == Mode475 || mode == Mode515 {
		cb3 = mr5153LSF[:]
	} else if mode == Mode795 {
		cb1 = mr7951LSF[:]
	}

	offset := int(indices[0]) * 3
	copy(lsfR[0:3], cb1[offset:offset+3])

	index := int(indices[1])
	if mode == Mode475 || mode == Mode515 {
		index <<= 1
	}
	offset = index * 3
	copy(lsfR[3:6], dico2LSF3[offset:offset+3])

	offset = int(indices[2]) * 4
	copy(lsfR[6:10], cb3[offset:offset+4])
	return lsfR, nil
}

func validatePLSF3Indices(mode Mode, indices []int16) error {
	if err := validatePLSF3Mode(mode); err != nil {
		return err
	}
	if len(indices) < 3 {
		return fmt.Errorf("decoding AMR-NB PLSF3: index count %d, want at least 3", len(indices))
	}

	cb1Len := len(dico1LSF3)
	cb3Len := len(dico3LSF3)
	index2Stride := 3
	if mode == Mode475 || mode == Mode515 {
		cb3Len = len(mr5153LSF)
		index2Stride = 6
	} else if mode == Mode795 {
		cb1Len = len(mr7951LSF)
	}
	if err := validateCodebookIndex("PLSF3 codebook 1", indices[0], 3, cb1Len); err != nil {
		return err
	}
	if err := validateCodebookIndex("PLSF3 codebook 2", indices[1], index2Stride, len(dico2LSF3)); err != nil {
		return err
	}
	return validateCodebookIndex("PLSF3 codebook 3", indices[2], 4, cb3Len)
}

func validatePLSF3Mode(mode Mode) error {
	if mode < Mode475 || mode > ModeDTX || mode == Mode1220 {
		return fmt.Errorf("decoding AMR-NB PLSF3: invalid mode %d", mode)
	}
	return nil
}

func validateCodebookIndex(name string, index int16, width int, tableLen int) error {
	offset := int(index) * width
	if index < 0 || offset+width > tableLen {
		return fmt.Errorf("decoding AMR-NB %s: index %d is outside codebook", name, index)
	}
	return nil
}
