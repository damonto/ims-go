/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_nb/dec/src/d_plsf_5.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	plsfBadFrameAlpha    int16 = 31128
	plsfBadFrameOneAlpha int16 = 1639
	lspPredFacMR122      int16 = 21299
)

type decodedPLSF5 struct {
	lsp1 [lpcOrder]int16
	lsp2 [lpcOrder]int16
}

type plsf5Residuals struct {
	lsf1 [lpcOrder]int16
	lsf2 [lpcOrder]int16
}

func (s *dPLSFState) decode5(indices []int16) (decodedPLSF5, error) {
	var out decodedPLSF5
	residuals, err := decode5Residuals(indices)
	if err != nil {
		return out, err
	}

	var lsf1Q, lsf2Q [lpcOrder]int16
	for i := range lpcOrder {
		predicted := fxp.Add16(meanLSF5[i], fxp.Mult(s.pastRQ[i], lspPredFacMR122))
		lsf1Q[i] = fxp.Add16(residuals.lsf1[i], predicted)
		lsf2Q[i] = fxp.Add16(residuals.lsf2[i], predicted)
	}

	reorderLSF(lsf1Q[:], lsfGap)
	reorderLSF(lsf2Q[:], lsfGap)
	out.lsp1 = lsfToLsp(lsf1Q[:])
	out.lsp2 = lsfToLsp(lsf2Q[:])
	s.pastRQ = residuals.lsf2
	s.pastLSFQ = lsf2Q
	return out, nil
}

func (s *dPLSFState) conceal5() decodedPLSF5 {
	var out decodedPLSF5
	var lsf1Q, lsf2Q, nextPastRQ [lpcOrder]int16
	for i := range lpcOrder {
		shifted := fxp.Add16(
			fxp.Mult(s.pastLSFQ[i], plsfBadFrameAlpha),
			fxp.Mult(meanLSF5[i], plsfBadFrameOneAlpha),
		)
		lsf1Q[i] = shifted
		lsf2Q[i] = shifted

		predicted := fxp.Add16(meanLSF5[i], fxp.Mult(s.pastRQ[i], lspPredFacMR122))
		nextPastRQ[i] = fxp.Sub16(lsf2Q[i], predicted)
	}

	reorderLSF(lsf1Q[:], lsfGap)
	reorderLSF(lsf2Q[:], lsfGap)
	out.lsp1 = lsfToLsp(lsf1Q[:])
	out.lsp2 = lsfToLsp(lsf2Q[:])
	s.pastRQ = nextPastRQ
	s.pastLSFQ = lsf2Q
	return out
}

func decode5Residuals(indices []int16) (plsf5Residuals, error) {
	var out plsf5Residuals
	if len(indices) < 5 {
		return out, fmt.Errorf("decoding AMR-NB PLSF5: index count %d, want at least 5", len(indices))
	}
	if err := validateCodebookIndex("PLSF5 codebook 1", indices[0], 4, len(dico1LSF5)); err != nil {
		return out, err
	}
	if err := validateCodebookIndex("PLSF5 codebook 2", indices[1], 4, len(dico2LSF5)); err != nil {
		return out, err
	}
	if indices[2] < 0 {
		return out, fmt.Errorf("decoding AMR-NB PLSF5 codebook 3: index %d is outside codebook", indices[2])
	}
	if err := validateCodebookIndex("PLSF5 codebook 3", indices[2]>>1, 4, len(dico3LSF5)); err != nil {
		return out, err
	}
	if err := validateCodebookIndex("PLSF5 codebook 4", indices[3], 4, len(dico4LSF5)); err != nil {
		return out, err
	}
	if err := validateCodebookIndex("PLSF5 codebook 5", indices[4], 4, len(dico5LSF5)); err != nil {
		return out, err
	}

	offset := int(indices[0]) * 4
	copy(out.lsf1[0:2], dico1LSF5[offset:offset+2])
	copy(out.lsf2[0:2], dico1LSF5[offset+2:offset+4])

	offset = int(indices[1]) * 4
	copy(out.lsf1[2:4], dico2LSF5[offset:offset+2])
	copy(out.lsf2[2:4], dico2LSF5[offset+2:offset+4])

	sign := indices[2] & 1
	index := indices[2] >> 1
	offset = int(index) * 4
	if sign == 0 {
		copy(out.lsf1[4:6], dico3LSF5[offset:offset+2])
		copy(out.lsf2[4:6], dico3LSF5[offset+2:offset+4])
	} else {
		out.lsf1[4] = fxp.Neg16(dico3LSF5[offset])
		out.lsf1[5] = fxp.Neg16(dico3LSF5[offset+1])
		out.lsf2[4] = fxp.Neg16(dico3LSF5[offset+2])
		out.lsf2[5] = fxp.Neg16(dico3LSF5[offset+3])
	}

	offset = int(indices[3]) * 4
	copy(out.lsf1[6:8], dico4LSF5[offset:offset+2])
	copy(out.lsf2[6:8], dico4LSF5[offset+2:offset+4])

	offset = int(indices[4]) * 4
	copy(out.lsf1[8:10], dico5LSF5[offset:offset+2])
	copy(out.lsf2[8:10], dico5LSF5[offset+2:offset+4])
	return out, nil
}
