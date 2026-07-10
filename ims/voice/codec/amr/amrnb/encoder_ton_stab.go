/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These encoder-side tone stabilizer primitives are ported from
 * enc/src/ton_stab.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const tonStabGainHistory = 7

type tonStabState struct {
	count int16
	gp    [tonStabGainHistory]int16
}

func (s *tonStabState) reset() {
	s.count = 0
	clear(s.gp[:])
}

func (s *tonStabState) checkLSP(lsp []int16) (bool, error) {
	if len(lsp) < lpcOrder {
		return false, fmt.Errorf("checking AMR-NB LSP stability: coefficient count %d, want at least %d", len(lsp), lpcOrder)
	}

	distMin1 := fxp.Max16
	for i := 3; i < lpcOrder-2; i++ {
		dist := fxp.Sub16(lsp[i], lsp[i+1])
		distMin1 = min(distMin1, dist)
	}

	distMin2 := fxp.Max16
	for i := 1; i < 3; i++ {
		dist := fxp.Sub16(lsp[i], lsp[i+1])
		distMin2 = min(distMin2, dist)
	}

	distTh := int16(1100)
	if fxp.Sub16(lsp[1], 32000) > 0 {
		distTh = 600
	} else if fxp.Sub16(lsp[1], 30500) > 0 {
		distTh = 800
	}

	if fxp.Sub16(distMin1, 1500) < 0 || fxp.Sub16(distMin2, distTh) < 0 {
		s.count = fxp.Add16(s.count, 1)
	} else {
		s.count = 0
	}
	if fxp.Sub16(s.count, 12) >= 0 {
		s.count = 12
		return true, nil
	}
	return false, nil
}

func (s *tonStabState) checkGPClipping(gainPitch int16) bool {
	sum := fxp.Shr16(gainPitch, 3)
	for i := range tonStabGainHistory {
		sum = fxp.Add16(sum, s.gp[i])
	}
	return fxp.Sub16(sum, gpClip) > 0
}

func (s *tonStabState) updateGPClipping(gainPitch int16) {
	copy(s.gp[:], s.gp[1:])
	s.gp[tonStabGainHistory-1] = fxp.Shr16(gainPitch, 3)
}
