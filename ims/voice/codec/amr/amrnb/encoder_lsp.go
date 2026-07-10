/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This encoder LSP state machine follows common/src/lsp.cpp.
 */

package amrnb

import "fmt"

type encoderLSPState struct {
	lspOld  [lpcOrder]int16
	lspOldQ [lpcOrder]int16
	q       dPLSFState
}

type encoderLSPAnalysis struct {
	az      [azFrameCount]int16
	azQ     [azFrameCount]int16
	lspNew  [lpcOrder]int16
	params  [5]int16
	written int
}

func newEncoderLSPState() encoderLSPState {
	var state encoderLSPState
	state.reset()
	return state
}

func (s *encoderLSPState) reset() {
	copy(s.lspOld[:], initialLSP[:])
	copy(s.lspOldQ[:], initialLSP[:])
	s.q.reset()
}

func (s *encoderLSPState) process(reqMode, usedMode Mode, az [azFrameCount]int16) (encoderLSPAnalysis, error) {
	var out encoderLSPAnalysis
	if reqMode < Mode475 || reqMode > ModeDTX {
		return out, fmt.Errorf("analyzing AMR-NB LSP: invalid requested mode %d", reqMode)
	}
	if usedMode < Mode475 || usedMode > ModeDTX {
		return out, fmt.Errorf("analyzing AMR-NB LSP: invalid used mode %d", usedMode)
	}

	out.az = az
	nextQ := s.q
	var nextLSPOldQ [lpcOrder]int16
	if reqMode == Mode1220 {
		lspMid, err := azToLSP(out.az[lpcCoeffCount:2*lpcCoeffCount], s.lspOld[:])
		if err != nil {
			return out, err
		}
		out.lspNew, err = azToLSP(out.az[3*lpcCoeffCount:4*lpcCoeffCount], lspMid[:])
		if err != nil {
			return out, err
		}
		interpolated := interpolateLPC1And3Partial(s.lspOld[:], lspMid[:], out.lspNew[:])
		copy(out.az[0:lpcCoeffCount], interpolated[0][:])
		copy(out.az[2*lpcCoeffCount:3*lpcCoeffCount], interpolated[1][:])

		if usedMode != ModeDTX {
			quantized, err := nextQ.quantize5(lspMid[:], out.lspNew[:])
			if err != nil {
				return out, err
			}
			out.azQ = interpolateLPC1And3(s.lspOldQ[:], quantized.lsp1[:], quantized.lsp2[:])
			out.params = quantized.indices
			out.written = len(quantized.indices)
			nextLSPOldQ = quantized.lsp2
		}
	} else {
		var err error
		out.lspNew, err = azToLSP(out.az[3*lpcCoeffCount:4*lpcCoeffCount], s.lspOld[:])
		if err != nil {
			return out, err
		}
		interpolated := interpolateLPC1To3Partial(s.lspOld[:], out.lspNew[:])
		for subframe := range interpolated {
			copy(out.az[subframe*lpcCoeffCount:(subframe+1)*lpcCoeffCount], interpolated[subframe][:])
		}

		if usedMode != ModeDTX {
			quantized, err := nextQ.quantize3(reqMode, out.lspNew[:])
			if err != nil {
				return out, err
			}
			out.azQ = interpolateLPC1To3(s.lspOldQ[:], quantized.lsp[:])
			copy(out.params[:], quantized.indices[:])
			out.written = len(quantized.indices)
			nextLSPOldQ = quantized.lsp
		}
	}

	s.lspOld = out.lspNew
	if usedMode != ModeDTX {
		s.lspOldQ = nextLSPOldQ
		s.q = nextQ
	}
	return out, nil
}
