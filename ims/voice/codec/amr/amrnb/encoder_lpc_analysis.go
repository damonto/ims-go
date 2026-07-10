/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This encoder LPC analysis glue follows amr_nb/enc/src/lpc.cpp.
 */

package amrnb

import "fmt"

type encoderLPCState struct {
	levinson levinsonState
}

func newEncoderLPCState() encoderLPCState {
	return encoderLPCState{levinson: newLevinsonState()}
}

func (s *encoderLPCState) reset() {
	s.levinson.reset()
}

func (s *encoderLPCState) analyze(mode Mode, speech []int16) ([azFrameCount]int16, error) {
	var a [azFrameCount]int16
	if mode < Mode475 || mode > ModeDTX {
		return a, fmt.Errorf("analyzing AMR-NB LPC: invalid mode %d", mode)
	}

	windowLen := len(window20040)
	if mode == Mode1220 {
		windowLen = max(len(window16080), len(window2328))
	}
	if len(speech) < windowLen {
		return a, fmt.Errorf(
			"analyzing AMR-NB LPC: speech sample count %d, want at least %d",
			len(speech),
			windowLen,
		)
	}

	if mode == Mode1220 {
		corr, err := autocorrelation(speech, window16080[:])
		if err != nil {
			return a, err
		}
		rh, rl := lagWindow(corr.rh, corr.rl)
		mid, err := s.levinson.levinson(rh[:], rl[:])
		if err != nil {
			return a, err
		}
		copy(a[lpcCoeffCount:2*lpcCoeffCount], mid.a[:])

		corr, err = autocorrelation(speech, window2328[:])
		if err != nil {
			return a, err
		}
		rh, rl = lagWindow(corr.rh, corr.rl)
		final, err := s.levinson.levinson(rh[:], rl[:])
		if err != nil {
			return a, err
		}
		copy(a[3*lpcCoeffCount:4*lpcCoeffCount], final.a[:])
		return a, nil
	}

	corr, err := autocorrelation(speech, window20040[:])
	if err != nil {
		return a, err
	}
	rh, rl := lagWindow(corr.rh, corr.rl)
	final, err := s.levinson.levinson(rh[:], rl[:])
	if err != nil {
		return a, err
	}
	copy(a[3*lpcCoeffCount:4*lpcCoeffCount], final.a[:])
	return a, nil
}
