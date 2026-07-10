/*
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This pitch-gain clipping state follows 3GPP TS 26.173 c-code/gpclip.c.
 */

package amrwb

import (
	"errors"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	pitchClipGain      int16 = 15565
	pitchClipISFMaxIO  int16 = 384
	pitchClipISFMax    int16 = 307
	pitchClipISFThres  int16 = 154
	pitchClipGainThres int16 = 14746
	pitchClipGainMin   int16 = 9830
)

type encoderPitchClipState struct {
	minISFDistance int16
	averageGain    int16
}

func (s *encoderPitchClipState) reset() {
	s.minISFDistance = pitchClipISFMax
	s.averageGain = pitchClipGainMin
}

func (s *encoderPitchClipState) clip(mode Mode) bool {
	if mode <= Mode885 {
		scale := int16(16384 / pitchClipISFMaxIO)
		thres := fxp.Add16(
			pitchClipGainThres,
			fxp.Mult(1638, fxp.ExtractL(fxp.LMult(s.minISFDistance, scale))),
		)
		return fxp.Sub16(s.averageGain, thres) > 0
	}
	return fxp.Sub16(s.minISFDistance, pitchClipISFThres) < 0 &&
		fxp.Sub16(s.averageGain, pitchClipGainThres) > 0
}

func (s *encoderPitchClipState) updateISF(mode Mode, isf []int16) error {
	if len(isf) < lpcOrder {
		return errors.New("pitch clipping ISF buffer is too short")
	}
	distMin := fxp.Sub16(isf[1], isf[0])
	for i := 2; i < lpcOrder-1; i++ {
		dist := fxp.Sub16(isf[i], isf[i-1])
		if fxp.Sub16(dist, distMin) < 0 {
			distMin = dist
		}
	}
	acc := fxp.LMult(26214, s.minISFDistance)
	acc = fxp.LMac(acc, 6554, distMin)
	dist := fxp.ExtractH(acc)
	if mode <= Mode885 {
		if fxp.Sub16(dist, pitchClipISFMaxIO) > 0 {
			dist = pitchClipISFMaxIO
		}
	} else if fxp.Sub16(dist, pitchClipISFMax) > 0 {
		dist = pitchClipISFMax
	}
	s.minISFDistance = dist
	return nil
}

func (s *encoderPitchClipState) updateGain(mode Mode, gainPitch int16) {
	var acc int32
	if mode <= Mode885 {
		acc = fxp.LMult(32113, s.averageGain)
		acc = fxp.LMac(acc, 655, gainPitch)
	} else {
		acc = fxp.LMult(29491, s.averageGain)
		acc = fxp.LMac(acc, 3277, gainPitch)
	}
	gain := fxp.ExtractH(acc)
	if fxp.Sub16(gain, pitchClipGainMin) < 0 {
		gain = pitchClipGainMin
	}
	s.averageGain = gain
}
