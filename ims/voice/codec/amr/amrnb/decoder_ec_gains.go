/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These algorithms are ported from amr_nb/dec/src/ec_gains.cpp and
 * amr_nb/common/src/gmed_n.cpp.
 */

package amrnb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

var ecGainCodeDown = [...]int16{32767, 32112, 32112, 32112, 32112, 32112, 22937}
var ecGainPitchDown = [...]int16{32767, 32112, 32112, 26214, 9830, 6553, 6553}

type ecGainCodeState struct {
	gbuf         [5]int16
	pastGainCode int16
	prevGC       int16
}

type ecGainPitchState struct {
	pbuf        [5]int16
	pastGainPit int16
	prevGP      int16
}

func (s *ecGainCodeState) reset() {
	for i := range s.gbuf {
		s.gbuf[i] = 1
	}
	s.pastGainCode = 0
	s.prevGC = 1
}

func (s *ecGainCodeState) conceal(pred *gainPredState, state int16) int16 {
	tmp := gmedN(s.gbuf[:])
	tmp = min(tmp, s.pastGainCode)

	gainCode := fxp.Mult(tmp, ecGainCodeDown[boundedECState(state)])
	enerMR122, ener := pred.averageLimited()
	pred.update(enerMR122, ener)
	return gainCode
}

func (s *ecGainCodeState) update(badFrame, previousBadFrame bool, gainCode int16) int16 {
	if !badFrame {
		if previousBadFrame && gainCode > s.prevGC {
			gainCode = s.prevGC
		}
		s.prevGC = gainCode
	}

	s.pastGainCode = gainCode
	copy(s.gbuf[:4], s.gbuf[1:])
	s.gbuf[4] = gainCode
	return gainCode
}

func (s *ecGainPitchState) reset() {
	for i := range s.pbuf {
		s.pbuf[i] = 1640
	}
	s.pastGainPit = 0
	s.prevGP = 16384
}

func (s *ecGainPitchState) conceal(state int16) int16 {
	tmp := gmedN(s.pbuf[:])
	tmp = min(tmp, s.pastGainPit)

	return fxp.Mult(tmp, ecGainPitchDown[boundedECState(state)])
}

func (s *ecGainPitchState) update(badFrame, previousBadFrame bool, gainPitch int16) int16 {
	if !badFrame {
		if previousBadFrame && gainPitch > s.prevGP {
			gainPitch = s.prevGP
		}
		s.prevGP = gainPitch
	}

	s.pastGainPit = gainPitch

	s.pastGainPit = min(s.pastGainPit, 16384)

	copy(s.pbuf[:4], s.pbuf[1:])
	s.pbuf[4] = s.pastGainPit
	return gainPitch
}

func gmedN(values []int16) int16 {
	var indices [9]int
	var tmp [9]int16
	copy(tmp[:], values)

	for i := range values {
		maxValue := int16(-32767)
		maxIndex := 0
		for j := range values {
			if tmp[j] >= maxValue {
				maxValue = tmp[j]
				maxIndex = j
			}
		}
		tmp[maxIndex] = fxp.Min16
		indices[i] = maxIndex
	}

	return values[indices[len(values)>>1]]
}

func boundedECState(state int16) int {
	if state < 0 {
		return 0
	}
	if int(state) >= len(ecGainCodeDown) {
		return len(ecGainCodeDown) - 1
	}
	return int(state)
}
