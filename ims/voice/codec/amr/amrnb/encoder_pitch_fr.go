/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These encoder-side pitch search helpers are ported from enc/src/pitch_fr.cpp
 * and enc/src/inter_36.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const pitchSearchInterpolationLen = 4

type pitchFrState struct {
	prevT0 int16
}

func (s *pitchFrState) reset() {
	s.prevT0 = 0
}

type pitchFrResult struct {
	t0                 int16
	t0Frac             int16
	useThirdResolution bool
	index              int16
}

type pitchModeParams struct {
	maxFracLag    int16
	flag3         bool
	firstFrac     int16
	lastFrac      int16
	deltaIntLow   int16
	deltaIntRange int16
	deltaFrcLow   int16
	deltaFrcRange int16
	pitMin        int16
}

var pitchModeTable = [...]pitchModeParams{
	{84, true, -2, 2, 5, 10, 5, 9, pitchMin},
	{84, true, -2, 2, 5, 10, 5, 9, pitchMin},
	{84, true, -2, 2, 3, 6, 5, 9, pitchMin},
	{84, true, -2, 2, 3, 6, 5, 9, pitchMin},
	{84, true, -2, 2, 3, 6, 5, 9, pitchMin},
	{84, true, -2, 2, 3, 6, 10, 19, pitchMin},
	{84, true, -2, 2, 3, 6, 5, 9, pitchMin},
	{94, false, -3, 3, 3, 6, 5, 9, pitchMinMR122},
}

var inter6Search = [...]int16{
	29519,
	28316, 24906, 19838, 13896, 7945, 2755,
	-1127, -3459, -4304, -3969, -2899, -1561,
	-336, 534, 970, 1023, 823, 516,
	220, 0, -131, -194, -215, 0,
}

func pitchRange(t0, deltaLow, deltaRange, pitMin, pitMax int16) (t0Min, t0Max int16) {
	t0Min = t0 - deltaLow

	t0Min = max(t0Min, pitMin)

	t0Max = t0Min + deltaRange
	if t0Max > pitMax {
		t0Max = pitMax
		t0Min = pitMax - deltaRange
	}
	return t0Min, t0Max
}

func searchFrac(lag int16, frac int16, lastFrac int16, corr []int16, flag3 bool) (int16, int16) {
	maxCorr := interpolate3or6(corr, lag, frac, flag3)
	for i := frac + 1; i <= lastFrac; i++ {
		corrInt := interpolate3or6(corr, lag, i, flag3)
		if corrInt > maxCorr {
			maxCorr = corrInt
			frac = i
		}
	}

	if !flag3 {
		if frac == -3 {
			frac = 3
			lag--
		}
		return lag, frac
	}

	if frac == -2 {
		frac = 1
		lag--
	}
	if frac == 2 {
		frac = -1
		lag++
	}
	return lag, frac
}

func interpolate3or6(corr []int16, lag int16, frac int16, flag3 bool) int16 {
	if flag3 {
		frac <<= 1
	}
	center := int(lag)
	if frac < 0 {
		frac += upSampleMax
		center--
	}
	if center-pitchSearchInterpolationLen+1 < 0 ||
		center+pitchSearchInterpolationLen >= len(corr) ||
		frac < 0 ||
		frac > upSampleMax {
		return 0
	}

	x1 := center
	x2 := center + 1
	c1 := int(frac)
	c2 := upSampleMax - int(frac)
	sum := int32(0x4000)
	for i := range pitchSearchInterpolationLen {
		k := i * upSampleMax
		sum = fxp.Add32(sum, int32(corr[x1-i])*int32(inter6Search[c1+k]))
		sum = fxp.Add32(sum, int32(corr[x2+i])*int32(inter6Search[c2+k]))
	}
	return int16(sum >> 15)
}

type normCorrRequest struct {
	excitation       []int16
	excitationOffset int
	target           []int16
	impulse          []int16
	tMin             int16
	tMax             int16
}

func normCorr(req normCorrRequest) ([pitchMax + 5]int16, error) {
	var correlations [pitchMax + 5]int16
	if len(req.target) < subframeSamples || len(req.impulse) < subframeSamples {
		return correlations, fmt.Errorf(
			"calculating AMR-NB normalized correlation: target/impulse sample counts %d/%d, want at least %d",
			len(req.target),
			len(req.impulse),
			subframeSamples,
		)
	}
	if req.tMin < 0 || req.tMax < req.tMin || int(req.tMax) >= len(correlations) {
		return correlations, fmt.Errorf(
			"calculating AMR-NB normalized correlation: invalid lag range %d..%d",
			req.tMin,
			req.tMax,
		)
	}
	firstStart := req.excitationOffset - int(req.tMin)
	lastStart := req.excitationOffset - int(req.tMax)
	if lastStart < 0 || firstStart+subframeSamples > len(req.excitation) {
		return correlations, fmt.Errorf(
			"calculating AMR-NB normalized correlation: excitation range %d..%d exceeds %d samples",
			lastStart,
			firstStart+subframeSamples,
			len(req.excitation),
		)
	}

	excf := convolve(req.excitation[firstStart:firstStart+subframeSamples], req.impulse)

	var scaled [subframeSamples]int16
	energy := int32(0)
	for i := range subframeSamples {
		scaled[i] = excf[i] >> 2
		energy = fxp.Add32(energy, fxp.LMult(excf[i], excf[i]))
	}

	source := excf[:]
	hFac := int16(3)
	scaling := int16(0)
	if energy > 67108864 {
		source = scaled[:]
		hFac = 1
		scaling = 2
	}

	k := -int(req.tMin)
	for lag := req.tMin; lag <= req.tMax; lag++ {
		correlation := int32(0)
		energy = 0
		for i := range subframeSamples {
			correlation = fxp.Add32(correlation, fxp.LMult(req.target[i], source[i]))
			energy = fxp.Add32(energy, fxp.LMult(source[i], source[i]))
		}

		invEnergy := invSqrt(energy)
		normHi, normLo := fxp.LExtract(invEnergy)
		corrHi, corrLo := fxp.LExtract(correlation)
		correlations[lag] = int16(fxp.Mpy32(corrHi, corrLo, normHi, normLo))

		if lag == req.tMax {
			continue
		}
		k--
		temp := req.excitation[req.excitationOffset+k]
		for j := subframeSamples - 1; j > 0; j-- {
			contribution := fxp.ExtractH(fxp.Shl32(fxp.LMult(temp, req.impulse[j]), hFac))
			source[j] = fxp.Add16(contribution, source[j-1])
		}
		source[0] = temp >> scaling
	}
	return correlations, nil
}

func (s *pitchFrState) pitch(
	mode Mode,
	tOp []int16,
	exc []int16,
	excOffset int,
	xn []int16,
	h []int16,
	subframeOffset int16,
) (pitchFrResult, error) {
	var out pitchFrResult
	if mode < Mode475 || mode > Mode1220 {
		return out, fmt.Errorf("searching AMR-NB closed-loop pitch: invalid mode %d", mode)
	}
	if len(tOp) < 2 {
		return out, fmt.Errorf("searching AMR-NB closed-loop pitch: open-loop lag count %d, want at least 2", len(tOp))
	}
	if subframeOffset < 0 || subframeOffset >= FrameSamples || subframeOffset%subframeSamples != 0 {
		return out, fmt.Errorf("searching AMR-NB closed-loop pitch: invalid subframe offset %d", subframeOffset)
	}

	params := pitchModeTable[mode]
	deltaSearch := true
	var t0Min, t0Max int16

	if subframeOffset == 0 || subframeOffset == FrameSamples/2 {
		if (mode != Mode475 && mode != Mode515) || subframeOffset != FrameSamples/2 {
			deltaSearch = false
			frameOffset := 1
			if subframeOffset == 0 {
				frameOffset = 0
			}
			t0Min, t0Max = pitchRange(
				tOp[frameOffset],
				params.deltaIntLow,
				params.deltaIntRange,
				params.pitMin,
				pitchMax,
			)
		} else {
			t0Min, t0Max = pitchRange(
				s.prevT0,
				params.deltaFrcLow,
				params.deltaFrcRange,
				params.pitMin,
				pitchMax,
			)
		}
	} else {
		t0Min, t0Max = pitchRange(
			s.prevT0,
			params.deltaFrcLow,
			params.deltaFrcRange,
			params.pitMin,
			pitchMax,
		)
	}

	tMin := t0Min - 4
	tMax := t0Max + 4
	corr, err := normCorr(normCorrRequest{
		excitation:       exc,
		excitationOffset: excOffset,
		target:           xn,
		impulse:          h,
		tMin:             tMin,
		tMax:             tMax,
	})
	if err != nil {
		return out, err
	}

	maxCorr := corr[t0Min]
	lag := t0Min
	for i := t0Min + 1; i <= t0Max; i++ {
		if corr[i] >= maxCorr {
			maxCorr = corr[i]
			lag = i
		}
	}

	frac := params.firstFrac
	lastFrac := params.lastFrac
	if !deltaSearch && lag > params.maxFracLag {
		frac = 0
	} else if deltaSearch && (mode == Mode475 || mode == Mode515 || mode == Mode590 || mode == Mode670) {
		tmpLag := s.prevT0
		if tmpLag-t0Min > 5 {
			tmpLag = t0Min + 5
		}
		if t0Max-tmpLag > 4 {
			tmpLag = t0Max - 4
		}
		switch lag {
		case tmpLag, tmpLag - 1:
			lag, frac = searchFrac(lag, frac, lastFrac, corr[:], params.flag3)
		case tmpLag - 2:
			frac = 0
			lag, frac = searchFrac(lag, frac, lastFrac, corr[:], params.flag3)
		case tmpLag + 1:
			lastFrac = 0
			lag, frac = searchFrac(lag, frac, lastFrac, corr[:], params.flag3)
		default:
			frac = 0
		}
	} else {
		lag, frac = searchFrac(lag, frac, lastFrac, corr[:], params.flag3)
	}

	var index int16
	if params.flag3 {
		flag4 := mode == Mode475 || mode == Mode515 || mode == Mode590 || mode == Mode670
		index = encodeLag3(lag, frac, s.prevT0, t0Min, t0Max, deltaSearch, flag4)
	} else {
		index = encodeLag6(lag, frac, t0Min, deltaSearch)
	}
	s.prevT0 = lag

	return pitchFrResult{
		t0:                 lag,
		t0Frac:             frac,
		useThirdResolution: params.flag3,
		index:              index,
	}, nil
}
