/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This decoder loop is ported from amr_wb/dec/src/pvamrwbdecoder.cpp.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type parameterCursor struct {
	values []int16
	offset int
}

func (c *parameterCursor) next() (int16, bool) {
	if c.offset >= len(c.values) {
		return 0, false
	}
	value := c.values[c.offset]
	c.offset++
	return value, true
}

func (c *parameterCursor) read(name string) (int16, error) {
	value, ok := c.next()
	if !ok {
		return 0, fmt.Errorf("decoding AMR-WB core: missing %s", name)
	}
	return value, nil
}

type decoderCoreFrame struct {
	mode          Mode
	params        []int16
	dtxState      dtxStateType
	badFrame      bool
	unusableFrame bool
	nbits         int16
	lpc           decodedLPC
	cursor        parameterCursor
	lagState      pitchLagState
	oldISF        [lpcOrder]int16
	aq            [4 * lpcCoeffCount]int16
	work          [pitchMax + interpolationLen + frameSamples12k8 + 1]int16
	code          [subframeSamples]int16
	exc2          [subframeSamples]int16
	excp          [subframeSamples]int16
	hfISF         [lpcOrder]int16
	indices       [8]int16
	qNew          int16
}

func (f *decoderCoreFrame) pastLength() int {
	return pitchMax + interpolationLen
}

func (f *decoderCoreFrame) excitation() []int16 {
	return f.work[f.pastLength():]
}

func (f *decoderCoreFrame) initExcitation(oldExc []int16) {
	copy(f.work[:f.pastLength()], oldExc)
}

type decoderSubframeContext struct {
	frame  *decoderCoreFrame
	offset int
}

func (c decoderSubframeContext) index() int {
	return c.offset / subframeSamples
}

func (c decoderSubframeContext) workOffset() int {
	return c.frame.pastLength() + c.offset
}

func (c decoderSubframeContext) excitation() []int16 {
	return c.frame.excitation()[c.offset : c.offset+subframeSamples]
}

func (c decoderSubframeContext) lpc() []int16 {
	return c.frame.aq[c.index()*lpcCoeffCount:]
}

func (c decoderSubframeContext) pitFlag() int16 {
	if c.offset == 2*subframeSamples && c.frame.nbits > nBits660 {
		return 0
	}
	return int16(c.offset)
}

func (c decoderSubframeContext) outputOffset() int {
	return c.offset + (c.offset >> 2)
}

type decodedSubframePitch struct {
	t0     int16
	t0Frac int16
}

func (s *decoderCoreState) decodeCore(
	dst []int16,
	mode Mode,
	params []int16,
	frameType RXFrameType,
) ([]int16, error) {
	if cap(dst) < FrameSamples {
		dst = make([]int16, FrameSamples)
	} else {
		dst = dst[:FrameSamples]
		clear(dst)
	}

	frame := decoderCoreFrame{
		mode:   mode,
		params: params,
		nbits:  int16(frameBits[mode]),
	}
	dtx := s.dtx
	frame.dtxState = dtx.rxHandler(frameType)
	var sid dtxSIDData
	if frame.dtxState != dtxStateSpeech && dtx.sidFrame && dtx.validData {
		var err error
		sid, err = parseDTXSID(params)
		if err != nil {
			return nil, fmt.Errorf("decode AMR-WB core: %w", err)
		}
	}
	s.dtx = dtx
	frame.badFrame, frame.unusableFrame = frameErrorFlags(frameType)
	s.updateCoreFrameState(&frame)

	if frame.dtxState != dtxStateSpeech {
		out, err := s.decodeComfortNoise(dst, mode, frame.dtxState, sid, frame.badFrame)
		if err != nil {
			return nil, fmt.Errorf("decode AMR-WB comfort noise: %w", err)
		}
		s.updatePrevBadFrame(frame.badFrame)
		return out, nil
	}

	if err := s.prepareSpeechCore(&frame); err != nil {
		return nil, err
	}
	frame.initExcitation(s.oldExc[:])
	for offset := 0; offset < frameSamples12k8; offset += subframeSamples {
		ctx := decoderSubframeContext{frame: &frame, offset: offset}
		if err := s.decodeSpeechSubframe(ctx, dst); err != nil {
			return nil, err
		}
	}

	s.finishSpeechCore(&frame)
	s.updatePrevBadFrame(frame.badFrame)
	return dst, nil
}

func (s *decoderCoreState) updateCoreFrameState(frame *decoderCoreFrame) {
	if frame.badFrame {
		s.state = min(fxp.Add16(s.state, 1), 6)
	} else {
		s.state >>= 1
	}
	switch s.dtx.globalState {
	case dtxStateDTX:
		s.state = 5
		s.prevBFI = false
	case dtxStateMute:
		s.state = 5
		s.prevBFI = true
	}
}

func (s *decoderCoreState) updatePrevBadFrame(badFrame bool) {
	if badFrame {
		s.prevBFI = true
	} else {
		s.prevBFI = false
	}
}

func (s *decoderCoreState) prepareSpeechCore(frame *decoderCoreFrame) error {
	if len(frame.params) == 0 {
		return errors.New("decoding AMR-WB core: missing VAD parameter")
	}
	oldISF := s.isfOld
	lpc, err := s.decodeLPC(frame.mode, frame.params, frame.badFrame)
	if err != nil {
		return fmt.Errorf("decode AMR-WB core LPC: %w", err)
	}

	vadFlag := frame.params[0]
	if !frame.badFrame {
		if vadFlag == 0 {
			s.vadHist = fxp.Add16(s.vadHist, 1)
		} else {
			s.vadHist = 0
		}
	}
	frame.oldISF = oldISF
	frame.lpc = lpc
	frame.aq = lpc.az
	frame.cursor = parameterCursor{values: frame.params, offset: lpc.paramsAfter}
	return nil
}

func (s *decoderCoreState) finishSpeechCore(frame *decoderCoreFrame) {
	pastLength := frame.pastLength()
	copy(s.oldExc[:], frame.work[frameSamples12k8:frameSamples12k8+pastLength])
	excitation := frame.excitation()
	scaleSignal(excitation[:frameSamples12k8], -frame.qNew)
	var frameExcitation [frameSamples12k8]int16
	copy(frameExcitation[:], excitation[:frameSamples12k8])
	s.dtx.activityUpdate(frame.lpc.isf, frameExcitation)
	s.dtx.globalState = frame.dtxState
}

func (s *decoderCoreState) decodeSpeechSubframe(ctx decoderSubframeContext, dst []int16) error {
	pitch, err := s.decodeSubframePitch(ctx)
	if err != nil {
		return err
	}
	if err := s.decodeSubframeInnovation(ctx, pitch); err != nil {
		return err
	}
	gains, gainCode, err := s.decodeSubframeGain(ctx, pitch)
	if err != nil {
		return err
	}
	s.buildSynthesisExcitation(ctx, gains, gainCode)

	corrGain, err := s.prepareSubframeSynthesis(ctx)
	if err != nil {
		return err
	}
	return s.synthesizeSubframe(ctx, dst, corrGain)
}

func (s *decoderCoreState) decodeSubframePitch(ctx decoderSubframeContext) (decodedSubframePitch, error) {
	var pitch decodedSubframePitch
	pitchIndex, err := ctx.frame.cursor.read("pitch index")
	if err != nil {
		return pitch, err
	}
	t0, t0Frac, nextLagState := decodePitchLag(pitchIndex, ctx.frame.nbits, ctx.pitFlag(), ctx.frame.lagState)
	ctx.frame.lagState = nextLagState
	if ctx.frame.badFrame {
		var gainHistory [lagHistCount]int16
		copy(gainHistory[:], s.decGain.pitchHistory2[:])
		t0, s.seed3 = concealLag(gainHistory, s.lagHist, t0, s.oldT0, s.seed3, ctx.frame.unusableFrame)
		t0Frac = 0
	}

	predictAdaptiveCodebook(ctx.frame.work[:], ctx.workOffset(), t0, t0Frac, subframeSamples+1)

	selectMode := int16(0)
	if ctx.frame.unusableFrame {
		selectMode = 1
	} else if ctx.frame.mode > Mode885 {
		selectMode, err = ctx.frame.cursor.read("interpolation selector")
		if err != nil {
			return pitch, err
		}
	}
	if selectMode == 0 {
		lowPassAdaptiveExcitation(ctx.frame.work[:], ctx.workOffset())
	}

	pitch.t0 = t0
	pitch.t0Frac = t0Frac
	return pitch, nil
}

func (s *decoderCoreState) decodeSubframeInnovation(ctx decoderSubframeContext, pitch decodedSubframePitch) error {
	innovation, err := decodeInnovation(
		&ctx.frame.cursor,
		ctx.frame.mode,
		ctx.frame.unusableFrame,
		s.seed,
	)
	if err != nil {
		return err
	}
	s.seed = innovation.seed
	ctx.frame.indices = innovation.indices
	ctx.frame.code = innovation.code
	preemphasis(ctx.frame.code[:], s.tiltCode)
	pitchLagForSharp := pitch.t0
	if pitch.t0Frac > 2 {
		pitchLagForSharp++
	}
	sharpenPitch(ctx.frame.code[:], pitchLagForSharp, pitSharp)
	return nil
}

func (s *decoderCoreState) decodeSubframeGain(
	ctx decoderSubframeContext,
	pitch decodedSubframePitch,
) (decodedGains, int16, error) {
	var gains decodedGains
	gainIndex, err := ctx.frame.cursor.read("gain index")
	if err != nil {
		return gains, 0, err
	}
	gainBits := int16(7)
	if ctx.frame.mode <= Mode885 {
		gainBits = 6
	}
	decoded, err := decodeGain(s.decGain, gainDecodeInput{
		index:          gainIndex,
		nbits:          gainBits,
		code:           ctx.frame.code[:],
		badFrame:       ctx.frame.badFrame,
		previousBad:    s.prevBFI,
		state:          s.state,
		unusableFrame:  ctx.frame.unusableFrame,
		vadHistory:     s.vadHist,
		subframeLength: subframeSamples,
	})
	if err != nil {
		return gains, 0, fmt.Errorf("decode subframe gain: %w", err)
	}
	s.decGain = decoded.memory
	gains = decoded.gains

	ctx.frame.qNew = s.nextExcitationQ(gains.code)
	gainCode := fxp.Round(fxp.Shl32(gains.code, ctx.frame.qNew))
	scaleSignal(
		ctx.frame.work[ctx.offset:ctx.offset+ctx.frame.pastLength()+subframeSamples],
		ctx.frame.qNew-s.qOld,
	)
	s.qOld = ctx.frame.qNew

	if !ctx.frame.badFrame {
		copy(s.lagHist[1:], s.lagHist[:4])
		s.lagHist[0] = pitch.t0
		s.oldT0 = pitch.t0
		s.oldT0Frac = 0
	}
	return gains, gainCode, nil
}

func (s *decoderCoreState) buildSynthesisExcitation(
	ctx decoderSubframeContext,
	gains decodedGains,
	gainCode int16,
) {
	excitation := ctx.excitation()
	copy(ctx.frame.exc2[:], excitation)
	scaleSignalExact(ctx.frame.exc2[:], -3)

	pitchSharpness := int16(0)
	if ctx.frame.mode <= Mode885 {
		pitchSharpness = fxp.Shl16(gains.pitch, 1)
		if pitchSharpness > 16384 {
			for i := range subframeSamples {
				tmp := fxp.Mult(ctx.frame.exc2[i], pitchSharpness)
				ctx.frame.excp[i] = fxp.Round(fxp.LMult(tmp, gains.pitch) >> 1)
			}
		}
	}

	voiceFac := voiceFactor(ctx.frame.exc2, -3, gains.pitch, ctx.frame.code, gainCode)
	s.tiltCode = fxp.Add16(voiceFac>>2, 8192)

	copy(ctx.frame.exc2[:], excitation)
	maxExc := int32(1)
	for i := range subframeSamples {
		acc := fxp.LMult(ctx.frame.code[i], gainCode)
		acc = fxp.Shl32(acc, 5)
		acc = fxp.Add32(acc, fxp.LMult(excitation[i], gains.pitch))
		acc = fxp.Shl32(acc, 1)
		sample := fxp.Round(acc)
		excitation[i] = sample
		tmp := sample
		if tmp < 0 {
			tmp--
		}
		maxExc |= int32(tmp ^ (tmp >> 15))
	}
	s.updateQHistory(fxp.Add16(fxp.NormS(int16(maxExc)), ctx.frame.qNew-1))

	dispersed := phaseDispersion(
		int16(gains.code>>16),
		gains.pitch,
		ctx.frame.code,
		phaseDispersionMode(ctx.frame.mode),
		s.dispMem,
	)
	ctx.frame.code = dispersed.code
	s.dispMem = dispersed.memory
	enhancedGain, gcThresh := enhanceCodeGain(s.gcThresh, gains.code, voiceFac, ctx.frame.lpc.stability)
	s.gcThresh = gcThresh
	enhanced := buildEnhancedExcitation(ctx.frame.exc2, ctx.frame.code, gains.pitch, enhancedGain, ctx.frame.qNew, voiceFac)
	ctx.frame.exc2 = enhanced.excitation

	if ctx.frame.mode <= Mode885 && pitchSharpness > 16384 {
		for i := range subframeSamples {
			ctx.frame.excp[i] = fxp.Add16(ctx.frame.excp[i], ctx.frame.exc2[i])
		}
		ctx.frame.exc2 = agc2AMRWB(ctx.frame.exc2, ctx.frame.excp)
	}
}

func (s *decoderCoreState) prepareSubframeSynthesis(ctx decoderSubframeContext) (int16, error) {
	if ctx.frame.mode <= Mode660 {
		var err error
		ctx.frame.hfISF, err = interpolateISFForSubframe(ctx.frame.oldISF[:], ctx.frame.lpc.isf[:], ctx.index())
		if err != nil {
			return 0, fmt.Errorf("prepare subframe synthesis: %w", err)
		}
	} else {
		clear(s.memSynHF[:lpcOrder16k-lpcOrder])
	}

	if ctx.frame.mode != Mode2385 {
		return 0, nil
	}
	corrGain, err := ctx.frame.cursor.read("HF correction gain")
	if err != nil {
		return 0, err
	}
	return corrGain, nil
}

func (s *decoderCoreState) synthesizeSubframe(ctx decoderSubframeContext, dst []int16, corrGain int16) error {
	outOffset := ctx.outputOffset()
	_, err := s.synthesize(
		ctx.lpc(),
		ctx.frame.exc2[:],
		ctx.frame.qNew,
		dst[outOffset:outOffset+subframeSamples16k],
		corrGain,
		ctx.frame.hfISF[:],
		ctx.frame.mode,
		ctx.frame.dtxState,
		ctx.frame.badFrame,
	)
	if err != nil {
		return fmt.Errorf("synthesize decoded subframe: %w", err)
	}
	return nil
}

func frameErrorFlags(frameType RXFrameType) (badFrame bool, unusableFrame bool) {
	switch frameType {
	case rxSpeechBad, rxSpeechProbablyDegraded:
		return true, false
	case rxNoData, rxSpeechLost:
		return true, true
	default:
		return false, false
	}
}

func (s *decoderCoreState) nextExcitationQ(gainCode int32) int16 {
	limit := s.qSubframe[0]
	for i := 1; i < len(s.qSubframe); i++ {
		limit = min(limit, s.qSubframe[i])
	}

	limit = min(limit, qMax)

	var qNew int16
	for gainCode < 0x08000000 && qNew < limit {
		gainCode <<= 1
		qNew++
	}
	return qNew
}

func (s *decoderCoreState) updateQHistory(q int16) {
	s.qSubframe[3] = s.qSubframe[2]
	s.qSubframe[2] = s.qSubframe[1]
	s.qSubframe[1] = s.qSubframe[0]
	s.qSubframe[0] = q
}

func lowPassAdaptiveExcitation(work []int16, offset int) {
	var filtered [subframeSamples]int16
	for i := range subframeSamples {
		center := offset + i
		acc := fxp.LMult(5898, work[center-1])
		acc = fxp.LMac(acc, 20972, work[center])
		acc = fxp.LMac(acc, 5898, work[center+1])
		filtered[i] = fxp.Round(acc)
	}
	copy(work[offset:offset+subframeSamples], filtered[:])
}

type decodedInnovation struct {
	seed    int16
	indices [8]int16
	code    [subframeSamples]int16
}

func decodeInnovation(cursor *parameterCursor, mode Mode, unusableFrame bool, seed int16) (decodedInnovation, error) {
	out := decodedInnovation{seed: seed}
	if unusableFrame {
		for i := range subframeSamples {
			out.seed = nextNoise(out.seed)
			out.code[i] = out.seed >> 3
		}
		return out, nil
	}

	read := func(count int) error {
		for i := range count {
			value, err := cursor.read("innovation index")
			if err != nil {
				return err
			}
			out.indices[i] = value
		}
		return nil
	}

	switch mode {
	case Mode660:
		if err := read(1); err != nil {
			return out, err
		}
		var err error
		out.code, err = decodeAcelp2PIn64(out.indices[0])
		if err != nil {
			return out, err
		}
	case Mode885:
		if err := read(4); err != nil {
			return out, err
		}
		var err error
		out.code, err = decodeAcelp4PIn64(out.indices[:], 20)
		if err != nil {
			return out, err
		}
	case Mode1265:
		if err := read(4); err != nil {
			return out, err
		}
		var err error
		out.code, err = decodeAcelp4PIn64(out.indices[:], 36)
		if err != nil {
			return out, err
		}
	case Mode1425:
		if err := read(4); err != nil {
			return out, err
		}
		var err error
		out.code, err = decodeAcelp4PIn64(out.indices[:], 44)
		if err != nil {
			return out, err
		}
	case Mode1585:
		if err := read(4); err != nil {
			return out, err
		}
		var err error
		out.code, err = decodeAcelp4PIn64(out.indices[:], 52)
		if err != nil {
			return out, err
		}
	case Mode1825:
		if err := read(8); err != nil {
			return out, err
		}
		var err error
		out.code, err = decodeAcelp4PIn64(out.indices[:], 64)
		if err != nil {
			return out, err
		}
	case Mode1985:
		if err := read(8); err != nil {
			return out, err
		}
		var err error
		out.code, err = decodeAcelp4PIn64(out.indices[:], 72)
		if err != nil {
			return out, err
		}
	default:
		if err := read(8); err != nil {
			return out, err
		}
		var err error
		out.code, err = decodeAcelp4PIn64(out.indices[:], 88)
		if err != nil {
			return out, err
		}
	}
	return out, nil
}

func interpolateISFForSubframe(old []int16, current []int16, subframe int) ([lpcOrder]int16, error) {
	var dst [lpcOrder]int16
	if len(old) < lpcOrder || len(current) < lpcOrder {
		return dst, errors.New("interpolate ISF: buffers are too short")
	}
	if subframe < 0 || subframe >= len(interpolFrac) {
		return dst, fmt.Errorf("interpolate ISF: invalid subframe %d", subframe)
	}
	facNew := interpolFrac[subframe]
	facOld := fxp.Sub16(fxp.Max16, facNew)
	for i := range lpcOrder {
		acc := int32(old[i]) * int32(facOld)
		acc += int32(current[i]) * int32(facNew)
		dst[i] = fxp.Round(acc << 1)
	}
	return dst, nil
}
