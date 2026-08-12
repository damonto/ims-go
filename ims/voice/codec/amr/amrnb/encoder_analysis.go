/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This encoder analysis front-end follows the speech buffer layout from
 * enc/src/cod_amr.cpp and enc/src/sp_enc.cpp.
 */

package amrnb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	lpcWindowSamples     = 240
	speechHistorySamples = 320
	lpcLookaheadSamples  = 40
	maxParamCount        = 57
	encoderExcOffset     = pitchMax + interpolationLen
)

type encoderAnalysis struct {
	az      [azFrameCount]int16
	azQ     [azFrameCount]int16
	lspNew  [lpcOrder]int16
	speech  [FrameSamples]int16
	wsp     [FrameSamples]int16
	tOp     [2]int16
	sub     [FrameSamples / subframeSamples]encoderSubframeAnalysis
	params  [maxParamCount]int16
	written int
}

type frameLPCAnalysis struct {
	az      [azFrameCount]int16
	azQ     [azFrameCount]int16
	lspNew  [lpcOrder]int16
	params  [5]int16
	written int
	lspFlag bool
}

type encoderFrameContext struct {
	speechWithHistory []int16
	currentSpeech     []int16
	synth             []int16
	params            *parameterWriter
	lspFlag           bool
	mr475             mr475AnalysisState
}

type encoderSubframeContext struct {
	frame    *encoderFrameContext
	analysis *encoderAnalysis
	index    int
}

func (c encoderSubframeContext) offset() int {
	return c.index * subframeSamples
}

func (c encoderSubframeContext) lpcOffset() int {
	return c.index * lpcCoeffCount
}

func (c encoderSubframeContext) subframe() *encoderSubframeAnalysis {
	return &c.analysis.sub[c.index]
}

func (c encoderSubframeContext) lpc() []int16 {
	start := c.lpcOffset()
	return c.analysis.az[start : start+lpcCoeffCount]
}

func (c encoderSubframeContext) quantLPC() []int16 {
	start := c.lpcOffset()
	return c.analysis.azQ[start : start+lpcCoeffCount]
}

type mr475AnalysisState struct {
	gainParamPos [2]int
	memSynSave   [lpcOrder]int16
	memW0Save    [lpcOrder]int16
	memErrSave   [lpcOrder]int16
	sharpSave    int16
	h1SF0        [subframeSamples]int16
}

func (e *Encoder) analyzeFrame(pcm []int16) (encoderAnalysis, error) {
	var out encoderAnalysis
	if len(pcm) != FrameSamples {
		return out, fmt.Errorf("analyzing AMR-NB frame: pcm sample count %d, want %d", len(pcm), FrameSamples)
	}

	out.speech = e.prepareAnalysisSpeech(pcm)
	lpc, err := e.analyzeFrameLPC()
	if err != nil {
		return out, err
	}
	out.az = lpc.az
	out.azQ = lpc.azQ
	out.lspNew = lpc.lspNew
	copy(out.params[:], lpc.params[:lpc.written])
	out.written = lpc.written

	speechWithHistory, wsp, err := e.prepareWeightedSpeech(out.az)
	if err != nil {
		return out, err
	}
	out.wsp = wsp
	tOp, err := e.estimateAnalysisOpenLoopPitch()
	if err != nil {
		return out, err
	}
	out.tOp = tOp

	params, err := newParameterWriter(out.params[:], out.written)
	if err != nil {
		return out, err
	}
	var synth [FrameSamples]int16
	frame := encoderFrameContext{
		speechWithHistory: speechWithHistory,
		currentSpeech:     speechWithHistory[lpcOrder:],
		synth:             synth[:],
		params:            &params,
		lspFlag:           lpc.lspFlag,
	}
	for subframe := range FrameSamples / subframeSamples {
		ctx := encoderSubframeContext{
			frame:    &frame,
			analysis: &out,
			index:    subframe,
		}
		if err := e.analyzeSubframe(ctx); err != nil {
			return out, err
		}
	}

	out.written = frame.params.count()
	e.advanceAnalysisHistory()

	return out, nil
}

func (e *Encoder) prepareAnalysisSpeech(pcm []int16) [FrameSamples]int16 {
	newSpeech := e.oldSpeech[speechHistorySamples-FrameSamples:]
	for i, sample := range pcm {
		newSpeech[i] = sample &^ 0x0007
	}
	e.preprocess.process(newSpeech)
	var speech [FrameSamples]int16
	copy(speech[:], newSpeech)
	return speech
}

func (e *Encoder) analyzeFrameLPC() (frameLPCAnalysis, error) {
	var out frameLPCAnalysis
	pWindow := e.oldSpeech[speechHistorySamples-lpcWindowSamples:]
	if e.mode == Mode1220 {
		pWindow = e.oldSpeech[speechHistorySamples-lpcWindowSamples-lpcLookaheadSamples:]
	}
	az, err := e.lpc.analyze(e.mode, pWindow)
	if err != nil {
		return out, err
	}
	lsp, err := e.lsp.process(e.mode, e.mode, az)
	if err != nil {
		return out, err
	}
	out.az = lsp.az
	out.azQ = lsp.azQ
	out.lspNew = lsp.lspNew
	out.params = lsp.params
	out.written = lsp.written
	out.lspFlag, err = e.tonStab.checkLSP(out.lspNew[:])
	if err != nil {
		return out, err
	}
	return out, nil
}

func (e *Encoder) prepareWeightedSpeech(az [azFrameCount]int16) ([]int16, [FrameSamples]int16, error) {
	speechWithHistory := e.oldSpeech[speechHistorySamples-FrameSamples-lpcLookaheadSamples-lpcOrder:]
	first, err := preBig(e.mode, az, 0, speechWithHistory, e.memW)
	if err != nil {
		return nil, [FrameSamples]int16{}, err
	}
	second, err := preBig(e.mode, az, FrameSamples/2, speechWithHistory, first.memW)
	if err != nil {
		return nil, [FrameSamples]int16{}, err
	}
	var frame [FrameSamples]int16
	copy(frame[:FrameSamples/2], first.samples[:])
	copy(frame[FrameSamples/2:], second.samples[:])
	copy(e.oldWsp[pitchMax:pitchMax+FrameSamples], frame[:])
	e.memW = second.memW
	return speechWithHistory, frame, nil
}

func (e *Encoder) estimateAnalysisOpenLoopPitch() ([2]int16, error) {
	var vad *encoderVADState
	var vad2 *encoderVAD2State
	if e.dtx {
		if e.vadOption == VAD2 {
			e.vad2.resetPitchCorrelation()
			vad2 = &e.vad2
		} else {
			vad = &e.vad
		}
	}
	tOp, err := openLoopPitchWithState(openLoopPitchInput{
		mode:       e.mode,
		wspHistory: e.oldWsp[:],
		weighted:   &e.olPitch,
		oldLags:    e.oldLags[:],
		olGainFlag: e.olGainFlag[:],
		vad:        vad,
		vad2:       vad2,
	})
	if err != nil {
		return [2]int16{}, err
	}
	if vad2 != nil {
		vad2.updateLTPFlag(e.mode)
	}
	return tOp, nil
}

func (e *Encoder) advanceAnalysisHistory() {
	copy(e.oldSpeech[:], e.oldSpeech[FrameSamples:])
	clear(e.oldSpeech[speechHistorySamples-FrameSamples:])
	copy(e.oldWsp[:pitchMax], e.oldWsp[FrameSamples:FrameSamples+pitchMax])
	clear(e.oldWsp[pitchMax:])
	copy(e.oldExc[:encoderExcOffset], e.oldExc[FrameSamples:FrameSamples+encoderExcOffset])
	clear(e.oldExc[encoderExcOffset:])
}

func (e *Encoder) analyzeSubframe(ctx encoderSubframeContext) error {
	if err := e.preprocessAnalysisSubframe(ctx); err != nil {
		return err
	}
	if err := e.analyzePitchForSubframe(ctx); err != nil {
		return err
	}
	if err := e.searchFixedCodebook(ctx); err != nil {
		return err
	}
	if e.mode == Mode475 {
		return e.processMR475Subframe(ctx)
	}
	if err := e.quantizeSubframeGain(ctx); err != nil {
		return err
	}
	if !ctx.subframe().hasFixed {
		return nil
	}
	return e.postprocessSubframe(ctx)
}

func (e *Encoder) preprocessAnalysisSubframe(ctx encoderSubframeContext) error {
	offset := ctx.offset()
	memW0 := e.memW0[:]
	if e.mode == Mode475 {
		memW0 = ctx.frame.mr475.beginSubframe(e, ctx.index)
	}
	preprocessed, err := subframePreprocessEncode(
		subframePreprocessInput{
			mode:        e.mode,
			lpc:         ctx.lpc(),
			quantLPC:    ctx.quantLPC(),
			speech:      ctx.frame.speechWithHistory,
			frameOffset: offset,
			memErr:      e.memErr[:],
			memW0:       memW0,
		},
	)
	if err != nil {
		return err
	}
	*ctx.subframe() = preprocessed
	ctx.frame.mr475.saveImpulse(e.mode, ctx.index, ctx.subframe())
	copy(e.oldExc[encoderExcOffset+offset:encoderExcOffset+offset+subframeSamples], ctx.subframe().exc[:])
	return nil
}

func (s *mr475AnalysisState) beginSubframe(e *Encoder, subframe int) []int16 {
	if subframe%2 == 0 {
		copy(s.memSynSave[:], e.memSyn[:])
		copy(s.memW0Save[:], e.memW0[:])
		copy(s.memErrSave[:], e.memErr[:])
		s.sharpSave = e.sharp
	}
	return s.memW0Save[:]
}

func (s *mr475AnalysisState) saveImpulse(mode Mode, subframe int, sub *encoderSubframeAnalysis) {
	if mode == Mode475 && subframe%2 == 0 {
		copy(s.h1SF0[:], sub.h1[:])
	}
}

func (e *Encoder) analyzePitchForSubframe(ctx encoderSubframeContext) error {
	offset := ctx.offset()
	sub := ctx.subframe()
	pitch, err := e.pitch.pitch(
		e.mode,
		ctx.analysis.tOp[:],
		e.oldExc[:],
		encoderExcOffset+offset,
		sub.xn[:],
		sub.h1[:],
		int16(offset),
	)
	if err != nil {
		return err
	}
	if err := ctx.frame.params.write(pitch.index); err != nil {
		return err
	}
	analysis, err := applyKnownPitch(
		knownPitchInput{
			mode:               e.mode,
			excitation:         e.oldExc[:],
			excitationOffset:   encoderExcOffset + offset,
			h1:                 sub.h1[:],
			xn:                 sub.xn[:],
			residual:           sub.res[:],
			t0:                 pitch.t0,
			t0Frac:             pitch.t0Frac,
			useThirdResolution: pitch.useThirdResolution,
			tonStab:            &e.tonStab,
			lspFlag:            ctx.frame.lspFlag,
		},
	)
	if err != nil {
		return err
	}
	sub.pitch = analysis
	sub.hasPitch = true
	if ctx.index == 0 && e.olGainFlag[0] > 0 {
		e.oldLags[1] = analysis.t0
	}
	if ctx.index == 3 && e.olGainFlag[1] > 0 {
		e.oldLags[0] = analysis.t0
	}
	if analysis.hasGainPitIndex {
		if err := ctx.frame.params.write(analysis.gainPitIndex); err != nil {
			return err
		}
	}
	return nil
}

func (e *Encoder) quantizeSubframeGain(ctx encoderSubframeContext) error {
	offset := ctx.offset()
	sub := ctx.subframe()
	fixed := &sub.fixed
	switch e.mode {
	case Mode515, Mode590, Mode670, Mode740, Mode1020:
		if err := ctx.frame.params.writeSlice(fixed.params[:fixed.paramCount]); err != nil {
			return err
		}
		gain := e.gain.quantizeJoint(jointGainInput{
			mode:    e.mode,
			xn:      sub.xn[:],
			xn2:     sub.pitch.xn2[:],
			y1:      sub.pitch.yl[:],
			y2:      fixed.y2[:],
			gCoeff:  sub.pitch.gCoeff[:],
			gpLimit: sub.pitch.gpLimit,
			code:    fixed.code[:],
		})
		sub.pitch.gainPit = gain.pitchGain
		fixed.gainCode = gain
		if err := ctx.frame.params.write(gain.index); err != nil {
			return err
		}
	case Mode795:
		if err := ctx.frame.params.writeSlice(fixed.params[:fixed.paramCount]); err != nil {
			return err
		}
		gain := e.gain.quantizeMR795(mr795GainInput{
			res:     sub.exc[:],
			exc:     e.oldExc[encoderExcOffset+offset : encoderExcOffset+offset+subframeSamples],
			xn:      sub.xn[:],
			xn2:     sub.pitch.xn2[:],
			y1:      sub.pitch.yl[:],
			y2:      fixed.y2[:],
			gCoeff:  sub.pitch.gCoeff[:],
			gpLimit: sub.pitch.gpLimit,
			gainPit: sub.pitch.gainPit,
			code:    fixed.code[:],
		})
		sub.pitch.gainPit = gain.pitchGain
		fixed.gainCode = gain
		if err := ctx.frame.params.write(gain.pitchIndex); err != nil {
			return err
		}
		if err := ctx.frame.params.write(gain.index); err != nil {
			return err
		}
	}
	return nil
}

func (e *Encoder) postprocessSubframe(ctx encoderSubframeContext) error {
	offset := ctx.offset()
	sub := ctx.subframe()
	e.tonStab.updateGPClipping(sub.pitch.gainPit)
	sharp, err := subframePostprocessEncode(
		subframePostprocessInput{
			mode:       e.mode,
			offset:     offset,
			gainPit:    sub.pitch.gainPit,
			gainCode:   sub.fixed.gainCode.gain,
			quantLPC:   ctx.quantLPC(),
			speech:     ctx.frame.currentSpeech,
			synth:      ctx.frame.synth,
			sub:        sub,
			memSyn:     e.memSyn[:],
			memErr:     e.memErr[:],
			memW0:      e.memW0[:],
			excitation: e.oldExc[encoderExcOffset : encoderExcOffset+FrameSamples],
		},
	)
	if err != nil {
		return err
	}
	e.sharp = sharp
	return nil
}

func (e *Encoder) processMR475Subframe(ctx encoderSubframeContext) error {
	sub := ctx.subframe()
	fixed := &sub.fixed
	if err := ctx.frame.params.writeSlice(fixed.params[:fixed.paramCount]); err != nil {
		return err
	}
	input := mr475GainInput(sub)
	if ctx.index%2 == 0 {
		return e.processMR475EvenSubframe(ctx, input)
	}
	return e.processMR475OddSubframe(ctx, input)
}

func mr475GainInput(sub *encoderSubframeAnalysis) mr475SubframeGainInput {
	return mr475SubframeGainInput{
		xn:     sub.xn[:],
		xn2:    sub.pitch.xn2[:],
		y1:     sub.pitch.yl[:],
		y2:     sub.fixed.y2[:],
		gCoeff: sub.pitch.gCoeff[:],
		code:   sub.fixed.code[:],
	}
}

func (e *Encoder) processMR475EvenSubframe(
	ctx encoderSubframeContext,
	input mr475SubframeGainInput,
) error {
	offset := ctx.offset()
	sub := ctx.subframe()
	sub.fixed.gainCode = e.gain.prepareMR475Even(input)
	gainParamPos, err := ctx.frame.params.reserve()
	if err != nil {
		return err
	}
	ctx.frame.mr475.gainParamPos[ctx.index/2] = gainParamPos
	e.tonStab.updateGPClipping(sub.pitch.gainPit)
	if _, err := subframePostprocessEncode(
		subframePostprocessInput{
			mode:       e.mode,
			offset:     offset,
			gainPit:    sub.pitch.gainPit,
			gainCode:   sub.fixed.gainCode.gain,
			quantLPC:   ctx.quantLPC(),
			speech:     ctx.frame.currentSpeech,
			synth:      ctx.frame.synth,
			sub:        sub,
			memSyn:     ctx.frame.mr475.memSynSave[:],
			memErr:     e.memErr[:],
			memW0:      ctx.frame.mr475.memW0Save[:],
			excitation: e.oldExc[encoderExcOffset : encoderExcOffset+FrameSamples],
		},
	); err != nil {
		return err
	}
	e.sharp = ctx.frame.mr475.sharpSave
	return nil
}

func (e *Encoder) processMR475OddSubframe(
	ctx encoderSubframeContext,
	input mr475SubframeGainInput,
) error {
	offset := ctx.offset()
	sub := ctx.subframe()
	fixed := &sub.fixed
	gain := e.gain.quantizeMR475Odd(input, sub.pitch.gpLimit)

	prev := &ctx.analysis.sub[ctx.index-1]
	prev.pitch.gainPit = gain.sf0GainPit
	prev.fixed.gainCode = encoderCodeGainAnalysis{
		index: gain.index,
		gain:  gain.sf0GainCode,
	}
	if err := ctx.frame.params.set(ctx.frame.mr475.gainParamPos[ctx.index/2], gain.index); err != nil {
		return err
	}

	sub.pitch.gainPit = gain.sf1GainPit
	fixed.gainCode = encoderCodeGainAnalysis{
		index: gain.index,
		gain:  gain.sf1GainCode,
	}
	e.tonStab.updateGPClipping(sub.pitch.gainPit)
	copy(e.memErr[:], ctx.frame.mr475.memErrSave[:])

	prevOffset := offset - subframeSamples
	if err := rebuildMR475Pitch(
		e.oldExc[:],
		encoderExcOffset+prevOffset,
		&prev.pitch,
		ctx.frame.mr475.h1SF0[:],
	); err != nil {
		return err
	}
	if _, err := subframePostprocessEncode(
		subframePostprocessInput{
			mode:       e.mode,
			offset:     prevOffset,
			gainPit:    prev.pitch.gainPit,
			gainCode:   prev.fixed.gainCode.gain,
			quantLPC:   ctx.analysis.azQ[ctx.lpcOffset()-lpcCoeffCount : ctx.lpcOffset()],
			speech:     ctx.frame.currentSpeech,
			synth:      ctx.frame.synth,
			sub:        prev,
			memSyn:     e.memSyn[:],
			memErr:     e.memErr[:],
			memW0:      e.memW0[:],
			excitation: e.oldExc[encoderExcOffset : encoderExcOffset+FrameSamples],
		},
	); err != nil {
		return err
	}

	postSub, err := subframePreprocessEncode(
		subframePreprocessInput{
			mode:        e.mode,
			lpc:         ctx.lpc(),
			quantLPC:    ctx.quantLPC(),
			speech:      ctx.frame.speechWithHistory,
			frameOffset: offset,
			memErr:      e.memErr[:],
			memW0:       e.memW0[:],
		},
	)
	if err != nil {
		return err
	}
	copy(e.oldExc[encoderExcOffset+offset:encoderExcOffset+offset+subframeSamples], postSub.exc[:])
	postSub.pitch = sub.pitch
	postSub.fixed = *fixed
	if err := rebuildMR475Pitch(
		e.oldExc[:],
		encoderExcOffset+offset,
		&postSub.pitch,
		postSub.h1[:],
	); err != nil {
		return err
	}
	sharp, err := subframePostprocessEncode(
		subframePostprocessInput{
			mode:       e.mode,
			offset:     offset,
			gainPit:    sub.pitch.gainPit,
			gainCode:   fixed.gainCode.gain,
			quantLPC:   ctx.quantLPC(),
			speech:     ctx.frame.currentSpeech,
			synth:      ctx.frame.synth,
			sub:        &postSub,
			memSyn:     e.memSyn[:],
			memErr:     e.memErr[:],
			memW0:      e.memW0[:],
			excitation: e.oldExc[encoderExcOffset : encoderExcOffset+FrameSamples],
		},
	)
	if err != nil {
		return err
	}
	e.sharp = sharp
	return nil
}

func (e *Encoder) searchFixedCodebook(ctx encoderSubframeContext) error {
	sub := ctx.subframe()
	pitch := sub.pitch
	switch e.mode {
	case Mode475, Mode515:
		fixed := code2I40At9Bits(
			int16(ctx.index),
			pitch.xn2[:],
			sub.h1[:],
			pitch.t0,
			e.sharp,
			sub.fixed.code[:],
			sub.fixed.y2[:],
		)
		sub.fixed.index = fixed.index
		sub.fixed.sign = fixed.sign
		sub.fixed.params[0] = fixed.index
		sub.fixed.params[1] = fixed.sign
		sub.fixed.paramCount = 2
		copy(sub.fixed.codeNoSharp[:], fixed.codeNoSharp[:])
		sub.hasFixed = true
	case Mode590:
		fixed := code2I40At11Bits(
			pitch.xn2[:],
			sub.h1[:],
			pitch.t0,
			e.sharp,
			sub.fixed.code[:],
			sub.fixed.y2[:],
		)
		sub.fixed.index = fixed.index
		sub.fixed.sign = fixed.sign
		sub.fixed.params[0] = fixed.index
		sub.fixed.params[1] = fixed.sign
		sub.fixed.paramCount = 2
		sub.hasFixed = true
	case Mode670:
		fixed := code3I40At14Bits(
			pitch.xn2[:],
			sub.h1[:],
			pitch.t0,
			e.sharp,
			sub.fixed.code[:],
			sub.fixed.y2[:],
		)
		sub.fixed.index = fixed.index
		sub.fixed.sign = fixed.sign
		sub.fixed.params[0] = fixed.index
		sub.fixed.params[1] = fixed.sign
		sub.fixed.paramCount = 2
		sub.hasFixed = true
	case Mode740, Mode795:
		fixed := code4I40At17Bits(
			pitch.xn2[:],
			sub.h1[:],
			pitch.t0,
			e.sharp,
			sub.fixed.code[:],
			sub.fixed.y2[:],
		)
		sub.fixed.index = fixed.index
		sub.fixed.sign = fixed.sign
		sub.fixed.params[0] = fixed.index
		sub.fixed.params[1] = fixed.sign
		sub.fixed.paramCount = 2
		sub.hasFixed = true
	case Mode1020:
		pitSharp := fxp.Shl16(e.sharp, 1)
		for i := int(pitch.t0); i < subframeSamples; i++ {
			contribution := fxp.Mult(sub.h1[i-int(pitch.t0)], pitSharp)
			sub.h1[i] = fxp.Add16(sub.h1[i], contribution)
		}
		fixed := code8I40At31Bits(
			pitch.xn2[:],
			sub.res[:],
			sub.h1[:],
			sub.fixed.code[:],
			sub.fixed.y2[:],
		)
		for i := int(pitch.t0); i < subframeSamples; i++ {
			contribution := fxp.Mult(sub.fixed.code[i-int(pitch.t0)], pitSharp)
			sub.fixed.code[i] = fxp.Add16(sub.fixed.code[i], contribution)
		}
		copy(sub.fixed.params[:], fixed.params[:])
		sub.fixed.paramCount = len(fixed.params)
		sub.hasFixed = true
	case Mode1220:
		pitSharp := fxp.Shl16(pitch.gainPit, 1)
		for i := int(pitch.t0); i < subframeSamples; i++ {
			contribution := int16((int32(sub.h1[i-int(pitch.t0)]) * int32(pitSharp)) >> 15)
			sub.h1[i] = fxp.Add16(sub.h1[i], contribution)
		}
		fixed := code10I40At35Bits(
			pitch.xn2[:],
			sub.res[:],
			sub.h1[:],
			sub.fixed.code[:],
			sub.fixed.y2[:],
		)
		for i := int(pitch.t0); i < subframeSamples; i++ {
			contribution := fxp.Mult(sub.fixed.code[i-int(pitch.t0)], pitSharp)
			sub.fixed.code[i] = fxp.Add16(sub.fixed.code[i], contribution)
		}
		copy(sub.fixed.params[:], fixed.params[:])
		sub.fixed.paramCount = len(fixed.params)
		if err := ctx.frame.params.writeSlice(fixed.params[:]); err != nil {
			return err
		}
		gain, err := e.gain.quantizeMR122(
			sub.fixed.code[:],
			pitch.xn2[:],
			sub.fixed.y2[:],
		)
		if err != nil {
			return err
		}
		sub.fixed.gainCode = gain
		if err := ctx.frame.params.write(gain.index); err != nil {
			return err
		}
		sub.hasFixed = true
	}
	return nil
}

func rebuildMR475Pitch(exc []int16, excOffset int, pitch *encoderPitchAnalysis, h1 []int16) error {
	if pitch == nil {
		return errors.New("AMR-NB MR475 pitch rebuild: missing pitch analysis")
	}
	if err := predictAdaptiveCodebook(
		exc,
		excOffset,
		pitch.t0,
		pitch.t0Frac,
		subframeSamples,
		pitch.useThirdResolution,
	); err != nil {
		return err
	}
	pitch.yl = convolve(exc[excOffset:excOffset+subframeSamples], h1)
	return nil
}
