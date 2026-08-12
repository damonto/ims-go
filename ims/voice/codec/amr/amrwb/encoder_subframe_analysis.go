package amrwb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type encoderSubframePitch struct {
	t0           int16
	t0Frac       int16
	index        int16
	param        int
	gain         int16
	selectLP     int16
	pitFlag      int16
	qxn          int16
	gCoeff       [4]int16
	target       [subframeSamples]int16
	target2      [subframeSamples]int16
	impulse      [subframeSamples]int16
	codeTarget   [subframeSamples]int16
	codeImpulse  [subframeSamples]int16
	code         [subframeSamples]int16
	codeFiltered [subframeSamples]int16
	codeIndex    int16
	codeIndices  [8]int16
	gainIndex    int16
	gainCode     int32
	gainBits     int16
	quantGain    int16
	hfGainIndex  int16
	filtered     [subframeSamples]int16
}

type encoderSubframeAnalysis struct {
	excitation [pitchMax + interpolationLen + frameSamples12k8 + 1]int16
	subframes  [4]encoderSubframePitch
}

type encoderSubframeContext struct {
	analysis   *encoderAnalysis
	speech     []int16
	excitation []int16
	subframe   int
}

func (c encoderSubframeContext) offset() int {
	return c.subframe * subframeSamples
}

func (c encoderSubframeContext) excitationOffset() int {
	return pitchMax + interpolationLen + c.offset()
}

func (c encoderSubframeContext) excitationFrame() []int16 {
	start := pitchMax + interpolationLen
	return c.excitation[start : start+frameSamples12k8]
}

func (c encoderSubframeContext) excitationSubframe() []int16 {
	start := c.excitationOffset()
	return c.excitation[start : start+subframeSamples]
}

func (c encoderSubframeContext) lpc() []int16 {
	start := c.subframe * lpcCoeffCount
	return c.analysis.lpc.a[start : start+lpcCoeffCount]
}

func (c encoderSubframeContext) quantLPC() []int16 {
	start := c.subframe * lpcCoeffCount
	return c.analysis.quantLPC.aq[start : start+lpcCoeffCount]
}

type analyzedSubframePitch struct {
	lagState pitchLagState
	clipGain bool
}

type highBandCorrection struct {
	sf          *encoderSubframePitch
	gainIndex   int
	active      bool
	adaptiveExc [subframeSamples]int16
	voiceFactor int16
}

func (e *Encoder) analyzePitchSubframes(analysis encoderAnalysis, params []int16) (encoderSubframeAnalysis, error) {
	var out encoderSubframeAnalysis
	copy(out.excitation[:pitchMax+interpolationLen], e.oldExc[:])

	speech, err := buildEncoderSpeechFrame(e.oldSpeech[:], e.speech12k8[:])
	if err != nil {
		return out, fmt.Errorf("analyze AMR-WB subframes: %w", err)
	}
	lagState := initialPitchLagState(analysis.tOp)
	for subframe := range 4 {
		ctx := encoderSubframeContext{
			analysis:   &analysis,
			speech:     speech[:],
			excitation: out.excitation[:],
			subframe:   subframe,
		}
		sf := &out.subframes[subframe]

		if err := e.prepareSubframeTarget(ctx, sf); err != nil {
			return out, fmt.Errorf("analyze AMR-WB subframe %d target: %w", subframe, err)
		}
		pitch, err := e.analyzeSubframePitch(ctx, sf, lagState, params)
		if err != nil {
			return out, fmt.Errorf("analyze AMR-WB subframe %d pitch: %w", subframe, err)
		}
		lagState = pitch.lagState

		if err := e.searchSubframeCodebook(sf, params); err != nil {
			return out, fmt.Errorf("analyze AMR-WB subframe %d codebook: %w", subframe, err)
		}

		gainIndex, err := e.quantizeSubframeGain(sf, pitch.clipGain, params)
		if err != nil {
			return out, fmt.Errorf("analyze AMR-WB subframe %d gain: %w", subframe, err)
		}
		highBand := e.prepareHighBandCorrection(ctx, sf, gainIndex)

		if err := e.updateSubframeFeedback(ctx, sf); err != nil {
			return out, fmt.Errorf("analyze AMR-WB subframe %d feedback: %w", subframe, err)
		}
		if err := e.applyHighBandCorrection(ctx, highBand, params); err != nil {
			return out, fmt.Errorf("analyze AMR-WB subframe %d high-band correction: %w", subframe, err)
		}
	}
	copy(e.oldExc[:], out.excitation[frameSamples12k8:frameSamples12k8+pitchMax+interpolationLen])
	return out, nil
}

func (e *Encoder) quantizeSubframeGain(sf *encoderSubframePitch, clipGain bool, params []int16) (int, error) {
	gainIndex := gainParameterIndex(e.mode, sf.param)
	if gainIndex < 0 || gainIndex >= len(params) {
		return 0, fmt.Errorf("quantize subframe gain: parameter index %d outside buffer length %d", gainIndex, len(params))
	}
	gain := e.gainQuant.quantize(e.mode, sf, clipGain)
	params[gainIndex] = gain.index
	sf.gainIndex = gain.index
	sf.gain = gain.pitch
	sf.gainCode = gain.code
	sf.gainBits = gain.nbits
	sf.quantGain = gain.codeTable
	e.pitchClip.updateGain(e.mode, sf.gain)
	return gainIndex, nil
}

func (e *Encoder) prepareHighBandCorrection(
	ctx encoderSubframeContext,
	sf *encoderSubframePitch,
	gainIndex int,
) highBandCorrection {
	out := highBandCorrection{
		sf:        sf,
		gainIndex: gainIndex,
		active:    e.mode == Mode2385,
	}
	if !out.active {
		return out
	}

	copy(out.adaptiveExc[:], ctx.excitationSubframe())
	gainCode := fxp.Round(fxp.Shl32(sf.gainCode, e.preprocess.qOld))
	var scaledExc [subframeSamples]int16
	copy(scaledExc[:], out.adaptiveExc[:])
	scaleSignalRound(scaledExc[:], ctx.analysis.weighted.shift)
	out.voiceFactor = voiceFactor(
		scaledExc,
		ctx.analysis.weighted.shift,
		sf.gain,
		sf.code,
		gainCode,
	)
	return out
}

func (e *Encoder) applyHighBandCorrection(
	ctx encoderSubframeContext,
	highBand highBandCorrection,
	params []int16,
) error {
	if !highBand.active {
		return nil
	}
	hfIndex := highBandCorrectionParameterIndex(e.mode, highBand.gainIndex)
	if hfIndex < 0 || hfIndex >= len(params) {
		return fmt.Errorf("apply high-band correction: parameter index %d outside buffer length %d", hfIndex, len(params))
	}
	sf := highBand.sf
	hfGainIndex, err := e.highBandCorrectionIndex(
		ctx.quantLPC(),
		highBand.adaptiveExc[:],
		sf,
		e.preprocess.qOld,
		highBand.voiceFactor,
		ctx.analysis.quantLPC.stability,
		ctx.subframe,
	)
	if err != nil {
		return fmt.Errorf("apply high-band correction: %w", err)
	}
	sf.hfGainIndex = hfGainIndex
	params[hfIndex] = sf.hfGainIndex
	return nil
}

func (e *Encoder) prepareSubframeTarget(ctx encoderSubframeContext, sf *encoderSubframePitch) error {
	iSubframe := ctx.offset()
	a := ctx.lpc()
	aq := ctx.quantLPC()
	if err := encoderResidual(
		aq,
		ctx.speech[iSubframe:iSubframe+lpcOrder+subframeSamples],
		ctx.excitationSubframe(),
	); err != nil {
		return fmt.Errorf("prepare subframe target excitation: %w", err)
	}

	var residualError [lpcOrder + subframeSamples]int16
	for i := range lpcOrder {
		residualError[i] = ctx.speech[iSubframe+i] - e.memSyn[i]
	}
	synthesizedError, err := encoderSynthesisFilter(aq, ctx.excitationSubframe(), residualError[:lpcOrder], subframeSamples)
	if err != nil {
		return fmt.Errorf("prepare subframe target synthesis error: %w", err)
	}
	copy(residualError[lpcOrder:], synthesizedError.signal[:])

	weightedA, err := weightLPC(a, encoderGamma1)
	if err != nil {
		return fmt.Errorf("prepare weighted subframe target: %w", err)
	}
	if err := encoderResidual(weightedA[:], residualError[:], sf.target[:]); err != nil {
		return fmt.Errorf("prepare weighted subframe target: %w", err)
	}
	e.memW0 = deemphasis2(sf.target[:], encoderTiltFac, e.memW0)
	sf.codeTarget, err = innovationSearchTarget(
		aq,
		weightedA[:],
		sf.target[:],
		ctx.excitationSubframe(),
	)
	if err != nil {
		return fmt.Errorf("prepare subframe innovation target: %w", err)
	}
	sf.impulse, err = impulseResponse(a, aq)
	if err != nil {
		return fmt.Errorf("prepare subframe impulse response: %w", err)
	}
	copy(sf.codeImpulse[:], sf.impulse[:])
	scaleSignalRound(sf.codeImpulse[:], -2)
	return nil
}

func (e *Encoder) analyzeSubframePitch(
	ctx encoderSubframeContext,
	sf *encoderSubframePitch,
	lagState pitchLagState,
	params []int16,
) (analyzedSubframePitch, error) {
	var out analyzedSubframePitch
	paramIndex := pitchParameterIndex(e.mode, ctx.subframe)
	if paramIndex < 0 || paramIndex >= len(params) {
		return out, fmt.Errorf("analyze subframe pitch: parameter index %d outside buffer length %d", paramIndex, len(params))
	}
	selectIndex := -1
	if e.mode > Mode885 {
		selectIndex = pitchSelectParameterIndex(e.mode, ctx.subframe)
		if selectIndex < 0 || selectIndex >= len(params) {
			return out, fmt.Errorf("analyze subframe pitch: selector index %d outside buffer length %d", selectIndex, len(params))
		}
	}

	var hSearch [subframeSamples]int16
	copy(hSearch[:], sf.impulse[:])
	scaleSignalRound(sf.target[:], ctx.analysis.weighted.shift)
	scaleSignalRound(hSearch[:], ctx.analysis.weighted.shift+1)

	pitFlag, searchState := subframePitchSearchState(e.mode, ctx.subframe, ctx.analysis.tOp2, lagState)
	t0Frac2, t0Frac1 := pitchMin, pitchFrac1At8Bits
	if e.mode > Mode885 {
		t0Frac2, t0Frac1 = pitchFrac2, pitchFrac1At9Bits
	}
	t0, t0Frac, err := pitchFR4(
		ctx.excitation,
		ctx.excitationOffset(),
		sf.target[:],
		hSearch[:],
		searchState.t0Min,
		searchState.t0Max,
		pitFlag,
		t0Frac2,
		t0Frac1,
	)
	if err != nil {
		return out, fmt.Errorf("analyze subframe pitch: %w", err)
	}
	pitchParam := encodeSubframePitchLag(subframePitchLagInput{
		mode: e.mode, subframe: ctx.subframe, openLoop: ctx.analysis.tOp2,
		lag: t0, fraction: t0Frac, state: lagState,
	})
	out.lagState = pitchParam.state
	params[paramIndex] = pitchParam.index

	predictAdaptiveCodebook(ctx.excitation, ctx.excitationOffset(), t0, t0Frac, subframeSamples+1)
	out.clipGain = e.pitchClip.clip(e.mode)
	pitch, err := selectPitchPrediction(
		e.mode,
		ctx.excitation[ctx.excitationOffset()-1:ctx.excitationOffset()+subframeSamples+1],
		sf.target[:],
		hSearch[:],
		out.clipGain,
	)
	if err != nil {
		return out, fmt.Errorf("analyze subframe pitch: %w", err)
	}
	if e.mode > Mode885 {
		params[selectIndex] = pitch.selectNoLP
	}
	copy(ctx.excitation[ctx.excitationOffset():], pitch.excitation[:])
	sf.codeTarget, err = updateTarget(
		sf.codeTarget[:],
		ctx.excitationSubframe(),
		pitch.gain,
	)
	if err != nil {
		return out, fmt.Errorf("analyze subframe pitch: %w", err)
	}
	scaleSignalRound(sf.codeTarget[:], ctx.analysis.weighted.shift)
	copy(sf.filtered[:], pitch.filtered[:])
	copy(sf.codeFiltered[:], pitch.codeSeed[:])
	copy(sf.target2[:], pitch.target2[:])
	copy(sf.gCoeff[:], pitch.gCoeff[:])
	sf.t0 = t0
	sf.t0Frac = t0Frac
	sf.index = pitchParam.index
	sf.param = paramIndex
	sf.gain = pitch.gain
	sf.selectLP = 1 - pitch.selectNoLP
	sf.pitFlag = pitchParam.pitFlag
	sf.qxn = e.preprocess.qOld + ctx.analysis.weighted.shift
	return out, nil
}

func (e *Encoder) searchSubframeCodebook(sf *encoderSubframePitch, params []int16) error {
	codeIndex := sf.param + 2
	codeIndexCount := 4
	if e.mode <= Mode885 {
		codeIndex = sf.param + 1
	}
	switch e.mode {
	case Mode660:
		codeIndexCount = 1
	case Mode885, Mode1265, Mode1425, Mode1585:
	case Mode1825, Mode1985, Mode2305, Mode2385:
		codeIndexCount = 8
	default:
		return fmt.Errorf("search subframe codebook: invalid mode %d", e.mode)
	}
	if codeIndex < 0 || codeIndex+codeIndexCount > len(params) {
		return fmt.Errorf("search subframe codebook: parameter range %d:%d outside buffer length %d", codeIndex, codeIndex+codeIndexCount, len(params))
	}

	var err error
	switch e.mode {
	case Mode660:
		err = e.searchMode660Codebook(sf)
	case Mode885:
		err = e.searchMode885Codebook(sf)
	case Mode1265:
		err = e.searchMode1265Codebook(sf)
	case Mode1425:
		err = e.searchMode1425Codebook(sf)
	case Mode1585:
		err = e.searchMode1585Codebook(sf)
	case Mode1825:
		err = e.searchMode1825Codebook(sf)
	case Mode1985:
		err = e.searchMode1985Codebook(sf)
	case Mode2305:
		err = e.searchMode2305Codebook(sf)
	case Mode2385:
		err = e.searchMode2385Codebook(sf)
	}
	if err != nil {
		return fmt.Errorf("search subframe codebook: %w", err)
	}

	if codeIndexCount == 1 {
		params[codeIndex] = sf.codeIndex
		return nil
	}
	copy(params[codeIndex:codeIndex+codeIndexCount], sf.codeIndices[:codeIndexCount])
	return nil
}

func pitchParameterIndex(mode Mode, subframe int) int {
	if subframe < 0 || subframe >= 4 {
		return -1
	}
	switch mode {
	case Mode660:
		return 5 + subframe*3
	case Mode885:
		return 8 + subframe*6
	case Mode1265, Mode1425, Mode1585:
		return 8 + subframe*7
	case Mode1825, Mode1985, Mode2305:
		return 8 + subframe*11
	case Mode2385:
		return 8 + subframe*12
	default:
		return -1
	}
}

func pitchSelectParameterIndex(mode Mode, subframe int) int {
	base := pitchParameterIndex(mode, subframe)
	if base < 0 || mode <= Mode885 {
		return -1
	}
	return base + 1
}
