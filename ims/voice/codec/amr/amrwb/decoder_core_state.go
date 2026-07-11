/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This state layout follows amr_wb/dec/src/e_pv_amrwbdec.h and
 * pvamrwbdecoder.cpp reset semantics.
 */

package amrwb

const (
	lpcOrder          = 16
	lpcOrder16k       = 20
	subframeSamples   = 64
	frameSamples12k8  = 256
	pitchMax          = 231
	oldWspSamples     = pitchMax / 2
	interpolationLen  = 17
	meanISFBufferSize = 3
	qMax              = 8
	randomInitialSeed = 21845
	initialOldT0      = 64
)

var initialISP = [...]int16{
	32138, 30274, 27246, 23170, 18205, 12540, 6393, 0,
	-6393, -12540, -18205, -23170, -27246, -30274, -32138, 1475,
}

var initialISF = [...]int16{
	1024, 2048, 3072, 4096, 5120, 6144, 7168, 8192,
	9216, 10240, 11264, 12288, 13312, 14336, 15360, 3840,
}

type decoderCoreState struct {
	oldExc    [pitchMax + interpolationLen]int16
	ispOld    [lpcOrder]int16
	isfOld    [lpcOrder]int16
	isfBuf    [meanISFBufferSize * lpcOrder]int16
	pastISFQ  [lpcOrder]int16
	tiltCode  int16
	qOld      int16
	qSubframe [4]int16
	gcThresh  int32

	memSynHi   [lpcOrder]int16
	memSynLo   [lpcOrder]int16
	memDeemph  int16
	memSigOut  [6]int16
	memOversmp [24]int16
	memSynHF   [lpcOrder16k]int16
	memHF      [30]int16
	memHF2     [30]int16
	memHF3     [30]int16
	memHP400   [6]int16

	seed       int16
	seed2      int16
	seed3      int16
	oldT0      int16
	oldT0Frac  int16
	lagHist    [5]int16
	decGain    gainDecoderState
	dispMem    [8]int16
	prevBFI    bool
	state      int16
	firstFrame bool
	vadHist    int16
	dtx        dtxDecState
}

type dtxDecState struct {
	sinceLastSID     int16
	trueSIDPeriodInv int16
	logEnergy        int16
	oldLogEnergy     int16
	level            int16
	isf              [lpcOrder]int16
	isfOld           [lpcOrder]int16
	cngSeed          int16
	isfHist          [lpcOrder * 8]int16
	logEnergyHist    [8]int16
	histPtr          int16
	dtxHangoverCount int16
	decAnaElapsed    int16
	sidFrame         bool
	validData        bool
	dtxHangoverAdded bool
	globalState      dtxStateType
	dataUpdated      bool
	ditherSeed       int16
	cnDither         bool
}

func newDecoderCoreState() decoderCoreState {
	var state decoderCoreState
	state.reset(true)
	return state
}

func (s *decoderCoreState) reset(resetAll bool) {
	clear(s.oldExc[:])
	clear(s.pastISFQ[:])
	s.oldT0Frac = 0
	s.oldT0 = initialOldT0
	s.firstFrame = true
	s.gcThresh = 0
	s.tiltCode = 0
	clear(s.dispMem[:])
	s.qOld = qMax
	for i := range s.qSubframe {
		s.qSubframe[i] = qMax
	}

	if !resetAll {
		return
	}

	s.decGain = resetGainDecoder()
	clear(s.memOversmp[:])
	clear(s.memHF[:])
	clear(s.memHF2[:])
	clear(s.memHF3[:])
	clear(s.memSigOut[:])
	clear(s.memHP400[:])
	s.lagHist = initialLagHistory()
	copy(s.ispOld[:], initialISP[:])
	copy(s.isfOld[:], initialISF[:])
	for i := range meanISFBufferSize {
		copy(s.isfBuf[i*lpcOrder:(i+1)*lpcOrder], initialISF[:])
	}
	s.memDeemph = 0
	s.seed = randomInitialSeed
	s.seed2 = randomInitialSeed
	s.seed3 = randomInitialSeed
	s.state = 0
	s.prevBFI = false
	clear(s.memSynHF[:])
	clear(s.memSynHi[:])
	clear(s.memSynLo[:])
	s.dtx.reset()
	s.vadHist = 0
}

func (s *dtxDecState) reset() {
	*s = dtxDecState{}
	s.trueSIDPeriodInv = 1 << 13
	s.logEnergy = 3500
	s.oldLogEnergy = 3500
	s.cngSeed = randomInitialSeed
	s.ditherSeed = randomInitialSeed
	copy(s.isf[:], initialISF[:])
	copy(s.isfOld[:], initialISF[:])
	for i := range 8 {
		copy(s.isfHist[i*lpcOrder:(i+1)*lpcOrder], initialISF[:])
		s.logEnergyHist[i] = 3500 >> 3
	}
	s.dtxHangoverCount = 7
	s.decAnaElapsed = 32767
	s.globalState = dtxStateSpeech
}
