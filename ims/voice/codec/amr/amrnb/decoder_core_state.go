package amrnb

const (
	lpcOrder         = 10
	pitchMax         = 143
	interpolationLen = 11
	subframeSamples  = 40

	excitationHistoryLen = 9
	ltpGainHistoryLen    = 9

	sharpMin     int16 = 0
	sharpMax     int16 = 13017
	initialOldT0 int16 = 40
	noDataSeed   int16 = 21845
)

var initialLSP = [...]int16{30000, 26000, 21000, 15000, 8000, 0, -8000, -15000, -21000, -26000}

type decoderCoreState struct {
	oldExc    [subframeSamples + pitchMax + interpolationLen]int16
	excOffset int

	code [subframeSamples]int16
	az   [azFrameCount]int16

	lspOld [lpcOrder]int16
	memSyn [lpcOrder]int16

	sharp          int16
	oldT0          int16
	gainIndexMR475 int16

	prevBF  bool
	prevPDF bool
	state   int16

	excEnergyHist [excitationHistoryLen]int16
	t0LagBuff     int16

	predState   gainPredState
	lspAvg      lspAvgState
	lsfState    dPLSFState
	ecGainPitch ecGainPitchState
	ecGainCode  ecGainCodeState
	cbGainAvg   cbGainAverageState
	background  backgroundNoiseState
	phaseDisp   phaseDispersionState

	inBackgroundNoise bool
	voicedHangover    int16
	ltpGainHistory    [ltpGainHistoryLen]int16

	nodataSeed int16
	overflow   bool

	dtx          dtxDecState
	lastDTXState dtxStateType
}

func newDecoderCoreState() decoderCoreState {
	var state decoderCoreState
	state.reset(Mode475)
	return state
}

func (s *decoderCoreState) reset(mode Mode) {
	s.excOffset = pitchMax + interpolationLen
	clear(s.oldExc[:pitchMax+interpolationLen])

	if mode != ModeDTX {
		clear(s.memSyn[:])
		copy(s.lspOld[:], initialLSP[:])
		clear(s.excEnergyHist[:])
		s.predState.reset()
		s.lspAvg.reset()
	}
	s.lsfState.reset()
	s.ecGainPitch.reset()
	s.ecGainCode.reset()
	s.cbGainAvg.reset()
	s.background.reset()
	s.phaseDisp.reset()

	s.sharp = sharpMin
	s.oldT0 = initialOldT0
	s.gainIndexMR475 = 0
	s.overflow = false

	s.prevBF = false
	s.prevPDF = false
	s.state = 0

	s.t0LagBuff = initialOldT0
	s.inBackgroundNoise = false
	s.voicedHangover = 0
	clear(s.ltpGainHistory[:])

	s.nodataSeed = noDataSeed
	if mode != ModeDTX {
		s.dtx.reset()
	}
}

func (s *decoderCoreState) beginFrame(mode Mode, rxType RXFrameType, params []int16) ([]int16, error) {
	s.lastDTXState = s.dtx.rxHandler(rxType)
	if s.lastDTXState != dtxStateSpeech {
		s.reset(ModeDTX)
		return params, nil
	}
	if rxType == RXNoData || rxType == RXOnset {
		params, nextSeed, err := buildCNParam(s.nodataSeed, mode, params)
		if err != nil {
			return nil, err
		}
		s.nodataSeed = nextSeed
		return params, nil
	}
	return params, nil
}

func (s *decoderCoreState) predictPitch(t0, frac int16, useThirdResolution bool) error {
	return predictAdaptiveCodebook(s.oldExc[:], s.excOffset, t0, frac, subframeSamples, useThirdResolution)
}

func (s *decoderCoreState) decodeFixed2i40_9bits(subframeNumber, sign, index int16) []int16 {
	s.code = decode2i40_9bits(subframeNumber, sign, index)
	return s.code[:]
}

func (s *decoderCoreState) decodeFixed2i40_11bits(sign, index int16) []int16 {
	s.code = decode2i40_11bits(sign, index)
	return s.code[:]
}

func (s *decoderCoreState) decodeFixed3i40_14bits(sign, index int16) []int16 {
	s.code = decode3i40_14bits(sign, index)
	return s.code[:]
}

func (s *decoderCoreState) decodeFixed4i40_17bits(sign, index int16) []int16 {
	s.code = decode4i40_17bits(sign, index)
	return s.code[:]
}

func (s *decoderCoreState) decodeFixed8i40_31bits(index []int16) []int16 {
	s.code = decode8i40_31bits(index)
	return s.code[:]
}

func (s *decoderCoreState) decodeFixed10i40_35bits(index []int16) []int16 {
	s.code = decode10i40_35bits(index)
	return s.code[:]
}
