/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This state machine is ported from amr_nb/dec/src/dtx_dec.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	dtxMaxEmptyThreshold   int16 = 50
	dtxHistorySize               = 8
	dtxElapsedFramesThresh int16 = 30
	dtxHangConst           int16 = 7
	dtxInitialLogEnergy    int16 = 3500
	dtxInitialElapsedCount int16 = 32767
	pnInitialSeed          int32 = 0x70816958
)

var meanLSF = [...]int16{1384, 2077, 3420, 5108, 6742, 8122, 9863, 11092, 12714, 13701}
var dtxLogEnergyAdjust = [...]int16{-1023, -878, -732, -586, -440, -294, -148, 0, 0}
var dtxLSFHistMeanScale = [...]int16{20000, 20000, 20000, 20000, 20000, 18000, 16384, 8192, 0, 0}

type dtxStateType int

const (
	dtxStateSpeech dtxStateType = iota
	dtxStateDTX
	dtxStateMute
)

type dtxDecState struct {
	sinceLastSID     int16
	trueSIDPeriodInv int16
	logEnergy        int16
	oldLogEnergy     int16
	pnSeedRX         int32

	lsp    [lpcOrder]int16
	lspOld [lpcOrder]int16

	lsfHist       [lpcOrder * dtxHistorySize]int16
	lsfHistPtr    int16
	lsfHistMean   [lpcOrder * dtxHistorySize]int16
	logPGMean     int16
	logEnergyHist [dtxHistorySize]int16
	logEnergyPtr  int16

	logEnergyAdjust int16

	dtxHangoverCount int16
	decAnaElapsed    int16

	sidFrame         int16
	validData        int16
	dtxHangoverAdded int16

	globalState dtxStateType
	dataUpdated int16
}

func (s *dtxDecState) reset() {
	s.sinceLastSID = 0
	s.trueSIDPeriodInv = 1 << 13
	s.logEnergy = dtxInitialLogEnergy
	s.oldLogEnergy = dtxInitialLogEnergy
	s.pnSeedRX = pnInitialSeed

	copy(s.lsp[:], initialLSP[:])
	copy(s.lspOld[:], initialLSP[:])

	s.lsfHistPtr = 0
	s.logPGMean = 0
	s.logEnergyPtr = 0
	for i := range dtxHistorySize {
		copy(s.lsfHist[i*lpcOrder:(i+1)*lpcOrder], meanLSF[:])
		s.logEnergyHist[i] = s.logEnergy
	}
	clear(s.lsfHistMean[:])

	s.logEnergyAdjust = 0
	s.dtxHangoverCount = dtxHangConst
	s.decAnaElapsed = dtxInitialElapsedCount

	s.sidFrame = 0
	s.validData = 0
	s.dtxHangoverAdded = 0

	s.globalState = dtxStateDTX
	s.dataUpdated = 0
}

func (s *dtxDecState) rxHandler(frameType RXFrameType) dtxStateType {
	newState := dtxStateSpeech
	if frameType == RXSIDFirst ||
		frameType == RXSIDUpdate ||
		frameType == RXSIDBad ||
		((s.globalState == dtxStateDTX || s.globalState == dtxStateMute) &&
			(frameType == RXNoData || frameType == RXSpeechBad || frameType == RXOnset)) {
		newState = dtxStateDTX
		if s.globalState == dtxStateMute &&
			(frameType == RXSIDBad || frameType == RXSIDFirst || frameType == RXOnset || frameType == RXNoData) {
			newState = dtxStateMute
		}
		s.sinceLastSID++
		if frameType != RXSIDUpdate && s.sinceLastSID > dtxMaxEmptyThreshold {
			newState = dtxStateMute
		}
	} else {
		newState = dtxStateSpeech
		s.sinceLastSID = 0
	}

	if s.dataUpdated == 0 && frameType == RXSIDUpdate {
		s.decAnaElapsed = 0
	}

	s.decAnaElapsed = fxp.Add16(s.decAnaElapsed, 1)
	s.dtxHangoverAdded = 0

	encState := dtxStateSpeech
	if frameType == RXSIDFirst ||
		frameType == RXSIDUpdate ||
		frameType == RXSIDBad ||
		frameType == RXOnset ||
		frameType == RXNoData {
		encState = dtxStateDTX
		if frameType == RXNoData && newState == dtxStateSpeech {
			encState = dtxStateSpeech
		}
	}

	if encState == dtxStateSpeech {
		s.dtxHangoverCount = dtxHangConst
	} else if s.decAnaElapsed > dtxElapsedFramesThresh {
		s.dtxHangoverAdded = 1
		s.decAnaElapsed = 0
		s.dtxHangoverCount = 0
	} else if s.dtxHangoverCount == 0 {
		s.decAnaElapsed = 0
	} else {
		s.dtxHangoverCount--
	}

	if newState != dtxStateSpeech {
		s.sidFrame = 0
		s.validData = 0
		switch frameType {
		case RXSIDFirst:
			s.sidFrame = 1
		case RXSIDUpdate:
			s.sidFrame = 1
			s.validData = 1
		case RXSIDBad:
			s.sidFrame = 1
			s.dtxHangoverAdded = 0
		}
	}

	return newState
}

func (s *dtxDecState) updateSID(
	lsfState *dPLSFState,
	predState *gainPredState,
	mode Mode,
	params []int16,
) error {
	if s.sidFrame != 0 && s.validData != 0 {
		if len(params) < 5 {
			return fmt.Errorf("updating AMR-NB SID: parameter count %d, want at least 5", len(params))
		}
		if err := validatePLSF3Indices(ModeDTX, params[1:4]); err != nil {
			return err
		}
	}

	if s.dtxHangoverAdded != 0 && s.sidFrame != 0 {
		s.prepareHangoverSID(mode)
	}

	if s.sidFrame != 0 {
		copy(s.lspOld[:], s.lsp[:])
		s.oldLogEnergy = s.logEnergy

		if s.validData != 0 {
			period := s.sinceLastSID
			s.sinceLastSID = 0
			if period >= 32 {
				period = 32
			}
			if period >= 2 {
				s.trueSIDPeriodInv = fxp.DivS(1<<10, fxp.Shl16(period, 10))
			} else {
				s.trueSIDPeriodInv = 1 << 14
			}

			lsfState.initFromPastRQ(params[0])
			lsp, err := lsfState.decode3(ModeDTX, params[1:4])
			if err != nil {
				return err
			}
			s.lsp = lsp
			clear(lsfState.pastRQ[:])

			s.logEnergy = decodeDTXLogEnergy(params[4])
			if s.dataUpdated == 0 || s.globalState == dtxStateSpeech {
				copy(s.lspOld[:], s.lsp[:])
				s.oldLogEnergy = s.logEnergy
			}
		}

		s.initGainPredictor(predState)
	}

	s.updateLogEnergyAdjust(mode)
	return nil
}

func (s *dtxDecState) finishSIDUpdate() {
	if s.sidFrame != 0 && (s.validData != 0 || (s.validData == 0 && s.dtxHangoverAdded != 0)) {
		s.sinceLastSID = 0
		s.dataUpdated = 1
	}
}

func (s *dtxDecState) prepareHangoverSID(mode Mode) {
	if mode < Mode475 || mode > ModeDTX {
		mode = ModeDTX
	}
	s.logEnergyAdjust = dtxLogEnergyAdjust[mode]

	nextLSFPtr := s.lsfHistPtr + lpcOrder
	if nextLSFPtr == lpcOrder*dtxHistorySize {
		nextLSFPtr = 0
	}
	copy(s.lsfHist[nextLSFPtr:nextLSFPtr+lpcOrder], s.lsfHist[s.lsfHistPtr:s.lsfHistPtr+lpcOrder])

	nextLogPtr := s.logEnergyPtr + 1
	if nextLogPtr == dtxHistorySize {
		nextLogPtr = 0
	}
	s.logEnergyHist[nextLogPtr] = s.logEnergyHist[s.logEnergyPtr]

	s.logEnergy = 0
	var lsfSum [lpcOrder]int32
	for i := range dtxHistorySize {
		s.logEnergy = fxp.Add16(s.logEnergy, fxp.Shr16(s.logEnergyHist[i], 3))
		for j := range lpcOrder {
			lsfSum[j] = fxp.Add32(lsfSum[j], int32(s.lsfHist[i*lpcOrder+j]))
		}
	}

	var lsf [lpcOrder]int16
	for i := range lpcOrder {
		lsf[i] = int16(fxp.Shr32(lsfSum[i], 3))
	}
	s.lsp = lsfToLsp(lsf[:])
	s.logEnergy = fxp.Sub16(s.logEnergy, s.logEnergyAdjust)

	copy(s.lsfHistMean[:], s.lsfHist[:])
	for i := range lpcOrder {
		mean := int32(0)
		for j := range dtxHistorySize {
			mean = fxp.Add32(mean, int32(s.lsfHistMean[i+j*lpcOrder]))
		}
		lsfMean := int16(fxp.Shr32(mean, 3))
		for j := range dtxHistorySize {
			offset := i + j*lpcOrder
			delta := fxp.Sub16(s.lsfHistMean[offset], lsfMean)
			delta = fxp.Mult(delta, dtxLSFHistMeanScale[i])

			negative := delta < 0
			delta = fxp.Abs16(delta)
			if delta > 655 {
				delta = fxp.Add16(655, fxp.Shr16(fxp.Sub16(delta, 655), 2))
			}

			delta = min(delta, 1310)

			if negative {
				delta = fxp.Neg16(delta)
			}
			s.lsfHistMean[offset] = delta
		}
	}
}

func (s *dtxDecState) activityUpdate(lsf []int16, frame []int16) {
	s.lsfHistPtr += lpcOrder
	if s.lsfHistPtr == lpcOrder*dtxHistorySize {
		s.lsfHistPtr = 0
	}
	copy(s.lsfHist[s.lsfHistPtr:s.lsfHistPtr+lpcOrder], lsf[:lpcOrder])

	frameEnergy := int32(0)
	for i := range FrameSamples {
		frameEnergy = fxp.Add32(frameEnergy, fxp.LMult(frame[i], frame[i]))
	}
	logEnergyExp, logEnergyFrac := log2Value(frameEnergy)
	logEnergy := fxp.Add16(fxp.Shl16(logEnergyExp, 10), fxp.Shr16(logEnergyFrac, 5))
	logEnergy = fxp.Sub16(logEnergy, 7497+1024)

	s.logEnergyPtr++
	if s.logEnergyPtr == dtxHistorySize {
		s.logEnergyPtr = 0
	}
	s.logEnergyHist[s.logEnergyPtr] = logEnergy
}

func decodeDTXLogEnergy(index int16) int16 {
	if index == 0 {
		return fxp.Min16
	}
	if index > 63 {
		return fxp.Max16
	}
	if index < -64 {
		return fxp.Min16
	}
	return fxp.Sub16(fxp.Shl16(index, 9), 5120)
}

func (s *dtxDecState) initGainPredictor(predState *gainPredState) {
	maPredInit := fxp.Shr16(s.logEnergy, 1)
	maPredInit = fxp.Sub16(maPredInit, 9000)

	maPredInit = min(max(maPredInit, -14436), 0)

	for i := range gainPredTaps {
		predState.pastQuaEn[i] = maPredInit
		predState.pastQuaEnMR122[i] = int16((int32(maPredInit) * int32(codeGainFactor)) >> 15)
	}
}

func (s *dtxDecState) updateLogEnergyAdjust(mode Mode) {
	if mode < Mode475 || mode > ModeDTX {
		mode = ModeDTX
	}
	adjust := dtxLogEnergyAdjust[mode]
	var scaled int16
	if adjust > 1023 {
		scaled = fxp.Max16
	} else if adjust < -1024 {
		scaled = fxp.Min16
	} else {
		scaled = int16(((int32(adjust) << 5) * 3277) >> 15)
	}
	scaled = fxp.Shr16(scaled, 5)
	s.logEnergyAdjust = fxp.Add16(fxp.Mult(29491, s.logEnergyAdjust), scaled)
}

func (s *dtxDecState) muteComfortNoise() {
	period := s.sinceLastSID
	if period > 32 {
		period = 32
	} else if period <= 0 {
		period = 8
	}
	s.trueSIDPeriodInv = fxp.DivS(1<<10, fxp.Shl16(period, 10))
	s.sinceLastSID = 0
	copy(s.lspOld[:], s.lsp[:])
	s.oldLogEnergy = s.logEnergy
	s.logEnergy = fxp.Sub16(s.logEnergy, 256)

	s.logEnergy = max(s.logEnergy, 0)

}
