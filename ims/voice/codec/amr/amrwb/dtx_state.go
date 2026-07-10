/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This state machine is ported from amr_wb/dec/src/dtx_decoder_amr_wb.cpp.
 */

package amrwb

import "github.com/damonto/ims-go/ims/voice/codec/amr/fxp"

const (
	dtxMaxEmptyThreshold   int16 = 50
	dtxElapsedFramesThresh int16 = 30
	dtxHangConst           int16 = 7
	dtxInitialElapsedCount int16 = 32767
)

// RXFrameType identifies the receive-side frame class used by the AMR-WB decoder.
type RXFrameType int16

const (
	rxSpeechGood RXFrameType = iota
	rxSpeechProbablyDegraded
	rxSpeechLost
	rxSpeechBad
	rxSIDFirst
	rxSIDUpdate
	rxSIDBad
	rxNoData
)

const (
	RXSpeechGood             RXFrameType = rxSpeechGood
	RXSpeechProbablyDegraded RXFrameType = rxSpeechProbablyDegraded
	RXSpeechLost             RXFrameType = rxSpeechLost
	RXSpeechBad              RXFrameType = rxSpeechBad
	RXSIDFirst               RXFrameType = rxSIDFirst
	RXSIDUpdate              RXFrameType = rxSIDUpdate
	RXSIDBad                 RXFrameType = rxSIDBad
	RXNoData                 RXFrameType = rxNoData
)

type dtxStateType int16

const (
	dtxStateSpeech dtxStateType = iota
	dtxStateDTX
	dtxStateMute
)

func (s *dtxDecState) rxHandler(frameType RXFrameType) dtxStateType {
	newState := dtxStateSpeech
	if frameType == rxSIDFirst ||
		frameType == rxSIDUpdate ||
		frameType == rxSIDBad ||
		((s.globalState == dtxStateDTX || s.globalState == dtxStateMute) &&
			(frameType == rxNoData || frameType == rxSpeechBad || frameType == rxSpeechLost)) {
		newState = dtxStateDTX
		if s.globalState == dtxStateMute &&
			(frameType == rxSIDBad || frameType == rxSIDFirst ||
				frameType == rxSpeechLost || frameType == rxNoData) {
			newState = dtxStateMute
		}
		s.sinceLastSID = fxp.Add16(s.sinceLastSID, 1)
		if s.sinceLastSID > dtxMaxEmptyThreshold {
			newState = dtxStateMute
		}
	} else {
		newState = dtxStateSpeech
		s.sinceLastSID = 0
	}

	if !s.dataUpdated && frameType == rxSIDUpdate {
		s.decAnaElapsed = 0
	}
	s.decAnaElapsed = fxp.Add16(s.decAnaElapsed, 1)
	s.dtxHangoverAdded = false

	encState := dtxStateSpeech
	if frameType == rxSIDFirst ||
		frameType == rxSIDUpdate ||
		frameType == rxSIDBad ||
		(frameType == rxNoData && s.globalState != dtxStateSpeech) {
		encState = dtxStateDTX
	}

	if encState == dtxStateSpeech {
		s.dtxHangoverCount = dtxHangConst
	} else if s.decAnaElapsed > dtxElapsedFramesThresh {
		s.dtxHangoverAdded = true
		s.decAnaElapsed = 0
		s.dtxHangoverCount = 0
	} else if s.dtxHangoverCount == 0 {
		s.decAnaElapsed = 0
	} else {
		s.dtxHangoverCount--
	}

	if newState != dtxStateSpeech {
		s.sidFrame = false
		s.validData = false
		switch frameType {
		case rxSIDFirst:
			s.sidFrame = true
		case rxSIDUpdate:
			s.sidFrame = true
			s.validData = true
		case rxSIDBad:
			s.sidFrame = true
			s.dtxHangoverAdded = false
		}
	}
	return newState
}
