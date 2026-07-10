/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This transmit-side DTX scheduling follows enc/src/dtx_enc.cpp and
 * enc/src/sid_sync.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	encoderDTXHangConst            int16 = 7
	encoderDTXElapsedFramesThresh  int16 = 30
	encoderDTXInitialElapsedCount  int16 = fxp.Max16
	encoderSIDUpdateRate           int16 = 8
	encoderInitialSIDUpdateCounter int16 = 3
)

type encoderTXFrameType int16

const (
	txSpeechGood encoderTXFrameType = iota
	txSIDFirst
	txSIDUpdate
	txNoData
)

type encoderDTXState struct {
	hangoverCount    int16
	decAnaElapsed    int16
	sidUpdateRate    int16
	sidUpdateCounter int16
	prevFrameType    encoderTXFrameType

	histPtr        int16
	logEnergyIndex int16
	initLSFVQIndex int16
	lspIndex       [3]int16
	lspHist        [lpcOrder * dtxHistorySize]int16
	logEnergyHist  [dtxHistorySize]int16
	lastSpeech     [FrameSamples]int16
}

func (s *encoderDTXState) reset() {
	s.hangoverCount = encoderDTXHangConst
	s.decAnaElapsed = encoderDTXInitialElapsedCount
	s.sidUpdateRate = encoderSIDUpdateRate
	s.sidUpdateCounter = encoderInitialSIDUpdateCounter
	s.prevFrameType = txSpeechGood

	s.histPtr = 0
	s.logEnergyIndex = 0
	s.initLSFVQIndex = 0
	clear(s.lspIndex[:])
	for i := range dtxHistorySize {
		copy(s.lspHist[i*lpcOrder:(i+1)*lpcOrder], initialLSP[:])
	}
	clear(s.logEnergyHist[:])
	clear(s.lastSpeech[:])
}

func (e *Encoder) encodeDTX(dst []byte, pcm []int16) ([]byte, error) {
	vadSpeech := e.vadInput(pcm)
	active, err := e.voiceActive(vadSpeech[:])
	if err != nil {
		return nil, err
	}
	if active {
		e.dtxState.handleActivity(true, e.mode)
		e.dtxState.noteSpeechFrame()
		data, err := e.encodeSpeech(dst, pcm)
		e.lastMode = e.mode
		return data, err
	}

	usedMode, computeSID := e.dtxState.handleActivity(false, e.mode)
	if usedMode != ModeDTX {
		e.dtxState.noteSpeechFrame()
		data, err := e.encodeSpeech(dst, pcm)
		e.lastMode = e.mode
		return data, err
	}

	frameType := e.dtxState.nextSIDFrameType()
	switch frameType {
	case txSIDFirst:
		data, err := e.encodeDTXSIDFrame(dst, pcm, false, computeSID)
		if err != nil {
			return nil, err
		}
		e.lastMode = ModeDTX
		return data, nil
	case txSIDUpdate:
		data, err := e.encodeDTXSIDFrame(dst, pcm, true, computeSID)
		if err != nil {
			return nil, err
		}
		e.lastMode = ModeDTX
		return data, nil
	default:
		analysis, err := e.analyzeSIDFrame(pcm)
		if err != nil {
			return nil, err
		}
		e.dtxState.buffer(analysis.lspNew[:], e.dtxState.lastSpeech[:])
		if _, err := e.buildSIDParams(computeSID); err != nil {
			return nil, err
		}
		e.resetAfterDTX()
		if err := e.finishDTXFrame(analysis.az); err != nil {
			return nil, err
		}
		e.lastMode = ModeNoData
		e.serial = e.serial[:0]
		e.params = e.params[:0]
		return dst[:0], nil
	}
}

func (e *Encoder) encodeDTXSIDFrame(dst []byte, pcm []int16, update bool, computeSID bool) ([]byte, error) {
	analysis, err := e.analyzeSIDFrame(pcm)
	if err != nil {
		return nil, err
	}
	e.dtxState.buffer(analysis.lspNew[:], e.dtxState.lastSpeech[:])
	params, err := e.buildSIDParams(computeSID)
	if err != nil {
		return nil, err
	}
	serial, err := sidParamsToSerial(e.serial[:0], params, e.dtxSIDMode(), update)
	if err != nil {
		return nil, err
	}
	e.serial = serial
	data, err := (Speech{Mode: ModeDTX, Serial: serial}).Pack(dst)
	if err != nil {
		return nil, err
	}
	e.resetAfterDTX()
	if err := e.finishDTXFrame(analysis.az); err != nil {
		return nil, err
	}
	return data, nil
}

func (e *Encoder) finishDTXFrame(az [azFrameCount]int16) error {
	speechWithHistory := e.oldSpeech[speechHistorySamples-FrameSamples-lpcLookaheadSamples-lpcOrder:]
	first, err := preBig(e.mode, az, 0, speechWithHistory, e.memW)
	if err != nil {
		return err
	}
	second, err := preBig(e.mode, az, FrameSamples/2, speechWithHistory, first.memW)
	if err != nil {
		return err
	}
	copy(e.oldWsp[pitchMax:pitchMax+FrameSamples/2], first.samples[:])
	copy(e.oldWsp[pitchMax+FrameSamples/2:pitchMax+FrameSamples], second.samples[:])
	e.memW = second.memW

	var vad *encoderVADState
	var vad2 *encoderVAD2State
	if e.vadOption == VAD2 {
		e.vad2.resetPitchCorrelation()
		vad2 = &e.vad2
	} else {
		vad = &e.vad
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
		return err
	}
	if vad2 != nil {
		e.vad2.updateLTPFlag(e.mode)
	} else {
		e.vad.pitchDetection(tOp[:])
	}

	e.shiftSIDHistory()
	copy(e.oldWsp[:pitchMax], e.oldWsp[FrameSamples:FrameSamples+pitchMax])
	clear(e.oldWsp[pitchMax:])
	return nil
}

func (e *Encoder) voiceActive(pcm []int16) (bool, error) {
	if len(pcm) != FrameSamples {
		return false, fmt.Errorf(
			"detecting AMR-NB voice activity: pcm sample count %d, want %d",
			len(pcm),
			FrameSamples,
		)
	}
	if e.vadOption == VAD2 {
		return e.vad2.active(pcm)
	}
	var powerPCM [FrameSamples]int16
	copy(powerPCM[:lpcLookaheadSamples], e.oldSpeech[speechHistorySamples-FrameSamples-lpcLookaheadSamples:speechHistorySamples-FrameSamples])
	copy(powerPCM[lpcLookaheadSamples:], pcm[:FrameSamples-lpcLookaheadSamples])
	return e.vad.activeWithPower(pcm, powerPCM[:])
}

func (e *Encoder) resetAfterDTX() {
	lspNew := e.lsp.lspOld
	clear(e.oldExc[:encoderExcOffset])
	clear(e.memW0[:])
	clear(e.memErr[:])
	e.pitch.reset()
	e.lsp.reset()
	copy(e.lsp.lspOld[:], lspNew[:])
	copy(e.lsp.lspOldQ[:], lspNew[:])
	e.sharp = sharpMin
}

func (e *Encoder) vadInput(pcm []int16) [FrameSamples]int16 {
	var speech [FrameSamples]int16
	for i, sample := range pcm {
		speech[i] = sample &^ 0x0007
	}
	preprocess := e.preprocess
	preprocess.process(speech[:])
	return speech
}

func (e *Encoder) encodeSpeech(dst []byte, pcm []int16) ([]byte, error) {
	if err := e.encodeParams(pcm); err != nil {
		return nil, err
	}
	serial, err := (Params{Mode: e.mode, Values: e.params}).Pack(e.serial[:0])
	if err != nil {
		return nil, err
	}
	e.serial = serial
	return (Speech{Mode: e.mode, Serial: serial}).Pack(dst)
}

func (s *encoderDTXState) handleActivity(active bool, mode Mode) (Mode, bool) {
	s.decAnaElapsed = fxp.Add16(s.decAnaElapsed, 1)
	if active {
		s.hangoverCount = encoderDTXHangConst
		return mode, false
	}

	if s.hangoverCount == 0 {
		s.decAnaElapsed = 0
		return ModeDTX, true
	}

	s.hangoverCount--
	if fxp.Add16(s.decAnaElapsed, s.hangoverCount) < encoderDTXElapsedFramesThresh {
		return ModeDTX, false
	}
	return mode, false
}

func (s *encoderDTXState) nextSIDFrameType() encoderTXFrameType {
	s.sidUpdateCounter--
	var frameType encoderTXFrameType
	if s.prevFrameType == txSpeechGood {
		frameType = txSIDFirst
		s.sidUpdateCounter = encoderInitialSIDUpdateCounter
	} else if s.sidUpdateCounter == 0 {
		frameType = txSIDUpdate
		s.sidUpdateCounter = encoderSIDUpdateRate
	} else {
		frameType = txNoData
	}
	s.prevFrameType = frameType
	return frameType
}

func (s *encoderDTXState) noteSpeechFrame() {
	s.sidUpdateCounter = s.sidUpdateRate
	s.prevFrameType = txSpeechGood
}

func (s *encoderDTXState) buffer(lsp []int16, speech []int16) {
	s.histPtr++
	if s.histPtr == dtxHistorySize {
		s.histPtr = 0
	}
	copy(s.lspHist[s.histPtr*lpcOrder:(s.histPtr+1)*lpcOrder], lsp[:lpcOrder])

	energy := int32(0)
	for i := range FrameSamples {
		next := int64(energy) + (int64(speech[i]) * int64(speech[i]) << 1)
		if next > int64(fxp.Max32) {
			energy = fxp.Max32
			break
		}
		energy = int32(next)
	}
	exp, frac := log2Value(energy)
	logEnergy := fxp.Add16(fxp.Shl16(exp, 10), fxp.Shr16(frac, 5))
	logEnergy = fxp.Sub16(logEnergy, 8521)
	s.logEnergyHist[s.histPtr] = fxp.Shr16(logEnergy, 1)
}
