/*
 * Copyright (C) 1998-2009 PacketVideo
 * Copyright 2003-2010, VisualOn, Inc.
 *
 * Licensed under the Apache License, Version 2.0.
 * This transmit-side DTX scheduling follows the AMR-WB dtx.h state machine
 * shape from OpenCORE/VisualOn.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	encoderDTXHangConst            int16 = 7
	encoderDTXElapsedFramesThresh  int16 = 30
	encoderDTXInitialElapsedCount  int16 = 32767
	encoderSIDUpdateRate           int16 = 8
	encoderInitialSIDUpdateCounter int16 = 3
	encoderDTXHistorySize                = 8
	encoderDTXGainThreshold        int16 = 180
	encoderDTXInvMedianThreshold   int64 = 14564
)

var encoderDTXEnergyAdjust = [...]int16{230, 179, 141, 128, 122, 115, 115, 115, 115}

type encoderTXFrameType int16

const (
	txSpeech encoderTXFrameType = iota
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
	histPtr          int
	isfHist          [encoderDTXHistorySize * lpcOrder]int16
	logEnergyHist    [encoderDTXHistorySize]int16
	cngSeed          int16
	distance         [28]int32
	sumD             [encoderDTXHistorySize]int32
}

func (s *encoderDTXState) reset() {
	s.hangoverCount = encoderDTXHangConst
	s.decAnaElapsed = encoderDTXInitialElapsedCount
	s.sidUpdateRate = encoderSIDUpdateRate
	s.sidUpdateCounter = encoderInitialSIDUpdateCounter
	s.prevFrameType = txSpeech
	s.histPtr = 0
	s.cngSeed = randomInitialSeed
	for i := range encoderDTXHistorySize {
		copy(s.isfHist[i*lpcOrder:(i+1)*lpcOrder], initialISF[:])
	}
	clear(s.logEnergyHist[:])
	clear(s.distance[:])
	clear(s.sumD[:])
}

func (e *Encoder) encodeDTX(dst []byte, pcm []int16) ([]byte, error) {
	if _, err := e.prepareFrame(pcm); err != nil {
		return nil, err
	}
	active, err := e.vad.decide(e.vadSpeech[:])
	if err != nil {
		return nil, fmt.Errorf("encode AMR-WB DTX frame: %w", err)
	}
	e.updateEncoderVADHistory(active)
	if active {
		e.dtxState.handleActivity(true, e.mode)
		e.dtxState.noteSpeechFrame()
		data, err := e.encodePreparedFrameSpeech(dst, false)
		e.lastMode = e.mode
		return data, err
	}

	usedMode, _ := e.dtxState.handleActivity(false, e.mode)
	if usedMode != ModeSID {
		e.dtxState.noteSpeechFrame()
		data, err := e.encodePreparedFrameSpeech(dst, true)
		e.lastMode = e.mode
		return data, err
	}

	frameType := e.dtxState.nextSIDFrameType()
	switch frameType {
	case txSIDFirst:
		data, err := e.encodeSID(dst, false)
		e.lastMode = ModeSID
		return data, err
	case txSIDUpdate:
		data, err := e.encodeSID(dst, true)
		e.lastMode = ModeSID
		return data, err
	default:
		params, err := e.sidParamsPrepared()
		if err != nil {
			return nil, err
		}
		if err := e.applySIDHighBandState(params); err != nil {
			return nil, fmt.Errorf("encode AMR-WB DTX frame: %w", err)
		}
		e.resetDTXEncoderCore()
		e.lastMode = ModeNoData
		e.serial = e.serial[:0]
		return dst[:0], nil
	}
}

func (e *Encoder) encodeSID(dst []byte, update bool) ([]byte, error) {
	params, err := e.sidParamsPrepared()
	if err != nil {
		return nil, err
	}
	if err := e.applySIDHighBandState(params); err != nil {
		return nil, fmt.Errorf("encode AMR-WB SID frame: %w", err)
	}
	serial, err := (Params{Mode: ModeSID, Values: params}).Pack(e.serial[:0])
	if err != nil {
		return nil, err
	}
	if update {
		serial[amrWBSIDRxTypeBitOffset] = 1
	}
	e.serial = serial
	e.resetDTXEncoderCore()
	return (Speech{Mode: ModeSID, Serial: serial}).Pack(dst)
}

func (e *Encoder) sidParams(pcm []int16) ([]int16, error) {
	if _, err := e.prepareFrame(pcm); err != nil {
		return nil, err
	}
	return e.sidParamsPrepared()
}

func (e *Encoder) sidParamsPrepared() ([]int16, error) {
	if cap(e.params) < 7 {
		e.params = make([]int16, 7)
	} else {
		e.params = e.params[:7]
		clear(e.params)
	}
	lpc, err := e.lpc.analyze(e.oldSpeech[:], e.speech12k8[:])
	if err != nil {
		return nil, fmt.Errorf("prepare AMR-WB SID parameters: %w", err)
	}
	isf, err := ispToISF(lpc.ispNew[:])
	if err != nil {
		return nil, fmt.Errorf("prepare AMR-WB SID parameters: %w", err)
	}
	weighted, err := e.buildWeightedSpeech(lpc.a[:])
	if err != nil {
		return nil, fmt.Errorf("prepare AMR-WB SID parameters: %w", err)
	}
	if _, _, err := e.estimateOpenLoopPitch(weighted); err != nil {
		return nil, fmt.Errorf("prepare AMR-WB SID parameters: %w", err)
	}
	logEnergy, err := e.dtxLogEnergyForUnquantizedLPC(lpc.a[3*lpcCoeffCount : 4*lpcCoeffCount])
	if err != nil {
		return nil, fmt.Errorf("prepare AMR-WB SID parameters: %w", err)
	}
	e.dtxState.bufferLogEnergy(isf[:], logEnergy)
	averageISF := e.dtxState.averageISF()
	indices, err := quantizeISFNoise(averageISF[:])
	if err != nil {
		return nil, fmt.Errorf("prepare AMR-WB SID parameters: %w", err)
	}
	copy(e.params[:5], indices[:])
	e.params[5] = e.dtxState.logEnergyIndex()
	e.params[6] = e.dtxState.ditheringControl()
	if err := updateEncoderOldSpeech(e.oldSpeech[:], e.speech12k8[:]); err != nil {
		return nil, fmt.Errorf("prepare AMR-WB SID parameters: %w", err)
	}
	return e.params, nil
}

func (e *Encoder) applySIDHighBandState(params []int16) error {
	sid, err := parseDTXSID(params)
	if err != nil {
		return fmt.Errorf("apply SID high-band state: %w", err)
	}
	copy(e.isfQuant.isfOld[:], sid.isf[:])
	isp, err := isfToISP(sid.isf[:])
	if err != nil {
		return fmt.Errorf("apply SID high-band state: %w", err)
	}
	aq, err := ispToAz(isp[:], true)
	if err != nil {
		return fmt.Errorf("apply SID high-band state: %w", err)
	}

	exc := e.dtxState.generateCNGExcitation(sid.logEnergyIndex)
	for iSubframe := 0; iSubframe < frameSamples12k8; iSubframe += subframeSamples {
		outOffset := iSubframe + (iSubframe >> 2)
		if _, err := e.hb.correctionIndex(
			aq[:],
			exc[iSubframe:iSubframe+subframeSamples],
			0,
			e.speech16k[outOffset:outOffset+subframeSamples16k],
			e.dtxState.hangoverCount,
		); err != nil {
			return fmt.Errorf("apply SID high-band state: subframe %d: %w", iSubframe/subframeSamples, err)
		}
	}
	return nil
}

func (e *Encoder) resetDTXEncoderCore() {
	clear(e.oldExc[:pitchMax+interpolationLen])
	clear(e.memSyn[:])
	clear(e.isfQuant.pastISFQ[:])
	e.memW0 = 0
	e.tiltCode = 0
	e.isfQuant.first = true
	e.pitchClip.reset()
	e.hb.gcThresh = 0
}

func quantizeISFNoise(isf []int16) ([5]int16, error) {
	var indices [5]int16
	if len(isf) < lpcOrder {
		return indices, errors.New("quantize comfort-noise ISF: buffer is too short")
	}
	var residual [lpcOrder]int16
	for i := range lpcOrder {
		residual[i] = fxp.Sub16(isf[i], meanISFNoise[i])
	}
	indices[0], _ = subVQ(residual[0:2], dico1ISFNoise[:], 2)
	indices[1], _ = subVQ(residual[2:5], dico2ISFNoise[:], 3)
	indices[2], _ = subVQ(residual[5:8], dico3ISFNoise[:], 3)
	indices[3], _ = subVQ(residual[8:12], dico4ISFNoise[:], 4)
	indices[4], _ = subVQ(residual[12:16], dico5ISFNoise[:], 4)
	return indices, nil
}

func (s *encoderDTXState) handleActivity(active bool, mode Mode) (Mode, bool) {
	s.decAnaElapsed = saturatingAdd16(s.decAnaElapsed, 1)
	if active {
		s.hangoverCount = encoderDTXHangConst
		return mode, false
	}

	if s.hangoverCount == 0 {
		s.decAnaElapsed = 0
		return ModeSID, true
	}

	s.hangoverCount--
	if saturatingAdd16(s.decAnaElapsed, s.hangoverCount) < encoderDTXElapsedFramesThresh {
		return ModeSID, false
	}
	return mode, false
}

func (s *encoderDTXState) nextSIDFrameType() encoderTXFrameType {
	s.sidUpdateCounter--
	var frameType encoderTXFrameType
	if s.prevFrameType == txSpeech {
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
	s.prevFrameType = txSpeech
}

func (s *encoderDTXState) buffer(isf []int16, speech []int16, mode Mode) {
	s.bufferLogEnergy(isf, sidLogEnergyQ7(speech, mode))
}

func (s *encoderDTXState) bufferLogEnergy(isf []int16, logEnergy int16) {
	s.histPtr++
	if s.histPtr == encoderDTXHistorySize {
		s.histPtr = 0
	}
	copy(s.isfHist[s.histPtr*lpcOrder:(s.histPtr+1)*lpcOrder], isf[:lpcOrder])
	s.logEnergyHist[s.histPtr] = logEnergy
}

func (s *encoderDTXState) averageISF() [lpcOrder]int16 {
	var dst [lpcOrder]int16
	replace := s.findFrameIndices()
	for j := range lpcOrder {
		var sum int32
		for i := range encoderDTXHistorySize {
			index := i
			if replace[0] == i || replace[1] == i {
				index = replace[2]
			}
			sum += int32(s.isfHist[index*lpcOrder+j])
		}
		dst[j] = int16(sum >> 3)
	}
	return dst
}

func (s *encoderDTXState) findFrameIndices() [3]int {
	tmp := int16(encoderDTXHistorySize - 1)
	j := int16(-1)
	for i := range encoderDTXHistorySize - 1 {
		j = fxp.Add16(j, tmp)
		s.sumD[i] = fxp.Sub32(s.sumD[i], s.distance[j])
		tmp = fxp.Sub16(tmp, 1)
	}

	for i := encoderDTXHistorySize - 1; i > 0; i-- {
		s.sumD[i] = s.sumD[i-1]
	}
	s.sumD[0] = 0

	tmp = 0
	for i := int16(27); i >= 12; i = fxp.Sub16(i, tmp) {
		tmp = fxp.Add16(tmp, 1)
		for j := tmp; j > 0; j-- {
			s.distance[int(i-j+1)] = s.distance[int(i-j-tmp)]
		}
	}

	ptr := s.histPtr
	for i := 1; i < encoderDTXHistorySize; i++ {
		ptr--
		if ptr < 0 {
			ptr = encoderDTXHistorySize - 1
		}
		distance := dtxISFDistance(
			s.isfHist[s.histPtr*lpcOrder:(s.histPtr+1)*lpcOrder],
			s.isfHist[ptr*lpcOrder:(ptr+1)*lpcOrder],
		)
		s.distance[i-1] = distance
		s.sumD[0] = fxp.Add32(s.sumD[0], distance)
		s.sumD[i] = fxp.Add32(s.sumD[i], distance)
	}

	maxIndex := 0
	minIndex := 0
	for i := 1; i < encoderDTXHistorySize; i++ {
		if fxp.Sub32(s.sumD[i], s.sumD[maxIndex]) > 0 {
			maxIndex = i
		}
		if fxp.Sub32(s.sumD[i], s.sumD[minIndex]) < 0 {
			minIndex = i
		}
	}
	sumMax := s.sumD[maxIndex]
	sumMin := s.sumD[minIndex]
	secondIndex := -1
	secondValue := int32(-2147483647)
	for i := range encoderDTXHistorySize {
		if fxp.Sub32(s.sumD[i], secondValue) > 0 && i != maxIndex {
			secondIndex = i
			secondValue = s.sumD[i]
		}
	}

	medianShift := fxp.NormL(sumMax)
	if !medianReplacementNeeded32(sumMax, sumMin, medianShift) {
		maxIndex = -1
	}
	if secondIndex >= 0 && !medianReplacementNeeded32(secondValue, sumMin, medianShift) {
		secondIndex = -1
	}

	for i, index := range [3]int{maxIndex, secondIndex, minIndex} {
		if index < 0 {
			continue
		}
		index = s.histPtr - index
		if index < 0 {
			index += encoderDTXHistorySize
		}
		switch i {
		case 0:
			maxIndex = index
		case 1:
			secondIndex = index
		default:
			minIndex = index
		}
	}
	return [3]int{maxIndex, secondIndex, minIndex}
}

func (s *encoderDTXState) logEnergyIndex() int16 {
	var logEnergy int16
	for _, value := range s.logEnergyHist {
		logEnergy = fxp.Add16(logEnergy, value)
	}
	logEnergy = fxp.Shr16(logEnergy, 2)
	logEnergy = fxp.Add16(logEnergy, 512)
	logEnergy = fxp.Mult(logEnergy, 21504)
	index := fxp.Shr16(logEnergy, 6)
	if index > 63 {
		return 63
	}
	if index < 0 {
		return 0
	}
	return index
}

func (s *encoderDTXState) ditheringControl() int16 {
	var isfDiff int32
	for _, value := range s.sumD {
		isfDiff = fxp.Add32(isfDiff, value)
	}
	if fxp.Shr32(isfDiff, 26) > 0 {
		return 1
	}

	var mean int16
	for _, value := range s.logEnergyHist {
		mean = fxp.Add16(mean, value)
	}
	mean = fxp.Shr16(mean, 3)

	var gainDiff int16
	for _, value := range s.logEnergyHist {
		gainDiff = fxp.Add16(gainDiff, fxp.Abs16(fxp.Sub16(value, mean)))
	}
	if gainDiff > encoderDTXGainThreshold {
		return 1
	}
	return 0
}

func sidLogEnergyQ7(samples []int16, mode Mode) int16 {
	var energy int64
	for _, sample := range samples {
		v := int64(sample)
		energy += v * v
	}

	energy = min(energy, int64(fxp.Max32))

	logEnergy := logEnergyQ7FromEnergy(int32(energy))
	adjust := int16(115)
	if ValidMode(mode) {
		adjust = encoderDTXEnergyAdjust[mode]
	}
	return fxp.Sub16(logEnergy, fxp.Add16(1024, adjust))
}

func (e *Encoder) dtxLogEnergyForUnquantizedLPC(a []int16) (int16, error) {
	speech, err := buildEncoderSpeechFrame(e.oldSpeech[:], e.speech12k8[:])
	if err != nil {
		return 0, fmt.Errorf("compute DTX energy: %w", err)
	}
	var residual [frameSamples12k8]int16
	if err := encoderResidual(a, speech[:], residual[:]); err != nil {
		return 0, fmt.Errorf("compute DTX energy: %w", err)
	}
	return dtxLogEnergyFromResidual(residual[:], e.preprocess.qOld, e.mode), nil
}

func (e *Encoder) dtxLogEnergyForQuantizedLPC(aq []int16) (int16, error) {
	speech, err := buildEncoderSpeechFrame(e.oldSpeech[:], e.speech12k8[:])
	if err != nil {
		return 0, fmt.Errorf("compute quantized DTX energy: %w", err)
	}
	var residual [frameSamples12k8]int16
	if err := residualFrame(aq, speech[:], residual[:]); err != nil {
		return 0, fmt.Errorf("compute quantized DTX energy: %w", err)
	}
	return dtxLogEnergyFromResidual(residual[:], e.preprocess.qOld, e.mode), nil
}

func dtxLogEnergyFromResidual(residual []int16, qNew int16, mode Mode) int16 {
	var energy int32
	for _, sample := range residual {
		scaled := fxp.Shr16(sample, qNew)
		energy = fxp.LMac(energy, scaled, scaled)
	}
	energy = fxp.Shr32(energy, 1)
	logEnergy := logEnergyQ7FromEnergy(energy)
	adjust := int16(115)
	if ValidMode(mode) {
		adjust = encoderDTXEnergyAdjust[mode]
	}
	return fxp.Sub16(logEnergy, fxp.Add16(1024, adjust))
}

func logEnergyQ7FromEnergy(value int32) int16 {
	if value <= 0 {
		return 0
	}
	exponent, fraction := log2WB(value)
	return fxp.Add16(fxp.Shl16(exponent, 7), fxp.Shr16(fraction, 8))
}

func (s *encoderDTXState) generateCNGExcitation(logEnergyIndex int16) [frameSamples12k8]int16 {
	var exc [frameSamples12k8]int16
	logEnergy := fxp.Shl16(logEnergyIndex, 15-6)
	logEnergy = fxp.Mult(logEnergy, 12483)
	logEnergyExp := fxp.Shr16(logEnergy, 10)
	logEnergyFrac := fxp.Shl16(logEnergy&0x03ff, 5)
	logEnergyExp = fxp.Add16(logEnergyExp, 16-1)

	level32 := powerOf2WB(logEnergyExp, logEnergyFrac)
	exp0 := normalizeAMRWB(level32)
	level32 = fxp.Shl32(level32, exp0)
	exp0 = fxp.Sub16(15, exp0)
	level := fxp.ExtractH(level32)
	for i := range frameSamples12k8 {
		s.cngSeed = nextNoise(s.cngSeed)
		exc[i] = s.cngSeed >> 4
	}

	energy, exp := dotProduct12(exc[:], exc[:], frameSamples12k8)
	energy, exp = oneOverSqrtNorm(energy, exp)
	gain := fxp.Mult(level, fxp.ExtractH(energy))
	exp = fxp.Add16(fxp.Add16(exp0, exp), 4)
	for i := range frameSamples12k8 {
		exc[i] = fxp.Shl16(fxp.Mult(exc[i], gain), exp)
	}
	return exc
}

func dtxISFDistance(a []int16, b []int16) int32 {
	var distance int32
	for i := range lpcOrder {
		diff := fxp.Sub16(a[i], b[i])
		distance = fxp.LMac(distance, diff, diff)
	}
	return distance
}

func medianReplacementNeeded32(candidate int32, minimum int32, shift int16) bool {
	candidate = fxp.Shl32(candidate, shift)
	minimum = fxp.Shl32(minimum, shift)
	threshold := fxp.LMult(fxp.Round(candidate), int16(encoderDTXInvMedianThreshold))
	return fxp.Sub32(threshold, minimum) > 0
}

func saturatingAdd16(a, b int16) int16 {
	sum := int32(a) + int32(b)
	if sum > 32767 {
		return 32767
	}
	if sum < -32768 {
		return -32768
	}
	return int16(sum)
}
