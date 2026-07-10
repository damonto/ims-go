/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This SID parameter path follows the AMR-NB DTX encoder boundary from
 * enc/src/dtx_enc.cpp and enc/src/amrencode.cpp.
 */

package amrnb

import (
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

type sidFrameAnalysis struct {
	az     [azFrameCount]int16
	lspNew [lpcOrder]int16
}

func (e *Encoder) encodeSID(dst []byte, pcm []int16, sidMode Mode, update bool) ([]byte, error) {
	params, err := e.encodeSIDParams(pcm)
	if err != nil {
		return nil, err
	}
	serial, err := sidParamsToSerial(e.serial[:0], params, sidMode, update)
	if err != nil {
		return nil, err
	}
	e.serial = serial
	return (Speech{Mode: ModeDTX, Serial: serial}).Pack(dst)
}

func (e *Encoder) dtxSIDMode() Mode {
	if e.mode >= Mode475 && e.mode <= Mode1220 {
		return e.mode
	}
	return Mode1220
}

func (e *Encoder) encodeSIDParams(pcm []int16) ([]int16, error) {
	analysis, err := e.analyzeSIDFrame(pcm)
	if err != nil {
		return nil, err
	}
	e.dtxState.buffer(analysis.lspNew[:], e.dtxState.lastSpeech[:])
	e.shiftSIDHistory()
	return e.buildSIDParams(true)
}

func (e *Encoder) buildSIDParams(compute bool) ([]int16, error) {
	if compute || e.dtxState.logEnergyIndex == 0 {
		if err := e.computeSIDParams(); err != nil {
			return nil, err
		}
	}

	count, err := ParameterCount(ModeDTX)
	if err != nil {
		return nil, err
	}
	if cap(e.params) < count {
		e.params = make([]int16, count)
	} else {
		e.params = e.params[:count]
		clear(e.params)
	}

	e.params[0] = e.dtxState.initLSFVQIndex
	copy(e.params[1:4], e.dtxState.lspIndex[:])
	e.params[4] = e.dtxState.logEnergyIndex
	return e.params, nil
}

func (e *Encoder) computeSIDParams() error {
	var lspSum [lpcOrder]int32
	logEnergy := int16(0)
	for i := range dtxHistorySize {
		logEnergy = fxp.Add16(logEnergy, fxp.Shr16(e.dtxState.logEnergyHist[i], 2))
		for j := range lpcOrder {
			lspSum[j] = fxp.Add32(lspSum[j], int32(e.dtxState.lspHist[i*lpcOrder+j]))
		}
	}
	logEnergy = fxp.Shr16(logEnergy, 1)

	var lsp [lpcOrder]int16
	for i := range lpcOrder {
		lsp[i] = int16(fxp.Shr32(lspSum[i], 3))
	}

	index := fxp.Add16(logEnergy, 2560)
	index = fxp.Add16(index, 128)
	index = fxp.Shr16(index, 8)
	index = min(max(index, 0), 63)

	e.dtxState.logEnergyIndex = index

	predEnergy := fxp.Shl16(index, 8)
	predEnergy = fxp.Sub16(predEnergy, 11560)
	predEnergy = min(max(predEnergy, -14436), 0)

	for i := range gainPredTaps {
		e.gain.pred.pastQuaEn[i] = predEnergy
		e.gain.pred.pastQuaEnMR122[i] = fxp.Mult(5443, predEnergy)
	}

	lsf := lspToLsf(lsp[:])
	reorderLSF(lsf[:], lsfGap)
	lsp = lsfToLsp(lsf[:])
	quantized, err := e.lsp.q.quantize3(ModeDTX, lsp[:])
	if err != nil {
		return err
	}
	e.dtxState.initLSFVQIndex = quantized.predInit
	e.dtxState.lspIndex = quantized.indices
	e.lsp.lspOldQ = quantized.lsp
	return nil
}

func (e *Encoder) analyzeSIDFrame(pcm []int16) (sidFrameAnalysis, error) {
	var out sidFrameAnalysis
	if len(pcm) != FrameSamples {
		return out, fmt.Errorf("analyzing AMR-NB SID frame: pcm sample count %d, want %d", len(pcm), FrameSamples)
	}

	newSpeech := e.oldSpeech[speechHistorySamples-FrameSamples:]
	for i, sample := range pcm {
		newSpeech[i] = sample &^ 0x0007
	}
	e.preprocess.process(newSpeech)
	copy(e.dtxState.lastSpeech[:], newSpeech)

	pWindow := e.oldSpeech[speechHistorySamples-lpcWindowSamples:]
	if e.mode == Mode1220 {
		pWindow = e.oldSpeech[speechHistorySamples-lpcWindowSamples-lpcLookaheadSamples:]
	}
	az, err := e.lpc.analyze(e.mode, pWindow)
	if err != nil {
		return out, err
	}
	lsp, err := e.lsp.process(e.mode, ModeDTX, az)
	if err != nil {
		return out, err
	}
	out.az = lsp.az
	out.lspNew = lsp.lspNew

	return out, nil
}

func (e *Encoder) shiftSIDHistory() {
	copy(e.oldSpeech[:], e.oldSpeech[FrameSamples:])
	clear(e.oldSpeech[speechHistorySamples-FrameSamples:])
}

func sidParamsToSerial(dst []byte, params []int16, sidMode Mode, update bool) ([]byte, error) {
	if sidMode < Mode475 || sidMode > Mode1220 {
		return nil, fmt.Errorf("AMR-NB SID mode %d is not a speech mode", sidMode)
	}
	paramSerial, err := (Params{Mode: ModeDTX, Values: params}).Pack(nil)
	if err != nil {
		return nil, err
	}
	bits, err := FrameBitLen(ModeDTX)
	if err != nil {
		return nil, err
	}
	if cap(dst) < bits {
		dst = make([]byte, bits)
	} else {
		dst = dst[:bits]
		clear(dst)
	}
	copy(dst, paramSerial)
	if update {
		dst[amrSIDRxTypeBitOffset] = 1
		for i := range numAMRSIDRxModeBits {
			dst[amrSIDRxModeBitOffset+i] = byte((sidMode >> i) & 1)
		}
	}
	return dst, nil
}
