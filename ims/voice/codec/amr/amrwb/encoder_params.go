package amrwb

import (
	"errors"
	"fmt"
)

func (e *Encoder) encodeLPCParameters(params []int16) (encoderLPCAnalysis, encoderQuantizedLPC, error) {
	var lpc encoderLPCAnalysis
	var quant encoderQuantizedLPC
	requiredParams := 8
	if e.mode == Mode660 {
		requiredParams = 5
	}
	if len(params) < requiredParams {
		return lpc, quant, fmt.Errorf("encode LPC parameters: buffer has length %d, need %d", len(params), requiredParams)
	}

	var err error
	lpc, err = e.lpc.analyze(e.oldSpeech[:], e.speech12k8[:])
	if err != nil {
		return lpc, quant, fmt.Errorf("encode LPC parameters: %w", err)
	}
	quant, err = e.isfQuant.quantizeLPC(e.mode, lpc.ispNew[:])
	if err != nil {
		return lpc, quant, fmt.Errorf("encode LPC parameters: %w", err)
	}
	if err := e.pitchClip.updateISF(e.mode, quant.isf[:]); err != nil {
		return lpc, quant, fmt.Errorf("encode LPC parameters: %w", err)
	}

	if e.vadActive {
		params[0] = 1
	} else {
		params[0] = 0
	}
	if e.mode == Mode660 {
		if quant.indexCount < 5 {
			return lpc, quant, errors.New("encode LPC parameters: 6.60 mode produced fewer than 5 ISF indices")
		}
		params[1] = quant.indices[0]
		params[2] = quant.indices[1]
		params[3] = (quant.indices[2] << 7) | quant.indices[3]
		params[4] = quant.indices[4]
		return lpc, quant, nil
	}

	if quant.indexCount < 7 {
		return lpc, quant, errors.New("encode LPC parameters: mode produced fewer than 7 ISF indices")
	}
	copy(params[1:8], quant.indices[:7])
	return lpc, quant, nil
}
