package amrwb

import (
	"fmt"
)

type encoderAnalysis struct {
	lpc      encoderLPCAnalysis
	quantLPC encoderQuantizedLPC
	weighted encoderWeightedSpeech
	tOp      int16
	tOp2     int16
}

func (e *Encoder) analyzeSpeech(params []int16) (encoderAnalysis, error) {
	var out encoderAnalysis
	lpc, quant, err := e.encodeLPCParameters(params)
	if err != nil {
		return out, fmt.Errorf("analyze AMR-WB speech: %w", err)
	}
	out.lpc = lpc
	out.quantLPC = quant

	weighted, err := e.buildWeightedSpeech(lpc.a[:])
	if err != nil {
		return out, fmt.Errorf("analyze AMR-WB speech: %w", err)
	}
	out.weighted = weighted

	tOp, tOp2, err := e.estimateOpenLoopPitch(weighted)
	if err != nil {
		return out, fmt.Errorf("analyze AMR-WB speech: %w", err)
	}
	out.tOp = tOp
	out.tOp2 = tOp2
	return out, nil
}
