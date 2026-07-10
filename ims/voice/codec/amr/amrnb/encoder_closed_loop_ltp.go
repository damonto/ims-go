/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * These closed-loop LTP primitives are ported from enc/src/convolve.cpp
 * and enc/src/g_pitch.cpp.
 */

package amrnb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const gpClip int16 = 15565

type encoderPitchAnalysis struct {
	t0                 int16
	t0Frac             int16
	useThirdResolution bool
	gainPit            int16
	gainPitIndex       int16
	hasGainPitIndex    bool
	gpLimit            int16
	yl                 [subframeSamples]int16
	xn2                [subframeSamples]int16
	gCoeff             [4]int16
}

type pitchGainResult struct {
	gain  int16
	coeff [4]int16
}

type knownPitchInput struct {
	mode               Mode
	excitation         []int16
	excitationOffset   int
	h1                 []int16
	xn                 []int16
	residual           []int16
	t0                 int16
	t0Frac             int16
	useThirdResolution bool
	tonStab            *tonStabState
	lspFlag            bool
}

func convolve(x, h []int16) [subframeSamples]int16 {
	var y [subframeSamples]int16
	for n := range subframeSamples {
		sum := int32(0)
		for i := 0; i <= n; i++ {
			sum = fxp.LMac(sum, x[i], h[n-i])
		}
		y[n] = fxp.ExtractH(fxp.Shl32(sum, 3))
	}
	return y
}

func applyKnownPitch(in knownPitchInput) (encoderPitchAnalysis, error) {
	var out encoderPitchAnalysis
	if in.mode < Mode475 || in.mode > Mode1220 {
		return out, fmt.Errorf("applying AMR-NB closed-loop pitch: invalid mode %d", in.mode)
	}
	if len(in.h1) < subframeSamples || len(in.xn) < subframeSamples || len(in.residual) < subframeSamples {
		return out, errors.New("AMR-NB closed-loop pitch: short subframe buffers")
	}
	if err := predictAdaptiveCodebook(
		in.excitation,
		in.excitationOffset,
		in.t0,
		in.t0Frac,
		subframeSamples,
		in.useThirdResolution,
	); err != nil {
		return out, err
	}

	currentExc := in.excitation[in.excitationOffset : in.excitationOffset+subframeSamples]
	out.yl = convolve(currentExc, in.h1)
	gain, err := pitchGain(in.mode, in.xn, out.yl[:])
	if err != nil {
		return out, err
	}
	out.gainPit = gain.gain
	out.gCoeff = gain.coeff
	out.gpLimit = fxp.Max16
	gpcFlag := false
	if in.lspFlag && fxp.Sub16(out.gainPit, gpClip) > 0 && in.tonStab != nil {
		gpcFlag = in.tonStab.checkGPClipping(out.gainPit)
	}
	if (in.mode == Mode475 || in.mode == Mode515) && fxp.Sub16(out.gainPit, 13926) > 0 {
		out.gainPit = 13926
	}
	if gpcFlag {
		out.gpLimit = gpClip
		if in.mode != Mode475 && in.mode != Mode515 {
			out.gainPit = gpClip
		}
	}
	if in.mode == Mode1220 {
		gain := quantizePitchGain(in.mode, out.gpLimit, out.gainPit)
		out.gainPit = gain.gain
		out.gainPitIndex = gain.index
		out.hasGainPitIndex = true
	}

	out.t0 = in.t0
	out.t0Frac = in.t0Frac
	out.useThirdResolution = in.useThirdResolution
	for i := range subframeSamples {
		pitchTarget := fxp.ExtractH(fxp.Shl32(fxp.LMult(out.yl[i], out.gainPit), 1))
		out.xn2[i] = fxp.Sub16(in.xn[i], pitchTarget)
		pitchResidual := fxp.ExtractH(fxp.Shl32(fxp.LMult(currentExc[i], out.gainPit), 1))
		in.residual[i] = fxp.Sub16(in.residual[i], pitchResidual)
	}
	return out, nil
}

func pitchGain(mode Mode, xn []int16, y1 []int16) (pitchGainResult, error) {
	var out pitchGainResult
	if mode < Mode475 || mode > Mode1220 {
		return out, fmt.Errorf("calculating AMR-NB pitch gain: invalid mode %d", mode)
	}
	if len(xn) < subframeSamples || len(y1) < subframeSamples {
		return out, fmt.Errorf(
			"calculating AMR-NB pitch gain: target/filter sample counts %d/%d, want at least %d",
			len(xn),
			len(y1),
			subframeSamples,
		)
	}

	var scaledY1 [subframeSamples]int16
	for i := range subframeSamples {
		scaledY1[i] = fxp.Shr16(y1[i], 2)
	}

	yySum, yyOverflow := dotProductOverflow(y1, y1)
	expYY := fxp.NormL(yySum)
	yy := fxp.Round(fxp.Shl32(yySum, expYY))
	if yyOverflow {
		yySum, _ = dotProductOverflow(scaledY1[:], scaledY1[:])
		expYY = fxp.NormL(yySum)
		yy = fxp.Round(fxp.Shl32(yySum, expYY))
		expYY = fxp.Sub16(expYY, 4)
	}

	xySum, xyOverflow := dotProductOverflow(xn, y1)
	expXY := fxp.NormL(xySum)
	xy := fxp.Round(fxp.Shl32(xySum, expXY))
	if xyOverflow {
		xySum, _ = dotProductOverflow(xn, scaledY1[:])
		expXY = fxp.NormL(xySum)
		xy = fxp.Round(fxp.Shl32(xySum, expXY))
		expXY = fxp.Sub16(expXY, 2)
	}

	out.coeff[0] = yy
	out.coeff[1] = fxp.Sub16(15, expYY)
	out.coeff[2] = xy
	out.coeff[3] = fxp.Sub16(15, expXY)

	if fxp.Sub16(xy, 4) < 0 {
		return out, nil
	}

	gain := fxp.DivS(fxp.Shr16(xy, 1), yy)
	gain = fxp.Shr16(gain, fxp.Sub16(expXY, expYY))
	if fxp.Sub16(gain, 19661) > 0 {
		gain = 19661
	}
	if mode == Mode1220 {
		gain &= ^int16(0x0003)
	}
	out.gain = gain
	return out, nil
}

func dotProductOverflow(a []int16, b []int16) (int32, bool) {
	sum := int32(1)
	overflow := false
	for i := range subframeSamples {
		product := fxp.LMult(a[i], b[i])
		if a[i] == fxp.Min16 && b[i] == fxp.Min16 {
			overflow = true
		}
		next64 := int64(sum) + int64(product)
		if next64 > int64(fxp.Max32) || next64 < int64(fxp.Min32) {
			overflow = true
		}
		sum = fxp.Add32(sum, product)
	}
	return sum, overflow
}
