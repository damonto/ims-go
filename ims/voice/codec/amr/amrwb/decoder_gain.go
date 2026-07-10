/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/dec_gain2_amr_wb.cpp,
 * q_gain2_tab.cpp, and pvamrwb_math_op.cpp.
 */

package amrwb

import (
	"errors"
	"fmt"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

const (
	gainMeanEnergy = 30
	gainPredOrder  = 4
)

var (
	gainPDownUnusable = [...]int16{32767, 31130, 29491, 24576, 7537, 1638, 328}
	gainCDownUnusable = [...]int16{32767, 16384, 8192, 8192, 8192, 4915, 3277}
	gainPDownUsable   = [...]int16{32767, 32113, 31457, 24576, 7537, 1638, 328}
	gainCDownUsable   = [...]int16{32767, 32113, 32113, 32113, 32113, 32113, 22938}
	gainPred          = [...]int16{4096, 3277, 2458, 1638}
)

var gainTable6Bit = [...]int16{
	1566, 1332, 1577, 3557, 3071, 6490, 4193, 10163,
	4496, 2534, 5019, 4488, 5586, 15614, 5725, 1422,
	6453, 580, 6724, 6831, 7657, 3527, 8072, 2099,
	8232, 5319, 8827, 8775, 9740, 2868, 9856, 1465,
	10087, 12488, 10241, 4453, 10859, 6618, 11321, 3587,
	11417, 1800, 11643, 2428, 11718, 988, 12312, 5093,
	12523, 8413, 12574, 26214, 12601, 3396, 13172, 1623,
	13285, 2423, 13418, 6087, 13459, 12810, 13656, 3607,
	14111, 4521, 14144, 1229, 14425, 1871, 14431, 7234,
	14445, 2834, 14628, 10036, 14860, 17496, 15161, 3629,
	15209, 5819, 15299, 2256, 15518, 4722, 15663, 1060,
	15759, 7972, 15939, 11964, 16020, 2996, 16086, 1707,
	16521, 4254, 16576, 6224, 16894, 2380, 16906, 681,
	17213, 8406, 17610, 3418, 17895, 5269, 18168, 11748,
	18230, 1575, 18607, 32767, 18728, 21684, 19137, 2543,
	19422, 6577, 19446, 4097, 19450, 9056, 20371, 14885,
}

var gainTable7Bit = [...]int16{
	204, 441, 464, 1977, 869, 1077, 1072, 3062,
	1281, 4759, 1647, 1539, 1845, 7020, 1853, 634,
	1995, 2336, 2351, 15400, 2661, 1165, 2702, 3900,
	2710, 10133, 3195, 1752, 3498, 2624, 3663, 849,
	3984, 5697, 4214, 3399, 4415, 1304, 4695, 2056,
	5376, 4558, 5386, 676, 5518, 23554, 5567, 7794,
	5644, 3061, 5672, 1513, 5957, 2338, 6533, 1060,
	6804, 5998, 6820, 1767, 6937, 3837, 7277, 414,
	7305, 2665, 7466, 11304, 7942, 794, 8007, 1982,
	8007, 1366, 8326, 3105, 8336, 4810, 8708, 7954,
	8989, 2279, 9031, 1055, 9247, 3568, 9283, 1631,
	9654, 6311, 9811, 2605, 10120, 683, 10143, 4179,
	10245, 1946, 10335, 1218, 10468, 9960, 10651, 3000,
	10951, 1530, 10969, 5290, 11203, 2305, 11325, 3562,
	11771, 6754, 11839, 1849, 11941, 4495, 11954, 1298,
	11975, 15223, 11977, 883, 11986, 2842, 12438, 2141,
	12593, 3665, 12636, 8367, 12658, 1594, 12886, 2628,
	12984, 4942, 13146, 1115, 13224, 524, 13341, 3163,
	13399, 1923, 13549, 5961, 13606, 1401, 13655, 2399,
	13782, 3909, 13868, 10923, 14226, 1723, 14232, 2939,
	14278, 7528, 14439, 4598, 14451, 984, 14458, 2265,
	14792, 1403, 14818, 3445, 14899, 5709, 15017, 15362,
	15048, 1946, 15069, 2655, 15405, 9591, 15405, 4079,
	15570, 7183, 15687, 2286, 15691, 1624, 15699, 3068,
	15772, 5149, 15868, 1205, 15970, 696, 16249, 3584,
	16338, 1917, 16424, 2560, 16483, 4438, 16529, 6410,
	16620, 11966, 16839, 8780, 17030, 3050, 17033, 18325,
	17092, 1568, 17123, 5197, 17351, 2113, 17374, 980,
	17566, 26214, 17609, 3912, 17639, 32767, 18151, 7871,
	18197, 2516, 18202, 5649, 18679, 3283, 18930, 1370,
	19271, 13757, 19317, 4120, 19460, 1973, 19654, 10018,
	19764, 6792, 19912, 5135, 20040, 2841, 21234, 19833,
}

var invSqrtTableWB = [...]int16{
	32767, 31790, 30894, 30070, 29309, 28602, 27945, 27330,
	26755, 26214, 25705, 25225, 24770, 24339, 23930, 23541,
	23170, 22817, 22479, 22155, 21845, 21548, 21263, 20988,
	20724, 20470, 20225, 19988, 19760, 19539, 19326, 19119,
	18919, 18725, 18536, 18354, 18176, 18004, 17837, 17674,
	17515, 17361, 17211, 17064, 16921, 16782, 16646, 16514,
	16384,
}

var pow2TableWB = [...]int16{
	16384, 16743, 17109, 17484, 17867, 18258, 18658, 19066,
	19484, 19911, 20347, 20792, 21247, 21713, 22188, 22674,
	23170, 23678, 24196, 24726, 25268, 25821, 26386, 26964,
	27554, 28158, 28774, 29405, 30048, 30706, 31379, 32066,
	32767,
}

var log2TableWB = [...]int16{
	0, 1455, 2866, 4236, 5568, 6863, 8124, 9352,
	10549, 11716, 12855, 13967, 15054, 16117, 17156, 18172,
	19167, 20142, 21097, 22033, 22951, 23852, 24735, 25603,
	26455, 27291, 28113, 28922, 29716, 30497, 31266, 32023,
	32767,
}

type gainDecodeInput struct {
	index          int16
	nbits          int16
	code           []int16
	badFrame       bool
	previousBad    bool
	state          int16
	unusableFrame  bool
	vadHistory     int16
	subframeLength int16
}

type decodedGains struct {
	pitch int16
	code  int32
}

type gainDecodeResult struct {
	gains  decodedGains
	memory [23]int16
}

func resetGainDecoder() [23]int16 {
	var mem [23]int16
	for i := range gainPredOrder {
		mem[i] = -14336
	}
	clear(mem[gainPredOrder:23])
	mem[22] = randomInitialSeed
	return mem
}

func decodeGain(memory [23]int16, input gainDecodeInput) (gainDecodeResult, error) {
	out := gainDecodeResult{memory: memory}
	if input.subframeLength == 0 {
		input.subframeLength = subframeSamples
	}
	if input.subframeLength < 0 || int(input.subframeLength) > len(input.code) {
		return out, errors.New("decode gain: code buffer is too short")
	}
	energy, exp := dotProduct12(input.code, input.code, input.subframeLength)
	exp -= 24
	energy, exp = oneOverSqrtNorm(energy, exp)
	gcodeInov := fxp.ExtractH(fxp.Shl32(energy, exp-3))

	if input.badFrame {
		return decodeErasedGain(out.memory, input, gcodeInov), nil
	}
	if input.nbits != 6 && input.nbits != 7 {
		return out, fmt.Errorf("decode gain: invalid index width %d", input.nbits)
	}

	mem := out.memory[:]

	pastQuaEn := mem[0:4]
	pastGainPit := &mem[4]
	pastGainCode := &mem[5]
	prevGC := &mem[6]
	pbuf := mem[7:12]
	gbuf := mem[12:17]
	pbuf2 := mem[17:22]

	predicted := int32(gainMeanEnergy) << 24
	for i := range gainPredOrder {
		predicted = fxp.Add32(predicted, fxp.LMult(gainPred[i], pastQuaEn[i]))
	}
	gcode0 := fxp.ExtractH(predicted)
	scaled := int32(gcode0) * 5443 >> 7
	expGcode0, frac := fxp.LExtract(scaled)
	gcode0 = int16(powerOf2WB(14, frac))
	expGcode0 -= 14

	table := gainTable7Bit[:]
	if input.nbits == 6 {
		table = gainTable6Bit[:]
	}
	offset := int(input.index) << 1
	if offset < 0 || offset+1 >= len(table) {
		return out, fmt.Errorf("decode gain: index %d is outside %d-bit table", input.index, input.nbits)
	}
	gainPit := table[offset]
	gCode := table[offset+1]
	gainCode := fxp.Shl32(fxp.LMult(gCode, gcode0), expGcode0+4)

	if input.previousBad {
		limit := fxp.LMult(*prevGC, 5120)
		if gainCode > limit && gainCode > 6553600 {
			gainCode = limit
		}
	}

	*pastGainCode = fxp.Round(fxp.Shl32(gainCode, 3))
	*pastGainPit = gainPit
	*prevGC = *pastGainCode
	for i := 1; i < 5; i++ {
		gbuf[i-1] = gbuf[i]
		pbuf[i-1] = pbuf[i]
		pbuf2[i-1] = pbuf2[i]
	}
	gbuf[4] = *pastGainCode
	pbuf[4] = *pastGainPit
	pbuf2[4] = *pastGainPit

	exp, frac = fxp.LExtract(gainCode)
	gainCode = fxp.Shl32(fxp.Mpy32By16(exp, frac, gcodeInov), 3)

	pastQuaEn[3] = pastQuaEn[2]
	pastQuaEn[2] = pastQuaEn[1]
	pastQuaEn[1] = pastQuaEn[0]
	exp, frac = log2WB(int32(gCode))
	exp -= 11
	pastQuaEn[0] = int16(fxp.Mpy32By16(exp, frac, 24660) >> 3)

	out.gains = decodedGains{pitch: gainPit, code: gainCode}
	return out, nil
}

func decodeErasedGain(memory [23]int16, input gainDecodeInput, gcodeInov int16) gainDecodeResult {
	out := gainDecodeResult{memory: memory}
	mem := out.memory[:]
	pastQuaEn := mem[0:4]
	pastGainPit := &mem[4]
	pastGainCode := &mem[5]
	pbuf := mem[7:12]
	gbuf := mem[12:17]

	state := int(input.state)
	if state < 0 {
		state = 0
	} else if state >= len(gainPDownUsable) {
		state = len(gainPDownUsable) - 1
	}

	*pastGainPit = median5(pbuf[0:5])
	if *pastGainPit > 15565 {
		*pastGainPit = 15565
	}
	gainPit := fxp.Mult(gainPDownUsable[state], *pastGainPit)
	if input.unusableFrame {
		gainPit = fxp.Mult(gainPDownUnusable[state], *pastGainPit)
	}

	tmp := median5(gbuf[0:5])
	if input.vadHistory > 2 {
		*pastGainCode = tmp
	} else if input.unusableFrame {
		*pastGainCode = fxp.Mult(gainCDownUnusable[state], tmp)
	} else {
		*pastGainCode = fxp.Mult(gainCDownUsable[state], tmp)
	}

	sum := int32(pastQuaEn[3]) + int32(pastQuaEn[2]) + int32(pastQuaEn[1]) + int32(pastQuaEn[0])
	pastQuaEn[3] = pastQuaEn[2]
	pastQuaEn[2] = pastQuaEn[1]
	pastQuaEn[1] = pastQuaEn[0]
	quaEner := int16(sum >> 3)
	quaEner -= 3072
	quaEner = max(quaEner, -14336)

	pastQuaEn[0] = quaEner

	for i := 1; i < 5; i++ {
		gbuf[i-1] = gbuf[i]
		pbuf[i-1] = pbuf[i]
	}
	gbuf[4] = *pastGainCode
	pbuf[4] = *pastGainPit

	out.gains = decodedGains{
		pitch: gainPit,
		code:  fxp.LMult(*pastGainCode, gcodeInov),
	}
	return out
}

func dotProduct12(x, y []int16, length int16) (int32, int16) {
	sum := int32(1)
	for i := range int(length) {
		sum = fxp.LMac(sum, x[i], y[i])
	}
	shift := normalizeAMRWB(sum)
	return fxp.Shl32(sum, shift), 30 - shift
}

func oneOverSqrtNorm(frac int32, exp int16) (int32, int16) {
	if frac <= 0 {
		return fxp.Max32, 0
	}
	if (exp & 1) == 1 {
		frac >>= 1
	}
	exp = fxp.Neg16((exp - 1) >> 1)
	shifted := frac >> 9
	index := int(fxp.ExtractH(shifted)) - 16
	shifted >>= 1
	a := int16(shifted) & 0x7fff
	if index < 0 {
		index = 0
	} else if index >= len(invSqrtTableWB)-1 {
		index = len(invSqrtTableWB) - 2
	}
	frac = int32(invSqrtTableWB[index]) << 16
	delta := invSqrtTableWB[index] - invSqrtTableWB[index+1]
	frac = fxp.Sub32(frac, fxp.LMult(delta, a))
	return frac, exp
}

func powerOf2WB(exponent, fraction int16) int32 {
	index := int(fraction >> 10)
	a := int16(fraction<<5) & 0x7fff
	if index < 0 {
		index = 0
	} else if index >= len(pow2TableWB)-1 {
		index = len(pow2TableWB) - 2
	}
	out := int32(pow2TableWB[index]) << 15
	delta := pow2TableWB[index] - pow2TableWB[index+1]
	out -= int32(delta) * int32(a)
	shift := 29 - exponent
	if shift > 0 {
		out = (out >> shift) + ((out >> (shift - 1)) & 1)
	}
	return out
}

func log2WB(value int32) (exponent, fraction int16) {
	if value <= 0 {
		return 0, 0
	}
	exp := normalizeAMRWB(value)
	normalized := fxp.Shl32(value, exp)
	exponent = 30 - exp
	shifted := normalized >> 9
	index := int(fxp.ExtractH(shifted)) - 32
	shifted >>= 1
	a := int16(shifted) & 0x7fff
	if index < 0 {
		index = 0
	} else if index >= len(log2TableWB)-1 {
		index = len(log2TableWB) - 2
	}
	out := int32(log2TableWB[index]) << 16
	delta := log2TableWB[index] - log2TableWB[index+1]
	out = fxp.Sub32(out, fxp.LMult(delta, a))
	fraction = fxp.ExtractH(out)
	return exponent, fraction
}
