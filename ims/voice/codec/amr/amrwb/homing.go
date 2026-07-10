/*
 * Copyright (C) 1998-2009 PacketVideo
 *
 * Licensed under the Apache License, Version 2.0.
 * This algorithm is ported from amr_wb/dec/src/homing_amr_wb_dec.cpp
 * and the AMR-WB decoder wrapper.
 */

package amrwb

const (
	homingParameterBits = 15
)

var homingFirstSubframeBits = [...]int{63, 81, 100, 108, 116, 128, 136, 152, 156}

var homingParams = [...][32]int16{
	{
		3168, 29954, 29213, 16121, 64, 13440, 30624, 16430, 19008,
	},
	{
		3168, 31665, 9943, 9123, 15599, 4358, 20248, 2048,
		17040, 27787, 16816, 13888,
	},
	{
		3168, 31665, 9943, 9128, 3647, 8129, 30930, 27926,
		18880, 12319, 496, 1042, 4061, 20446, 25629, 28069,
		13948,
	},
	{
		3168, 31665, 9943, 9131, 24815, 655, 26616, 26764,
		7238, 19136, 6144, 88, 4158, 25733, 30567, 30494,
		221, 20321, 17823,
	},
	{
		3168, 31665, 9943, 9131, 24815, 700, 3824, 7271,
		26400, 9528, 6594, 26112, 108, 2068, 12867, 16317,
		23035, 24632, 7528, 1752, 6759, 24576,
	},
	{
		3168, 31665, 9943, 9135, 14787, 14423, 30477, 24927,
		25345, 30154, 916, 5728, 18978, 2048, 528, 16449,
		2436, 3581, 23527, 29479, 8237, 16810, 27091, 19052,
		0,
	},
	{
		3168, 31665, 9943, 9129, 8637, 31807, 24646, 736,
		28643, 2977, 2566, 25564, 12930, 13960, 2048, 834,
		3270, 4100, 26920, 16237, 31227, 17667, 15059, 20589,
		30249, 29123, 0,
	},
	{
		3168, 31665, 9943, 9132, 16748, 3202, 28179, 16317,
		30590, 15857, 19960, 8818, 21711, 21538, 4260, 16690,
		20224, 3666, 4194, 9497, 16320, 15388, 5755, 31551,
		14080, 3574, 15932, 50, 23392, 26053, 31216,
	},
	{
		3168, 31665, 9943, 9134, 24776, 5857, 18475, 28535,
		29662, 14321, 16725, 4396, 29353, 10003, 17068, 20504,
		720, 0, 8465, 12581, 28863, 24774, 9709, 26043,
		7941, 27649, 13965, 15236, 18026, 22047, 16681, 3968,
	},
}

func homingFrameTest(serial []byte, mode Mode) bool {
	if !ValidMode(mode) {
		return false
	}
	return dhfTest(serial, mode, frameBits[mode])
}

func homingFrameTestFirst(serial []byte, mode Mode) bool {
	if !ValidMode(mode) {
		return false
	}
	return dhfTest(serial, mode, homingFirstSubframeBits[mode])
}

func homingSerial(mode Mode, nbits int) []byte {
	serial := make([]byte, 0, nbits)
	params := homingParams[mode]
	for i := 0; len(serial) < nbits; i++ {
		width := homingParameterBits
		remaining := nbits - len(serial)
		value := params[i]
		if remaining < width {
			width = remaining
			value >>= homingParameterBits - width
		}
		for bit := width - 1; bit >= 0; bit-- {
			serial = append(serial, byte((value>>bit)&1))
		}
	}
	return serial
}

func dhfTest(serial []byte, mode Mode, nbits int) bool {
	if len(serial) < nbits {
		return false
	}

	params := homingParams[mode]
	if mode == Mode2385 {
		return dhfTest2385(serial, params[:])
	}

	offset := 0
	paramIndex := 0
	for nbits-offset > homingParameterBits {
		if serialParm(serial[offset:offset+homingParameterBits], homingParameterBits) != params[paramIndex] {
			return false
		}
		offset += homingParameterBits
		paramIndex++
	}

	remaining := nbits - offset
	if remaining <= 0 {
		return true
	}
	got := serialParm(serial[offset:offset+remaining], remaining)
	shift := homingParameterBits - remaining
	got <<= shift
	mask := int16(0x7fff>>shift) << shift
	return got == params[paramIndex]&mask
}

func dhfTest2385(serial []byte, params []int16) bool {
	if len(serial) < frameBits[Mode2385] {
		return false
	}

	offset := 0
	for i := range 10 {
		if serialParm(serial[offset:offset+homingParameterBits], homingParameterBits) != params[i] {
			return false
		}
		offset += homingParameterBits
	}
	if maskedHomingParam(serial[offset:offset+homingParameterBits], 0x61ff) != int(params[10])&0x61ff {
		return false
	}
	offset += homingParameterBits

	for i := 11; i < 17; i++ {
		if serialParm(serial[offset:offset+homingParameterBits], homingParameterBits) != params[i] {
			return false
		}
		offset += homingParameterBits
	}
	if maskedHomingParam(serial[offset:offset+homingParameterBits], 0xe0ff) != int(params[17])&0xe0ff {
		return false
	}
	offset += homingParameterBits

	for i := 18; i < 24; i++ {
		if serialParm(serial[offset:offset+homingParameterBits], homingParameterBits) != params[i] {
			return false
		}
		offset += homingParameterBits
	}
	if maskedHomingParam(serial[offset:offset+homingParameterBits], 0x7f0f) != int(params[24])&0x7f0f {
		return false
	}
	offset += homingParameterBits

	for i := 25; i < 31; i++ {
		if serialParm(serial[offset:offset+homingParameterBits], homingParameterBits) != params[i] {
			return false
		}
		offset += homingParameterBits
	}

	return serialParm(serial[offset:offset+8], 8)<<7 == params[31]
}

func serialParm(bits []byte, nbits int) int16 {
	var value int16
	for i := range nbits {
		value <<= 1
		if bits[i] == 1 {
			value |= 1
		}
	}
	return value
}

func maskedHomingParam(bits []byte, mask int) int {
	return int(serialParm(bits, homingParameterBits)) & mask
}

func mask14BitOutput(pcm []int16) {
	for i := range pcm {
		pcm[i] &= ^int16(3)
	}
}
