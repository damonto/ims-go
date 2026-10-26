// Package fxp provides saturating fixed-point arithmetic for AMR codecs.
package fxp

import "math/bits"

const (
	// Min16 is the smallest signed 16-bit value used by AMR fixed-point code.
	Min16 int16 = -32768
	// Max16 is the largest signed 16-bit value used by AMR fixed-point code.
	Max16 int16 = 32767
	// Min32 is the smallest signed 32-bit value used by AMR fixed-point code.
	Min32 int32 = -2147483648
	// Max32 is the largest signed 32-bit value used by AMR fixed-point code.
	Max32 int32 = 2147483647
)

// Add16 returns a + b with 16-bit AMR saturation.
func Add16(a, b int16) int16 {
	return Saturate16(int32(a) + int32(b))
}

// Sub16 returns a - b with 16-bit AMR saturation.
func Sub16(a, b int16) int16 {
	return Saturate16(int32(a) - int32(b))
}

// Neg16 returns -v with AMR saturation.
func Neg16(v int16) int16 {
	if v == Min16 {
		return Max16
	}
	return -v
}

// Abs16 returns abs(v), saturating abs(-32768) to 32767.
func Abs16(v int16) int16 {
	if v == Min16 {
		return Max16
	}
	if v < 0 {
		return -v
	}
	return v
}

// Shl16 returns v shifted left by n with 16-bit saturation.
//
// Negative n delegates to Shr16, matching the AMR reference operators.
func Shl16(v int16, n int16) int16 {
	shift := int(n)
	if shift < 0 {
		return shr16(v, -shift)
	}
	return shl16(v, shift)
}

func shl16(v int16, shift int) int16 {
	if shift >= 15 {
		if v > 0 {
			return Max16
		}
		if v < 0 {
			return Min16
		}
		return 0
	}
	return Saturate16(int32(v) << shift)
}

// Shr16 returns v arithmetically shifted right by n.
//
// Negative n delegates to Shl16, matching the AMR reference operators.
func Shr16(v int16, n int16) int16 {
	shift := int(n)
	if shift < 0 {
		return shl16(v, -shift)
	}
	return shr16(v, shift)
}

func shr16(v int16, shift int) int16 {
	if shift >= 15 {
		if v < 0 {
			return -1
		}
		return 0
	}
	return int16(v >> shift)
}

// ShrRound16 returns Shr16(v, n) with AMR rounding.
func ShrRound16(v int16, n int16) int16 {
	shift := int(n)
	if shift <= 0 {
		return shl16(v, -shift)
	}
	out := shr16(v, shift)
	if shift <= 15 && uint16(v)&(uint16(1)<<uint(shift-1)) != 0 {
		out = Add16(out, 1)
	}
	return out
}

// Mult returns (a*b)>>15 with 16-bit saturation.
func Mult(a, b int16) int16 {
	product := (int32(a) * int32(b)) >> 15
	return Saturate16(product)
}

// MultRound returns ((a*b)+16384)>>15 with 16-bit saturation.
func MultRound(a, b int16) int16 {
	product := int32(a)*int32(b) + 0x4000
	product >>= 15
	return Saturate16(product)
}

// DivS returns the AMR fractional quotient var1/var2 in Q15.
//
// The reference operator expects 0 <= var1 <= var2. OpenCORE's production
// implementation returns 0 for invalid inputs instead of aborting, and this
// package follows that behavior so corrupt frames cannot panic the decoder.
func DivS(var1, var2 int16) int16 {
	if var1 > var2 || var1 < 0 || var2 <= 0 {
		return 0
	}
	if var1 == 0 {
		return 0
	}
	if var1 == var2 {
		return Max16
	}

	var out int16
	num := int32(var1)
	denom := int32(var2)
	denom2 := denom << 1
	denom4 := denom << 2
	for range 5 {
		out <<= 3
		num <<= 3
		if num >= denom4 {
			num -= denom4
			out |= 4
		}
		if num >= denom2 {
			num -= denom2
			out |= 2
		}
		if num >= denom {
			num -= denom
			out |= 1
		}
	}
	return out
}

// LMult returns 2*a*b with 32-bit AMR saturation.
func LMult(a, b int16) int32 {
	product := int64(a) * int64(b)
	if product == 0x40000000 {
		return Max32
	}
	return int32(product << 1)
}

// LMac returns acc + 2*a*b with 32-bit AMR saturation after each operation.
func LMac(acc int32, a, b int16) int32 {
	return Add32(acc, LMult(a, b))
}

// LMsu returns acc - 2*a*b with 32-bit AMR saturation after each operation.
func LMsu(acc int32, a, b int16) int32 {
	return Sub32(acc, LMult(a, b))
}

// LDepositH returns v in the high 16 bits of a 32-bit AMR word.
func LDepositH(v int16) int32 {
	return int32(v) << 16
}

// Add32 returns a + b with 32-bit AMR saturation.
func Add32(a, b int32) int32 {
	return Saturate32(int64(a) + int64(b))
}

// Sub32 returns a - b with 32-bit AMR saturation.
func Sub32(a, b int32) int32 {
	return Saturate32(int64(a) - int64(b))
}

// Neg32 returns -v with AMR saturation.
func Neg32(v int32) int32 {
	if v == Min32 {
		return Max32
	}
	return -v
}

// Abs32 returns abs(v), saturating abs(Min32) to Max32.
func Abs32(v int32) int32 {
	if v == Min32 {
		return Max32
	}
	if v < 0 {
		return -v
	}
	return v
}

// Shl32 returns v shifted left by n with 32-bit saturation.
//
// Negative n delegates to Shr32. The explicit 64-bit intermediate avoids Go's
// wraparound surprises while preserving the AMR saturating intent.
func Shl32(v int32, n int16) int32 {
	shift := int(n)
	if shift < 0 {
		return shr32(v, -shift)
	}
	return shl32(v, shift)
}

func shl32(v int32, shift int) int32 {
	if shift >= 31 {
		if v > 0 {
			return Max32
		}
		if v < 0 {
			return Min32
		}
		return 0
	}
	return Saturate32(int64(v) << shift)
}

// Shr32 returns v arithmetically shifted right by n.
//
// Negative n delegates to Shl32, matching the AMR reference operators.
func Shr32(v int32, n int16) int32 {
	shift := int(n)
	if shift < 0 {
		return shl32(v, -shift)
	}
	return shr32(v, shift)
}

func shr32(v int32, shift int) int32 {
	if shift >= 31 {
		if v < 0 {
			return -1
		}
		return 0
	}
	return v >> shift
}

// ShrRound32 returns Shr32(v, n) with AMR rounding.
func ShrRound32(v int32, n int16) int32 {
	shift := int(n)
	if shift <= 0 {
		return shl32(v, -shift)
	}
	out := shr32(v, shift)
	if shift <= 31 && uint32(v)&(uint32(1)<<uint(shift-1)) != 0 {
		out = Add32(out, 1)
	}
	return out
}

// Round returns the high 16 bits of v after adding 0x8000 with saturation.
func Round(v int32) int16 {
	return ExtractH(Add32(v, 0x8000))
}

// ExtractH returns the high 16 bits of v.
func ExtractH(v int32) int16 {
	return int16(v >> 16)
}

// ExtractL returns the low 16 bits of v.
func ExtractL(v int32) int16 {
	return int16(v)
}

// LExtract splits v into the Q31 high/low representation used by AMR.
func LExtract(v int32) (hi, lo int16) {
	hi = ExtractH(v)
	lo = int16((v - (int32(hi) << 16)) >> 1)
	return hi, lo
}

// LComp combines an AMR Q31 high/low pair into a 32-bit value.
func LComp(hi, lo int16) int32 {
	return Add32(int32(hi)<<16, int32(lo)<<1)
}

// Mpy32 multiplies two AMR Q31 high/low pairs.
func Mpy32(hi1, lo1, hi2, lo2 int16) int32 {
	out := LMult(hi1, hi2)
	out = Add32(out, LMult(Mult(hi1, lo2), 1))
	out = Add32(out, LMult(Mult(hi2, lo1), 1))
	return out
}

// Mpy32By16 multiplies an AMR Q31 high/low pair by a Q15 value.
func Mpy32By16(hi, lo, n int16) int32 {
	out := LMult(hi, n)
	return LMac(out, Mult(lo, n), 1)
}

// Div32 returns num divided by the AMR Q31 denominator represented by hi/lo.
func Div32(num int32, denomHi int16, denomLo int16) int32 {
	if num <= 0 || denomHi <= 0 {
		return 0
	}
	approx := DivS(0x3fff, denomHi)
	out := Mpy32By16(denomHi, denomLo, approx)
	out = Sub32(Max32, out)
	hi, lo := LExtract(out)
	out = Mpy32By16(hi, lo, approx)

	hi, lo = LExtract(out)
	numHi, numLo := LExtract(num)
	out = Mpy32(numHi, numLo, hi, lo)
	return Shl32(out, 2)
}

// NormS returns the number of left shifts needed to normalize v.
func NormS(v int16) int16 {
	if v == 0 {
		return 0
	}
	if v == -1 {
		return 15
	}
	if v < 0 {
		v = ^v
	}
	return int16(bits.LeadingZeros16(uint16(v)) - 1)
}

// NormL returns the number of left shifts needed to normalize v.
func NormL(v int32) int16 {
	if v == 0 {
		return 0
	}
	if v == -1 {
		return 31
	}
	if v < 0 {
		v = ^v
	}
	return int16(bits.LeadingZeros32(uint32(v)) - 1)
}

// Saturate16 clamps v to signed 16-bit range.
func Saturate16(v int32) int16 {
	return int16(min(max(v, int32(Min16)), int32(Max16)))
}

// Saturate32 clamps v to signed 32-bit range.
func Saturate32(v int64) int32 {
	return int32(min(max(v, int64(Min32)), int64(Max32)))
}
