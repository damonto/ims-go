package fxp

import "testing"

func TestAddSub16Saturate(t *testing.T) {
	tests := []struct {
		name string
		got  int16
		want int16
	}{
		{name: "add high", got: Add16(30000, 30000), want: Max16},
		{name: "add low", got: Add16(-30000, -30000), want: Min16},
		{name: "add exact", got: Add16(1200, -200), want: 1000},
		{name: "sub high", got: Sub16(30000, -30000), want: Max16},
		{name: "sub low", got: Sub16(-30000, 30000), want: Min16},
		{name: "neg min", got: Neg16(Min16), want: Max16},
		{name: "abs min", got: Abs16(Min16), want: Max16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestShift16(t *testing.T) {
	tests := []struct {
		name string
		got  int16
		want int16
	}{
		{name: "left exact", got: Shl16(1024, 2), want: 4096},
		{name: "left high", got: Shl16(20000, 1), want: Max16},
		{name: "left low", got: Shl16(-20000, 1), want: Min16},
		{name: "left negative delegates right", got: Shl16(-8, -1), want: -4},
		{name: "right positive", got: Shr16(7, 1), want: 3},
		{name: "right negative", got: Shr16(-7, 1), want: -4},
		{name: "right large positive", got: Shr16(123, 20), want: 0},
		{name: "right large negative", got: Shr16(-123, 20), want: -1},
		{name: "right rounded", got: ShrRound16(3, 1), want: 2},
		{name: "left minimum shift", got: Shl16(1, Min16), want: 0},
		{name: "left minimum shift negative", got: Shl16(-1, Min16), want: -1},
		{name: "right minimum shift", got: Shr16(1, Min16), want: Max16},
		{name: "right minimum shift negative", got: Shr16(-1, Min16), want: Min16},
		{name: "rounded minimum shift", got: ShrRound16(1, Min16), want: Max16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestMultiply(t *testing.T) {
	tests := []struct {
		name string
		got  int64
		want int64
	}{
		{name: "mult max", got: int64(Mult(Max16, Max16)), want: 32766},
		{name: "mult saturate", got: int64(Mult(Min16, Min16)), want: int64(Max16)},
		{name: "mult rounded", got: int64(MultRound(16384, 16384)), want: 8192},
		{name: "lmult saturate", got: int64(LMult(Min16, Min16)), want: int64(Max32)},
		{name: "lmult exact", got: int64(LMult(16384, 2)), want: 65536},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestDivS(t *testing.T) {
	tests := []struct {
		name string
		got  int16
		want int16
	}{
		{name: "zero", got: DivS(0, 1000), want: 0},
		{name: "equal", got: DivS(1234, 1234), want: Max16},
		{name: "half", got: DivS(1, 2), want: 16384},
		{name: "quarter", got: DivS(1, 4), want: 8192},
		{name: "truncated", got: DivS(1000, 3000), want: 10922},
		{name: "invalid greater", got: DivS(3, 2), want: 0},
		{name: "invalid negative", got: DivS(-1, 2), want: 0},
		{name: "invalid denominator", got: DivS(1, 0), want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestAddSub32Saturate(t *testing.T) {
	tests := []struct {
		name string
		got  int32
		want int32
	}{
		{name: "add high", got: Add32(Max32, 1), want: Max32},
		{name: "add low", got: Add32(Min32, -1), want: Min32},
		{name: "sub high", got: Sub32(Max32, -1), want: Max32},
		{name: "sub low", got: Sub32(Min32, 1), want: Min32},
		{name: "neg min", got: Neg32(Min32), want: Max32},
		{name: "abs min", got: Abs32(Min32), want: Max32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestShift32(t *testing.T) {
	tests := []struct {
		name string
		got  int32
		want int32
	}{
		{name: "left exact", got: Shl32(1, 30), want: 0x40000000},
		{name: "left high", got: Shl32(0x40000000, 1), want: Max32},
		{name: "left low", got: Shl32(-0x40000000, 2), want: Min32},
		{name: "left negative delegates right", got: Shl32(-8, -1), want: -4},
		{name: "right positive", got: Shr32(7, 1), want: 3},
		{name: "right negative", got: Shr32(-7, 1), want: -4},
		{name: "right large positive", got: Shr32(123, 40), want: 0},
		{name: "right large negative", got: Shr32(-123, 40), want: -1},
		{name: "right rounded", got: ShrRound32(3, 1), want: 2},
		{name: "left minimum shift", got: Shl32(1, Min16), want: 0},
		{name: "left minimum shift negative", got: Shl32(-1, Min16), want: -1},
		{name: "right minimum shift", got: Shr32(1, Min16), want: Max32},
		{name: "right minimum shift negative", got: Shr32(-1, Min16), want: Min32},
		{name: "rounded minimum shift", got: ShrRound32(1, Min16), want: Max32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}

func TestRoundExtractAndCompose(t *testing.T) {
	if got := Round(0x00007fff); got != 0 {
		t.Fatalf("Round(0x7fff) = %d, want 0", got)
	}
	if got := Round(0x00008000); got != 1 {
		t.Fatalf("Round(0x8000) = %d, want 1", got)
	}
	hi, lo := LExtract(0x12345678)
	if hi != 0x1234 || lo != 0x2b3c {
		t.Fatalf("LExtract() = %#x/%#x, want 0x1234/0x2b3c", uint16(hi), uint16(lo))
	}
	if got := LComp(hi, lo); got != 0x12345678 {
		t.Fatalf("LComp() = %#x, want 0x12345678", uint32(got))
	}
}

func TestQ31Math(t *testing.T) {
	tests := []struct {
		name string
		got  int32
		want int32
	}{
		{name: "mpy32 half by half", got: Mpy32(16384, 0, 16384, 0), want: 0x20000000},
		{name: "mpy32 by 16", got: Mpy32By16(16384, 0, 16384), want: 0x20000000},
		{name: "div32 quarter by half", got: Div32(0x20000000, 0x4000, 0), want: 0x3ffffff8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %#x, want %#x", tt.name, uint32(tt.got), uint32(tt.want))
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		got  int16
		want int16
	}{
		{name: "norm_s zero", got: NormS(0), want: 0},
		{name: "norm_s minus one", got: NormS(-1), want: 15},
		{name: "norm_s one", got: NormS(1), want: 14},
		{name: "norm_s normalized", got: NormS(0x4000), want: 0},
		{name: "norm_l zero", got: NormL(0), want: 0},
		{name: "norm_l minus one", got: NormL(-1), want: 31},
		{name: "norm_l one", got: NormL(1), want: 30},
		{name: "norm_l normalized", got: NormL(0x40000000), want: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("%s = %d, want %d", tt.name, tt.got, tt.want)
			}
		})
	}
}
