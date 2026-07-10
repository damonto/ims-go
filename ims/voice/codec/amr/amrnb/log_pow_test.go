package amrnb

import "testing"

func TestLog2ValueKnownPowers(t *testing.T) {
	tests := []struct {
		name         string
		value        int32
		wantExponent int16
		wantFraction int16
	}{
		{name: "zero", value: 0, wantExponent: 0, wantFraction: 0},
		{name: "one", value: 1, wantExponent: 0, wantFraction: 0},
		{name: "q30_one", value: 0x40000000, wantExponent: 30, wantFraction: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotExponent, gotFraction := log2Value(tt.value)

			if gotExponent != tt.wantExponent || gotFraction != tt.wantFraction {
				t.Fatalf("log2Value(%d) = (%d, %d), want (%d, %d)",
					tt.value, gotExponent, gotFraction, tt.wantExponent, tt.wantFraction)
			}
		})
	}
}

func TestPow2ValueKnownFractions(t *testing.T) {
	tests := []struct {
		name     string
		exponent int16
		fraction int16
		want     int32
	}{
		{name: "unity_q0", exponent: 0, fraction: 0, want: 1},
		{name: "unity_q14", exponent: 14, fraction: 0, want: 16384},
		{name: "sqrt2_q14_table_point", exponent: 14, fraction: 16384, want: 23170},
		{name: "unity_q30", exponent: 30, fraction: 0, want: 1073741824},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pow2Value(tt.exponent, tt.fraction)

			if got != tt.want {
				t.Fatalf("pow2Value(%d, %d) = %d, want %d",
					tt.exponent, tt.fraction, got, tt.want)
			}
		})
	}
}
