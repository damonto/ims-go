package amrnb

import "testing"

func TestEncodeLag3FullSearchRoundTripFractional(t *testing.T) {
	index := encodeLag3(40, 1, 0, 0, 0, false, false)

	t0, frac := decodeLag3(index, 0, 0, 0, 0, false)

	if index != 63 {
		t.Fatalf("index = %d, want 63", index)
	}
	if t0 != 40 || frac != 1 {
		t.Fatalf("decodeLag3(%d) = %d/%d, want 40/1", index, t0, frac)
	}
}

func TestEncodeLag3FullSearchRoundTripInteger(t *testing.T) {
	index := encodeLag3(90, 0, 0, 0, 0, false, false)

	t0, frac := decodeLag3(index, 0, 0, 0, 0, false)

	if index != 202 {
		t.Fatalf("index = %d, want 202", index)
	}
	if t0 != 90 || frac != 0 {
		t.Fatalf("decodeLag3(%d) = %d/%d, want 90/0", index, t0, frac)
	}
}

func TestEncodeLag3DeltaFlag4Branches(t *testing.T) {
	tests := []struct {
		name string
		t0   int16
		frac int16
		want int16
	}{
		{name: "left_integer", t0: 38, frac: 0, want: 3},
		{name: "fractional_window", t0: 40, frac: -1, want: 8},
		{name: "right_integer", t0: 43, frac: 0, want: 14},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeLag3(tt.t0, tt.frac, 40, 35, 44, true, true)
			if got != tt.want {
				t.Fatalf("encodeLag3 = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestEncodeLag6FullSearchRoundTrip(t *testing.T) {
	index := encodeLag6(40, 2, 0, false)

	t0, frac := decodeLag6(index, pitchMinMR122, pitchMax, 0, 0)

	if index != 137 {
		t.Fatalf("index = %d, want 137", index)
	}
	if t0 != 40 || frac != 2 {
		t.Fatalf("decodeLag6(%d) = %d/%d, want 40/2", index, t0, frac)
	}
}

func TestEncodeLag6Delta(t *testing.T) {
	index := encodeLag6(42, -2, 38, true)

	if index != 25 {
		t.Fatalf("index = %d, want 25", index)
	}
}
