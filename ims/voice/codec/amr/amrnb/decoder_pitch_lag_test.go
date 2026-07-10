package amrnb

import "testing"

func TestDecodeLag3FirstOrThirdSubframe(t *testing.T) {
	tests := []struct {
		index    int16
		wantT0   int16
		wantFrac int16
	}{
		{index: 0, wantT0: 19, wantFrac: 1},
		{index: 196, wantT0: 85, wantFrac: -1},
		{index: 197, wantT0: 85, wantFrac: 0},
		{index: 255, wantT0: 143, wantFrac: 0},
	}
	for _, tt := range tests {
		t0, frac := decodeLag3(tt.index, 0, 0, 0, 0, false)
		if t0 != tt.wantT0 || frac != tt.wantFrac {
			t.Fatalf("decodeLag3(%d) = %d/%d, want %d/%d", tt.index, t0, frac, tt.wantT0, tt.wantFrac)
		}
	}
}

func TestDecodeLag3RelativeNormal(t *testing.T) {
	t0, frac := decodeLag3(20, 20, 29, subframeSamples, 0, false)
	if t0 != 26 || frac != 0 {
		t.Fatalf("decodeLag3(relative normal) = %d/%d, want 26/0", t0, frac)
	}
}

func TestDecodeLag3RelativeFourBit(t *testing.T) {
	tests := []struct {
		name     string
		index    int16
		previous int16
		wantT0   int16
		wantFrac int16
	}{
		{name: "low index", index: 2, previous: 60, wantT0: 43, wantFrac: 0},
		{name: "middle index", index: 7, previous: 45, wantT0: 45, wantFrac: 1},
		{name: "high index", index: 12, previous: 60, wantT0: 47, wantFrac: 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t0, frac := decodeLag3(tt.index, 40, 50, subframeSamples, tt.previous, true)
			if t0 != tt.wantT0 || frac != tt.wantFrac {
				t.Fatalf("decodeLag3(4-bit) = %d/%d, want %d/%d", t0, frac, tt.wantT0, tt.wantFrac)
			}
		})
	}
}

func TestDecodeLag6FirstOrThirdSubframe(t *testing.T) {
	tests := []struct {
		index    int16
		wantT0   int16
		wantFrac int16
	}{
		{index: 0, wantT0: 17, wantFrac: 3},
		{index: 200, wantT0: 51, wantFrac: -1},
		{index: 463, wantT0: 95, wantFrac: 0},
		{index: 511, wantT0: 143, wantFrac: 0},
	}
	for _, tt := range tests {
		t0, frac := decodeLag6(tt.index, 18, pitchMax, 0, 0)
		if t0 != tt.wantT0 || frac != tt.wantFrac {
			t.Fatalf("decodeLag6(%d) = %d/%d, want %d/%d", tt.index, t0, frac, tt.wantT0, tt.wantFrac)
		}
	}
}

func TestDecodeLag6RelativeSubframe(t *testing.T) {
	t0, frac := decodeLag6(20, 18, pitchMax, subframeSamples, 40)
	if t0 != 38 || frac != -1 {
		t.Fatalf("decodeLag6(relative) = %d/%d, want 38/-1", t0, frac)
	}

	t0, frac = decodeLag6(20, 18, pitchMax, subframeSamples, 140)
	if t0 != 137 || frac != -1 {
		t.Fatalf("decodeLag6(relative clipped) = %d/%d, want 137/-1", t0, frac)
	}
}
