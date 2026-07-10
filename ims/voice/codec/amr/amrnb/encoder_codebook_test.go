package amrnb

import (
	"slices"
	"testing"
)

func TestAddPitchSharpness(t *testing.T) {
	tests := []struct {
		name       string
		in         []int16
		t0         int16
		pitchSharp int16
		want       []int16
	}{
		{
			name:       "adds delayed pitch contribution",
			in:         []int16{1000, -500, 200, 300},
			t0:         2,
			pitchSharp: 8192,
			want:       []int16{1000, -500, 700, 50},
		},
		{
			name:       "no pitch sharpness",
			in:         []int16{1000, -500, 200, 300},
			t0:         2,
			pitchSharp: 0,
			want:       []int16{1000, -500, 200, 300},
		},
		{
			name:       "lag outside subframe",
			in:         []int16{1000, -500, 200, 300},
			t0:         subframeSamples,
			pitchSharp: 8192,
			want:       []int16{1000, -500, 200, 300},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := slices.Clone(tt.in)
			addPitchSharpness(got, tt.t0, tt.pitchSharp)
			if !slices.Equal(got, tt.want) {
				t.Fatalf("addPitchSharpness() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSetSignConvertsCorrelationToMagnitudeAndSign(t *testing.T) {
	dn := make([]int16, subframeSamples)
	dn[0] = -120
	dn[1] = 80
	sign := make([]int16, subframeSamples)
	dn2 := make([]int16, subframeSamples)

	setSign(dn, sign, dn2, 8)

	if dn[0] != 120 || sign[0] != -32767 {
		t.Fatalf("negative correlation = %d/%d, want magnitude/sign 120/-32767", dn[0], sign[0])
	}
	if dn[1] != 80 || sign[1] != 32767 {
		t.Fatalf("positive correlation = %d/%d, want magnitude/sign 80/32767", dn[1], sign[1])
	}
}

func TestBuildCode2i40RoundTripsThroughDecoder(t *testing.T) {
	codvec := [pulseCount2]int16{10, 17}
	dnSign := make([]int16, subframeSamples)
	for i := range dnSign {
		dnSign[i] = 32767
	}
	dnSign[17] = -32767
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := buildCode2i40(0, codvec, dnSign, code, h, y)

	decoded := decode2i40_9bits(0, got.sign, got.index)
	if decoded[10] != 8191 || decoded[17] != -8192 {
		t.Fatalf("decoded pulses = %d/%d, want 8191/-8192", decoded[10], decoded[17])
	}
	if got.sign != 1 {
		t.Fatalf("sign index = %d, want first pulse positive only", got.sign)
	}
	if y[10] == 0 || y[17] == 0 {
		t.Fatalf("filtered code missing pulse response y[10]=%d y[17]=%d", y[10], y[17])
	}
}

func TestCode2i409BitsSelectsStrongTargetPulses(t *testing.T) {
	x := make([]int16, subframeSamples)
	x[10] = 3000
	x[17] = -2800
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := code2i40_9bits(0, x, h, subframeSamples, 0, code, y)

	decoded := decode2i40_9bits(0, got.sign, got.index)
	if decoded[10] != 8191 || decoded[17] != -8192 {
		t.Fatalf("decoded pulses = %d/%d, want target pulse positions", decoded[10], decoded[17])
	}
	if code[10] != 8191 || code[17] != -8192 {
		t.Fatalf("code pulses = %d/%d, want target pulse positions", code[10], code[17])
	}
	if y[10] == 0 || y[17] == 0 {
		t.Fatalf("filtered code missing pulse response y[10]=%d y[17]=%d", y[10], y[17])
	}
}

func TestBuildCode2i40_11RoundTripsThroughDecoder(t *testing.T) {
	codvec := [pulseCount2]int16{11, 22}
	dnSign := make([]int16, subframeSamples)
	for i := range dnSign {
		dnSign[i] = 32767
	}
	dnSign[22] = -32767
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := buildCode2i40_11(codvec, dnSign, code, h, y)

	decoded := decode2i40_11bits(got.sign, got.index)
	if decoded[11] != 8191 || decoded[22] != -8192 {
		t.Fatalf("decoded pulses = %d/%d, want 8191/-8192", decoded[11], decoded[22])
	}
	if got.sign != 1 {
		t.Fatalf("sign index = %d, want first pulse positive only", got.sign)
	}
	if y[11] == 0 || y[22] == 0 {
		t.Fatalf("filtered code missing pulse response y[11]=%d y[22]=%d", y[11], y[22])
	}
}

func TestCode2i4011BitsSelectsStrongTargetPulses(t *testing.T) {
	x := make([]int16, subframeSamples)
	x[11] = 3000
	x[22] = -2800
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := code2i40_11bits(x, h, subframeSamples, 0, code, y)

	decoded := decode2i40_11bits(got.sign, got.index)
	if decoded[11] != 8191 || decoded[22] != -8192 {
		t.Fatalf("decoded pulses = %d/%d, want target pulse positions", decoded[11], decoded[22])
	}
	if code[11] != 8191 || code[22] != -8192 {
		t.Fatalf("code pulses = %d/%d, want target pulse positions", code[11], code[22])
	}
	if y[11] == 0 || y[22] == 0 {
		t.Fatalf("filtered code missing pulse response y[11]=%d y[22]=%d", y[11], y[22])
	}
}

func TestBuildCode3i40RoundTripsThroughDecoder(t *testing.T) {
	codvec := [3]int16{10, 16, 22}
	dnSign := make([]int16, subframeSamples)
	for i := range dnSign {
		dnSign[i] = 32767
	}
	dnSign[16] = -32767
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := buildCode3i40(codvec, dnSign, code, h, y)

	decoded := decode3i40_14bits(got.sign, got.index)
	if decoded[10] != 8191 || decoded[16] != -8192 || decoded[22] != 8191 {
		t.Fatalf(
			"decoded pulses = %d/%d/%d, want 8191/-8192/8191",
			decoded[10],
			decoded[16],
			decoded[22],
		)
	}
	if got.sign != 5 {
		t.Fatalf("sign index = %d, want tracks 0 and 2 positive", got.sign)
	}
	if y[10] == 0 || y[16] == 0 || y[22] == 0 {
		t.Fatalf("filtered code missing pulse response y[10]=%d y[16]=%d y[22]=%d", y[10], y[16], y[22])
	}
}

func TestCode3i4014BitsSelectsStrongTargetPulses(t *testing.T) {
	x := make([]int16, subframeSamples)
	x[10] = 3200
	x[16] = -3000
	x[22] = 2800
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := code3i40_14bits(x, h, subframeSamples, 0, code, y)

	decoded := decode3i40_14bits(got.sign, got.index)
	if decoded[10] != 8191 || decoded[16] != -8192 || decoded[22] != 8191 {
		t.Fatalf(
			"decoded pulses = %d/%d/%d, want target pulse positions",
			decoded[10],
			decoded[16],
			decoded[22],
		)
	}
	if code[10] != 8191 || code[16] != -8192 || code[22] != 8191 {
		t.Fatalf("code pulses = %d/%d/%d, want target pulse positions", code[10], code[16], code[22])
	}
	if y[10] == 0 || y[16] == 0 || y[22] == 0 {
		t.Fatalf("filtered code missing pulse response y[10]=%d y[16]=%d y[22]=%d", y[10], y[16], y[22])
	}
}

func TestBuildCode4i40RoundTripsThroughDecoder(t *testing.T) {
	codvec := [4]int16{10, 16, 22, 33}
	dnSign := make([]int16, subframeSamples)
	for i := range dnSign {
		dnSign[i] = 32767
	}
	dnSign[16] = -32767
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := buildCode4i40(codvec, dnSign, code, h, y)

	decoded := decode4i40_17bits(got.sign, got.index)
	if decoded[10] != 8191 || decoded[16] != -8192 || decoded[22] != 8191 || decoded[33] != 8191 {
		t.Fatalf(
			"decoded pulses = %d/%d/%d/%d, want 8191/-8192/8191/8191",
			decoded[10],
			decoded[16],
			decoded[22],
			decoded[33],
		)
	}
	if got.sign != 13 {
		t.Fatalf("sign index = %d, want tracks 0, 2 and 3 positive", got.sign)
	}
	if y[10] == 0 || y[16] == 0 || y[22] == 0 || y[33] == 0 {
		t.Fatalf(
			"filtered code missing pulse response y[10]=%d y[16]=%d y[22]=%d y[33]=%d",
			y[10],
			y[16],
			y[22],
			y[33],
		)
	}
}

func TestCode4i4017BitsSelectsStrongTargetPulses(t *testing.T) {
	x := make([]int16, subframeSamples)
	x[10] = 3400
	x[16] = -3200
	x[22] = 3000
	x[33] = 2800
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := code4i40_17bits(x, h, subframeSamples, 0, code, y)

	decoded := decode4i40_17bits(got.sign, got.index)
	if decoded[10] != 8191 || decoded[16] != -8192 || decoded[22] != 8191 || decoded[33] != 8191 {
		t.Fatalf(
			"decoded pulses = %d/%d/%d/%d, want target pulse positions",
			decoded[10],
			decoded[16],
			decoded[22],
			decoded[33],
		)
	}
	if code[10] != 8191 || code[16] != -8192 || code[22] != 8191 || code[33] != 8191 {
		t.Fatalf("code pulses = %d/%d/%d/%d, want target pulse positions", code[10], code[16], code[22], code[33])
	}
	if y[10] == 0 || y[16] == 0 || y[22] == 0 || y[33] == 0 {
		t.Fatalf(
			"filtered code missing pulse response y[10]=%d y[16]=%d y[22]=%d y[33]=%d",
			y[10],
			y[16],
			y[22],
			y[33],
		)
	}
}

func TestBuildCode8i40RoundTripsThroughDecoder(t *testing.T) {
	codvec := [pulseCount8]int16{0, 1, 2, 3, 8, 5, 14, 7}
	dnSign := make([]int16, subframeSamples)
	for i := range dnSign {
		dnSign[i] = 32767
	}
	dnSign[5] = -32767
	dnSign[14] = -32767
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := buildCode8i40(codvec, dnSign, code, h, y)

	decoded := decode8i40_31bits(got.params[:])
	for i := range code {
		if decoded[i] != code[i] {
			t.Fatalf("decoded[%d] = %d, want %d", i, decoded[i], code[i])
		}
	}
	if y[0] == 0 || y[14] == 0 {
		t.Fatalf("filtered code missing pulse response y[0]=%d y[14]=%d", y[0], y[14])
	}
}

func TestCode8i4031BitsSelectsStrongTargetPulses(t *testing.T) {
	x := make([]int16, subframeSamples)
	cn := make([]int16, subframeSamples)
	targets := []struct {
		pos   int
		value int16
	}{
		{0, 3600},
		{1, 3500},
		{2, -3400},
		{3, 3300},
		{8, 3200},
		{5, -3100},
		{14, -3000},
		{7, 2900},
	}
	for _, target := range targets {
		x[target.pos] = target.value
		cn[target.pos] = target.value
	}
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := code8i40_31bits(x, cn, h, code, y)

	decoded := decode8i40_31bits(got.params[:])
	for _, target := range targets {
		if decoded[target.pos] == 0 {
			t.Fatalf("decoded[%d] = 0, want selected target pulse", target.pos)
		}
	}
	if allZero(code) {
		t.Fatal("code vector is all zero")
	}
	if allZero(y) {
		t.Fatal("filtered code vector is all zero")
	}
}

func TestBuildCode10i40RoundTripsThroughDecoder(t *testing.T) {
	codvec := [pulseCount10]int16{0, 1, 2, 3, 4, 10, 6, 17, 8, 24}
	dnSign := make([]int16, subframeSamples)
	for i := range dnSign {
		dnSign[i] = 32767
	}
	dnSign[6] = -32767
	dnSign[17] = -32767
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := buildCode10i40(codvec, dnSign, code, h, y)

	decoded := decode10i40_35bits(got.params[:])
	for i := range code {
		if decoded[i] != code[i] {
			t.Fatalf("decoded[%d] = %d, want %d", i, decoded[i], code[i])
		}
	}
	if y[0] == 0 || y[24] == 0 {
		t.Fatalf("filtered code missing pulse response y[0]=%d y[24]=%d", y[0], y[24])
	}
}

func TestCode10i4035BitsSelectsStrongTargetPulses(t *testing.T) {
	x := make([]int16, subframeSamples)
	cn := make([]int16, subframeSamples)
	targets := []struct {
		pos   int
		value int16
	}{
		{0, 3800},
		{1, 3700},
		{2, 3600},
		{3, 3500},
		{4, 3400},
		{10, 3300},
		{6, -3200},
		{17, -3100},
		{8, 3000},
		{24, 2900},
	}
	for _, target := range targets {
		x[target.pos] = target.value
		cn[target.pos] = target.value
	}
	h := make([]int16, subframeSamples)
	h[0] = 4096
	code := make([]int16, subframeSamples)
	y := make([]int16, subframeSamples)

	got := code10i40_35bits(x, cn, h, code, y)

	decoded := decode10i40_35bits(got.params[:])
	for _, target := range targets {
		if decoded[target.pos] == 0 {
			t.Fatalf("decoded[%d] = 0, want selected target pulse", target.pos)
		}
	}
	if allZero(code) {
		t.Fatal("code vector is all zero")
	}
	if allZero(y) {
		t.Fatal("filtered code vector is all zero")
	}
}
