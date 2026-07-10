package amrnb

import "testing"

func TestGainPredStateResetAndUpdate(t *testing.T) {
	state := newGainPredState()

	gotMR122, got := state.averageLimited()
	if gotMR122 != minEnergyMR122 || got != -8192 {
		t.Fatalf("averageLimited after reset = (%d, %d), want (%d, %d)",
			gotMR122, got, minEnergyMR122, int16(-8192))
	}

	state.update(100, 200)
	state.update(300, 400)

	if state.pastQuaEnMR122 != [gainPredTaps]int16{300, 100, minEnergyMR122, minEnergyMR122} {
		t.Fatalf("pastQuaEnMR122 = %v", state.pastQuaEnMR122)
	}
	if state.pastQuaEn != [gainPredTaps]int16{400, 200, minEnergy, minEnergy} {
		t.Fatalf("pastQuaEn = %v", state.pastQuaEn)
	}

	gotMR122, got = state.averageLimited()
	if gotMR122 != -1091 || got != -7018 {
		t.Fatalf("averageLimited after updates = (%d, %d), want (-1091, -7018)", gotMR122, got)
	}
}

func TestInnovationEnergyKnownVector(t *testing.T) {
	code := make([]int16, subframeSamples)
	code[0] = 8191
	code[1] = -8192

	got := innovationEnergy(code)
	const want = 268402690
	if got != want {
		t.Fatalf("innovationEnergy = %d, want %d", got, want)
	}
}

func TestGainPredPredictKnownVectors(t *testing.T) {
	code := make([]int16, subframeSamples)
	code[0] = 8191
	code[7] = -8192
	code[19] = 4096

	tests := []struct {
		name       string
		mode       Mode
		wantExp    int16
		wantFrac   int16
		wantExpEn  int16
		wantFracEn int16
	}{
		{name: "MR475", mode: Mode475, wantExp: 3, wantFrac: 12937},
		{name: "MR74", mode: Mode740, wantExp: 2, wantFrac: 29306},
		{name: "MR795", mode: Mode795, wantExp: 3, wantFrac: 29266, wantExpEn: -13, wantFracEn: 18430},
		{name: "MR122", mode: Mode1220, wantExp: 2, wantFrac: 28752},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newGainPredState()

			gotExp, gotFrac, gotExpEn, gotFracEn := state.predict(tt.mode, code)

			if gotExp != tt.wantExp || gotFrac != tt.wantFrac ||
				gotExpEn != tt.wantExpEn || gotFracEn != tt.wantFracEn {
				t.Fatalf("predict = (%d, %d, %d, %d), want (%d, %d, %d, %d)",
					gotExp, gotFrac, gotExpEn, gotFracEn,
					tt.wantExp, tt.wantFrac, tt.wantExpEn, tt.wantFracEn)
			}
		})
	}
}
