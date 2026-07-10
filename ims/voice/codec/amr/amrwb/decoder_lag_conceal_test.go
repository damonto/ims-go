package amrwb

import "testing"

func TestInitLagConceal(t *testing.T) {
	hist := initialLagHistory()

	for i, got := range hist {
		if got != initialOldT0 {
			t.Fatalf("hist[%d] = %d, want %d", i, got, initialOldT0)
		}
	}
}

func TestConcealLagUnusableUsesOldStableLag(t *testing.T) {
	gainHist := [lagHistCount]int16{9000, 10000, 11000, 12000, 13000}
	lagHist := [lagHistCount]int16{64, 65, 66, 64, 65}
	oldT0 := int16(70)
	seed := int16(randomInitialSeed)

	got, nextSeed := concealLag(gainHist, lagHist, 80, oldT0, seed, true)

	if got != 66 {
		t.Fatalf("concealed lag = %d, want clamped old lag 66", got)
	}
	if nextSeed != seed {
		t.Fatalf("seed = %d, want unchanged %d", nextSeed, seed)
	}
}

func TestConcealLagBadFrameKeepsPlausibleLag(t *testing.T) {
	gainHist := [lagHistCount]int16{1000, 7000, 9000, 5000, 1000}
	lagHist := [lagHistCount]int16{60, 80, 90, 100, 110}
	oldT0 := int16(70)
	seed := int16(randomInitialSeed)

	got, nextSeed := concealLag(gainHist, lagHist, 95, oldT0, seed, false)

	if got != 95 {
		t.Fatalf("concealed lag = %d, want accepted lag 95", got)
	}
	if nextSeed != seed {
		t.Fatalf("seed = %d, want unchanged %d", nextSeed, seed)
	}
}

func TestConcealLagClampsGeneratedLagToHistory(t *testing.T) {
	gainHist := [lagHistCount]int16{1000, 2000, 3000, 4000, 5000}
	lagHist := [lagHistCount]int16{40, 80, 120, 160, 200}
	oldT0 := int16(70)
	seed := int16(randomInitialSeed)

	got, nextSeed := concealLag(gainHist, lagHist, 250, oldT0, seed, true)

	if got < 40 || got > 200 {
		t.Fatalf("concealed lag = %d, want within history range", got)
	}
	if nextSeed == seed {
		t.Fatal("seed did not advance while generating a concealed lag")
	}
}

func TestInsertionSort16(t *testing.T) {
	values := []int16{5, 1, 4, 2, 3}

	insertionSort16(values)

	want := []int16{1, 2, 3, 4, 5}
	for i := range want {
		if values[i] != want[i] {
			t.Fatalf("values[%d] = %d, want %d", i, values[i], want[i])
		}
	}
}
