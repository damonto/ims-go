package amrnb

import "testing"

func TestControlExcitationNoScale(t *testing.T) {
	excitation := make([]int16, subframeSamples)
	excitation[0], excitation[1], excitation[2] = 100, -100, 50
	energyHist := []int16{10, 20, 30, 40, 50, 60, 70, 80, 90}

	got, err := controlExcitation(excitation, 100, energyHist, 0, 0, 0)
	if err != nil {
		t.Fatalf("controlExcitation() error = %v", err)
	}

	want := []int16{100, -100, 50}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("excitation[%d] = %d, want %d", i, got[i], want[i])
		}
	}
}

func TestControlExcitationScalesTowardHistory(t *testing.T) {
	excitation := make([]int16, subframeSamples)
	for i := range excitation {
		excitation[i] = 100
	}
	energyHist := []int16{60, 70, 80, 90, 100, 110, 120, 100, 100}

	got, err := controlExcitation(excitation, 20, energyHist, 8, 0, 0)
	if err != nil {
		t.Fatalf("controlExcitation() error = %v", err)
	}

	if got[0] <= 100 {
		t.Fatalf("excitation[0] = %d, want scaled above 100", got[0])
	}
	for i, sample := range got {
		if sample != got[0] {
			t.Fatalf("excitation[%d] = %d, want uniform %d", i, sample, got[0])
		}
	}
}

func TestControlExcitationCarefulFlagCapsScale(t *testing.T) {
	excitation := make([]int16, subframeSamples)
	uncapped := make([]int16, subframeSamples)
	for i := range excitation {
		excitation[i] = 1000
		uncapped[i] = 1000
	}
	energyHist := []int16{400, 500, 600, 700, 800, 900, 1000, 1000, 1000}

	uncappedResult, err := controlExcitation(uncapped, 10, energyHist, 8, 0, 0)
	if err != nil {
		t.Fatalf("controlExcitation(uncapped) error = %v", err)
	}
	got, err := controlExcitation(excitation, 10, energyHist, 8, 0, 1)
	if err != nil {
		t.Fatalf("controlExcitation(careful) error = %v", err)
	}

	if got[0] >= uncappedResult[0] {
		t.Fatalf("careful excitation = %d, want below uncapped %d", got[0], uncappedResult[0])
	}
	if got[0] != 3000 {
		t.Fatalf("careful excitation = %d, want scale cap result 3000", got[0])
	}
}

func TestControlExcitationRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name       string
		excitation []int16
		history    []int16
	}{
		{name: "short excitation", excitation: make([]int16, subframeSamples-1), history: make([]int16, excitationHistoryLen)},
		{name: "short history", excitation: make([]int16, subframeSamples), history: make([]int16, excitationHistoryLen-1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := controlExcitation(tt.excitation, 10, tt.history, 0, 0, 0); err == nil {
				t.Fatal("controlExcitation() error = nil, want invalid input error")
			}
		})
	}
}
