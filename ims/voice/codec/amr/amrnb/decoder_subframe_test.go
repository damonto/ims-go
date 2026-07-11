package amrnb

import "testing"

func TestDecodeGoodSubframeConsumesModeParameters(t *testing.T) {
	tests := []struct {
		name        string
		mode        Mode
		params      []int16
		wantUsed    int
		wantGainPit int16
	}{
		{name: "MR475", mode: Mode475, params: []int16{197, 0, 0, 0}, wantUsed: 4, wantGainPit: 812},
		{name: "MR515", mode: Mode515, params: []int16{197, 0, 0, 0}, wantUsed: 4, wantGainPit: 10813},
		{name: "MR590", mode: Mode590, params: []int16{197, 0, 0, 0}, wantUsed: 4, wantGainPit: 10813},
		{name: "MR670", mode: Mode670, params: []int16{197, 0, 0, 0}, wantUsed: 4, wantGainPit: 577},
		{name: "MR740", mode: Mode740, params: []int16{197, 0, 0, 0}, wantUsed: 4, wantGainPit: 577},
		{name: "MR795", mode: Mode795, params: []int16{197, 0, 0, 0, 0}, wantUsed: 5, wantGainPit: 0},
		{name: "MR102", mode: Mode1020, params: []int16{197, 0, 0, 0, 0, 0, 0, 0, 0}, wantUsed: 9, wantGainPit: 577},
		{name: "MR122", mode: Mode1220, params: []int16{463, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, wantUsed: 13, wantGainPit: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := newDecoderCoreState()
			setIdentityLPC(&state)

			used, got, err := state.decodeGoodSubframe(decodeGoodSubframeInput{
				mode:     tt.mode,
				subframe: 0,
				params:   tt.params,
			})

			if err != nil {
				t.Fatalf("decodeGoodSubframe error = %v", err)
			}
			if used != tt.wantUsed {
				t.Fatalf("used = %d, want %d", used, tt.wantUsed)
			}
			if got.gainPit != tt.wantGainPit {
				t.Fatalf("gainPit = %d, want %d", got.gainPit, tt.wantGainPit)
			}
			if len(got.samples) != subframeSamples {
				t.Fatalf("samples length = %d, want %d", len(got.samples), subframeSamples)
			}
			if state.oldT0 != got.t0 {
				t.Fatalf("oldT0 = %d, want decoded T0 %d", state.oldT0, got.t0)
			}
			if state.ltpGainHistory[ltpGainHistoryLen-1] != got.gainPit {
				t.Fatalf("ltp gain tail = %d, want %d", state.ltpGainHistory[ltpGainHistoryLen-1], got.gainPit)
			}
			if state.ecGainPitch.pbuf[4] != minInt16(got.gainPit, 16384) {
				t.Fatalf("EC pitch gain tail = %d, want %d", state.ecGainPitch.pbuf[4], got.gainPit)
			}
			if state.ecGainCode.gbuf[4] != got.gainCode {
				t.Fatalf("EC code gain tail = %d, want %d", state.ecGainCode.gbuf[4], got.gainCode)
			}
		})
	}
}

func TestDecodeGoodSubframeMR475ReusesGainIndexOnOddSubframe(t *testing.T) {
	state := newDecoderCoreState()
	setIdentityLPC(&state)

	if used, _, err := state.decodeGoodSubframe(decodeGoodSubframeInput{
		mode:     Mode475,
		subframe: 0,
		params:   []int16{197, 0, 0, 5},
	}); err != nil || used != 4 {
		t.Fatalf("first MR475 subframe used=%d err=%v, want used=4 nil", used, err)
	}
	used, got, err := state.decodeGoodSubframe(decodeGoodSubframeInput{
		mode:     Mode475,
		subframe: 1,
		params:   []int16{4, 0, 0},
	})

	if err != nil {
		t.Fatalf("odd MR475 subframe error = %v", err)
	}
	if used != 3 {
		t.Fatalf("odd MR475 used = %d, want 3", used)
	}
	if got.gainPit != 11807 {
		t.Fatalf("odd MR475 gainPit = %d, want reused-index odd gain 11807", got.gainPit)
	}
}

func TestDecodeSubframeGainMR102KeepsPitchGainForSynthesis(t *testing.T) {
	state := newDecoderCoreState()
	state.oldT0 = subframeSamples + 6

	gain, err := state.decodeSubframeGain(decodeSubframeGainInput{
		mode:     Mode1020,
		even:     1,
		params:   []int16{0},
		badFrame: false,
		code:     state.code[:],
	})

	if err != nil {
		t.Fatalf("decodeSubframeGain(MR102) error = %v", err)
	}
	if gain.consumed != 1 {
		t.Fatalf("used = %d, want 1", gain.consumed)
	}
	if gain.pitch != 577 {
		t.Fatalf("gainPit = %d, want full decoded gain 577", gain.pitch)
	}
}

func TestGoodSubframeGainUpdateLimitsAfterBadFrame(t *testing.T) {
	state := newDecoderCoreState()
	state.prevBF = true
	state.ecGainPitch.prevGP = 100
	state.ecGainCode.prevGC = 50

	gainPit := int16(200)
	gainCode := int16(90)
	gainPit, gainCode = state.updateSubframeGains(false, gainPit, gainCode)

	if gainPit != 100 {
		t.Fatalf("gainPit after previous bad frame = %d, want 100", gainPit)
	}
	if gainCode != 50 {
		t.Fatalf("gainCode after previous bad frame = %d, want 50", gainCode)
	}
	if state.ecGainPitch.pbuf[4] != 100 || state.ecGainCode.gbuf[4] != 50 {
		t.Fatalf("EC gain tails = %d/%d, want 100/50", state.ecGainPitch.pbuf[4], state.ecGainCode.gbuf[4])
	}
}

func TestDecodeGoodSubframeRejectsShortParams(t *testing.T) {
	state := newDecoderCoreState()
	setIdentityLPC(&state)

	if _, _, err := state.decodeGoodSubframe(decodeGoodSubframeInput{
		mode:     Mode1020,
		subframe: 0,
		params:   []int16{197, 0, 0},
	}); err == nil {
		t.Fatal("decodeGoodSubframe short MR102 params error = nil, want error")
	}
}

func TestDecodeBadSubframeUsesConcealedGains(t *testing.T) {
	state := newDecoderCoreState()
	setIdentityLPC(&state)
	state.state = 2
	state.ecGainPitch.pastGainPit = 6000
	state.ecGainPitch.pbuf = [5]int16{6000, 6000, 6000, 6000, 6000}
	state.ecGainCode.pastGainCode = 200
	state.ecGainCode.gbuf = [5]int16{200, 200, 200, 200, 200}

	used, got, err := state.decodeGoodSubframe(decodeGoodSubframeInput{
		mode:     Mode590,
		subframe: 0,
		params:   []int16{197, 0, 0, 0},
		badFrame: true,
	})

	if err != nil {
		t.Fatalf("decode bad subframe error = %v", err)
	}
	if used != 4 {
		t.Fatalf("used = %d, want 4", used)
	}
	if got.gainPit == 0 || got.gainCode == 0 {
		t.Fatalf("concealed gains = %d/%d, want non-zero", got.gainPit, got.gainCode)
	}
	if state.ltpGainHistory[ltpGainHistoryLen-1] != 0 {
		t.Fatalf("bad frame updated LTP gain history tail = %d, want 0", state.ltpGainHistory[ltpGainHistoryLen-1])
	}
}

func minInt16(a, b int16) int16 {
	if a < b {
		return a
	}
	return b
}

func setIdentityLPC(state *decoderCoreState) {
	for subframe := range 4 {
		state.az[subframe*lpcCoeffCount] = 4096
	}
}
