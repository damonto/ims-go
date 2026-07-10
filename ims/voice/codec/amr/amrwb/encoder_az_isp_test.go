package amrwb

import (
	"testing"

	"github.com/damonto/ims-go/ims/voice/codec/amr/fxp"
)

func TestEncoderAzToISPRoundTripInitialISP(t *testing.T) {
	a, err := ispToAz(initialISP[:], false)
	if err != nil {
		t.Fatalf("ispToAz() error = %v", err)
	}
	isp, err := encoderAzToISP(a[:], initialISP[:])
	if err != nil {
		t.Fatalf("encoderAzToISP() error = %v", err)
	}
	for i := range lpcOrder - 1 {
		delta := fxp.Abs16(fxp.Sub16(isp[i], initialISP[i]))
		if delta > 120 {
			t.Fatalf("encoderAzToISP() isp[%d] = %d, want near %d", i, isp[i], initialISP[i])
		}
	}
	if got, want := isp[lpcOrder-1], initialISP[lpcOrder-1]; fxp.Abs16(fxp.Sub16(got, want)) > 4 {
		t.Fatalf("encoderAzToISP() last isp = %d, want near %d", got, want)
	}
}

func TestEncoderAzToISPRejectsShortBuffers(t *testing.T) {
	var a [lpcOrder + 1]int16
	a[0] = 4096

	if _, err := encoderAzToISP(a[:lpcOrder], initialISP[:]); err == nil {
		t.Fatal("encoderAzToISP(short) error = nil")
	}
}

func TestEncoderChebps2ConstantPolynomial(t *testing.T) {
	f := []int16{1024, 0}

	got := encoderChebps2(0, f, 1)

	if got == 0 {
		t.Fatal("encoderChebps2() returned zero for non-zero constant")
	}
}
