package command

import (
	"bytes"
	"testing"
)

func TestSMSPPDownloadEnvelope(t *testing.T) {
	tests := []struct {
		name string
		cmd  SMSPPDownload
		want []byte
	}{
		{
			name: "service center and tpdu",
			cmd: SMSPPDownload{
				ServiceCenterAddress: "+1234",
				TPDU:                 []byte{0x00, 0x7F, 0xF6, 0x00, 0x00, 0x00},
			},
			want: []byte{
				0xD1, 0x11,
				0x82, 0x02, 0x83, 0x81,
				0x86, 0x03, 0x91, 0x21, 0x43,
				0x8B, 0x06, 0x00, 0x7F, 0xF6, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "without service center",
			cmd:  SMSPPDownload{TPDU: []byte{0x00, 0x7F, 0x16}},
			want: []byte{
				0xD1, 0x09,
				0x82, 0x02, 0x83, 0x81,
				0x8B, 0x03, 0x00, 0x7F, 0x16,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cmd.Envelope()
			if err != nil {
				t.Fatalf("Envelope() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("Envelope() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestSMSPPDownloadMarshalBinary(t *testing.T) {
	cmd := SMSPPDownload{
		ServiceCenterAddress: "+1234",
		TPDU:                 []byte{0x00, 0x7F, 0xF6},
	}
	got, err := cmd.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	want := []byte{
		0x80, 0xC2, 0x00, 0x00, 0x10,
		0xD1, 0x0E,
		0x82, 0x02, 0x83, 0x81,
		0x86, 0x03, 0x91, 0x21, 0x43,
		0x8B, 0x03, 0x00, 0x7F, 0xF6,
		0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("MarshalBinary() = % X, want % X", got, want)
	}
}

func TestSMSPPDownloadMarshalBinaryUsesExtendedLength(t *testing.T) {
	tpdu := bytes.Repeat([]byte{0xAA}, 250)
	cmd := SMSPPDownload{
		ServiceCenterAddress: "+1234",
		TPDU:                 tpdu,
	}
	envelope, err := cmd.Envelope()
	if err != nil {
		t.Fatalf("Envelope() error = %v", err)
	}
	if len(envelope) <= 0xFF {
		t.Fatalf("len(Envelope()) = %d, want extended APDU length", len(envelope))
	}

	got, err := cmd.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	wantPrefix := []byte{0x80, 0xC2, 0x00, 0x00, 0x00, byte(len(envelope) >> 8), byte(len(envelope))}
	if !bytes.Equal(got[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("MarshalBinary() prefix = % X, want % X", got[:len(wantPrefix)], wantPrefix)
	}
	if !bytes.Equal(got[len(wantPrefix):len(got)-2], envelope) {
		t.Fatalf("MarshalBinary() data = % X, want % X", got[len(wantPrefix):len(got)-2], envelope)
	}
	if !bytes.Equal(got[len(got)-2:], []byte{0x00, 0x00}) {
		t.Fatalf("MarshalBinary() Le = % X, want 00 00", got[len(got)-2:])
	}
}
