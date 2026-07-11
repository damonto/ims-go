package codec

import "testing"

func TestEVSSessionConfigureKeepsDecodeFormat(t *testing.T) {
	tests := []struct {
		name       string
		initial    EVSFormat
		configured EVSFormat
	}{
		{name: "native-to-amr-wb-io", initial: EVSNative, configured: EVSAMRWBIO},
		{name: "amr-wb-io-to-native", initial: EVSAMRWBIO, configured: EVSNative},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := t.Context()
			initialMode := EVSMode13200
			configuredMode := AMRWBMode1265
			if tt.initial == EVSAMRWBIO {
				initialMode, configuredMode = AMRWBMode1265, EVSMode13200
			}
			session, err := NewSession(ctx, Config{
				Name: EVS,
				Mode: initialMode,
				EVS:  EVSConfig{Format: tt.initial, Bandwidth: EVSBandwidthWB},
			})
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}
			defer session.Close(ctx)

			evsSession := session.(*evsSession)
			want, err := toEVSFormat(tt.initial)
			if err != nil {
				t.Fatalf("toEVSFormat() error = %v", err)
			}
			if err := session.Configure(ctx, Config{
				Name: EVS,
				Mode: configuredMode,
				EVS:  EVSConfig{Format: tt.configured, Bandwidth: EVSBandwidthWB},
			}); err != nil {
				t.Fatalf("Configure() error = %v", err)
			}
			if evsSession.decodeFormat != want {
				t.Fatalf("decode format = %s, want %s", evsSession.decodeFormat, want)
			}
		})
	}
}
