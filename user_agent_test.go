package imsclient

import "testing"

func TestDefaultUserAgent(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "matches requested android style format",
			got:  defaultUserAgent(),
			want: "Google_Pixel 3XLAndroid12SQ3A.220705.004",
		},
		{
			name: "ims config falls back to requested user agent",
			got: func() string {
				cfg, err := (IMSConfig{}).Normalized()
				if err != nil {
					t.Fatalf("IMSConfig.Normalized() error = %v", err)
				}
				return cfg.UserAgent
			}(),
			want: "Google_Pixel 3XLAndroid12SQ3A.220705.004",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("user agent = %q, want %q", tt.got, tt.want)
			}
		})
	}
}

func TestRenderWFCUserAgent(t *testing.T) {
	tests := []struct {
		name     string
		template string
		cfg      Config
		profile  wfcProfile
		want     string
	}{
		{
			name:     "replaces known wfc placeholders",
			template: "#MANUFACTURE#/#MODEL# Android #AV# #BUILD# #TYPE# #MCCMNC# #IMEISV# #OPERATOR# #HWSKU#",
			cfg:      Config{IMEI: "356789012345678"},
			profile: wfcProfile{
				MCC:    "530",
				MNC:    "24",
				WFCSPN: "2degrees",
			},
			want: "Google/Pixel 3XL Android 12 SQ3A.220705.004 Smartphone 53024 3567890123456700 2degrees Pixel 3XL",
		},
		{
			name:     "plain user agent is unchanged",
			template: "profile-agent",
			cfg:      Config{IMEI: "356789012345678"},
			profile:  wfcProfile{},
			want:     "profile-agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := renderWFCUserAgent(tt.template, tt.cfg, tt.profile); got != tt.want {
				t.Fatalf("renderWFCUserAgent() = %q, want %q", got, tt.want)
			}
		})
	}
}
