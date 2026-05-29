package vowifi

import "testing"

func TestUserAgent(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{
			name: "client ims config leaves user agent empty",
			got: func() string {
				cfg, err := Config{Terminal: TerminalInfo{ID: "356789012345678"}}.normalizedIMS()
				if err != nil {
					t.Fatalf("normalizedIMS() error = %v", err)
				}
				return cfg.UserAgent
			}(),
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

func TestConfigNormalizedIMSUsesTerminalInfo(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{
			name: "does not build ims user agent from terminal info",
			cfg: Config{
				Terminal: TerminalInfo{
					ID:              "356789012345678",
					Vendor:          "Samsung",
					Model:           "SM-S921B",
					SoftwareVersion: "14",
					Build:           "UP1A.231005.007",
				},
			},
		},
		{
			name: "explicit ims user agent wins",
			cfg: Config{
				Terminal: TerminalInfo{
					ID:     "356789012345678",
					Vendor: "Samsung",
					Model:  "SM-S921B",
				},
				IMS: IMSConfig{
					UserAgent: "explicit-agent",
				},
			},
			want: "explicit-agent",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.normalizedIMS()
			if err != nil {
				t.Fatalf("normalizedIMS() error = %v", err)
			}
			if got.UserAgent != tt.want {
				t.Fatalf("UserAgent = %q, want %q", got.UserAgent, tt.want)
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
			cfg: Config{
				Terminal: TerminalInfo{
					ID:              "356789012345678",
					Vendor:          "Google",
					Model:           "Pixel 10 Pro",
					SoftwareVersion: "16",
					Build:           "BD1A.250702.001",
					Type:            "Smartphone",
					HardwareSKU:     "Pixel 10 Pro",
				},
			},
			profile: wfcProfile{
				MCC:    "530",
				MNC:    "24",
				WFCSPN: "2degrees",
			},
			want: "Google/Pixel 10 Pro Android 16 BD1A.250702.001 Smartphone 53024 3567890123456700 2degrees Pixel 10 Pro",
		},
		{
			name:     "uses configured terminal info",
			template: "#MANUFACTURER#/#MODEL# Android #AV# #BUILD# #TYPE# #HWSKU#",
			cfg: Config{
				Terminal: TerminalInfo{
					Vendor:          "Samsung",
					Model:           "SM-S921B",
					SoftwareVersion: "14",
					Build:           "UP1A.231005.007",
					Type:            "Phone",
					HardwareSKU:     "dm1q",
				},
			},
			want: "Samsung/SM-S921B Android 14 UP1A.231005.007 Phone dm1q",
		},
		{
			name:     "plain user agent is unchanged",
			template: "profile-agent",
			cfg:      Config{Terminal: TerminalInfo{ID: "356789012345678"}},
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
