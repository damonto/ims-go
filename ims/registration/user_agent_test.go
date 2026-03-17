package registration

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
			name: "normalize config falls back to requested user agent",
			got:  normalizeConfig(Config{}).UserAgent,
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
