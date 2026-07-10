package amrwb

import "testing"

func BenchmarkAcelp4t64Indexed(b *testing.B) {
	tests := []struct {
		name  string
		nbits int16
	}{
		{name: "64 bits", nbits: 64},
		{name: "72 bits", nbits: 72},
		{name: "88 bits", nbits: 88},
	}
	for _, tt := range tests {
		b.Run(tt.name, func(b *testing.B) {
			var dn, cn, h [subframeSamples]int16
			for i := range dn {
				dn[i] = int16((i%29 - 14) * 40)
				cn[i] = int16((13 - i%27) * 32)
			}
			h[0] = 4096
			h[1] = 1536
			h[2] = -768
			h[3] = 384
			b.ReportAllocs()
			for b.Loop() {
				if _, err := acelp4t64Indexed(
					dn[:],
					cn[:],
					h[:],
					tt.nbits,
					int16(frameBits[Mode2385]),
				); err != nil {
					b.Fatalf("acelp4t64Indexed() error = %v", err)
				}
			}
		})
	}
}
