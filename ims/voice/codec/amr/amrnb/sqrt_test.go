package amrnb

import "testing"

func TestSqrtLExp(t *testing.T) {
	tests := []struct {
		name    string
		in      int32
		want    int32
		wantExp int16
	}{
		{name: "zero", in: 0, want: 0, wantExp: 0},
		{name: "quarter", in: 0x20000000, want: 0x40000000, wantExp: 0},
		{name: "half", in: 0x40000000, want: 0x5a820000, wantExp: 0},
		{name: "small", in: 1, want: 0x5a820000, wantExp: 30},
	}
	for _, tt := range tests {
		got, exp := sqrtLExp(tt.in)
		if got != tt.want || exp != tt.wantExp {
			t.Fatalf("%s sqrtLExp(%#x) = %#x/%d, want %#x/%d",
				tt.name, tt.in, got, exp, tt.want, tt.wantExp)
		}
	}
}
