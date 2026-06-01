package identity

import "testing"

func TestMSISDN(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "sip name addr",
			value: "<sip:+12242255559@one.att.net;user=phone;isup-oli=00>;tag=remote",
			want:  "+12242255559",
		},
		{
			name:  "tel name addr",
			value: "<tel:+12242255559>;tag=remote",
			want:  "+12242255559",
		},
		{
			name:  "local sip user with phone context",
			value: "sip:55559;phone-context=one.example@one.example;user=phone",
			want:  "55559",
		},
		{
			name:  "wfc sip uri",
			value: "sip:+64210647889@ims.mnc001.mcc530.3gppnetwork.org",
			want:  "+64210647889",
		},
		{
			name:  "percent encoded plus",
			value: "sip:%2B64210647889@ims.mnc001.mcc530.3gppnetwork.org",
			want:  "+64210647889",
		},
		{
			name:  "non numeric sip user",
			value: "sip:sender@example.net",
		},
		{
			name:  "star code is not msisdn",
			value: "sip:*123@example.net",
		},
		{
			name:  "tel star code is not msisdn",
			value: "tel:*123",
		},
		{
			name:  "bare plus is not msisdn",
			value: "sip:+@example.net",
		},
		{
			name:  "tel bare plus is not msisdn",
			value: "tel:+",
		},
		{
			name:  "unknown scheme",
			value: "mailto:+12242255559@example.net",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MSISDN(tt.value); got != tt.want {
				t.Fatalf("MSISDN() = %q, want %q", got, tt.want)
			}
		})
	}
}
