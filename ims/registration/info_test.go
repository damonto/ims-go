package registration

import (
	"slices"
	"testing"

	"github.com/damonto/ims-go/ims/sip"
)

func TestRegistrationMSISDN(t *testing.T) {
	tests := []struct {
		name      string
		headers   []string
		want      string
		ambiguous bool
	}{
		{name: "no identities"},
		{name: "TEL", headers: []string{"<tel:+15551234567>"}, want: "+15551234567"},
		{name: "SIP phone", headers: []string{"<sip:+15551234567@example.test;user=phone>"}, want: "+15551234567"},
		{name: "global SIP without marker", headers: []string{"<sip:+15551234567@example.test>"}, want: "+15551234567"},
		{name: "encoded SIPS", headers: []string{"<SIPS:%2B15551234567@example.test;USER=PHONE>"}, want: "+15551234567"},
		{name: "aliases across headers", headers: []string{"<sip:alice@example.test>, <tel:+1-(555)-123.4567>", "<sip:+15551234567@example.test;user=phone>"}, want: "+15551234567"},
		{name: "quoted display name", headers: []string{"\"Subscriber, Mobile\" <tel:+15551234567>;tag=remote"}, want: "+15551234567"},
		{name: "IMSI before phone", headers: []string{"<sip:310260123456789@ims.example.test>,<tel:+15551234567>"}, want: "+15551234567"},
		{name: "bare URI", headers: []string{"tel:+15551234567"}, want: "+15551234567"},
		{name: "IMSI only", headers: []string{"<sip:310260123456789@ims.example.test>"}},
		{name: "local TEL", headers: []string{"<tel:5551234567;phone-context=+1>"}},
		{name: "local SIP", headers: []string{"<sip:5551234567;phone-context=example.test@example.test;user=phone>"}},
		{name: "national number with marker", headers: []string{"<sip:15551234567@example.test;user=phone>"}},
		{name: "conflicting TEL identities", headers: []string{"<tel:+15551234567>,<tel:+15557654321>"}, ambiguous: true},
		{name: "conflicting TEL and SIP", headers: []string{"<tel:+15551234567>", "<sip:+15557654321@example.test;user=phone>"}, ambiguous: true},
		{name: "extension", headers: []string{"<tel:+15551234567;ext=12>"}},
		{name: "bare extension preserved", headers: []string{"tel:+15551234567;ext=12"}},
		{name: "SIP extension", headers: []string{"<sip:+15551234567;ext=12@example.test;user=phone>"}},
		{name: "subaddress", headers: []string{"<tel:+15551234567;isub=12>"}},
		{name: "mandatory parameter", headers: []string{"<tel:+15551234567;m-plan=unknown>"}},
		{name: "malformed escape", headers: []string{"<sip:%2X15551234567@example.test>"}},
		{name: "missing SIP host", headers: []string{"<sip:+15551234567@>"}},
		{name: "no SIP user", headers: []string{"<sip:+15551234567>"}},
		{name: "SIP password", headers: []string{"<sip:+15551234567:secret@example.test>"}},
		{name: "non-phone SIP user type", headers: []string{"<sip:+15551234567@example.test;user=ip>"}},
		{name: "dummy number", headers: []string{"<tel:+000000000000000>"}},
		{name: "too many digits", headers: []string{"<tel:+1234567890123456>"}},
		{name: "only plus", headers: []string{"<tel:+>"}},
		{name: "service code", headers: []string{"<tel:*123>"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewResponse(200, "OK")
			for _, value := range tt.headers {
				msg.Headers.Add("P-Associated-URI", value)
			}
			uris := associatedURIsFromMessage(msg)
			if got, ambiguous := associatedMSISDN(uris); got != tt.want || ambiguous != tt.ambiguous {
				t.Fatalf("associatedMSISDN(%q) = %q, %v; want %q, %v", uris, got, ambiguous, tt.want, tt.ambiguous)
			}
		})
	}
}

func TestRegistrationInfoCopiesIdentities(t *testing.T) {
	for _, registered := range []bool{false, true} {
		name := "unregistered"
		if registered {
			name = "registered"
		}
		t.Run(name, func(t *testing.T) {
			uris := []string{"tel:+15551234567"}
			reg := &Registrar{state: State{Registered: registered, AssociatedURIs: slices.Clone(uris)}}
			info := reg.Info()
			if info.Registered != registered {
				t.Fatalf("Registered = %v", info.Registered)
			}
			if !registered {
				if len(info.AssociatedURIs) != 0 || info.MSISDN != "" {
					t.Fatalf("unregistered Info = %+v", info)
				}
				return
			}
			info.AssociatedURIs[0] = "tel:+15557654321"
			if got := reg.Info(); !slices.Equal(got.AssociatedURIs, uris) || got.MSISDN != "+15551234567" {
				t.Fatalf("Info changed through a snapshot: %+v", got)
			}
		})
	}
}
