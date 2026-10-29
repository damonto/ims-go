package registration

import (
	"fmt"
	"testing"

	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func TestNotifyRegInfoMatchesRewrittenContact(t *testing.T) {
	tests := []struct {
		name           string
		state          string
		event          string
		wantRegistered bool
		wantEvent      error
	}{
		{name: "active", state: "active", event: "created", wantRegistered: true},
		{name: "network deregistration", state: "terminated", event: "deactivated", wantEvent: errNetworkDeregistered},
		{name: "expired", state: "terminated", event: "expired", wantEvent: errInitialRegistrationNeeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			svc.setRegistered(true)
			expires := svc.State().RegisterExpires

			notify := sip.NewRequest("NOTIFY", svc.currentRegisterContactURI())
			notify.Headers.Add("Event", regEventPackage)
			notify.Headers.Add("Content-Type", regInfoContentType)
			notify.Body = fmt.Appendf(nil, `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="0" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="%s" event="%s">
      <uri>sip:%s@192.0.2.200:5060;dtg=test;reg-info=contact-1</uri>
    </contact>
  </registration>
</reginfo>`, svc.State().PublicIdentity, tt.state, tt.event, svc.contactUser)

			handled, err := svc.HandleRequest(t.Context(), session.Request{Message: notify, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			if got := svc.State().Registered; got != tt.wantRegistered {
				t.Fatalf("Registered = %t, want %t", got, tt.wantRegistered)
			}
			if tt.wantEvent != nil {
				expectRegistrationEvent(t, svc, tt.wantEvent)
			} else {
				expectNoRegistrationEvent(t, svc)
				if got := svc.State().RegisterExpires; got != expires {
					t.Fatalf("RegisterExpires = %v, want %v without NOTIFY expires", got, expires)
				}
			}
			if got := countWrites(transport); got != 1 {
				t.Fatalf("write count = %d, want NOTIFY 200 response", got)
			}
		})
	}
}

func TestRegInfoRewrittenContactKeepsBindingIdentity(t *testing.T) {
	const contactURI = "sip:CONTACTTOKEN@[2001:db8::10]:5062;transport=tcp"
	tests := []struct {
		name  string
		uri   string
		regID string
		want  bool
	}{
		{name: "same user at rewritten host", uri: "sip:CONTACTTOKEN@192.0.2.200:5060;dtg=test", want: true},
		{name: "same user with registration id", uri: "sip:CONTACTTOKEN@192.0.2.200:5060", regID: "1", want: true},
		{name: "another flow", uri: "sip:CONTACTTOKEN@192.0.2.200:5060", regID: "2"},
		{name: "another user", uri: "sip:OTHERCONTACT@192.0.2.200:5060"},
		{name: "user is case sensitive", uri: "sip:contacttoken@192.0.2.200:5060"},
		{name: "missing user", uri: "sip:192.0.2.200:5060"},
		{name: "another scheme", uri: "sips:CONTACTTOKEN@192.0.2.200:5060"},
		{name: "missing host", uri: "sip:CONTACTTOKEN@"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contact := regInfoContact{URI: tt.uri}
			if tt.regID != "" {
				contact.Unknown = []regInfoUnknownParam{{Name: "reg-id", Value: tt.regID}}
			}
			state := State{registrationID: 1}
			if got := contactMatchesCurrentBinding(contact, state, contactURI, "register-call", 2); got != tt.want {
				t.Fatalf("contactMatchesCurrentBinding() = %t, want %t", got, tt.want)
			}
		})
	}
}
