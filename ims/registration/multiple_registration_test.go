package registration

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func TestMultipleRegistrationRequestFields(t *testing.T) {
	tests := []struct {
		name           string
		regID          uint32
		preference     int
		wantPreference string
	}{
		{name: "VoWiFi preferred", regID: 1, preference: 1000, wantPreference: "1.0"},
		{name: "VoLTE fallback", regID: 2, preference: 500, wantPreference: "0.5"},
		{name: "three digit preference", regID: 3, preference: 751, wantPreference: "0.751"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newMultipleRegistrationService(t, tt.regID, tt.preference)
			req := svc.buildRegister(nil, nil)
			if got := req.Header("Contact"); !strings.Contains(got, ";audio;") {
				t.Fatalf("Contact = %q, want audio media feature tag", got)
			}
			_, params := sip.AddressURIAndParams(req.Header("Contact"))
			if got := sip.HeaderParam(params, "reg-id"); got != strconv.FormatUint(uint64(tt.regID), 10) {
				t.Fatalf("Contact reg-id = %q, want %d", got, tt.regID)
			}
			if got := sip.HeaderParam(params, "q"); got != tt.wantPreference {
				t.Fatalf("Contact q = %q, want %q", got, tt.wantPreference)
			}
			if got := normalizeSIPInstance(sip.HeaderParam(params, "+sip.instance")); got != "urn:gsma:imei:12345678-901234-0" {
				t.Fatalf("Contact +sip.instance = %q", got)
			}
			if !req.HeaderHasToken("Supported", "path") || !req.HeaderHasToken("Supported", "outbound") {
				t.Fatalf("Supported = %q, want path and outbound", req.Header("Supported"))
			}

			deregister := svc.buildDeregister(nil, nil)
			if got := deregister.Header("Contact"); got == "*" {
				t.Fatal("deregister Contact = *, want only the current flow")
			}
			if got := deregister.Header("Expires"); got != "0" {
				t.Fatalf("deregister Expires = %q, want 0", got)
			}
			_, deregisterParams := sip.AddressURIAndParams(deregister.Header("Contact"))
			if got := sip.HeaderParam(deregisterParams, "expires"); got != "0" {
				t.Fatalf("deregister Contact expires = %q, want 0", got)
			}
			if got := sip.HeaderParam(deregisterParams, "reg-id"); got != strconv.FormatUint(uint64(tt.regID), 10) {
				t.Fatalf("deregister Contact reg-id = %q, want %d", got, tt.regID)
			}
		})
	}
}

func TestValidateMultipleRegistrationSuccess(t *testing.T) {
	tests := []struct {
		name                  string
		require               string
		contactRegistrationID uint32
		wantErr               error
		wantMultiple          bool
		wantSingle            bool
	}{
		{
			name:                  "outbound and own binding confirmed",
			require:               "outbound",
			contactRegistrationID: 1,
			wantMultiple:          true,
		},
		{
			name:                  "outbound can be on a repeated header",
			require:               "timer|outbound",
			contactRegistrationID: 1,
			wantMultiple:          true,
		},
		{
			name:                  "missing outbound falls back to one flow",
			contactRegistrationID: 1,
			wantSingle:            true,
		},
		{
			name:                  "missing own registration flow",
			require:               "outbound",
			contactRegistrationID: 2,
			wantErr:               errRegisterBindingMissing,
			wantMultiple:          true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newMultipleRegistrationService(t, 1, 1000)
			req := svc.buildRegister(nil, nil)
			contact := req.Header("Contact") + ";expires=600"
			if tt.contactRegistrationID != 1 {
				contact = strings.Replace(contact, "reg-id=1", "reg-id="+strconv.FormatUint(uint64(tt.contactRegistrationID), 10), 1)
			}
			resp := sip.NewResponse(200, "OK")
			for _, value := range strings.Split(tt.require, "|") {
				if value != "" {
					resp.Headers.Add("Require", value)
				}
			}
			resp.Headers.Add("Contact", contact)
			singleRegistration, err := svc.validateRegisterSuccess(resp)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("validateRegisterSuccess() error = %v, want %v", err, tt.wantErr)
				}
			} else if err != nil {
				t.Fatalf("validateRegisterSuccess() error = %v", err)
			}
			if singleRegistration != tt.wantSingle {
				t.Fatalf("single registration = %t, want %t", singleRegistration, tt.wantSingle)
			}
			if !svc.multipleRegistration() {
				t.Fatal("validation changed registration capability")
			}
			if err != nil {
				return
			}

			svc.applyRegisterCapability(singleRegistration)
			if got := svc.multipleRegistration(); got != tt.wantMultiple {
				t.Fatalf("multipleRegistration() = %t, want %t", got, tt.wantMultiple)
			}
			state := svc.State()
			if state.Flow.Outbound != tt.wantMultiple {
				t.Fatalf("Flow.Outbound = %t, want %t", state.Flow.Outbound, tt.wantMultiple)
			}
			if got := strings.HasSuffix(state.RequestContactURI(), ";ob"); got != tt.wantMultiple {
				t.Fatalf("RequestContactURI() = %q, outbound marker = %t, want %t", state.RequestContactURI(), got, tt.wantMultiple)
			}
			request := sip.NewRequest("INVITE", "sip:callee@example.com")
			svc.RequestPolicy().Apply(&request)
			if got := request.HeaderHasToken("Supported", "outbound"); got != tt.wantMultiple {
				t.Fatalf("Supported = %q, outbound = %t, want %t", request.Header("Supported"), got, tt.wantMultiple)
			}

			svc.applyRegisterSuccess(resp)
			if !svc.State().Registered {
				t.Fatal("registration was not accepted after successful response")
			}
			if tt.wantMultiple {
				return
			}

			next := svc.buildRegister(nil, nil)
			if next.HeaderHasToken("Supported", "outbound") {
				t.Fatalf("Supported = %q, want single registration", next.Header("Supported"))
			}
			_, params := sip.AddressURIAndParams(next.Header("Contact"))
			if got := sip.HeaderParam(params, "reg-id"); got != "" {
				t.Fatalf("fallback Contact reg-id = %q, want empty", got)
			}
			if got := sip.HeaderParam(params, "q"); got != "" {
				t.Fatalf("fallback Contact q = %q, want empty", got)
			}
			deregister := svc.buildDeregister(nil, nil)
			if got := deregister.Header("Contact"); got == "*" {
				t.Fatal("fallback deregister Contact = *, want current binding only")
			}
		})
	}
}

func TestPreferredFlowReplacesSingleRegistrationOwnerAfterSuccess(t *testing.T) {
	tests := []struct {
		name               string
		preferredCode      int
		wantErr            bool
		wantOldRegistered  bool
		wantNewRegistered  bool
		wantOwner          uint32
		confirmReplacement bool
	}{
		{
			name:               "successful replacement waits for network deregistration",
			wantOldRegistered:  true,
			wantNewRegistered:  true,
			wantOwner:          1,
			confirmReplacement: true,
		},
		{
			name:              "failed replacement keeps old owner",
			preferredCode:     sipStatusForbidden,
			wantErr:           true,
			wantOldRegistered: true,
			wantOwner:         2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &Group{}
			oldTransport := newTCPTransport(5062, 5060)
			old := newTestService(t, Config{
				IMEI:                   "123456789012345",
				RegistrationGroup:      group,
				RegistrationID:         2,
				RegistrationPreference: 500,
			}, oldTransport, stubCard{})

			oldTransport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				switch countWrites(oldTransport) {
				case 1:
					oldTransport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
				case 2:
					oldTransport.queue(newResponse(req, sipStatusOK, "OK",
						sip.Header{Name: "Authentication-Info", Value: authenticationInfoForRequest(t, req, testNonce)},
						sip.Header{Name: "Contact", Value: req.Header("Contact") + ";expires=600"},
					))
				default:
					t.Fatalf("old flow sent unexpected REGISTER count %d", countWrites(oldTransport))
				}
			}

			if err := old.Register(context.Background()); err != nil {
				t.Fatalf("registering old flow: %v", err)
			}

			preferredTransport := newTCPTransport(5072, 5060)
			preferred := newTestService(t, Config{
				IMEI:                   "123456789012345",
				RegistrationGroup:      group,
				RegistrationID:         1,
				RegistrationPreference: 1000,
			}, preferredTransport, stubCard{})
			preferredTransport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				switch countWrites(preferredTransport) {
				case 1:
					if tt.preferredCode != 0 {
						preferredTransport.queue(newResponse(req, tt.preferredCode, "Replacement Result"))
						return
					}
					preferredTransport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
				case 2:
					preferredTransport.queue(newResponse(req, sipStatusOK, "OK",
						sip.Header{Name: "Authentication-Info", Value: authenticationInfoForRequest(t, req, testNonce)},
						sip.Header{Name: "Contact", Value: req.Header("Contact") + ";expires=600"},
					))
				default:
					t.Fatalf("preferred flow sent unexpected REGISTER count %d", countWrites(preferredTransport))
				}
			}

			err := preferred.Register(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("preferred Register() error = %v, want error %t", err, tt.wantErr)
			}
			if got := old.State().Registered; got != tt.wantOldRegistered {
				t.Fatalf("old owner Registered = %t, want %t", got, tt.wantOldRegistered)
			}
			if got := preferred.State().Registered; got != tt.wantNewRegistered {
				t.Fatalf("preferred flow Registered = %t, want %t", got, tt.wantNewRegistered)
			}
			if got := countWrites(oldTransport); got != 2 {
				t.Fatalf("old flow REGISTER writes = %d, want 2 without Expires: 0", got)
			}

			group.mu.Lock()
			owner := group.singleRegistrationID
			group.mu.Unlock()
			if owner != tt.wantOwner {
				t.Fatalf("single registration owner = %d, want %d", owner, tt.wantOwner)
			}
			expectNoRegistrationEvent(t, old)
			if !tt.confirmReplacement {
				return
			}

			oldTransport.onWrite = nil
			notify := sip.NewRequest("NOTIFY", "sip:user@example.com")
			notify.Headers.Add("Event", regEventPackage)
			notify.Headers.Add("Content-Type", regInfoContentType)
			notify.Body = fmt.Appendf(nil, `<?xml version="1.0"?>
<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
  <registration aor="%s" id="reg-1" state="active">
    <contact id="contact-1" state="terminated" event="unregistered">
      <uri>%s</uri>
    </contact>
  </registration>
</reginfo>`, old.State().PublicIdentity, old.currentRegisterContactURI())
			if handled, err := old.HandleRequest(context.Background(), session.Request{Message: notify, Transport: oldTransport}); err != nil {
				t.Fatalf("handling replacement NOTIFY: %v", err)
			} else if !handled {
				t.Fatal("replacement NOTIFY was not handled")
			}
			if old.State().Registered {
				t.Fatal("old owner remains registered after replacement NOTIFY")
			}
			expectRegistrationEvent(t, old, ErrRegistrationReplaced)
		})
	}
}

func TestSingleRegistrationReplacementFallsBackAfterNotifyTimeout(t *testing.T) {
	tests := []struct {
		name    string
		timeout time.Duration
	}{
		{name: "missing NOTIFY retires the old flow locally", timeout: 20 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &Group{}
			transport := newTCPTransport(5062, 5060)
			old := newConfiguredTestService(t, testServiceConfig{
				registrar: Config{
					IMEI:                   "123456789012345",
					RegistrationGroup:      group,
					RegistrationID:         2,
					RegistrationPreference: 500,
				},
				session:   session.Config{TransactionTimers: session.TransactionTimers{TF: tt.timeout}},
				transport: transport,
				card:      stubCard{},
			})
			old.setRegistered(true)
			group.setSingleRegistrationOwner(2, 500, old.retireSingleRegistration)

			secureOutbound := newTCPTransport(5064, 4060)
			secureOutboundAttachment, err := old.sess.AddTransport(secureOutbound)
			if err != nil {
				t.Fatalf("adding secure outbound transport: %v", err)
			}
			if err := old.commitRegisterSecurity(&registerSecurity{
				outbound:           secureOutbound,
				outboundAttachment: secureOutboundAttachment,
			}); err != nil {
				t.Fatalf("committing secure transport: %v", err)
			}

			secureInbound := newTCPTransport(5063, 4060)
			attachment, err := old.sess.AddTransport(secureInbound)
			if err != nil {
				t.Fatalf("adding secure inbound transport: %v", err)
			}
			old.replaceSecureServerAttachments([]session.Attachment{attachment})

			old.retireSingleRegistration()
			expectNoRegistrationEvent(t, old)
			if !old.State().Registered {
				t.Fatal("old owner retired before replacement timeout")
			}
			if got := closeCount(secureInbound); got != 0 {
				t.Fatalf("secure inbound close count before timeout = %d, want 0", got)
			}
			if got := closeCount(secureOutbound); got != 0 {
				t.Fatalf("secure outbound close count before timeout = %d, want 0", got)
			}

			waitForRegistrationEvent(t, old, ErrRegistrationReplaced)
			if old.State().Registered {
				t.Fatal("old owner remains registered after replacement timeout")
			}
			if old.sess.LocalAddr() != transport.LocalAddr() {
				t.Fatalf("LocalAddr() = %v, want restored transport %v", old.sess.LocalAddr(), transport.LocalAddr())
			}
			waitForCloseCount(t, secureOutbound, 1)
			waitForCloseCount(t, secureInbound, 1)
		})
	}
}

func TestContactMatchesRegisterBinding(t *testing.T) {
	multiple := registerBinding{
		uri:      "sip:subscriber@192.0.2.10:5060;transport=tcp",
		instance: "urn:gsma:imei:12345678-901234-0",
		regID:    1,
	}
	tests := []struct {
		name    string
		value   string
		binding registerBinding
		want    bool
	}{
		{
			name:    "matches instance and registration id",
			value:   `<sip:192.0.2.10:5060;transport=tcp>;reg-id=1;+sip.instance="<urn:gsma:imei:12345678-901234-0>"`,
			binding: multiple,
			want:    true,
		},
		{
			name:    "normalizes legacy unformatted IMEI instance",
			value:   `<sip:192.0.2.10:5060;transport=tcp>;reg-id=1;+sip.instance="<urn:gsma:imei:123456789012345>"`,
			binding: multiple,
			want:    true,
		},
		{
			name:    "accepts omitted transport and instance",
			value:   `<sip:subscriber@192.0.2.10:5060>;reg-id=1`,
			binding: multiple,
			want:    true,
		},
		{
			name:    "matches URI when registrar ignores outbound parameters",
			value:   `<sip:subscriber@192.0.2.10:5060>`,
			binding: multiple,
			want:    true,
		},
		{
			name:    "rejects another registration id on the same endpoint",
			value:   `<sip:subscriber@192.0.2.10:5060>;reg-id=2`,
			binding: multiple,
		},
		{
			name:    "rejects different instance",
			value:   `<sip:subscriber@192.0.2.10:5060;transport=tcp>;reg-id=1;+sip.instance="<urn:gsma:imei:999999999999999>"`,
			binding: multiple,
		},
		{
			name:    "rejects omitted instance on another endpoint",
			value:   `<sip:subscriber@192.0.2.11:5060>;reg-id=1`,
			binding: multiple,
		},
		{
			name:    "single registration matches contact",
			value:   `<sip:subscriber@192.0.2.10:5060>`,
			binding: registerBinding{uri: multiple.uri},
			want:    true,
		},
		{
			name:    "single registration rejects unrelated user",
			value:   `<sip:another-user@192.0.2.10:5060>`,
			binding: registerBinding{uri: multiple.uri},
		},
		{
			name:    "single registration rejects explicit different transport",
			value:   `<sip:subscriber@192.0.2.10:5060;transport=udp>`,
			binding: registerBinding{uri: multiple.uri},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := contactMatchesRegisterBinding(tt.value, tt.binding); got != tt.want {
				t.Fatalf("contactMatchesRegisterBinding() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestRegisterResponseExpiresMatchesRegistrationID(t *testing.T) {
	binding := registerBinding{
		uri:      "sip:192.0.2.10:5060",
		instance: "urn:gsma:imei:12345678-901234-0",
		regID:    1,
	}
	contacts := []string{
		`<sip:192.0.2.10:5060>;reg-id=2;+sip.instance="<urn:gsma:imei:12345678-901234-0>";expires=200`,
		`<sip:192.0.2.10:5060>;reg-id=1;+sip.instance="<urn:gsma:imei:12345678-901234-0>";expires=100`,
	}
	tests := []struct {
		name    string
		binding registerBinding
		want    time.Duration
	}{
		{name: "first flow", binding: binding, want: 100 * time.Second},
		{name: "second flow", binding: registerBinding{uri: binding.uri, instance: binding.instance, regID: 2}, want: 200 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := sip.NewResponse(200, "OK")
			for _, contact := range contacts {
				resp.Headers.Add("Contact", contact)
			}
			got, ok := registerResponseExpires(resp, tt.binding)
			if !ok || got != tt.want {
				t.Fatalf("registerResponseExpires() = %v, %t, want %v, true", got, ok, tt.want)
			}
		})
	}
}

func TestRegInfoContactMatchesRegistrationID(t *testing.T) {
	state := State{IMEI: "123456789012345", registrationID: 1}
	tests := []struct {
		name    string
		contact regInfoContact
		want    bool
	}{
		{
			name: "same instance and registration id",
			contact: regInfoContact{Unknown: []regInfoUnknownParam{
				{Name: "+sip.instance", Value: "urn:gsma:imei:123456789012345"},
				{Name: "reg-id", Value: "1"},
			}},
			want: true,
		},
		{
			name: "same instance but another flow",
			contact: regInfoContact{Unknown: []regInfoUnknownParam{
				{Name: "+sip.instance", Value: "urn:gsma:imei:123456789012345"},
				{Name: "reg-id", Value: "2"},
			}},
		},
		{
			name: "same contact URI but another flow",
			contact: regInfoContact{
				URI: "sip:192.0.2.10:5060",
				Unknown: []regInfoUnknownParam{
					{Name: "reg-id", Value: "2"},
				},
			},
		},
		{
			name: "same instance without registration id",
			contact: regInfoContact{Unknown: []regInfoUnknownParam{
				{Name: "+sip.instance", Value: "urn:gsma:imei:123456789012345"},
			}},
		},
		{
			name:    "same contact URI remains authoritative",
			contact: regInfoContact{URI: "sip:192.0.2.10:5060"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := contactMatchesCurrentBinding(tt.contact, state, "sip:192.0.2.10:5060", "call-id", 1)
			if got != tt.want {
				t.Fatalf("contactMatchesCurrentBinding() = %t, want %t", got, tt.want)
			}
		})
	}
}

func newMultipleRegistrationService(t *testing.T, regID uint32, preference int) *Registrar {
	t.Helper()
	return newTestService(t, Config{
		IMEI:                   "123456789012345",
		RegistrationGroup:      &Group{},
		RegistrationID:         regID,
		RegistrationPreference: preference,
	}, newTCPTransport(5062, 5060), stubCard{})
}
