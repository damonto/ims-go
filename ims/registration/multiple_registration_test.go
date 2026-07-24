package registration

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

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
			if got := normalizeSIPInstance(sip.HeaderParam(params, "+sip.instance")); got != "urn:gsma:imei:123456789012345" {
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

func TestPreferredFlowRevokesSingleRegistrationOwner(t *testing.T) {
	tests := []struct {
		name           string
		deregisterCode int
		cleanupFails   bool
		wantErr        bool
		wantRegistered bool
		wantOwner      uint32
		wantEvent      bool
	}{
		{
			name:           "successful deregistration releases owner",
			deregisterCode: sipStatusOK,
			wantEvent:      true,
		},
		{
			name:           "local cleanup error still releases owner",
			deregisterCode: sipStatusOK,
			cleanupFails:   true,
			wantErr:        true,
			wantEvent:      true,
		},
		{
			name:           "rejected deregistration keeps owner",
			deregisterCode: sipStatusForbidden,
			wantErr:        true,
			wantRegistered: true,
			wantOwner:      2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			group := &Group{}
			transport := newTCPTransport(5062, 5060)
			svc := newTestService(t, Config{
				IMEI:                   "123456789012345",
				RegistrationGroup:      group,
				RegistrationID:         2,
				RegistrationPreference: 500,
			}, transport, stubCard{})

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				switch countWrites(transport) {
				case 1:
					transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 0))
				case 2:
					transport.queue(newResponse(req, sipStatusOK, "OK",
						sip.Header{Name: "Authentication-Info", Value: authenticationInfoForRequest(t, req, testNonce)},
						sip.Header{Name: "Contact", Value: req.Header("Contact") + ";expires=600"},
					))
				case 3:
					if got := req.Header("Expires"); got != "0" {
						t.Errorf("deregister Expires = %q, want 0", got)
					}
					transport.queue(newResponse(req, tt.deregisterCode, "Deregister Result"))
				default:
					t.Fatalf("unexpected write count %d", countWrites(transport))
				}
			}

			if err := svc.Register(context.Background()); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			if tt.cleanupFails {
				svc.mu.Lock()
				svc.unprotectedPrimary = newTCPTransport(5099, 5060)
				svc.mu.Unlock()
			}
			release, err := group.beginRegistrationForFlow(context.Background(), 1, 1000)
			if release != nil {
				release()
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("beginRegistrationForFlow() error = %v, want error %t", err, tt.wantErr)
			}
			if got := svc.State().Registered; got != tt.wantRegistered {
				t.Fatalf("old owner Registered = %t, want %t", got, tt.wantRegistered)
			}

			group.mu.Lock()
			owner := group.singleRegistrationID
			group.mu.Unlock()
			if owner != tt.wantOwner {
				t.Fatalf("single registration owner = %d, want %d", owner, tt.wantOwner)
			}
			if tt.wantEvent {
				expectRegistrationEvent(t, svc, errRegistrationReplaced)
			} else {
				expectNoRegistrationEvent(t, svc)
			}
		})
	}
}

func TestContactMatchesRegisterBinding(t *testing.T) {
	multiple := registerBinding{
		uri:      "sip:subscriber@192.0.2.10:5060;transport=tcp",
		instance: "urn:gsma:imei:123456789012345",
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
		instance: "urn:gsma:imei:123456789012345",
		regID:    1,
	}
	contacts := []string{
		`<sip:192.0.2.10:5060>;reg-id=2;+sip.instance="<urn:gsma:imei:123456789012345>";expires=200`,
		`<sip:192.0.2.10:5060>;reg-id=1;+sip.instance="<urn:gsma:imei:123456789012345>";expires=100`,
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
