package voice

import (
	"context"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestIncomingInviteRingingResponseIncludesContact(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "ringing response carries voice contact"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			defer func() {
				_ = sess.Close()
			}()
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:    "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:        "ims.mnc001.mcc001.3gppnetwork.org",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
			}()

			var ringing sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 180 {
					ringing = msg
				}
			}
			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: delayedInvite(), Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}

			if ringing.StartLine == "" {
				t.Fatal("180 Ringing was not sent")
			}
			if got := ringing.Header("Contact"); !strings.Contains(got, `+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`) {
				t.Fatalf("180 Contact = %q, want MMTEL feature tag", got)
			}
			if got := ringing.Header("Accept"); got != "application/sdp" {
				t.Fatalf("180 Accept = %q, want application/sdp", got)
			}
			if got := ringing.Header("P-Access-Network-Info"); got != "IEEE-802.11;i-wlan-node-id=aabbcc" {
				t.Fatalf("180 P-Access-Network-Info = %q, want access network", got)
			}
		})
	}
}

func TestIncomingInviteRejectsTooSmallSessionInterval(t *testing.T) {
	tests := []struct {
		name    string
		minSE   string
		wantMin string
		callID  string
		cfg     Config
	}{
		{
			name:    "below absolute minimum",
			wantMin: "90",
			callID:  "too-small-se-absolute",
			cfg:     Config{SessionTimer: true},
		},
		{
			name:    "below requested minimum",
			minSE:   "600",
			wantMin: "600",
			callID:  "too-small-se-requested",
			cfg:     Config{SessionTimer: true},
		},
		{
			name:    "below configured minimum",
			wantMin: "300",
			callID:  "too-small-se-configured",
			cfg:     Config{SessionTimer: true, MinSessionExpires: 300 * time.Second},
		},
		{
			name:    "configured minimum below absolute minimum",
			wantMin: "90",
			callID:  "too-small-se-configured-below-absolute",
			cfg:     Config{SessionTimer: true, MinSessionExpires: 30 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			cfg := tt.cfg
			cfg.Logger = testLogger()
			svc, err := New(cfg, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			invite := delayedInvite()
			invite.Headers.Set("Call-ID", tt.callID)
			invite.Headers.Add("Supported", "timer")
			invite.Headers.Add("Session-Expires", "60;refresher=uac")
			if tt.minSE != "" {
				invite.Headers.Add("Min-SE", tt.minSE)
			}

			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: invite, Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}

			responses := transport.messagesByStatus(sipStatusSessionIntervalTooSmall, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("422 count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Min-SE"); got != tt.wantMin {
				t.Fatalf("422 Min-SE = %q, want %q", got, tt.wantMin)
			}
			if call := svc.lookupCall(tt.callID); call != nil {
				t.Fatalf("lookupCall() = %v, want no call stored after 422", call)
			}
		})
	}
}

func TestIncomingInviteRejectsRefresherWithoutTimerSupport(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "refresher without Supported timer is malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			invite := delayedInvite()
			invite.Headers.Set("Call-ID", "bad-session-refresher")
			invite.Headers.Del("Supported")
			invite.Headers.Add("Session-Expires", "180;refresher=uas")

			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: invite, Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}

			responses := transport.messagesByStatus(sipStatusBadRequest, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("400 INVITE count = %d, want 1", len(responses))
			}
			if call := svc.lookupCall("bad-session-refresher"); call != nil {
				t.Fatalf("lookupCall() = %v, want no call stored after 400", call)
			}
		})
	}
}

func TestIncomingInviteRejectsRequiredTimerWhenUnsupported(t *testing.T) {
	transport := newVoiceStubTransport()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	reg, err := registration.New(registration.Config{Logger: testLogger(),
		PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
	}, sess, voiceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	svc, err := New(Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	defer func() {
		_ = svc.Close()
		_ = sess.Close()
	}()

	invite := delayedInvite()
	invite.Headers.Set("Call-ID", "required-timer-unsupported")
	invite.Headers.Add("Require", sessionTimerOption)

	handled, err := svc.HandleRequest(context.Background(), session.Request{Message: invite, Transport: transport})
	if err != nil {
		t.Fatalf("HandleRequest() error = %v", err)
	}
	if !handled {
		t.Fatal("HandleRequest() handled = false, want true")
	}
	responses := transport.messagesByStatus(sipStatusBadExtension, "INVITE")
	if len(responses) != 1 {
		t.Fatalf("420 count = %d, want 1", len(responses))
	}
	if got := responses[0].Header("Unsupported"); got != sessionTimerOption {
		t.Fatalf("Unsupported = %q, want %q", got, sessionTimerOption)
	}
	if got := transport.countMethod("INVITE"); got != 0 {
		t.Fatalf("outbound INVITE count = %d, want 0", got)
	}
	if call := svc.lookupCall("required-timer-unsupported"); call != nil {
		t.Fatalf("lookupCall() = %v, want no call stored after 420", call)
	}
}

func TestIncomingInviteRequiredReliableProvisional(t *testing.T) {
	tests := []struct {
		name            string
		reliableEnabled bool
		wantStatus      int
		wantRequire     string
		wantUnsupported string
		wantStoredCall  bool
	}{
		{
			name:            "unsupported required 100rel rejected",
			wantStatus:      sipStatusBadExtension,
			wantUnsupported: reliableProvisionalOption,
		},
		{
			name:            "required 100rel sends reliable provisional",
			reliableEnabled: true,
			wantStatus:      sipStatusSessionProgress,
			wantRequire:     reliableProvisionalOption,
			wantStoredCall:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), ReliableProvisional: tt.reliableEnabled}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			invite := delayedInvite()
			invite.Headers.Set("Call-ID", "required-100rel-"+tt.name)
			invite.Headers.Del("Supported")
			invite.Headers.Add("Require", reliableProvisionalOption)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: invite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(tt.wantStatus, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("%d count = %d, want 1", tt.wantStatus, len(responses))
			}
			if got := responses[0].Header("Require"); got != tt.wantRequire {
				t.Fatalf("Require = %q, want %q", got, tt.wantRequire)
			}
			if got := responses[0].Header("Unsupported"); got != tt.wantUnsupported {
				t.Fatalf("Unsupported = %q, want %q", got, tt.wantUnsupported)
			}
			if tt.wantRequire != "" && responses[0].Header("RSeq") == "" {
				t.Fatal("RSeq = empty, want reliable provisional sequence")
			}
			call := svc.lookupCall(invite.Header("Call-ID"))
			if (call != nil) != tt.wantStoredCall {
				t.Fatalf("lookupCall() = %v, stored = %t", call, tt.wantStoredCall)
			}
		})
	}
}

func TestIncomingInvitePreconditionResponseRequiresPrecondition(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 answer uses precondition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{
				Logger:        testLogger(),
				Preconditions: true,
				PrepareMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			invite := inviteWithSDP()
			invite.Headers.Set("Call-ID", "incoming-precondition")
			invite.Headers.Add("Supported", reliableProvisionalOption+","+preconditionOption)
			invite.Body = append(invite.Body,
				[]byte("a=curr:qos local none\r\n"+
					"a=curr:qos remote none\r\n"+
					"a=des:qos mandatory local sendrecv\r\n"+
					"a=des:qos optional remote sendrecv\r\n")...)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: invite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			progress := transport.messagesByStatus(sipStatusSessionProgress, "INVITE")
			if len(progress) != 1 {
				t.Fatalf("183 count = %d, want 1", len(progress))
			}
			if got := progress[0].Header("Require"); !sip.TokenListContains(got, reliableProvisionalOption) || !sip.TokenListContains(got, preconditionOption) {
				t.Fatalf("183 Require = %q, want 100rel and precondition", got)
			}
			body := string(progress[0].Body)
			if !strings.Contains(body, "a=conf:qos remote sendrecv\r\n") {
				t.Fatalf("183 SDP body missing resource confirmation request:\n%s", body)
			}
		})
	}
}

func TestIncomingInvitePreconditionFinalOKRequiresPrecondition(t *testing.T) {
	tests := []struct {
		name        string
		invite      func() sip.Message
		wantSDPLine string
	}{
		{
			name: "offer answer in final 200",
			invite: func() sip.Message {
				msg := inviteWithSDP()
				msg.Headers.Set("Call-ID", "incoming-precondition-final-answer")
				msg.Headers.Add("Supported", preconditionOption)
				msg.Body = append(msg.Body,
					[]byte("a=curr:qos local none\r\n"+
						"a=curr:qos remote none\r\n"+
						"a=des:qos mandatory local sendrecv\r\n"+
						"a=des:qos optional remote sendrecv\r\n")...)
				return msg
			},
			wantSDPLine: "a=curr:qos local none\r\n",
		},
		{
			name: "delayed offer in final 200",
			invite: func() sip.Message {
				msg := delayedInvite()
				msg.Headers.Set("Call-ID", "incoming-precondition-final-offer")
				msg.Headers.Add("Supported", preconditionOption)
				return msg
			},
			wantSDPLine: "a=des:qos mandatory local sendrecv\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			svc, err := New(Config{
				Logger:        testLogger(),
				Preconditions: true,
				OnIncomingCall: func(event IncomingCall) {
					incoming <- event
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: tt.invite(), Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			got := <-incoming
			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			responses := transport.messagesByStatus(sipStatusOK, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("200 INVITE count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Require"); !sip.TokenListContains(got, preconditionOption) {
				t.Fatalf("200 INVITE Require = %q, want %q", got, preconditionOption)
			}
			body := string(responses[0].Body)
			if !strings.Contains(body, tt.wantSDPLine) {
				t.Fatalf("200 INVITE SDP body missing %q:\n%s", tt.wantSDPLine, body)
			}
		})
	}
}

func TestIncomingUPDATESessionRefresh(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote refresher updates dialog timer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				service:   svc,
				id:        "update-refresh-call",
				sessionID: "update-refresh-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			update := sip.NewRequest("UPDATE", "sip:001010123456789@192.0.2.20:5062")
			update.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKrefresh")
			update.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
			update.Headers.Add("To", "<sip:001010123456789@example.com>;tag=local-tag")
			update.Headers.Add("Call-ID", "update-refresh-call")
			update.Headers.Add("CSeq", "2 UPDATE")
			update.Headers.Add("Contact", "<sip:caller-refresh@192.0.2.11:5070>")
			update.Headers.Add("Supported", "timer")
			update.Headers.Add("Session-Expires", "600;refresher=uac")
			update.Headers.Add("Min-SE", "600")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: update, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "UPDATE")
			if len(responses) != 1 {
				t.Fatalf("200 UPDATE count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Session-Expires"); got != "600;refresher=uac" {
				t.Fatalf("200 UPDATE Session-Expires = %q, want 600;refresher=uac", got)
			}
			if got := responses[0].Header("Require"); got != "timer" {
				t.Fatalf("200 UPDATE Require = %q, want timer", got)
			}
			call.mu.Lock()
			timer := call.sessionTimer
			targetURI := call.targetURI
			call.mu.Unlock()
			if !timer.active || timer.localRefresher || timer.minSE != 600 {
				t.Fatalf("session timer = %+v, want active remote refresher", timer)
			}
			if targetURI != "sip:caller-refresh@192.0.2.11:5070" {
				t.Fatalf("targetURI = %q, want UPDATE Contact remote target", targetURI)
			}
		})
	}
}

func TestIncomingUPDATESessionRefreshWithOfferAnswersSDP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "normal UPDATE refresh can carry offer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{
				Logger:       testLogger(),
				SessionTimer: true,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					if err := media.ConfigureRemote(ctx, cfg); err != nil {
						return nil, err
					}
					return media, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				service:   svc,
				id:        "update-offer-call",
				sessionID: "update-offer-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			update := sip.NewRequest("UPDATE", "sip:001010123456789@192.0.2.20:5062")
			update.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKupdateoffer")
			update.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
			update.Headers.Add("To", "<sip:001010123456789@example.com>;tag=local-tag")
			update.Headers.Add("Call-ID", "update-offer-call")
			update.Headers.Add("CSeq", "2 UPDATE")
			update.Headers.Add("Supported", "timer")
			update.Headers.Add("Session-Expires", "600;refresher=uac")
			update.Headers.Add("Content-Type", "application/sdp")
			update.Body = inviteWithSDP().Body

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: update, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "UPDATE")
			if len(responses) != 1 {
				t.Fatalf("200 UPDATE count = %d, want 1", len(responses))
			}
			if _, ok := sdpBody(responses[0]); !ok {
				t.Fatalf("200 UPDATE SDP present = false, want true")
			}
			if got := responses[0].Header("Session-Expires"); got != "600;refresher=uac" {
				t.Fatalf("200 UPDATE Session-Expires = %q, want 600;refresher=uac", got)
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 {
				t.Fatalf("media remote port = %d, want offered port 50000", remote.Port)
			}
		})
	}
}

func TestIncomingUPDATEPreconditionAnswerRequiresPrecondition(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "UPDATE offer uses precondition"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), Preconditions: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				service:   svc,
				id:        "update-precondition-call",
				sessionID: "update-precondition-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			update := sip.NewRequest("UPDATE", "sip:001010123456789@192.0.2.20:5062")
			update.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKupdateprecondition")
			update.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
			update.Headers.Add("To", "<sip:001010123456789@example.com>;tag=local-tag")
			update.Headers.Add("Call-ID", "update-precondition-call")
			update.Headers.Add("CSeq", "2 UPDATE")
			update.Headers.Add("Supported", preconditionOption)
			update.Headers.Add("Content-Type", "application/sdp")
			update.Body = append(inviteWithSDP().Body,
				[]byte("a=curr:qos local none\r\n"+
					"a=curr:qos remote none\r\n"+
					"a=des:qos mandatory local sendrecv\r\n"+
					"a=des:qos optional remote sendrecv\r\n")...)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: update, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "UPDATE")
			if len(responses) != 1 {
				t.Fatalf("200 UPDATE count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Require"); got != preconditionOption {
				t.Fatalf("200 UPDATE Require = %q, want %q", got, preconditionOption)
			}
			body := string(responses[0].Body)
			if !strings.Contains(body, "a=conf:qos remote sendrecv\r\n") {
				t.Fatalf("200 UPDATE body missing resource confirmation request:\n%s", body)
			}
		})
	}
}

func TestIncomingReINVITESessionRefresh(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "existing dialog re-invite refreshes session"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				service:   svc,
				id:        "reinvite-refresh-call",
				sessionID: "reinvite-refresh-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			reinvite := inviteWithSDP()
			reinvite.Headers.Set("Call-ID", "reinvite-refresh-call")
			reinvite.Headers.Set("From", "<sip:caller@example.com>;tag=remote-tag")
			reinvite.Headers.Set("To", "<sip:001010123456789@example.com>;tag=local-tag")
			reinvite.Headers.Set("CSeq", "2 INVITE")
			reinvite.Headers.Add("Supported", "timer")
			reinvite.Headers.Add("Session-Expires", "180;refresher=uac")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: reinvite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("200 INVITE count = %d, want 1", len(responses))
			}
			if got := responses[0].Header("Session-Expires"); got != "180;refresher=uac" {
				t.Fatalf("200 re-INVITE Session-Expires = %q, want 180;refresher=uac", got)
			}
			if _, ok := sdpBody(responses[0]); !ok {
				t.Fatalf("200 re-INVITE SDP present = false, want true")
			}
			call.mu.Lock()
			timer := call.sessionTimer
			call.mu.Unlock()
			if !timer.active || timer.localRefresher {
				t.Fatalf("session timer = %+v, want active remote refresher", timer)
			}
		})
	}
}

func TestIncomingReINVITEGlareWhileLocalINVITEPending(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "local re-invite in progress"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				service:            svc,
				id:                 "local-pending-reinvite-call",
				sessionID:          "local-pending-reinvite-session",
				direction:          CallDirectionOutgoing,
				state:              CallStateActive,
				localURI:           "sip:001010123456789@example.com",
				localTag:           "local-tag",
				remoteURI:          "sip:callee@example.com",
				remoteTag:          "remote-tag",
				remoteTo:           "<sip:callee@example.com>;tag=remote-tag",
				targetURI:          "sip:callee@192.0.2.10:5060",
				inviteSeq:          1,
				localPort:          40000,
				localINVITEPending: true,
				rtcpSSRC:           randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			reinvite := inviteWithSDP()
			reinvite.Headers.Set("Call-ID", "local-pending-reinvite-call")
			reinvite.Headers.Set("From", "<sip:callee@example.com>;tag=remote-tag")
			reinvite.Headers.Set("To", "<sip:001010123456789@example.com>;tag=local-tag")
			reinvite.Headers.Set("CSeq", "2 INVITE")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: reinvite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusRequestPending, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("491 re-INVITE count = %d, want 1", len(responses))
			}
		})
	}
}

func TestIncomingRemoteHoldReINVITEUpdatesHoldState(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote recvonly marks remote hold"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 4)
			svc, err := New(Config{
				Logger:      testLogger(),
				OnCallEvent: func(event CallEvent) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				service:   svc,
				id:        "remote-hold-call",
				sessionID: "remote-hold-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			reinvite := inviteWithSDP()
			reinvite.Headers.Set("Call-ID", "remote-hold-call")
			reinvite.Headers.Set("From", "<sip:caller@example.com>;tag=remote-tag")
			reinvite.Headers.Set("To", "<sip:001010123456789@example.com>;tag=local-tag")
			reinvite.Headers.Set("CSeq", "2 INVITE")
			reinvite.Body = append(reinvite.Body, []byte("a=recvonly\r\n")...)

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: reinvite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusOK, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("200 INVITE count = %d, want 1", len(responses))
			}
			if !strings.Contains(string(responses[0].Body), "a=sendonly\r\n") {
				t.Fatalf("remote hold answer missing sendonly:\n%s", string(responses[0].Body))
			}
			if got := call.HoldState(); got != CallHoldRemote {
				t.Fatalf("hold state = %s, want %s", got, CallHoldRemote)
			}
			event := nextCallEvent(t, events, CallStateActive, "remote session modification", time.Second)
			if event.Hold != CallHoldRemote {
				t.Fatalf("event hold = %s, want %s", event.Hold, CallHoldRemote)
			}
		})
	}
}

func TestSecondIncomingReINVITEGetsRetryAfterWhileFirstPending(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "second re-invite receives 500 retry-after"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			openStarted := make(chan struct{})
			releaseOpen := make(chan struct{})
			var openOnce sync.Once
			var releaseOnce sync.Once
			svc, err := New(Config{
				Logger:       testLogger(),
				SessionTimer: true,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					openOnce.Do(func() { close(openStarted) })
					select {
					case <-ctx.Done():
						return nil, ctx.Err()
					case <-releaseOpen:
					}
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}}, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				releaseOnce.Do(func() { close(releaseOpen) })
				_ = svc.Close()
				_ = sess.Close()
			}()

			call := &Call{
				service:   svc,
				id:        "remote-pending-reinvite-call",
				sessionID: "remote-pending-reinvite-session",
				direction: CallDirectionIncoming,
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:caller@example.com",
				remoteTag: "remote-tag",
				remoteTo:  "<sip:caller@example.com>;tag=remote-tag",
				targetURI: "sip:caller@192.0.2.10:5060",
				inviteSeq: 1,
				localPort: 40000,
				rtcpSSRC:  randomRTCPSSRC(),
			}
			if err := svc.storeCall(call); err != nil {
				t.Fatalf("storeCall() error = %v", err)
			}

			first := inviteWithSDP()
			first.Headers.Set("Call-ID", "remote-pending-reinvite-call")
			first.Headers.Set("From", "<sip:caller@example.com>;tag=remote-tag")
			first.Headers.Set("To", "<sip:001010123456789@example.com>;tag=local-tag")
			first.Headers.Set("CSeq", "2 INVITE")

			firstErr := make(chan error, 1)
			go func() {
				_, err := svc.HandleRequest(context.Background(), session.Request{Message: first, Transport: transport})
				firstErr <- err
			}()
			select {
			case <-openStarted:
			case <-time.After(time.Second):
				t.Fatal("OpenMedia was not called for first re-INVITE")
			}

			second := first
			second.Headers = first.Headers.Clone()
			second.Body = append([]byte(nil), first.Body...)
			second.Headers.Set("CSeq", "3 INVITE")
			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: second, Transport: transport})
			if err != nil {
				t.Fatalf("second HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("second HandleRequest() handled = false, want true")
			}

			responses := transport.messagesByStatus(sipStatusServerInternalError, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("500 re-INVITE count = %d, want 1", len(responses))
			}
			retryAfter, err := strconv.Atoi(responses[0].Header("Retry-After"))
			if err != nil || retryAfter < 0 || retryAfter > 10 {
				t.Fatalf("Retry-After = %q, want 0..10 seconds", responses[0].Header("Retry-After"))
			}

			releaseOnce.Do(func() { close(releaseOpen) })
			if err := <-firstErr; err != nil {
				t.Fatalf("first HandleRequest() error = %v", err)
			}
			if got := len(transport.messagesByStatus(sipStatusOK, "INVITE")); got != 1 {
				t.Fatalf("200 re-INVITE count = %d, want 1", got)
			}
		})
	}
}

func TestUnknownReINVITEDialogGets481(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "unknown dialog"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer func() {
				_ = svc.Close()
				_ = sess.Close()
			}()

			reinvite := sip.NewRequest("INVITE", "sip:001010123456789@192.0.2.20:5062")
			reinvite.Headers.Add("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKmissingreinvite")
			reinvite.Headers.Add("From", "<sip:caller@example.com>;tag=remote-tag")
			reinvite.Headers.Add("To", "<sip:001010123456789@example.com>;tag=local-tag")
			reinvite.Headers.Add("Call-ID", "missing-reinvite-call")
			reinvite.Headers.Add("CSeq", "2 INVITE")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: reinvite, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusCallTransactionDoesNotExist, "INVITE")
			if len(responses) != 1 {
				t.Fatalf("481 re-INVITE count = %d, want 1", len(responses))
			}
		})
	}
}

func TestIncomingCancelEndsRingingCall(t *testing.T) {
	tests := []struct {
		name      string
		wantState CallState
		wantCause string
	}{
		{name: "cancel before answer", wantState: CallStateEnded, wantCause: "remote cancel"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration New() error = %v", err)
			}
			events := make(chan CallEvent, 4)
			svc, err := New(Config{Logger: testLogger(),
				OnCallEvent: func(event CallEvent) {
					events <- event
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			invite := delayedInvite()
			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: invite, Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}
			cancel := cancelForInvite(invite)
			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: cancel, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest(CANCEL) error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest(CANCEL) = false, want true")
			}
			call := svc.lookupCall(invite.Header("Call-ID"))
			if call != nil {
				t.Fatalf("lookupCall() = %v, want nil after CANCEL", call)
			}
			if !waitForCallEvent(events, tt.wantState, tt.wantCause, time.Second) {
				t.Fatalf("event %s/%q not observed", tt.wantState, tt.wantCause)
			}
		})
	}
}

func TestIncomingRingingTimeoutRejectsInvite(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "unanswered ringing call receives 486"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(),
				RingingTimeout: 50 * time.Millisecond,
				OnCallEvent:    func(event CallEvent) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			transport.queue(delayedInvite())
			if !waitForCallTest(func() bool { return len(transport.messagesByStatus(486, "INVITE")) == 1 }) {
				t.Fatalf("486 count = %d, want 1", len(transport.messagesByStatus(486, "INVITE")))
			}
			if !waitForCallEvent(events, CallStateEnded, "ringing timeout", time.Second) {
				t.Fatal("ringing timeout event was not observed")
			}
			resp := transport.messagesByStatus(486, "INVITE")[0]
			if got := resp.Header("Server"); got == "" {
				t.Fatal("486 Server header is empty")
			}
		})
	}
}

func TestIncomingReliableDelayedOfferUsesPRACKAnswer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 carries offer and PRACK answer opens media"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			progressCh := make(chan sip.Message, 1)
			ringingCh := make(chan sip.Message, 1)
			prackOKCh := make(chan sip.Message, 2)
			inviteOKCh := make(chan sip.Message, 1)
			transport.onWrite = func(msg sip.Message) {
				switch {
				case msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					progressCh <- msg
				case msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					ringingCh <- msg
				case msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "PRACK":
					prackOKCh <- msg
				case msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					inviteOKCh <- msg
				}
			}

			invite := reliableDelayedInvite()
			transport.queue(invite)
			var got IncomingCall
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			var progress sip.Message
			select {
			case progress = <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress timed out")
			}
			if got := progress.Header("Require"); got != "100rel" {
				t.Fatalf("183 Require = %q, want 100rel", got)
			}
			progressRSeq, err := strconv.ParseInt(progress.Header("RSeq"), 10, 64)
			if err != nil || progressRSeq < 1 || progressRSeq > rseqInitialMax {
				t.Fatalf("183 RSeq = %q, want 1..%d", progress.Header("RSeq"), rseqInitialMax)
			}
			if got := progress.Header("Server"); got == "" {
				t.Fatal("183 Server header is empty")
			}
			if body, ok := sdpBody(progress); !ok || !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("183 SDP present = %v body=%q, want audio offer", ok, string(body))
			}
			if len(transport.messagesByStatus(180, "INVITE")) != 0 {
				t.Fatal("180 Ringing was sent before PRACK")
			}

			goodPRACK := prackForReliableProvisional(invite, progress)
			transport.queue(goodPRACK)
			select {
			case <-prackOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for PRACK timed out")
			}
			var ringing sip.Message
			select {
			case ringing = <-ringingCh:
			case <-time.After(time.Second):
				t.Fatal("180 Ringing after PRACK timed out")
			}
			if got := ringing.Header("Require"); got != "100rel" {
				t.Fatalf("180 Require = %q, want 100rel", got)
			}
			ringingRSeq, err := strconv.ParseInt(ringing.Header("RSeq"), 10, 64)
			if err != nil || ringingRSeq != progressRSeq+1 {
				t.Fatalf("180 RSeq = %q, want %d", ringing.Header("RSeq"), progressRSeq+1)
			}
			ringingPRACK := prackWithoutSDPForReliableProvisional(invite, ringing)
			ringingPRACK.Headers.Set("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKprack2")
			ringingPRACK.Headers.Set("CSeq", "3 PRACK")
			transport.queue(ringingPRACK)
			select {
			case <-prackOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for 180 PRACK timed out")
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("media remote = %v, want 192.0.2.10:50000", remote)
			}

			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			var inviteOK sip.Message
			select {
			case inviteOK = <-inviteOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for INVITE timed out")
			}
			if len(inviteOK.Body) != 0 {
				t.Fatalf("200 OK INVITE body len = %d, want no SDP after PRACK answer", len(inviteOK.Body))
			}
			transport.queue(ackWithoutSDP(invite, inviteOK))
			if !waitForCallEvent(events, CallStateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK", got.Call.State())
			}
		})
	}
}

func TestIncomingReliableDelayedOfferRejectsMismatchedPRACK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "wrong RAck does not complete reliable provisional"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			progressCh := make(chan sip.Message, 1)
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					progressCh <- msg
				}
			}

			invite := reliableDelayedInvite()
			transport.queue(invite)
			var progress sip.Message
			select {
			case progress = <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress timed out")
			}
			badPRACK := prackForReliableProvisional(invite, progress)
			badPRACK.Headers.Set("RAck", "99 1 INVITE")
			transport.queue(badPRACK)

			if !waitForCallTest(func() bool { return len(transport.messagesByStatus(481, "PRACK")) == 1 }) {
				t.Fatalf("481 PRACK count = %d, want 1", len(transport.messagesByStatus(481, "PRACK")))
			}
			if len(transport.messagesByStatus(180, "INVITE")) != 0 {
				t.Fatal("180 Ringing was sent after mismatched PRACK")
			}
			if media.RemoteAddr() != nil {
				t.Fatalf("media remote = %v, want nil after rejected PRACK", media.RemoteAddr())
			}

			goodPRACK := prackForReliableProvisional(invite, progress)
			goodPRACK.Headers.Set("Via", "SIP/2.0/TCP 192.0.2.10:5060;branch=z9hG4bKprack2")
			goodPRACK.Headers.Set("CSeq", "3 PRACK")
			transport.queue(goodPRACK)
			if !waitForCallTest(func() bool { return len(transport.messagesByStatus(200, "PRACK")) == 1 }) {
				t.Fatalf("200 PRACK count = %d, 400=%d 481=%d, want 1", len(transport.messagesByStatus(200, "PRACK")), len(transport.messagesByStatus(400, "PRACK")), len(transport.messagesByStatus(481, "PRACK")))
			}
			if !waitForCallTest(func() bool { return len(transport.messagesByStatus(180, "INVITE")) == 1 }) {
				t.Fatalf("180 count = %d, want 1 after matching PRACK", len(transport.messagesByStatus(180, "INVITE")))
			}
		})
	}
}

func TestIncomingReliablePRACKOfferGetsAnswer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "PRACK offer is answered in 200 OK"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			prepared := make(chan MediaConfig, 1)
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					prepared <- cfg
					return nil, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			invite := inviteWithSDP()
			invite.Headers.Add("Supported", "100rel")
			invite.Headers.Add("Allow", sip.DefaultClientAllow)
			transport.queue(invite)
			var call *Call
			select {
			case event := <-incoming:
				call = event.Call
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			var progress sip.Message
			if !waitForCallTest(func() bool {
				messages := transport.messagesByStatus(sipStatusSessionProgress, "INVITE")
				if len(messages) == 0 {
					return false
				}
				progress = messages[0]
				return true
			}) {
				t.Fatal("183 Session Progress was not sent")
			}

			prack := prackForReliableProvisional(invite, progress)
			prack.Body = []byte("v=0\r\n" +
				"o=- 3 1 IN IP4 192.0.2.10\r\n" +
				"s=-\r\n" +
				"c=IN IP4 192.0.2.10\r\n" +
				"t=0 0\r\n" +
				"m=audio 51002 RTP/AVP 104 110\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				"a=rtpmap:110 telephone-event/16000\r\n" +
				"a=ptime:20\r\n")
			transport.queue(prack)

			var ok sip.Message
			if !waitForCallTest(func() bool {
				messages := transport.messagesByStatus(sipStatusOK, "PRACK")
				if len(messages) == 0 {
					return false
				}
				ok = messages[0]
				return true
			}) {
				t.Fatal("200 OK for PRACK was not sent")
			}
			if got := ok.Header("Content-Type"); got != "application/sdp" {
				t.Fatalf("200 PRACK Content-Type = %q, want application/sdp", got)
			}
			if !strings.Contains(string(ok.Body), "m=audio ") {
				t.Fatalf("200 PRACK body = %q, want SDP answer", string(ok.Body))
			}
			select {
			case cfg := <-prepared:
				if cfg.Media.RemotePort != 51002 || !cfg.Media.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) {
					t.Fatalf("prepared media remote = %v:%d, want 192.0.2.10:51002", cfg.Media.RemoteIP, cfg.Media.RemotePort)
				}
			case <-time.After(time.Second):
				t.Fatal("PrepareMedia was not called after PRACK")
			}
			if media := call.Media(); media.RemotePort != 51002 || !media.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("call media remote = %v:%d, want 192.0.2.10:51002", media.RemoteIP, media.RemotePort)
			}
		})
	}
}

func TestIncomingDelayedOfferPRACKConfirmationSendsPreconditionUPDATE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "PRACK answer requests terminating resource confirmation"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			updateCh := make(chan sip.Message, 1)
			svc, err := New(Config{
				Logger:        testLogger(),
				Preconditions: true,
				PrepareMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() == "UPDATE" {
					updateCh <- msg
					transport.queue(callStatus(msg, sipStatusOK, "OK"))
				}
			}

			invite := delayedInvite()
			invite.Headers.Add("Supported", reliableProvisionalOption+","+preconditionOption)
			invite.Headers.Add("Allow", sip.DefaultClientAllow)
			transport.queue(invite)
			select {
			case <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			var progress sip.Message
			if !waitForCallTest(func() bool {
				messages := transport.messagesByStatus(sipStatusSessionProgress, "INVITE")
				if len(messages) == 0 {
					return false
				}
				progress = messages[0]
				return true
			}) {
				t.Fatal("183 Session Progress was not sent")
			}
			if got := progress.Header("Require"); !sip.TokenListContains(got, reliableProvisionalOption) || !sip.TokenListContains(got, preconditionOption) {
				t.Fatalf("183 Require = %q, want 100rel and precondition", got)
			}

			prack := prackForReliableProvisional(invite, progress)
			prack.Headers.Add("Require", preconditionOption)
			prack.Body = append(prack.Body,
				[]byte("a=curr:qos local none\r\n"+
					"a=curr:qos remote none\r\n"+
					"a=des:qos mandatory local sendrecv\r\n"+
					"a=des:qos optional remote sendrecv\r\n"+
					"a=conf:qos remote sendrecv\r\n")...)
			transport.queue(prack)

			if !waitForCallTest(func() bool {
				return len(transport.messagesByStatus(sipStatusOK, "PRACK")) == 1
			}) {
				t.Fatalf("200 PRACK count = %d, want 1", len(transport.messagesByStatus(sipStatusOK, "PRACK")))
			}
			var update sip.Message
			select {
			case update = <-updateCh:
			case <-time.After(time.Second):
				t.Fatal("precondition UPDATE was not sent")
			}
			if got := update.Header("Require"); got != preconditionOption {
				t.Fatalf("UPDATE Require = %q, want %q", got, preconditionOption)
			}
			body := string(update.Body)
			for _, want := range []string{
				"a=curr:qos local sendrecv",
				"a=des:qos mandatory local sendrecv",
				"a=des:qos optional remote sendrecv",
			} {
				if !strings.Contains(body, want+"\r\n") {
					t.Fatalf("UPDATE body missing %q:\n%s", want, body)
				}
			}
		})
	}
}

func TestIncomingReliableInviteAnswerUnblocksWhenCallEndsBeforePRACK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote cancel closes PRACK wait"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			progressCh := make(chan sip.Message, 1)
			events := make(chan CallEvent, 4)
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					progressCh <- msg
				}
			}
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{}, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			invite := inviteWithSDP()
			invite.Headers.Add("Supported", "100rel")
			invite.Headers.Add("Allow", sip.DefaultClientAllow)
			if err := svc.handleIncomingInvite(context.Background(), session.Request{Message: invite, Transport: transport}); err != nil {
				t.Fatalf("handleIncomingInvite() error = %v", err)
			}
			var got IncomingCall
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			select {
			case <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress timed out")
			}

			answerErr := make(chan error, 1)
			go func() {
				answerErr <- got.Call.Answer(context.Background(), MediaOffer{})
			}()
			select {
			case err := <-answerErr:
				t.Fatalf("Answer() completed before call ended: %v", err)
			case <-time.After(80 * time.Millisecond):
			}

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: cancelForInvite(invite), Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest(CANCEL) error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest(CANCEL) = false, want true")
			}
			select {
			case err := <-answerErr:
				if err == nil {
					t.Fatal("Answer() error = nil, want closed call error")
				}
				if strings.Contains(err.Error(), "context") {
					t.Fatalf("Answer() error = %v, want immediate closed call error", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Answer() did not return after call ended")
			}
			if got := got.Call.State(); got != CallStateEnded {
				t.Fatalf("call.State() = %s, want %s", got, CallStateEnded)
			}
			if !waitForCallEvent(events, CallStateEnded, "remote cancel", time.Second) {
				t.Fatal("remote cancel event was not observed")
			}
		})
	}
}

func TestIncomingInvitePreparesMediaBeforeRinging(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "180 waits for prepared local media resource"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			prepareStarted := make(chan struct{}, 1)
			releasePrepare := make(chan struct{})
			incoming := make(chan IncomingCall, 1)
			svc, err := New(Config{Logger: testLogger(),
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					prepareStarted <- struct{}{}
					select {
					case <-releasePrepare:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}}, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			progressCh := make(chan sip.Message, 1)
			ringingCh := make(chan sip.Message, 1)
			transport.onWrite = func(msg sip.Message) {
				switch {
				case msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					progressCh <- msg
				case msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					ringingCh <- msg
				}
			}
			transport.queue(inviteWithSDP())
			var progress sip.Message
			select {
			case progress = <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress was not sent while media was unavailable")
			}
			if got := progress.Header("Require"); got != "" {
				t.Fatalf("183 Require = %q, want empty without 100rel", got)
			}
			if body, ok := sdpBody(progress); !ok || !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("183 SDP present = %v body=%q, want audio answer", ok, string(body))
			}
			select {
			case <-prepareStarted:
			case <-time.After(time.Second):
				t.Fatal("PrepareMedia was not called")
			}
			select {
			case ringing := <-ringingCh:
				t.Fatalf("180 Ringing was sent before media prepared: %s", ringing.StartLine)
			case <-time.After(80 * time.Millisecond):
			}
			close(releasePrepare)
			select {
			case <-ringingCh:
			case <-time.After(time.Second):
				t.Fatal("180 Ringing was not sent after media prepared")
			}
			select {
			case got := <-incoming:
				if got.Call == nil {
					t.Fatal("incoming call is nil")
				}
			case <-time.After(time.Second):
				t.Fatal("incoming callback was not called")
			}
		})
	}
}

func TestIncomingReliableInviteAnswerWaitsForPRACKBeforeRinging(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 answer is reliable and 180 waits for PRACK plus media resource"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			prepareStarted := make(chan struct{}, 1)
			releasePrepare := make(chan struct{})
			incoming := make(chan IncomingCall, 1)
			events := make(chan CallEvent, 8)
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					prepareStarted <- struct{}{}
					select {
					case <-releasePrepare:
					case <-ctx.Done():
						return nil, ctx.Err()
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			progressCh := make(chan sip.Message, 1)
			ringingCh := make(chan sip.Message, 1)
			prackOKCh := make(chan sip.Message, 1)
			inviteOKCh := make(chan sip.Message, 1)
			transport.onWrite = func(msg sip.Message) {
				switch {
				case msg.StatusCode() == 183 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					progressCh <- msg
				case msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					ringingCh <- msg
				case msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "PRACK":
					prackOKCh <- msg
				case msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE":
					inviteOKCh <- msg
				}
			}

			invite := inviteWithSDP()
			invite.Headers.Add("Supported", "100rel")
			invite.Headers.Add("Allow", sip.DefaultClientAllow)
			transport.queue(invite)

			var got IncomingCall
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			var progress sip.Message
			select {
			case progress = <-progressCh:
			case <-time.After(time.Second):
				t.Fatal("183 Session Progress timed out")
			}
			if got := progress.Header("Require"); got != "100rel" {
				t.Fatalf("183 Require = %q, want 100rel", got)
			}
			progressRSeq, err := strconv.ParseInt(progress.Header("RSeq"), 10, 64)
			if err != nil || progressRSeq < 1 || progressRSeq > rseqInitialMax {
				t.Fatalf("183 RSeq = %q, want 1..%d", progress.Header("RSeq"), rseqInitialMax)
			}
			if got := progress.Header("P-Early-Media"); got != "" {
				t.Fatalf("183 P-Early-Media = %q, want empty for terminating UE", got)
			}
			if body, ok := sdpBody(progress); !ok || !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("183 SDP present = %v body=%q, want audio answer", ok, string(body))
			}
			select {
			case <-prepareStarted:
				t.Fatal("PrepareMedia was called before PRACK")
			case <-time.After(80 * time.Millisecond):
			}
			select {
			case ringing := <-ringingCh:
				t.Fatalf("180 Ringing was sent before PRACK: %s", ringing.StartLine)
			case <-time.After(80 * time.Millisecond):
			}

			answerErr := make(chan error, 1)
			go func() {
				answerErr <- got.Call.Answer(context.Background(), MediaOffer{})
			}()
			select {
			case err := <-answerErr:
				t.Fatalf("Answer() completed before PRACK: %v", err)
			case <-time.After(80 * time.Millisecond):
			}

			transport.queue(prackWithoutSDPForReliableProvisional(invite, progress))
			select {
			case <-prackOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for PRACK timed out")
			}
			select {
			case <-prepareStarted:
			case <-time.After(time.Second):
				t.Fatal("PrepareMedia was not called after PRACK")
			}
			select {
			case ringing := <-ringingCh:
				t.Fatalf("180 Ringing was sent before media prepared: %s", ringing.StartLine)
			case <-time.After(80 * time.Millisecond):
			}
			close(releasePrepare)
			var ringing sip.Message
			select {
			case ringing = <-ringingCh:
			case <-time.After(time.Second):
				t.Fatal("180 Ringing was not sent after PRACK and media preparation")
			}
			ringingRSeq, err := strconv.ParseInt(ringing.Header("RSeq"), 10, 64)
			if err != nil || ringingRSeq != progressRSeq+1 {
				t.Fatalf("180 RSeq = %q, want %d", ringing.Header("RSeq"), progressRSeq+1)
			}

			if err := <-answerErr; err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			var inviteOK sip.Message
			select {
			case inviteOK = <-inviteOKCh:
			case <-time.After(time.Second):
				t.Fatal("200 OK for INVITE timed out")
			}
			if len(inviteOK.Body) != 0 {
				t.Fatalf("200 OK INVITE body len = %d, want no duplicate SDP answer", len(inviteOK.Body))
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("media remote = %v, want 192.0.2.10:50000", remote)
			}
			transport.queue(ackWithoutSDP(invite, inviteOK))
			if !waitForCallEvent(events, CallStateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK", got.Call.State())
			}
		})
	}
}

func TestIncomingDelayedOfferCall(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "invite without sdp is answered with offer and ack answer activates call"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			incoming := make(chan IncomingCall, 1)
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.RemotePort != 0 || len(cfg.RemoteIP) != 0 {
						t.Fatalf("PrepareMedia remote = %v:%d, want empty", cfg.RemoteIP, cfg.RemotePort)
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			invite := delayedInvite()
			var ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					ok200 = msg
				}
			}
			transport.queue(invite)

			var got IncomingCall
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			if len(got.Offer.Codecs) != 0 {
				t.Fatalf("incoming offer codecs = %v, want empty delayed offer", got.Offer.Codecs)
			}
			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			if !waitForCallTest(func() bool { return ok200.StartLine != "" }) {
				t.Fatal("200 OK with SDP offer was not sent")
			}
			if len(ok200.Body) == 0 || !strings.Contains(ok200.Header("Content-Type"), "application/sdp") {
				t.Fatalf("200 OK SDP = content-type %q body len %d, want application/sdp body", ok200.Header("Content-Type"), len(ok200.Body))
			}

			transport.queue(delayedOfferACK(invite, ok200))
			if !waitForCallEvent(events, CallStateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK SDP answer", got.Call.State())
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("media remote = %v, want 192.0.2.10:50000", remote)
			}
		})
	}
}

func TestIncomingInviteAnswerOmitsGeolocationPIDF(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "200 OK carries SDP only under invite/register PIDF config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@one.att.net",
				PublicIdentity:    "sip:001010123456789@one.att.net",
				HomeDomain:        "one.att.net",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
				IMEI:              "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			incoming := make(chan IncomingCall, 1)
			svc, err := New(Config{Logger: testLogger(),
				GeolocationPIDFInvite: []int{GeolocationPIDFNonEmergencyWiFi},
				GeolocationCountry:    "US",
				OnIncomingCall:        func(event IncomingCall) { incoming <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			var ringing, ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					ringing = msg
				}
				if msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					ok200 = msg
				}
			}
			transport.queue(delayedInvite())

			var got IncomingCall
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			if !waitForCallTest(func() bool { return ok200.StartLine != "" }) {
				t.Fatal("200 OK was not sent")
			}
			if ringing.StartLine == "" {
				t.Fatal("180 Ringing was not sent")
			}
			if got, want := sip.HeaderTag(ok200.Header("To")), sip.HeaderTag(ringing.Header("To")); got != want {
				t.Fatalf("200 OK To tag = %q, want same tag as 180 Ringing %q", got, want)
			}
			if got := ok200.Header("Allow"); got != sip.DefaultClientAllow {
				t.Fatalf("200 OK Allow = %q, want %q", got, sip.DefaultClientAllow)
			}
			if got := ok200.Header("Accept"); got != "application/sdp" {
				t.Fatalf("200 OK Accept = %q, want application/sdp", got)
			}
			if got := ok200.Header("Geolocation"); got != "" {
				t.Fatalf("200 OK Geolocation = %q, want empty", got)
			}
			if got := ok200.Header("Geolocation-Routing"); got != "" {
				t.Fatalf("200 OK Geolocation-Routing = %q, want empty", got)
			}
			body, ok := sdpBody(ok200)
			if !ok {
				t.Fatal("sdpBody() ok = false, want SDP part")
			}
			if !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("SDP body = %q, want audio media", string(body))
			}
			if got := ok200.Header("Content-Type"); got != "application/sdp" {
				t.Fatalf("200 OK Content-Type = %q, want application/sdp", got)
			}
			if strings.Contains(string(ok200.Body), "application/pidf+xml") {
				t.Fatalf("200 OK body contains PIDF, want SDP only:\n%s", string(ok200.Body))
			}
		})
	}
}

func TestIncomingDelayedOfferAnswersInFinalOK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "final 200 carries delayed-offer SDP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}

			incoming := make(chan IncomingCall, 1)
			events := make(chan CallEvent, 8)
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
				OnCallEvent:    func(event CallEvent) { events <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			invite := reliableDelayedInvite()
			var ringing, inviteOK sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.StatusCode() == 180 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					ringing = msg
				}
				if msg.StatusCode() == 200 && sip.CSeqMethod(msg.Header("CSeq")) == "INVITE" {
					inviteOK = msg
				}
			}
			transport.queue(invite)

			var got IncomingCall
			select {
			case got = <-incoming:
			case <-time.After(time.Second):
				t.Fatal("incoming call event timed out")
			}
			if !waitForCallTest(func() bool { return ringing.StartLine != "" }) {
				t.Fatal("180 Ringing was not sent")
			}
			if err := got.Call.Answer(context.Background(), MediaOffer{}); err != nil {
				t.Fatalf("Answer() error = %v", err)
			}
			if !waitForCallTest(func() bool { return inviteOK.StartLine != "" }) {
				t.Fatal("200 OK for INVITE was not sent")
			}
			if body, ok := sdpBody(inviteOK); !ok || !strings.Contains(string(body), "m=audio ") {
				t.Fatalf("200 OK INVITE SDP present = %v body=%q, want audio offer", ok, string(body))
			}
			if got := inviteOK.Header("Session-Expires"); got != "" {
				t.Fatalf("200 OK INVITE Session-Expires = %q, want empty", got)
			}

			transport.queue(delayedOfferACK(invite, inviteOK))
			if !waitForCallEvent(events, CallStateActive, "", time.Second) {
				t.Fatalf("call state = %s, want active after ACK", got.Call.State())
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 50000 || !remote.IP.Equal(net.IPv4(192, 0, 2, 10)) {
				t.Fatalf("media remote = %v, want 192.0.2.10:50000", remote)
			}
		})
	}
}
