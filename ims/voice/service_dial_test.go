package voice

import (
	"context"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialHandlesRetransmittedInvite2xx(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "repeated 200 OK sends another ACK and preserves DTMF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{
				TransactionTimers: session.TransactionTimers{T1: 10 * time.Millisecond, T2: 20 * time.Millisecond},
			}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity:   "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:    "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:        "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:              "123456789012345",
				AccessNetworkInfo: "IEEE-802.11;i-wlan-node-id=aabbcc",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
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

			var ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" || ok200.StartLine != "" {
					return
				}
				ok200 = callOK(msg)
				transport.queue(ok200)
			}

			dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
			defer dialCancel()
			call, err := svc.Dial(dialCtx, DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			media := call.Media()
			if media.DTMFPayloadType != 110 || media.DTMFClockRate != 16000 {
				t.Fatalf("Media() DTMF = %d/%d, want 110/16000", media.DTMFPayloadType, media.DTMFClockRate)
			}
			if !waitForCallTest(func() bool { return transport.countMethod("ACK") == 1 }) {
				t.Fatalf("ACK count = %d, want 1", transport.countMethod("ACK"))
			}

			transport.queue(ok200)
			if !waitForCallTest(func() bool { return transport.countMethod("ACK") == 2 }) {
				t.Fatalf("ACK count after retransmitted 2xx = %d, want 2", transport.countMethod("ACK"))
			}
		})
	}
}

func TestDialPreparesMediaBeforeInvite(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "prepare media sees local port before invite is written"},
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
			prepared := false
			svc, err := New(Config{Logger: testLogger(),
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.LocalPort != 40000 {
						t.Fatalf("PrepareMedia LocalPort = %d, want 40000", cfg.LocalPort)
					}
					if len(cfg.RemoteIP) != 0 || cfg.RemotePort != 0 {
						t.Fatalf("PrepareMedia remote = %v:%d, want empty", cfg.RemoteIP, cfg.RemotePort)
					}
					prepared = true
					return nil, nil
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

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				if !prepared {
					t.Fatal("INVITE was written before PrepareMedia")
				}
				if got := msg.Header("P-Early-Media"); got != "supported" {
					t.Fatalf("INVITE P-Early-Media = %q, want supported", got)
				}
				if got := msg.Header("Supported"); strings.Contains(got, "100rel") {
					t.Fatalf("INVITE Supported = %q, want no 100rel option tag by default", got)
				}
				if got := msg.Header("Supported"); !strings.Contains(got, "199") {
					t.Fatalf("INVITE Supported = %q, want 199 option tag", got)
				}
				if got := msg.Header("Session-Expires"); got != "" {
					t.Fatalf("INVITE Session-Expires = %q, want empty initial session interval", got)
				}
				if got := msg.Header("Allow"); !strings.Contains(got, "PRACK") {
					t.Fatalf("INVITE Allow = %q, want PRACK", got)
				}
				if got := msg.Header("P-Preferred-Service"); got != mmtelICSI {
					t.Fatalf("INVITE P-Preferred-Service = %q, want %q", got, mmtelICSI)
				}
				if got := msg.Header("Accept-Contact"); !strings.Contains(got, `+g.3gpp.icsi-ref="`+mmtelICSIEncoded+`"`) {
					t.Fatalf("INVITE Accept-Contact = %q, want MMTEL ICSI", got)
				}
				if got := msg.Header("Contact"); !strings.Contains(got, ";audio;") {
					t.Fatalf("INVITE Contact = %q, want audio media feature tag", got)
				}
				transport.queue(callOK(msg))
			}
			if _, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
		})
	}
}

func TestHangupCancelsOutgoingDialBeforeFinalResponse(t *testing.T) {
	tests := []struct {
		name        string
		finalInvite func(sip.Message) sip.Message
		wantBYE     bool
	}{
		{
			name: "487 after cancel",
			finalInvite: func(invite sip.Message) sip.Message {
				return inviteTerminated(invite)
			},
		},
		{
			name: "2xx races with cancel",
			finalInvite: func(invite sip.Message) sip.Message {
				return callOK(invite)
			},
			wantBYE: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{
				TransactionTimers: session.TransactionTimers{T1: 10 * time.Millisecond, T2: 20 * time.Millisecond},
			}, transport)
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
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(), OnCallEvent: func(event CallEvent) { events <- event }}, sess, reg)
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

			var invite sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					transport.queue(trying(msg))
				case "CANCEL":
					transport.queue(cancelOK(msg))
					transport.queue(tt.finalInvite(invite))
				case "BYE":
					transport.queue(okForRequest(msg))
				}
			}

			dialErr := make(chan error, 1)
			go func() {
				_, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
				dialErr <- err
			}()

			event := nextCallEvent(t, events, CallStateDialing, "", time.Second)
			call := svc.lookupCall(event.CallID)
			if call == nil {
				t.Fatalf("lookupCall(%q) = nil", event.CallID)
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}

			if !waitForCallEvent(events, CallStateEnded, "cancelled", time.Second) {
				t.Fatalf("call state = %s, want ended after cancel", call.State())
			}
			select {
			case err := <-dialErr:
				if err == nil || !strings.Contains(err.Error(), "cancelled") {
					t.Fatalf("Dial() error = %v, want cancelled", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Dial() did not return after cancel")
			}

			cancels := transport.messagesByMethod("CANCEL")
			if len(cancels) != 1 {
				t.Fatalf("CANCEL count = %d, want 1", len(cancels))
			}
			if got := cancels[0].Header("P-Access-Network-Info"); got != "" {
				t.Fatalf("CANCEL P-Access-Network-Info = %q, want empty", got)
			}
			if got := cancels[0].Header("Reason"); got != reasonUserTriggered {
				t.Fatalf("CANCEL Reason = %q, want %q", got, reasonUserTriggered)
			}
			if got, want := sip.CSeqNumber(cancels[0].Header("CSeq")), sip.CSeqNumber(invite.Header("CSeq")); got != want {
				t.Fatalf("CANCEL CSeq number = %d, want %d", got, want)
			}
			if tt.wantBYE {
				if !waitForCallTest(func() bool { return transport.countMethod("BYE") == 1 }) {
					t.Fatalf("BYE count = %d, want 1", transport.countMethod("BYE"))
				}
			}
		})
	}
}

func TestDialRetriesInviteAfterSessionIntervalTooSmall(t *testing.T) {
	tests := []struct {
		name       string
		cfg        Config
		wantFirst  string
		wantSecond string
	}{
		{
			name:       "422 with Min-SE",
			cfg:        Config{Logger: testLogger(), SessionTimer: true},
			wantFirst:  "3600",
			wantSecond: "4000",
		},
		{
			name:       "422 omits configured UAS refresher",
			cfg:        Config{Logger: testLogger(), SessionTimer: true, SessionRefresher: sessionRefresherUAS},
			wantFirst:  "3600",
			wantSecond: "4000",
		},
		{
			name:       "422 preserves configured UAC refresher",
			cfg:        Config{Logger: testLogger(), SessionTimer: true, SessionRefresher: sessionRefresherUAC},
			wantFirst:  "3600;refresher=uac",
			wantSecond: "4000;refresher=uac",
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
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			svc, err := New(tt.cfg, sess, reg)
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				switch invites {
				case 1:
					if got := msg.Header("Session-Expires"); got != "" {
						t.Fatalf("initial Session-Expires = %q, want omitted", got)
					}
					resp := callStatus(msg, 422, "Session Interval Too Small")
					resp.Headers.Add("Min-SE", "3600")
					transport.queue(resp)
				case 2:
					if got := msg.Header("Session-Expires"); got != tt.wantFirst {
						t.Fatalf("retry Session-Expires = %q, want %q", got, tt.wantFirst)
					}
					if got := msg.Header("Min-SE"); got != "3600" {
						t.Fatalf("retry Min-SE = %q, want 3600", got)
					}
					resp := callStatus(msg, 422, "Session Interval Too Small")
					resp.Headers.Add("Min-SE", "4000")
					transport.queue(resp)
				case 3:
					if got := msg.Header("Session-Expires"); got != tt.wantSecond {
						t.Fatalf("second retry Session-Expires = %q, want %q", got, tt.wantSecond)
					}
					if got := msg.Header("Min-SE"); got != "4000" {
						t.Fatalf("second retry Min-SE = %q, want 4000", got)
					}
					transport.queue(callOK(msg))
				default:
					t.Fatalf("INVITE count = %d, want 3", invites)
				}
			}

			if _, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if invites != 3 {
				t.Fatalf("INVITE count = %d, want 3", invites)
			}
		})
	}
}

func TestDialRejectsInvalidMinSEOnSessionIntervalRetry(t *testing.T) {
	tests := []struct {
		name  string
		minSE string
	}{
		{name: "missing Min-SE"},
		{name: "below RFC minimum", minSE: "60"},
		{name: "not seconds", minSE: "invalid"},
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
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				if invites != 1 {
					t.Fatalf("INVITE count = %d, want 1", invites)
				}
				resp := callStatus(msg, 422, "Session Interval Too Small")
				if tt.minSE != "" {
					resp.Headers.Add("Min-SE", tt.minSE)
				}
				transport.queue(resp)
			}

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil {
				t.Fatal("Dial() error = nil, want invalid Min-SE")
			}
			if !strings.Contains(err.Error(), "session timer retry: invalid Min-SE") {
				t.Fatalf("Dial() error = %v, want invalid Min-SE", err)
			}
			if invites != 1 {
				t.Fatalf("INVITE count = %d, want 1", invites)
			}
		})
	}
}

func TestDialRejectsTimerRequiredResponseWithoutSessionExpires(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "Require timer missing Session-Expires"},
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
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
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
				if msg.Method() != "INVITE" {
					return
				}
				resp := callOK(msg)
				resp.Headers.Add("Require", "timer")
				transport.queue(resp)
			}

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil {
				t.Fatal("Dial() error = nil, want missing Session-Expires")
			}
			if !strings.Contains(err.Error(), "Require timer without Session-Expires") {
				t.Fatalf("Dial() error = %v, want missing Session-Expires", err)
			}
		})
	}
}

func TestDialSkipsSessionTimerRetryAfterCancel(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "cancelled call does not retry after 422"},
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
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true}, sess, reg)
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				if invites != 1 {
					t.Fatalf("INVITE count = %d, want no retry after cancel", invites)
				}
				call := svc.lookupCall(msg.Header("Call-ID"))
				if call == nil {
					t.Fatalf("lookupCall(%q) = nil", msg.Header("Call-ID"))
				}
				if err := call.Hangup(context.Background()); err != nil {
					t.Fatalf("Hangup() error = %v", err)
				}
				resp := callStatus(msg, 422, "Session Interval Too Small")
				resp.Headers.Add("Min-SE", "3600")
				transport.queue(resp)
			}

			if _, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"}); err == nil || !strings.Contains(err.Error(), "cancelled") {
				t.Fatalf("Dial() error = %v, want cancelled", err)
			}
			if invites != 1 {
				t.Fatalf("INVITE count = %d, want 1", invites)
			}
		})
	}
}

func TestDialMOCallRequestTimeoutStopsAfterFirstProvisional(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "100 Trying stops first provisional timer"},
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
			svc, err := New(Config{Logger: testLogger(),
				MOCallRequestTimeout: 50 * time.Millisecond,
				OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
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

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				transport.queue(trying(msg))
				go func() {
					time.Sleep(100 * time.Millisecond)
					transport.queue(callOK(msg))
				}()
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if call.State() != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", call.State(), CallStateConfirmed)
			}
		})
	}
}

func TestDialMOCallRequestTimeoutBeforeFirstProvisional(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "no 1xx aborts invite wait"},
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
			svc, err := New(Config{Logger: testLogger(), MOCallRequestTimeout: 40 * time.Millisecond}, sess, reg)
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

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil || !strings.Contains(err.Error(), "first provisional") {
				t.Fatalf("Dial() error = %v, want first provisional timeout", err)
			}
		})
	}
}

func TestDialRingbackTimeoutCancelsInvite(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "180 ringing without final response is cancelled"},
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
				RingbackTimeout: 50 * time.Millisecond,
				OnCallEvent:     func(event CallEvent) { events <- event },
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

			var invite sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					resp := callStatus(msg, 180, "Ringing")
					resp.Headers = sip.UpsertHeader(resp.Headers, "To", sip.WithTag(msg.Header("To"), "", "remote-tag"))
					transport.queue(resp)
				case "CANCEL":
					transport.queue(cancelOK(msg))
					transport.queue(inviteTerminated(invite))
				}
			}

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil || !strings.Contains(err.Error(), "cancelled") {
				t.Fatalf("Dial() error = %v, want cancelled", err)
			}
			if transport.countMethod("CANCEL") != 1 {
				t.Fatalf("CANCEL count = %d, want 1", transport.countMethod("CANCEL"))
			}
			if !waitForCallEvent(events, CallStateEnded, "cancelled", time.Second) {
				t.Fatal("cancelled event was not observed")
			}
		})
	}
}

func TestDialPreconditionSendsUPDATEAfterReliableAnswer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 requires precondition"},
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
				OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
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

			var invite sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					if got := msg.Header("Supported"); !sip.TokenListContains(got, preconditionOption) {
						t.Fatalf("INVITE Supported = %q, want precondition", got)
					}
					if got := msg.Header("Supported"); !sip.TokenListContains(got, reliableProvisionalOption) {
						t.Fatalf("INVITE Supported = %q, want 100rel", got)
					}
					progress := reliableCallProgress(msg)
					progress.Headers.Add("Require", preconditionOption)
					progress.Body = append(progress.Body,
						[]byte("a=curr:qos local none\r\n"+
							"a=curr:qos remote none\r\n"+
							"a=des:qos mandatory local sendrecv\r\n"+
							"a=des:qos optional remote sendrecv\r\n")...)
					transport.queue(progress)
				case "PRACK":
					transport.queue(callStatus(msg, sipStatusOK, "OK"))
				case "UPDATE":
					if got := sip.RequestURI(msg); got != "sip:early@192.0.2.10:5060" {
						t.Fatalf("UPDATE Request-URI = %q, want early dialog target", got)
					}
					if got := sip.HeaderTag(msg.Header("To")); got != "early-tag" {
						t.Fatalf("UPDATE To tag = %q, want early-tag", got)
					}
					if got := msg.Header("Require"); got != preconditionOption {
						t.Fatalf("UPDATE Require = %q, want %q", got, preconditionOption)
					}
					body := string(msg.Body)
					for _, want := range []string{
						"m=audio 40000 RTP/AVP 104 110",
						"a=curr:qos local sendrecv",
						"a=des:qos mandatory local sendrecv",
						"a=des:qos optional remote sendrecv",
					} {
						if !strings.Contains(body, want+"\r\n") {
							t.Fatalf("UPDATE body missing %q:\n%s", want, body)
						}
					}
					if strings.Contains(body, "a=rtpmap:102") {
						t.Fatalf("UPDATE body included unselected codec:\n%s", body)
					}
					transport.queue(callStatus(msg, sipStatusOK, "OK"))
					transport.queue(callOK(invite))
				}
			}

			dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
			defer dialCancel()
			if _, err := svc.Dial(dialCtx, DialRequest{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if got := len(transport.messagesByMethod("PRACK")); got != 1 {
				t.Fatalf("PRACK count = %d, want 1", got)
			}
			if got := len(transport.messagesByMethod("UPDATE")); got != 1 {
				t.Fatalf("UPDATE count = %d, want 1", got)
			}
		})
	}
}

func TestDialDoesNotUseTerminatedEarlyDialogAnswer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "199 removes provisional SDP answer"},
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
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(),
				OnCallEvent: func(event CallEvent) {
					events <- event
				},
				OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 40000}}, nil
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

			var invite sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					transport.queue(reliableCallProgress(msg))
				case "PRACK":
					transport.queue(callStatus(msg, 200, "OK"))
					transport.queue(earlyDialogTerminated(invite, "early-tag"))
					transport.queue(callOKWithoutSDP(invite, "voicemail-tag"))
				}
			}

			_, err = svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err == nil || !strings.Contains(err.Error(), "missing answer sdp") {
				t.Fatalf("Dial() error = %v, want missing answer sdp", err)
			}
			if !waitForCallEvent(events, CallStateDialing, "early dialog terminated", time.Second) {
				t.Fatal("early dialog terminated event was not observed")
			}
		})
	}
}

func TestOutgoingRemoteBYEEndsCall(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "confirmed dialog bye"},
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
			events := make(chan CallEvent, 8)
			svc, err := New(Config{Logger: testLogger(),
				OnCallEvent: func(event CallEvent) {
					events <- event
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

			var ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" || ok200.StartLine != "" {
					return
				}
				ok200 = callOK(msg)
				transport.queue(ok200)
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			transport.queue(byeForConfirmedDialog(ok200))

			if !waitForCallEvent(events, CallStateEnded, "remote bye", time.Second) {
				t.Fatal("remote bye event was not observed")
			}
			if got := call.State(); got != CallStateEnded {
				t.Fatalf("call.State() = %q, want %q", got, CallStateEnded)
			}
		})
	}
}

func TestHangupAcceptsBYETerminationResponses(t *testing.T) {
	tests := []struct {
		name       string
		byeStatus  int
		byeReason  string
		noResponse bool
	}{
		{name: "ok", byeStatus: 200, byeReason: "OK"},
		{name: "accepted", byeStatus: 202, byeReason: "Accepted"},
		{name: "missing dialog", byeStatus: 481, byeReason: "Call/Transaction Does Not Exist"},
		{name: "request timeout", byeStatus: 408, byeReason: "Request Timeout"},
		{name: "no response", noResponse: true},
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
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
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
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					if !tt.noResponse {
						transport.queue(callStatus(msg, tt.byeStatus, tt.byeReason))
					}
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			hangupCtx := context.Background()
			hangupCancel := func() {}
			if tt.noResponse {
				hangupCtx, hangupCancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
			}
			defer hangupCancel()
			if err := call.Hangup(hangupCtx); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
			if got := call.State(); got != CallStateEnded {
				t.Fatalf("call.State() = %s, want %s", got, CallStateEnded)
			}
		})
	}
}

func TestDialReleasesForkedInvite2xx(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "different final dialog is acked then released"},
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
			svc, err := New(Config{Logger: testLogger()}, sess, reg)
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

			var firstOK, forkedOK sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					if firstOK.StartLine != "" {
						return
					}
					firstOK = callOK(msg)
					forkedOK = callOK(msg)
					forkedOK.Headers = sip.UpsertHeader(forkedOK.Headers, "To", sip.WithTag(msg.Header("To"), "", "forked-tag"))
					forkedOK.Headers = sip.UpsertHeader(forkedOK.Headers, "Contact", "<sip:forked@192.0.2.11:5060>")
					transport.queue(firstOK)
				case "BYE":
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}

			if _, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"}); err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			transport.queue(forkedOK)

			if !waitForCallTest(func() bool { return transport.countMethod("ACK") == 2 && transport.countMethod("BYE") == 1 }) {
				t.Fatalf("ACK/BYE count = %d/%d, want 2/1", transport.countMethod("ACK"), transport.countMethod("BYE"))
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("To"); !strings.Contains(got, "forked-tag") {
				t.Fatalf("forked BYE To = %q, want forked tag", got)
			}
			if got := byes[0].Header("Reason"); got != reasonUserTriggered {
				t.Fatalf("forked BYE Reason = %q, want %q", got, reasonUserTriggered)
			}
		})
	}
}

func TestHangupIsIdempotentForTerminalStates(t *testing.T) {
	tests := []struct {
		name  string
		state CallState
	}{
		{name: "ending", state: CallStateEnding},
		{name: "ended", state: CallStateEnded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{state: tt.state}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
		})
	}
}
