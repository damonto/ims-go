package voice

import (
	"context"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"net"
	"testing"
	"time"
)

func TestDialSendsPRACKForReliableProvisionalResponse(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 with 100rel is acknowledged"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(secureRegistrationConfig(transport, registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}), sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration New() error = %v", err)
			}

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "REGISTER" {
					return
				}
				if transport.countMethod("REGISTER") == 1 {
					resp := callStatus(msg, 401, "Unauthorized")
					resp.Headers.Add("WWW-Authenticate", `Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=",algorithm=AKAv1-MD5,qop="auth"`)
					resp.Headers.Add("Security-Server", `ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=4062;port-s=4060;prot=esp;spi-c=1111;spi-s=2222`)
					transport.queue(resp)
					return
				}
				resp := callStatus(msg, 200, "OK")
				resp.Headers.Add("Authentication-Info", `nextnonce="AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="`)
				resp.Headers.Add("Service-Route", "<sip:pcscf.example.com;lr>")
				transport.queue(resp)
			}
			if err := reg.Register(context.Background()); err != nil {
				t.Fatalf("Register() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger(), SessionTimer: true,
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
			prackCount := 0
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					transport.queue(reliableCallProgress(msg))
				case "PRACK":
					prackCount++
					transport.queue(callStatus(msg, 200, "OK"))
					if prackCount == 1 {
						progress := sip.NewResponse(180, "Ringing")
						progress.Headers = sip.ResponseHeaders(invite, 180)
						progress.Headers = sip.UpsertHeader(progress.Headers, "To", sip.WithTag(invite.Header("To"), "", "early-tag"))
						progress.Headers.Add("Require", "100rel")
						progress.Headers.Add("RSeq", "8")
						transport.queue(progress)
						return
					}
					if prackCount == 2 {
						transport.queue(callOKWithoutSDP(invite, "early-tag"))
					}
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if call.State() != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", call.State(), CallStateConfirmed)
			}
			pracks := transport.messagesByMethod("PRACK")
			if len(pracks) != 2 {
				t.Fatalf("PRACK count = %d, want 2", len(pracks))
			}
			prack := pracks[0]
			if got := prack.Header("RAck"); got != "7 1 INVITE" {
				t.Fatalf("PRACK RAck = %q, want %q", got, "7 1 INVITE")
			}
			if got := sip.RequestURI(prack); got != "sip:early@192.0.2.10:5060" {
				t.Fatalf("PRACK Request-URI = %q, want early Contact URI", got)
			}
			if got := sip.HeaderTag(prack.Header("To")); got != "early-tag" {
				t.Fatalf("PRACK To tag = %q, want early-tag", got)
			}
			if got := prack.Header("Require"); got != "sec-agree" {
				t.Fatalf("PRACK Require = %q, want sec-agree", got)
			}
			if got := prack.Header("Supported"); !sip.TokenListContains(got, sessionTimerOption) {
				t.Fatalf("PRACK Supported = %q, want timer", got)
			}
			nextPRACK := pracks[1]
			if got := nextPRACK.Header("RAck"); got != "8 1 INVITE" {
				t.Fatalf("second PRACK RAck = %q, want %q", got, "8 1 INVITE")
			}
			if got := sip.RequestURI(nextPRACK); got != "sip:early@192.0.2.10:5060" {
				t.Fatalf("second PRACK Request-URI = %q, want early dialog target", got)
			}
			if got := nextPRACK.Header("Route"); got != "<sip:pcscf.example.com;lr>" {
				t.Fatalf("second PRACK Route = %q, want early dialog route set", got)
			}
			media := call.Media()
			if !media.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) || media.RemotePort != 50000 {
				t.Fatalf("call media = %+v, want early SDP answer media", media)
			}
		})
	}
}

func TestUnknownPRACKDialogGets481(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "unknown early dialog"},
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

			prack := sip.NewRequest("PRACK", "sip:001010123456789@192.0.2.20:5062")
			prack.Headers.Add("Via", "SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bKunknownprack")
			prack.Headers.Add("From", `<sip:caller@example.com>;tag=remote-tag`)
			prack.Headers.Add("To", `<sip:001010123456789@example.com>;tag=missing-local-tag`)
			prack.Headers.Add("Call-ID", "missing-call")
			prack.Headers.Add("CSeq", "2 PRACK")
			prack.Headers.Add("RAck", "1 1 INVITE")

			handled, err := svc.HandleRequest(context.Background(), session.Request{Message: prack, Transport: transport})
			if err != nil {
				t.Fatalf("HandleRequest() error = %v", err)
			}
			if !handled {
				t.Fatal("HandleRequest() handled = false, want true")
			}
			responses := transport.messagesByStatus(sipStatusCallTransactionDoesNotExist, "PRACK")
			if len(responses) != 1 {
				t.Fatalf("481 PRACK count = %d, want 1", len(responses))
			}
		})
	}
}

func TestDialDoesNotOpenUnauthorizedEarlyMedia(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "provisional SDP without P-Early-Media is stored but not rendered"},
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
			opened := make(chan MediaConfig, 2)
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					opened <- cfg
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: cfg.LocalPort}}, nil
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
			prackSeen := make(chan struct{}, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					transport.queue(reliableCallProgress(msg))
				case "PRACK":
					prackSeen <- struct{}{}
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}

			errCh := make(chan error, 1)
			go func() {
				_, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
				errCh <- err
			}()
			select {
			case <-prackSeen:
			case <-time.After(time.Second):
				t.Fatal("PRACK was not sent")
			}
			select {
			case cfg := <-opened:
				t.Fatalf("OpenMedia before authorized early media/final response = %+v", cfg)
			case <-time.After(80 * time.Millisecond):
			}

			transport.queue(callOKWithoutSDP(invite, "early-tag"))
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("Dial() error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("Dial() did not complete after final response")
			}
			select {
			case cfg := <-opened:
				if cfg.RemotePort != 50000 || !cfg.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) {
					t.Fatalf("OpenMedia remote = %v:%d, want 192.0.2.10:50000", cfg.RemoteIP, cfg.RemotePort)
				}
			case <-time.After(time.Second):
				t.Fatal("OpenMedia was not called after final response")
			}
		})
	}
}

func TestDialOpensAuthorizedEarlyMediaBeforeConfirmed(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "183 with P-Early-Media sendrecv opens early media"},
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
			events := make(chan CallEvent, 16)
			opened := make(chan MediaConfig, 2)
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					opened <- cfg
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: cfg.LocalPort}}, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
					progress := reliableCallProgress(msg)
					progress.Headers.Add("P-Early-Media", "sendrecv")
					transport.queue(progress)
				case "PRACK":
					transport.queue(callStatus(msg, 200, "OK"))
					transport.queue(callOKWithoutSDP(invite, "early-tag"))
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if !waitForCallEvent(events, CallStateEarlyMedia, "", time.Second) {
				t.Fatalf("call state = %s, want early media event", call.State())
			}
			if !waitForCallEvent(events, CallStateConfirmed, "", time.Second) {
				t.Fatalf("call state = %s, want confirmed event", call.State())
			}
			if got := call.State(); got != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, CallStateConfirmed)
			}
			select {
			case cfg := <-opened:
				if cfg.RemotePort != 50000 || !cfg.RemoteIP.Equal(net.IPv4(192, 0, 2, 10)) {
					t.Fatalf("OpenMedia remote = %v:%d, want 192.0.2.10:50000", cfg.RemoteIP, cfg.RemotePort)
				}
			default:
				t.Fatal("OpenMedia was not called for authorized early media")
			}
		})
	}
}

func TestDialSendsACKBeforeOpeningFinalMedia(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "final 2xx is acknowledged before local media open"},
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
			ackSeen := make(chan struct{}, 1)
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					select {
					case <-ackSeen:
					default:
						t.Fatal("OpenMedia was called before final INVITE ACK")
					}
					return &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}}, nil
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
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "ACK":
					select {
					case ackSeen <- struct{}{}:
					default:
					}
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if got := call.State(); got != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, CallStateConfirmed)
			}
			if got := transport.countMethod("ACK"); got != 1 {
				t.Fatalf("ACK count = %d, want 1", got)
			}
		})
	}
}

func TestDialRoutesInDialogRequestImmediatelyAfterACK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote bye after ack matches refreshed dialog"},
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

			matchedRemoteBYE := make(chan struct{}, 1)
			var ok200 sip.Message
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					ok200 = callOK(msg)
					transport.queue(ok200)
				case "ACK":
					if _, ok := sess.LookupDialogKey(byeForConfirmedDialog(ok200)); !ok {
						t.Error("remote BYE after ACK did not match refreshed dialog")
						return
					}
					matchedRemoteBYE <- struct{}{}
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			select {
			case <-matchedRemoteBYE:
			default:
				t.Fatal("remote BYE after ACK did not match dialog")
			}
			if got := call.State(); got != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, CallStateConfirmed)
			}
		})
	}
}

func TestDialKeepsEarlyMediaCallAfterRTCPBye(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "early media rtcp bye does not prevent final 2xx ack"},
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
			events := make(chan CallEvent, 16)
			opened := make(chan *voiceMediaTransport, 2)
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}, onPacket: cfg.OnPacket}
					opened <- media
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
			ackSeen := make(chan struct{}, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					invite = msg
					progress := reliableCallProgress(msg)
					progress.Headers.Add("P-Early-Media", "sendrecv")
					transport.queue(progress)
				case "PRACK":
					transport.queue(callStatus(msg, 200, "OK"))
				case "ACK":
					select {
					case ackSeen <- struct{}{}:
					default:
					}
				}
			}

			errCh := make(chan error, 1)
			callCh := make(chan *Call, 1)
			go func() {
				call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
				if err != nil {
					errCh <- err
					return
				}
				callCh <- call
			}()

			earlyMedia := nextCallEvent(t, events, CallStateEarlyMedia, "", time.Second).Call
			var firstMedia *voiceMediaTransport
			select {
			case firstMedia = <-opened:
			case <-time.After(time.Second):
				t.Fatal("early media transport was not opened")
			}
			firstMedia.notify(MediaPacket{RTCP: true, RTCPBye: true})
			if !waitForCallTest(firstMedia.isClosed) {
				t.Fatal("early media transport was not closed after RTCP BYE")
			}
			if got := earlyMedia.State(); got != CallStateEarlyMedia {
				t.Fatalf("call.State() after early RTCP BYE = %q, want %q", got, CallStateEarlyMedia)
			}

			transport.queue(callOKWithoutSDP(invite, "early-tag"))
			var call *Call
			select {
			case err := <-errCh:
				t.Fatalf("Dial() error = %v", err)
			case call = <-callCh:
			case <-time.After(time.Second):
				t.Fatal("Dial() did not complete after final response")
			}
			select {
			case <-ackSeen:
			default:
				t.Fatal("final INVITE ACK was not sent")
			}
			if got := call.State(); got != CallStateConfirmed {
				t.Fatalf("call.State() = %q, want %q", got, CallStateConfirmed)
			}
			select {
			case <-opened:
			case <-time.After(time.Second):
				t.Fatal("final media transport was not reopened")
			}
		})
	}
}

func TestDialContinuesAfterRTCPInactivityWhenPolicyOmitsRTCP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "rtp activity keeps call alive without rtcp"},
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

			rtcpTimeout := 40 * time.Millisecond
			rtpTimeout := 180 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:          Duration(rtpTimeout),
				RTCPInactivityTimeout:         Duration(rtcpTimeout),
				AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{AudioInactivityRTPOnConnected},
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
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
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			time.Sleep(2 * rtcpTimeout)
			media.notify(MediaPacket{})
			if waitForCallEvent(events, CallStateEnded, "rtcp inactivity timeout", rtcpTimeout) {
				t.Fatal("call ended after RTCP inactivity despite RTP activity")
			}
			if got := transport.countMethod("BYE"); got != 0 {
				t.Fatalf("BYE count before hangup = %d, want 0", got)
			}

			time.Sleep(2 * rtcpTimeout)
			if call.State() == CallStateEnded {
				t.Fatalf("call state = %s, want active call before RTP timeout", call.State())
			}
			if got := transport.countMethod("BYE"); got != 0 {
				t.Fatalf("BYE count before hangup = %d, want 0", got)
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
		})
	}
}
