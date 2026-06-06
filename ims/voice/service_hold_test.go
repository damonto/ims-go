package voice

import (
	"bytes"
	"context"
	"errors"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"net"
	"strings"
	"testing"
)

func TestCallHoldAndResumeSendReINVITEs(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "local hold and resume modify dialog media"},
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
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
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

			transport.onWrite = func(msg sip.Message) {
				if msg.Method() == "INVITE" {
					transport.queue(callOK(msg))
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if err := call.Hold(context.Background()); err != nil {
				t.Fatalf("Hold() error = %v", err)
			}
			if got := call.HoldState(); got != CallHoldLocal {
				t.Fatalf("hold state after Hold = %s, want %s", got, CallHoldLocal)
			}
			if err := call.Resume(context.Background()); err != nil {
				t.Fatalf("Resume() error = %v", err)
			}
			if got := call.HoldState(); got != CallHoldNone {
				t.Fatalf("hold state after Resume = %s, want %s", got, CallHoldNone)
			}

			invites := transport.messagesByMethod("INVITE")
			if len(invites) != 3 {
				t.Fatalf("INVITE count = %d, want initial plus hold plus resume", len(invites))
			}
			if !strings.Contains(string(invites[1].Body), "a=sendonly\r\n") {
				t.Fatalf("hold re-INVITE body missing sendonly:\n%s", string(invites[1].Body))
			}
			if !strings.Contains(string(invites[2].Body), "a=sendrecv\r\n") {
				t.Fatalf("resume re-INVITE body missing sendrecv:\n%s", string(invites[2].Body))
			}
			if got := transport.countMethod("ACK"); got != 3 {
				t.Fatalf("ACK count = %d, want initial plus hold plus resume", got)
			}
		})
	}
}

func TestCallHoldRejectsPendingAndEmergency(t *testing.T) {
	tests := []struct {
		name      string
		call      func() *Call
		cfg       Config
		wantError string
	}{
		{
			name:      "local re-invite pending",
			call:      func() *Call { return &Call{state: CallStateActive, localINVITEPending: true} },
			wantError: "local re-INVITE is already pending",
		},
		{
			name:      "emergency default rejects hold",
			call:      func() *Call { return &Call{state: CallStateActive, emergency: true} },
			wantError: "emergency hold is disabled",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{cfg: tt.cfg}
			call := tt.call()
			call.service = svc
			err := call.Hold(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("Hold() error = %v, want containing %q", err, tt.wantError)
			}
		})
	}
}

func TestCallHoldResumeAlreadyAppliedAreIdempotent(t *testing.T) {
	tests := []struct {
		name string
		call func() *Call
		run  func(*Call) error
	}{
		{
			name: "hold already local held",
			call: func() *Call { return &Call{state: CallStateActive, hold: CallHoldLocal} },
			run:  func(call *Call) error { return call.Hold(context.Background()) },
		},
		{
			name: "resume already locally resumed",
			call: func() *Call { return &Call{state: CallStateActive} },
			run:  func(call *Call) error { return call.Resume(context.Background()) },
		},
		{
			name: "resume keeps remote hold",
			call: func() *Call { return &Call{state: CallStateActive, hold: CallHoldRemote} },
			run:  func(call *Call) error { return call.Resume(context.Background()) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := tt.call()
			call.service = &Service{}
			before := call.HoldState()
			if err := tt.run(call); err != nil {
				t.Fatalf("hold operation error = %v", err)
			}
			if got := call.HoldState(); got != before {
				t.Fatalf("hold state = %s, want %s", got, before)
			}
		})
	}
}

func TestCallHoldAllowsEmergencyOverride(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "carrier override allows emergency hold request"},
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
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			cfg, err := (Config{AllowHoldDuringEmergency: true}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			call := &Call{
				service:   &Service{cfg: cfg, sess: sess, reg: reg},
				state:     CallStateActive,
				localURI:  "sip:001010123456789@example.com",
				localTag:  "local-tag",
				remoteURI: "sip:callee@example.com",
				remoteTo:  "<sip:callee@example.com>;tag=remote-tag",
				targetURI: "sip:callee@192.0.2.10:5060",
				localPort: 40000,
				emergency: true,
				localSDP:  inviteWithSDP().Body,
			}
			if _, _, _, _, _, clearPending, err := call.beginLocalHoldModification(callActionHold, true, mediaDirectionSendOnly); err != nil {
				t.Fatalf("beginLocalHoldModification() error = %v", err)
			} else {
				clearPending()
			}
		})
	}
}

func TestCallHoldPreconditionReINVITEMarksQoSMet(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "hold session modification reuses established qos"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{Preconditions: true}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			call := &Call{
				service: &Service{cfg: cfg},
				state:   CallStateActive,
				media:   NegotiatedMedia{Codec: CodecAMRWB},
				localSDP: []byte("v=0\r\n" +
					"o=- 1 1 IN IP4 10.0.0.1\r\n" +
					"s=-\r\n" +
					"c=IN IP4 10.0.0.1\r\n" +
					"t=0 0\r\n" +
					"m=audio 40000 RTP/AVP 104\r\n" +
					"a=rtpmap:104 AMR-WB/16000\r\n" +
					"a=sendrecv\r\n" +
					"a=curr:qos local none\r\n" +
					"a=curr:qos remote none\r\n" +
					"a=des:qos mandatory local sendrecv\r\n" +
					"a=des:qos optional remote sendrecv\r\n"),
			}
			body, err := call.localSDPWithDirection(mediaDirectionSendOnly)
			if err != nil {
				t.Fatalf("localSDPWithDirection() error = %v", err)
			}
			snap := dialogSnapshot{targetURI: "sip:remote@example.com", preconditions: true}
			msg := snap.buildMediaReINVITE(2, sessionTimerState{}, body)
			got := string(msg.Body)
			for _, want := range []string{
				"a=sendonly\r\n",
				"a=curr:qos local sendrecv\r\n",
				"a=curr:qos remote sendrecv\r\n",
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("hold re-INVITE body missing %q:\n%s", want, got)
				}
			}
			if got := msg.Header("Supported"); !sip.TokenListContains(got, preconditionOption) {
				t.Fatalf("hold re-INVITE Supported = %q, want precondition", got)
			}
		})
	}
}

func TestCallHoldNon2xxRestoresState(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "hold rejected by remote"},
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				if invites == 1 {
					transport.queue(callOK(msg))
					return
				}
				transport.queue(callStatus(msg, sipStatusNotAcceptableHere, "Not Acceptable Here"))
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			before := append([]byte(nil), call.localSDP...)
			err = call.Hold(context.Background())
			if err == nil {
				t.Fatal("Hold() error = nil, want remote rejection")
			}
			if got := call.HoldState(); got != CallHoldNone {
				t.Fatalf("hold state = %s, want %s", got, CallHoldNone)
			}
			if !bytes.Equal(call.localSDP, before) {
				t.Fatalf("localSDP changed after failed hold:\n%s", string(call.localSDP))
			}
		})
	}
}

func TestCallHoldContextCancelRestoresPendingState(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "cancelled hold does not leave local invite pending"},
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

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				if invites == 1 {
					transport.queue(callOK(msg))
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			before := append([]byte(nil), call.localSDP...)
			holdCtx, holdCancel := context.WithCancel(context.Background())
			holdCancel()
			err = call.Hold(holdCtx)
			if err == nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("Hold() error = %v, want context canceled", err)
			}
			if got := call.HoldState(); got != CallHoldNone {
				t.Fatalf("hold state = %s, want %s", got, CallHoldNone)
			}
			call.mu.Lock()
			pending := call.localINVITEPending
			localSDP := append([]byte(nil), call.localSDP...)
			call.mu.Unlock()
			if pending {
				t.Fatal("localINVITEPending = true, want false")
			}
			if !bytes.Equal(localSDP, before) {
				t.Fatalf("localSDP changed after cancelled hold:\n%s", string(localSDP))
			}
		})
	}
}

func TestCallHoldBlocksRTPButAllowsRTCP(t *testing.T) {
	tests := []struct {
		name      string
		hold      CallHoldState
		direction mediaDirection
		wantRTP   bool
	}{
		{name: "local hold", hold: CallHoldLocal, direction: mediaDirectionSendOnly},
		{name: "inactive media", hold: CallHoldRemote, direction: mediaDirectionInactive},
		{name: "remote hold sendonly answer allows rtp", hold: CallHoldRemote, direction: mediaDirectionSendOnly, wantRTP: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rtcpCh := make(chan []byte, 1)
			call := &Call{
				state: CallStateActive,
				hold:  tt.hold,
				media: NegotiatedMedia{Direction: tt.direction},
				transport: &voiceMediaTransport{
					local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
					rtcpCh: rtcpCh,
				},
			}
			err := call.WriteRTP(context.Background(), []byte("rtp"))
			if tt.wantRTP && err != nil {
				t.Fatalf("WriteRTP() error = %v, want nil", err)
			}
			if !tt.wantRTP && err == nil {
				t.Fatal("WriteRTP() error = nil, want hold rejection")
			}
			if err := call.WriteRTCP(context.Background(), []byte("rtcp")); err != nil {
				t.Fatalf("WriteRTCP() error = %v", err)
			}
			select {
			case got := <-rtcpCh:
				if string(got) != "rtcp" {
					t.Fatalf("RTCP packet = %q, want rtcp", string(got))
				}
			default:
				t.Fatal("RTCP packet was not written")
			}
		})
	}
}
