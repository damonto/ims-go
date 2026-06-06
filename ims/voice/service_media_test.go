package voice

import (
	"bytes"
	"context"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"net"
	"strings"
	"testing"
	"time"
)

func TestDialEndsAfterRTPInactivity(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "rtp packet resets inactivity timer before call ends"},
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

			timeout := 80 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(timeout),
				RTCPInactivityTimeout: Duration(time.Second),
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

			mediaClosedBeforeBYE := make(chan bool, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					mediaClosedBeforeBYE <- media.isClosed()
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			time.Sleep(timeout / 2)
			media.notify(MediaPacket{})
			if waitForCallEvent(events, CallStateEnded, "rtp inactivity timeout", timeout*3/4) {
				t.Fatal("call ended before reset RTP inactivity timeout elapsed")
			}
			if !waitForCallEvent(events, CallStateEnded, "rtp inactivity timeout", 2*timeout) {
				t.Fatalf("call state = %s, want %s after RTP inactivity", call.State(), CallStateEnded)
			}
			select {
			case closed := <-mediaClosedBeforeBYE:
				if !closed {
					t.Fatal("media transport was open while sending inactivity BYE")
				}
			default:
				t.Fatal("BYE was not sent after RTP inactivity")
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaTimeout {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaTimeout)
			}
		})
	}
}

func TestOpenMediaRequiresTransport(t *testing.T) {
	tests := []struct {
		name   string
		closed bool
	}{
		{name: "active call"},
		{name: "closed call", closed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{
				service: &Service{cfg: Config{
					OpenMedia: func(context.Context, MediaConfig) (MediaTransport, error) {
						return nil, nil
					},
				}},
				media:  NegotiatedMedia{RemoteIP: net.IPv4(192, 0, 2, 10), RemotePort: 50000},
				closed: tt.closed,
			}

			err := call.openMedia(context.Background())
			if err == nil || !strings.Contains(err.Error(), "media transport is nil") {
				t.Fatalf("openMedia() error = %v, want nil transport error", err)
			}
		})
	}
}

func TestDialEndsAfterRTCPBye(t *testing.T) {
	tests := []struct {
		name      string
		byeStatus int
		byeReason string
		wantError bool
	}{
		{name: "rtcp bye releases dialog", byeStatus: 200, byeReason: "OK"},
		{name: "rtcp bye accepts missing dialog response", byeStatus: 481, byeReason: "Call/Transaction Does Not Exist"},
		{name: "rtcp bye accepts request timeout response", byeStatus: 408, byeReason: "Request Timeout"},
		{name: "rtcp bye reports non-terminating response", byeStatus: 500, byeReason: "Server Internal Error", wantError: true},
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
			errCh := make(chan error, 1)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(time.Second),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnCallEvent: func(event CallEvent) { events <- event },
				OnError:     func(err error) { errCh <- err },
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

			mediaClosedBeforeBYE := make(chan bool, 1)
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					transport.queue(callOK(msg))
				case "BYE":
					mediaClosedBeforeBYE <- media.isClosed()
					transport.queue(callStatus(msg, tt.byeStatus, tt.byeReason))
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			media.notify(MediaPacket{RTCP: true, RTCPBye: true})
			if !waitForCallEvent(events, CallStateEnded, "rtcp bye", time.Second) {
				t.Fatalf("call state = %s, want %s after RTCP BYE", call.State(), CallStateEnded)
			}
			select {
			case closed := <-mediaClosedBeforeBYE:
				if !closed {
					t.Fatal("media transport was open while sending RTCP BYE release")
				}
			default:
				t.Fatal("BYE was not sent after RTCP BYE")
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaBearerReleased {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaBearerReleased)
			}
			if tt.wantError {
				select {
				case err := <-errCh:
					if !strings.Contains(err.Error(), tt.byeReason) {
						t.Fatalf("OnError() = %v, want %q", err, tt.byeReason)
					}
				case <-time.After(time.Second):
					t.Fatal("OnError() was not called")
				}
			} else {
				select {
				case err := <-errCh:
					t.Fatalf("OnError() = %v, want none", err)
				default:
				}
			}
		})
	}
}

func TestDialSendsRTCPReports(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "confirmed call sends compound rtcp receiver report"},
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

			rtcpCh := make(chan []byte, 2)
			media := &voiceMediaTransport{
				local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				rtcpCh: rtcpCh,
			}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(time.Second),
				RTCPSendInterval:      Duration(20 * time.Millisecond),
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					if cfg.OnPacket == nil {
						t.Fatal("OpenMedia OnPacket is nil")
					}
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

			var packet []byte
			select {
			case packet = <-rtcpCh:
			case <-time.After(time.Second):
				t.Fatal("RTCP report was not sent")
			}
			if len(packet) < 12 {
				t.Fatalf("RTCP packet len = %d, want compound report", len(packet))
			}
			if got := packet[1]; got != rtcpRRPacketType {
				t.Fatalf("RTCP first packet type = %d, want %d", got, rtcpRRPacketType)
			}
			if got := packet[9]; got != rtcpSDESPacketType {
				t.Fatalf("RTCP second packet type = %d, want %d", got, rtcpSDESPacketType)
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
		})
	}
}

func TestDialDoesNotSendRTCPWhenAnswerDisablesRTCP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "answer b=RS:0 and b=RR:0 disables rtcp sender"},
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

			rtcpCh := make(chan []byte, 2)
			media := &voiceMediaTransport{
				local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				rtcpCh: rtcpCh,
			}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(40 * time.Millisecond),
				RTCPSendInterval:      Duration(20 * time.Millisecond),
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
				switch msg.Method() {
				case "INVITE":
					resp := callOK(msg)
					resp.Body = bytes.Replace(resp.Body, []byte("m=audio 50000 RTP/AVP 104 110\r\n"), []byte("m=audio 50000 RTP/AVP 104 110\r\nb=RS:0\r\nb=RR:0\r\n"), 1)
					transport.queue(resp)
				case "BYE":
					transport.queue(callStatus(msg, 200, "OK"))
				}
			}
			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			if media := call.Media(); !media.RTCPDisabled {
				t.Fatalf("Call.Media().RTCPDisabled = false, want true")
			}

			select {
			case packet := <-rtcpCh:
				t.Fatalf("RTCP packet was sent despite disabled RTCP: %x", packet)
			case <-time.After(80 * time.Millisecond):
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
		})
	}
}

func TestEarlyMediaHoldInactivityWatchDoesNotEndCall(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "early media hold ignores rtp and rtcp timeout release"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rtpTimeout := 40 * time.Millisecond
			rtcpTimeout := 160 * time.Millisecond
			cfg, err := (Config{
				Logger:                testLogger(),
				RTPInactivityTimeout:  Duration(rtpTimeout),
				RTCPInactivityTimeout: Duration(rtcpTimeout),
				RTCPSendInterval:      Duration(0),
				AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{
					AudioInactivityRTPOnConnected,
					AudioInactivityRTCPOnHold,
				},
			}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			events := make(chan CallEvent, 2)
			cfg.OnCallEvent = func(event CallEvent) { events <- event }
			svc := &Service{
				cfg:       cfg,
				logger:    testLogger(),
				calls:     make(map[string]*Call),
				incomings: make(map[string]*Call),
			}
			call := &Call{
				service: svc,
				id:      "hold-watch-call",
				state:   CallStateEarlyMedia,
				hold:    CallHoldLocal,
				transport: &voiceMediaTransport{
					local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				},
			}
			svc.calls[call.id] = call
			call.startMediaInactivityWatch()
			defer func() {
				call.finish(CallStateEnded, "test cleanup")
			}()

			if waitForCallEvent(events, CallStateEnded, "rtp inactivity timeout", 2*rtpTimeout) {
				t.Fatal("call ended on RTP inactivity while held")
			}
			if waitForCallEvent(events, CallStateEnded, "rtcp inactivity timeout", 2*rtcpTimeout) {
				t.Fatal("early media call ended on RTCP inactivity while held")
			}
			if got := call.State(); got != CallStateEarlyMedia {
				t.Fatalf("call.State() = %q, want %q", got, CallStateEarlyMedia)
			}
		})
	}
}

func TestHeldCallInactivityWatchUsesRTCPOnHoldPolicy(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "active hold keeps rtcp timeout release policy"},
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
			rtpTimeout := 40 * time.Millisecond
			rtcpTimeout := 160 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(rtpTimeout),
				RTCPInactivityTimeout: Duration(rtcpTimeout),
				RTCPSendInterval:      Duration(0),
				AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{
					AudioInactivityRTPOnConnected,
					AudioInactivityRTCPOnHold,
				},
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
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
			call.mu.Lock()
			call.hold = CallHoldLocal
			call.mu.Unlock()
			call.restartMediaInactivityWatch()

			if waitForCallEvent(events, CallStateEnded, "rtp inactivity timeout", 2*rtpTimeout) {
				t.Fatal("held call ended on RTP inactivity")
			}
			if !waitForCallEvent(events, CallStateEnded, "rtcp inactivity timeout", 2*rtcpTimeout) {
				t.Fatalf("call state = %s, want RTCP-on-hold timeout", call.State())
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaTimeout {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaTimeout)
			}
		})
	}
}

func TestDialDoesNotWriteRTCPReportsToRTPTransport(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "transport without rtcp writer does not receive rtcp on rtp path"},
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

			rtpWrites := make(chan []byte, 2)
			media := &voiceRTPOnlyMediaTransport{
				local:   &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				writeCh: rtpWrites,
			}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(time.Second),
				RTCPSendInterval:      Duration(20 * time.Millisecond),
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
			if err := call.WriteRTCP(context.Background(), []byte("rtcp")); err == nil {
				t.Fatal("WriteRTCP() error = nil, want unsupported transport error")
			}

			select {
			case packet := <-rtpWrites:
				t.Fatalf("RTP WritePacket received RTCP fallback packet: %x", packet)
			case <-time.After(80 * time.Millisecond):
			}
			if err := call.Hangup(context.Background()); err != nil {
				t.Fatalf("Hangup() error = %v", err)
			}
		})
	}
}

func TestDialEndsAfterRTCPInactivityWhenPolicyIncludesRTCP(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "connected rtcp timeout ends call"},
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
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:  Duration(time.Second),
				RTCPInactivityTimeout: Duration(rtcpTimeout),
				AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{
					AudioInactivityRTCPOnConnected,
				},
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

			if !waitForCallEvent(events, CallStateEnded, "rtcp inactivity timeout", 3*rtcpTimeout) {
				t.Fatalf("call state = %s, want ended after RTCP inactivity", call.State())
			}
			byes := transport.messagesByMethod("BYE")
			if len(byes) != 1 {
				t.Fatalf("BYE count = %d, want 1", len(byes))
			}
			if got := byes[0].Header("Reason"); got != reasonMediaTimeout {
				t.Fatalf("BYE Reason = %q, want %q", got, reasonMediaTimeout)
			}
		})
	}
}

func TestDialUsesEmergencyAudioInactivityPolicy(t *testing.T) {
	tests := []struct {
		name       string
		reasons    []AudioInactivityCallEndReason
		wantEnded  bool
		wantReason string
	}{
		{
			name:       "emergency rtcp reason ends emergency call",
			reasons:    []AudioInactivityCallEndReason{AudioInactivityE911RTCP},
			wantEnded:  true,
			wantReason: "rtcp inactivity timeout",
		},
		{
			name:    "normal connected rtcp reason does not end emergency call",
			reasons: []AudioInactivityCallEndReason{AudioInactivityRTCPOnConnected},
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

			rtcpTimeout := 40 * time.Millisecond
			events := make(chan CallEvent, 16)
			media := &voiceMediaTransport{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			svc, err := New(Config{Logger: testLogger(),
				RTPInactivityTimeout:          Duration(time.Second),
				RTCPInactivityTimeout:         Duration(rtcpTimeout),
				AudioInactivityCallEndReasons: tt.reasons,
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
			call, err := svc.Dial(context.Background(), DialRequest{To: "911", Emergency: true})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}

			ended := waitForCallEvent(events, CallStateEnded, tt.wantReason, 3*rtcpTimeout)
			if ended != tt.wantEnded {
				t.Fatalf("ended after RTCP inactivity = %t, want %t", ended, tt.wantEnded)
			}
			if tt.wantEnded {
				return
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
