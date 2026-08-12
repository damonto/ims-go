package voice

import (
	"context"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func TestRouteSetFromResponseExpandsAndReversesValues(t *testing.T) {
	tests := []struct {
		name    string
		headers sip.Headers
		want    []string
	}{
		{
			name: "comma list",
			headers: sip.Headers{
				{Name: "Record-Route", Value: "<sip:p1.example.com;lr>,<sip:p2.example.com;lr>"},
			},
			want: []string{"<sip:p2.example.com;lr>", "<sip:p1.example.com;lr>"},
		},
		{
			name: "multiple lines and comma list",
			headers: sip.Headers{
				{Name: "Record-Route", Value: "<sip:p1.example.com;lr>,<sip:p2.example.com;lr>"},
				{Name: "Record-Route", Value: "<sip:p3.example.com;lr>"},
			},
			want: []string{"<sip:p3.example.com;lr>", "<sip:p2.example.com;lr>", "<sip:p1.example.com;lr>"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.Message{Headers: tt.headers}
			if got := routeSetFromResponse(msg); !slices.Equal(got, tt.want) {
				t.Fatalf("routeSetFromResponse() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestRSeqHeaderText(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		want     int64
		wantText string
		wantErr  bool
	}{
		{name: "positive", value: "7", want: 7, wantText: "7"},
		{name: "trimmed", value: " 42 ", want: 42, wantText: "42"},
		{name: "max uint32", value: "4294967295", want: 4294967295, wantText: "4294967295"},
		{name: "empty", value: "", wantErr: true},
		{name: "zero", value: "0", wantErr: true},
		{name: "negative", value: "-1", wantErr: true},
		{name: "above uint32", value: "4294967296", wantErr: true},
		{name: "text", value: "abc", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got rseqHeader
			err := got.UnmarshalText([]byte(tt.value))
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalText() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if int64(got) != tt.want {
				t.Fatalf("UnmarshalText() = %d, want %d", got, tt.want)
			}
			text, err := got.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if string(text) != tt.wantText {
				t.Fatalf("MarshalText() = %q, want %q", text, tt.wantText)
			}
		})
	}
}

func TestRAckHeaderText(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		want     rackHeader
		wantText string
		wantErr  bool
	}{
		{name: "valid", value: "7 1 INVITE", want: rackHeader{rseq: 7, cseq: 1, method: "INVITE"}, wantText: "7 1 INVITE"},
		{name: "method case preserved", value: "7 1 invite", want: rackHeader{rseq: 7, cseq: 1, method: "invite"}, wantText: "7 1 invite"},
		{name: "missing method", value: "7 1", wantErr: true},
		{name: "zero rseq", value: "0 1 INVITE", wantErr: true},
		{name: "zero cseq", value: "7 0 INVITE", wantErr: true},
		{name: "rseq above uint32", value: "4294967296 1 INVITE", wantErr: true},
		{name: "cseq above uint32", value: "7 4294967296 INVITE", wantErr: true},
		{name: "extra token", value: "7 1 INVITE extra", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got rackHeader
			err := got.UnmarshalText([]byte(tt.value))
			if tt.wantErr {
				if err == nil {
					t.Fatal("UnmarshalText() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("UnmarshalText() = %+v, want %+v", got, tt.want)
			}
			text, err := got.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if string(text) != tt.wantText {
				t.Fatalf("MarshalText() = %q, want %q", text, tt.wantText)
			}
		})
	}
}

func TestReliableProvisionalRetransmitIntervalDoublesPastT2(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		want     time.Duration
	}{
		{name: "before T2", interval: 10 * time.Millisecond, want: 20 * time.Millisecond},
		{name: "at T2", interval: 20 * time.Millisecond, want: 40 * time.Millisecond},
		{name: "past T2", interval: 40 * time.Millisecond, want: 80 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := nextReliableProvisionalRetransmitInterval(tt.interval); got != tt.want {
				t.Fatalf("nextReliableProvisionalRetransmitInterval() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestReliableProvisionalMatchesRAckCaseSensitiveMethod(t *testing.T) {
	tests := []struct {
		name string
		rack rackHeader
		want bool
	}{
		{name: "exact method", rack: rackHeader{rseq: 7, cseq: 1, method: "INVITE"}, want: true},
		{name: "different method case", rack: rackHeader{rseq: 7, cseq: 1, method: "invite"}},
	}
	pending := reliableProvisional{rseq: 7, cseq: 1, method: "INVITE"}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := pending.matches(tt.rack); got != tt.want {
				t.Fatalf("matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsReliableProvisional(t *testing.T) {
	tests := []struct {
		name string
		msg  sip.Message
		want bool
	}{
		{
			name: "100 Trying ignores 100rel",
			msg: func() sip.Message {
				msg := sip.NewResponse(sipStatusTrying, "Trying")
				msg.Headers.Add("Require", reliableProvisionalOption)
				msg.Headers.Add("RSeq", "7")
				return msg
			}(),
		},
		{
			name: "183 missing RSeq",
			msg: func() sip.Message {
				msg := sip.NewResponse(sipStatusSessionProgress, "Session Progress")
				msg.Headers.Add("Require", reliableProvisionalOption)
				return msg
			}(),
		},
		{
			name: "183 missing Require 100rel",
			msg: func() sip.Message {
				msg := sip.NewResponse(sipStatusSessionProgress, "Session Progress")
				msg.Headers.Add("RSeq", "7")
				return msg
			}(),
		},
		{
			name: "183 reliable",
			msg:  reliableResponseForTest("early-a", "7"),
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isReliableProvisional(tt.msg); got != tt.want {
				t.Fatalf("isReliableProvisional() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestRecordReliableProvisionalRSeq(t *testing.T) {
	tests := []struct {
		name    string
		msg     sip.Message
		want    bool
		wantErr bool
	}{
		{name: "first response starts dialog sequence", msg: reliableResponseForTest("early-a", "7"), want: true},
		{name: "duplicate retransmission ignored", msg: reliableResponseForTest("early-a", "7")},
		{name: "out of order jump ignored", msg: reliableResponseForTest("early-a", "9")},
		{name: "next ordered response accepted", msg: reliableResponseForTest("early-a", "8"), want: true},
		{name: "new early dialog starts independent sequence", msg: reliableResponseForTest("early-b", "21"), want: true},
		{name: "invalid rseq rejected", msg: reliableResponseForTest("early-b", "bad"), wantErr: true},
		{name: "initial rseq above RFC 3262 initial range rejected", msg: reliableResponseForTest("early-c", "2147483648"), wantErr: true},
		{name: "missing To tag rejected", msg: reliableResponseWithoutToTagForTest("7"), wantErr: true},
	}
	call := &Call{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := call.recordReliableProvisional(tt.msg)
			if tt.wantErr {
				if err == nil {
					t.Fatal("recordReliableProvisional() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("recordReliableProvisional() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("recordReliableProvisional() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestBeginReliableProvisionalInitialRSeq(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "initial sequence is in RFC 3262 range and increments by one"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{}
			first := call.beginReliableProvisional(sipStatusSessionProgress, 1, "INVITE")
			second := call.beginReliableProvisional(sipStatusRinging, 1, "INVITE")
			if first < 1 || first > rseqInitialMax {
				t.Fatalf("first RSeq = %d, want 1..%d", first, rseqInitialMax)
			}
			if second != first+1 {
				t.Fatalf("second RSeq = %d, want %d", second, first+1)
			}
		})
	}
}

func TestReliableProvisionalOutOfOrderIsNotProcessed(t *testing.T) {
	msg := reliableResponseForTest("early-a", "9")
	msg.Headers.Add("Content-Type", "application/sdp")
	msg.Body = []byte("v=0\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 50000 RTP/AVP 0\r\n")
	call := &Call{
		direction:    CallDirectionOutgoing,
		inviteSeq:    1,
		reliableRSeq: map[string]int64{"early-a": 7},
	}

	if err := call.handleProvisionalResponse(t.Context(), msg); err != nil {
		t.Fatalf("handleProvisionalResponse() error = %v", err)
	}
	if dialog, ok := call.earlyDialogs["early-a"]; ok && dialog.hasAnswer {
		t.Fatalf("early dialog answer was processed for out-of-order reliable response: %+v", dialog)
	}
}

func TestReliableProvisionalRetransmitsUntilPRACK(t *testing.T) {
	transport := newVoiceStubTransport()
	sess, err := session.Open(session.Config{
		TransactionTimers: session.TransactionTimers{
			T1: 10 * time.Millisecond,
			T2: 20 * time.Millisecond,
		},
	}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	reg, err := newTestRegistrar(registration.Config{Logger: testLogger(),
		PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
		UserAgent:       "test-agent",
	}, sess, voiceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	incoming := make(chan IncomingCall, 1)
	media := &voiceMediaTransport{}
	svc, err := New(Config{Logger: testLogger(),
		ReliableProvisional: true,
		PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
			media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
			media.onPacket = cfg.OnPacket
			return media, nil
		},
		OnIncomingCall: func(event IncomingCall) { incoming <- event },
	}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
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
		closeEndpointAndStackAfterTest(t, svc, sess)
		<-runErr
	}()

	invite := reliableDelayedInvite()
	transport.queue(invite)
	select {
	case event := <-incoming:
		t.Fatalf("incoming call was reported before PRACK: %v", event.Call)
	case <-time.After(20 * time.Millisecond):
	}
	if !waitForCallTest(func() bool {
		return len(transport.messagesByStatus(183, "INVITE")) >= 2
	}) {
		t.Fatalf("183 count = %d, want retransmission before PRACK", len(transport.messagesByStatus(183, "INVITE")))
	}
	progress := transport.messagesByStatus(183, "INVITE")[0]
	transport.queue(prackForReliableProvisional(invite, progress))
	if !waitForCallTest(func() bool {
		return len(transport.messagesByStatus(200, "PRACK")) == 1
	}) {
		t.Fatalf("200 PRACK count = %d, want 1", len(transport.messagesByStatus(200, "PRACK")))
	}
	select {
	case event := <-incoming:
		if event.Call == nil {
			t.Fatal("incoming call is nil")
		}
	case <-time.After(time.Second):
		t.Fatal("incoming call was not reported after PRACK")
	}
	afterPRACK := len(transport.messagesByStatus(183, "INVITE"))
	time.Sleep(60 * time.Millisecond)
	if got := len(transport.messagesByStatus(183, "INVITE")); got != afterPRACK {
		t.Fatalf("183 count after PRACK = %d, want retransmission stopped at %d", got, afterPRACK)
	}
}

func TestReliableProvisionalDuplicateInviteDoesNotAdvanceRSeq(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "duplicate INVITE retransmits pending reliable response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{
				TransactionTimers: session.TransactionTimers{
					T1: 200 * time.Millisecond,
					T2: 400 * time.Millisecond,
				},
			}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := newTestRegistrar(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(t.Context())
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
				closeEndpointAndStackAfterTest(t, svc, sess)
				<-runErr
			}()

			invite := reliableDelayedInvite()
			transport.queue(invite)
			select {
			case event := <-incoming:
				t.Fatalf("incoming call was reported before PRACK: %v", event.Call)
			case <-time.After(20 * time.Millisecond):
			}
			if !waitForCallTest(func() bool {
				return len(transport.messagesByStatus(183, "INVITE")) == 1
			}) {
				t.Fatalf("183 count = %d, want 1", len(transport.messagesByStatus(183, "INVITE")))
			}

			transport.queue(invite)
			if !waitForCallTest(func() bool {
				return len(transport.messagesByStatus(183, "INVITE")) >= 2
			}) {
				t.Fatalf("183 count after duplicate INVITE = %d, want at least 2", len(transport.messagesByStatus(183, "INVITE")))
			}
			if got := len(transport.messagesByStatus(180, "INVITE")); got != 0 {
				t.Fatalf("180 count before PRACK = %d, want 0", got)
			}
			firstRSeq := ""
			for _, msg := range transport.messagesByStatus(183, "INVITE") {
				got := msg.Header("RSeq")
				if firstRSeq == "" {
					firstRSeq = got
				}
				if got != firstRSeq {
					t.Fatalf("183 RSeq = %q, want pending RSeq %s", got, firstRSeq)
				}
				var rseq rseqHeader
				if err := rseq.UnmarshalText([]byte(got)); err != nil {
					t.Fatalf("183 RSeq parse error = %v", err)
				}
			}

			progress := transport.messagesByStatus(183, "INVITE")[0]
			transport.queue(prackForReliableProvisional(invite, progress))
			if !waitForCallTest(func() bool {
				return len(transport.messagesByStatus(sipStatusOK, "PRACK")) == 1
			}) {
				t.Fatalf("200 PRACK count = %d, want 1", len(transport.messagesByStatus(sipStatusOK, "PRACK")))
			}
			select {
			case event := <-incoming:
				if event.Call == nil {
					t.Fatal("incoming call is nil")
				}
			case <-time.After(time.Second):
				t.Fatal("incoming call was not reported after PRACK")
			}
		})
	}
}

func TestReliableProvisionalTimeoutRejectsInvite(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "missing PRACK gets 500"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{
				TransactionTimers: session.TransactionTimers{
					T1: 2 * time.Millisecond,
					T2: 4 * time.Millisecond,
				},
			}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := newTestRegistrar(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				UserAgent:       "test-agent",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			incoming := make(chan IncomingCall, 1)
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				ReliableProvisional: true,
				PrepareMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
				OnIncomingCall: func(event IncomingCall) { incoming <- event },
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(t.Context())
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
				closeEndpointAndStackAfterTest(t, svc, sess)
				<-runErr
			}()

			invite := reliableDelayedInvite()
			transport.queue(invite)
			var call *Call
			if !waitForCallTest(func() bool {
				call = svc.lookupCall(invite.Header("Call-ID"))
				return call != nil
			}) {
				t.Fatal("incoming call was not stored while PRACK was pending")
			}

			if !waitForCallTest(func() bool {
				return len(transport.messagesByStatus(sipStatusServerInternalError, "INVITE")) >= 1
			}) {
				t.Fatalf("500 INVITE count = %d, want at least 1", len(transport.messagesByStatus(sipStatusServerInternalError, "INVITE")))
			}
			if call.State() != CallStateFailed {
				t.Fatalf("call state = %s, want %s", call.State(), CallStateFailed)
			}
			select {
			case event := <-incoming:
				t.Fatalf("incoming call was reported even though PRACK timed out: %v", event.Call)
			default:
			}
		})
	}
}

func reliableResponseForTest(tag, rseq string) sip.Message {
	msg := sip.NewResponse(183, "Session Progress")
	msg.Headers.Add("To", "<sip:remote@example.com>;tag="+tag)
	msg.Headers.Add("CSeq", "1 INVITE")
	msg.Headers.Add("Require", "100rel")
	msg.Headers.Add("RSeq", rseq)
	return msg
}

func reliableResponseWithoutToTagForTest(rseq string) sip.Message {
	msg := sip.NewResponse(183, "Session Progress")
	msg.Headers.Add("To", "<sip:remote@example.com>")
	msg.Headers.Add("CSeq", "1 INVITE")
	msg.Headers.Add("Require", "100rel")
	msg.Headers.Add("RSeq", rseq)
	return msg
}
