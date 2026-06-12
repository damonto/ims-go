package registration

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRefreshUsesAuthenticationInfoNextNonce(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	registerService(t, svc, transport)

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if !bytes.Contains([]byte(req.Header("Authorization")), []byte(`nonce="`+testNonce+`"`)) {
			t.Fatalf("Authorization = %q, want next nonce", req.Header("Authorization"))
		}
		transport.queue(newResponse(req, 200, "OK"))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
}

func TestRefreshRequiresInitialRegistrationOnRestartStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
		reason string
	}{
		{name: "forbidden", status: 403, reason: "Forbidden"},
		{name: "timeout", status: 408, reason: "Request Timeout"},
		{name: "server error", status: 500, reason: "Server Internal Error"},
		{name: "gateway timeout", status: 504, reason: "Server Time-out"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newUDPTransport(5062, 5060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			registerService(t, svc, transport)

			transport.onWrite = func(data []byte) {
				req := mustParseMessage(t, data)
				transport.queue(newResponse(req, tt.status, tt.reason))
			}

			err := svc.Refresh(context.Background())
			if err == nil {
				t.Fatal("Refresh() error = nil, want initial registration required")
			}
			if !errors.Is(err, errInitialRegistrationNeeded) {
				t.Fatalf("Refresh() error = %v, want %v", err, errInitialRegistrationNeeded)
			}
			if !strings.Contains(err.Error(), "initial registration required") {
				t.Fatalf("Refresh() error = %v, want initial registration required", err)
			}
			if got := countWrites(transport); got != 3 {
				t.Fatalf("write count = %d, want one refresh attempt after registration", got)
			}
		})
	}
}

func TestRefreshReauthenticationRequiresSecureDialer(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}

	err = svc.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() error = nil, want missing secure dialer")
	}
	if !strings.Contains(err.Error(), "UDP dialer is not configured") {
		t.Fatalf("Refresh() error = %v, want missing UDP dialer", err)
	}
}

func TestRefreshReauthenticationRequiresSecureInboundTransport(t *testing.T) {
	old := newTCPTransport(5062, 5060)
	nextOutbound := newTCPTransport(45000, 4060)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
	}, old, stubCard{})

	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}

	err := svc.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() error = nil, want missing secure inbound transport")
	}
	if !strings.Contains(err.Error(), "secure inbound transport is not configured") {
		t.Fatalf("Refresh() error = %v, want missing secure inbound transport", err)
	}
}

func TestRefreshReauthenticatesWithNewSecurityAssociation(t *testing.T) {
	old := newTCPTransport(5062, 5060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)

	var dialCfg session.SecureTCPConfig
	var listenCfg session.SecureTCPConfig
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			dialCfg = cfg
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			listenCfg = cfg
			return nextInbound, nil
		},
	}, old, stubCard{})

	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	oldSecurityClient := svc.CurrentFlow().SecurityClient

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if countWrites(old) != 1 {
			t.Fatalf("old write count = %d, want 1", countWrites(old))
		}
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if countWrites(nextOutbound) > 1 {
			return
		}
		if req.Method() != "REGISTER" {
			t.Fatalf("new outbound method = %q, want REGISTER", req.Method())
		}
		if got := req.Header("Security-Verify"); !strings.Contains(got, "port-c=4600") {
			t.Fatalf("Security-Verify = %q, want new Security-Server", got)
		}
		var securityClients security.Params
		if err := securityClients.UnmarshalText([]byte(req.Header("Security-Client"))); err != nil {
			t.Fatalf("parsing Security-Client: %v", err)
		}
		if len(securityClients) != 8 {
			t.Fatalf("Security-Client count = %d, want 8", len(securityClients))
		}
		if !strings.Contains(req.Header("Security-Client"), "mod=UDP-enc-tun") {
			t.Fatalf("Security-Client = %q, want UDP-enc-tun capability", req.Header("Security-Client"))
		}
		securityClient := securityClients[0]
		if securityClient.PortS != oldSecurityClient.PortS {
			t.Fatalf("Security-Client port-s = %d, want unchanged protected server port %d", securityClient.PortS, oldSecurityClient.PortS)
		}
		if securityClient.PortC == oldSecurityClient.PortC {
			t.Fatalf("Security-Client port-c = %d, want changed protected client port", securityClient.PortC)
		}
		if securityClient.SPIC == oldSecurityClient.SPIC || securityClient.SPIS == oldSecurityClient.SPIS {
			t.Fatalf("Security-Client SPIs = (%d, %d), want changed from (%d, %d)", securityClient.SPIC, securityClient.SPIS, oldSecurityClient.SPIC, oldSecurityClient.SPIS)
		}
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if dialCfg.RemotePort != 4060 || listenCfg.RemotePort != 4600 {
		t.Fatalf("secure cfg remote ports = dial %d listen %d, want 4060 and 4600", dialCfg.RemotePort, listenCfg.RemotePort)
	}
	if dialCfg.LocalPort == oldSecurityClient.PortC {
		t.Fatalf("dial local port = %d, want changed UE protected client port", dialCfg.LocalPort)
	}
	if listenCfg.LocalPort != oldSecurityClient.PortS {
		t.Fatalf("listen local port = %d, want unchanged UE protected server port %d", listenCfg.LocalPort, oldSecurityClient.PortS)
	}
	if dialCfg.InboundSPI == oldSecurityClient.SPIC || listenCfg.InboundSPI == oldSecurityClient.SPIS {
		t.Fatalf("inbound SPIs = dial %d listen %d, want new UE SPIs", dialCfg.InboundSPI, listenCfg.InboundSPI)
	}
	if got := countWrites(nextOutbound); got != 1 {
		t.Fatalf("next outbound write count = %d, want 1", got)
	}
	if err := svc.sess.Send(context.Background(), svc.buildSubscribe()); err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if got := countWrites(nextOutbound); got != 2 {
		t.Fatalf("next outbound write count after promote = %d, want 2", got)
	}
	waitForCloseCount(t, old, 1)

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRefreshReauthenticationCompletesBeforeSessionRun(t *testing.T) {
	old := newTCPTransport(5062, 5060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, old, stubCard{})

	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := svc.Refresh(ctx); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if svc.sess.LocalAddr() != nextOutbound.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want promoted transport %v", svc.sess.LocalAddr(), nextOutbound.LocalAddr())
	}
	waitForCloseCount(t, old, 1)
}

func TestRefreshReauthenticationAcceptsTCPResponseOnOutboundSecurityAssociation(t *testing.T) {
	old := newTCPTransport(5062, 5060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, old, stubCard{})

	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextOutbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if svc.sess.LocalAddr() != nextOutbound.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want promoted transport %v", svc.sess.LocalAddr(), nextOutbound.LocalAddr())
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestReauthResponseTransportsFollowProtectedFlowRules(t *testing.T) {
	tests := []struct {
		name         string
		newTransport func(localPort, remotePort int) *stubTransport
		wantOutbound bool
	}{
		{
			name:         "tcp reuses UE established connection",
			newTransport: newTCPTransport,
			wantOutbound: true,
		},
		{
			name:         "udp receives on protected server flow",
			newTransport: newUDPTransport,
			wantOutbound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			outbound := tt.newTransport(45000, 4060)
			inbound := tt.newTransport(5063, 45000)
			got := reauthResponseTransports(outbound, []session.Transport{inbound})
			want := []session.Transport{inbound}
			if tt.wantOutbound {
				want = []session.Transport{outbound, inbound}
			}
			if !slices.Equal(got, want) {
				t.Fatalf("reauthResponseTransports() = %v, want %v", got, want)
			}
		})
	}
}

func TestRefreshReauthenticationDrainsOldInboundSecurityAssociations(t *testing.T) {
	oldOutbound := newTCPTransport(5062, 4060)
	oldInbound := newTCPTransport(5063, 4060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	timers := session.TransactionTimers{
		T1: 100 * time.Millisecond,
		T2: 100 * time.Millisecond,
		T4: 100 * time.Millisecond,
		TB: 100 * time.Millisecond,
		TD: 100 * time.Millisecond,
		TF: 100 * time.Millisecond,
		TH: 100 * time.Millisecond,
		TJ: 100 * time.Millisecond,
	}
	sess, err := session.Open(session.Config{TransactionTimers: timers}, oldOutbound)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	svc, err := New(Config{
		Logger: testLogger(),
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, sess, stubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	oldInboundAttachment, err := sess.AddTransport(oldInbound)
	if err != nil {
		t.Fatalf("AddTransport(oldInbound) error = %v", err)
	}
	svc.replaceSecureServerAttachments([]session.Attachment{oldInboundAttachment})

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	oldOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		oldOutbound.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	waitForCloseCount(t, oldOutbound, 1)
	waitForCloseCount(t, oldInbound, 1)
	if got := closeCount(nextInbound); got != 0 {
		t.Fatalf("next inbound closeCount = %d, want active new inbound SA", got)
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRefreshReauthenticationKeepsOldSAsUntilPendingTransactionCompletes(t *testing.T) {
	oldOutbound := newTCPTransport(5062, 4060)
	oldInbound := newTCPTransport(5063, 4060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	timers := session.TransactionTimers{
		T1: 500 * time.Millisecond,
		T2: 500 * time.Millisecond,
		T4: 500 * time.Millisecond,
		TB: 500 * time.Millisecond,
		TD: 500 * time.Millisecond,
		TF: 500 * time.Millisecond,
		TH: 500 * time.Millisecond,
		TJ: 500 * time.Millisecond,
	}
	sess, err := session.Open(session.Config{TransactionTimers: timers}, oldOutbound)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	svc, err := New(Config{
		Logger: testLogger(),
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, sess, stubCard{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}
	oldInboundAttachment, err := sess.AddTransport(oldInbound)
	if err != nil {
		t.Fatalf("AddTransport(oldInbound) error = %v", err)
	}
	svc.replaceSecureServerAttachments([]session.Attachment{oldInboundAttachment})

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	pending := sip.NewRequest("MESSAGE", "sip:ims.mnc001.mcc001.3gppnetwork.org")
	pending.Headers = sip.Headers{
		{Name: "Via", Value: "SIP/2.0/TCP 127.0.0.1:5062;branch=z9hG4bK-old-pending"},
		{Name: "From", Value: `<sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org>;tag=old`},
		{Name: "To", Value: `<sip:ims.mnc001.mcc001.3gppnetwork.org>`},
		{Name: "Call-ID", Value: "old-pending"},
		{Name: "CSeq", Value: "1 MESSAGE"},
	}
	oldOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(oldOutbound) {
		case 1:
		case 2:
			oldOutbound.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
		default:
			t.Fatalf("unexpected old outbound write count %d", countWrites(oldOutbound))
		}
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}
	pendingErrCh := make(chan error, 1)
	go func() {
		_, err := sess.ExchangeWithTransport(context.Background(), oldOutbound, pending, session.ExchangeOptions{})
		pendingErrCh <- err
	}()
	waitForWriteCount(t, oldOutbound, 1)

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := closeCount(oldOutbound); got != 0 {
		t.Fatalf("old outbound closeCount = %d, want 0 while old transaction is pending", got)
	}
	if got := closeCount(oldInbound); got != 0 {
		t.Fatalf("old inbound closeCount = %d, want 0 while old transaction is pending", got)
	}

	oldOutbound.queue(newResponse(pending, 200, "OK"))
	if err := <-pendingErrCh; err != nil {
		t.Fatalf("pending Exchange() error = %v", err)
	}
	waitForCloseCount(t, oldOutbound, 1)
	waitForCloseCount(t, oldInbound, 1)

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRefreshReauthenticationFailureDeletesIncompleteSecurityAssociations(t *testing.T) {
	old := newTCPTransport(5062, 4060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, old, stubCard{})
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		nextInbound.queue(newResponse(req, 403, "Forbidden"))
	}

	err := svc.Refresh(context.Background())
	if err == nil {
		t.Fatal("Refresh() error = nil, want re-authentication failure")
	}
	if !errors.Is(err, errInitialRegistrationNeeded) {
		t.Fatalf("Refresh() error = %v, want %v", err, errInitialRegistrationNeeded)
	}
	if got := closeCount(nextOutbound); got != 1 {
		t.Fatalf("next outbound closeCount = %d, want incomplete SA closed", got)
	}
	if got := closeCount(nextInbound); got != 1 {
		t.Fatalf("next inbound closeCount = %d, want incomplete SA closed", got)
	}
	if got := closeCount(old); got != 0 {
		t.Fatalf("old closeCount = %d, want old SA retained", got)
	}
	if svc.sess.LocalAddr() != old.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want old transport %v", svc.sess.LocalAddr(), old.LocalAddr())
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestMaintainReturnsRegistrationEvent(t *testing.T) {
	svc := newTestService(t, Config{}, newUDPTransport(5062, 5060), stubCard{})
	want := errors.New("network deregistered")
	svc.publishRegistrationEvent(want)

	if err := svc.Maintain(context.Background()); !errors.Is(err, want) {
		t.Fatalf("Maintain() error = %v, want %v", err, want)
	}
}

func TestRefreshReauthenticationSynchronizationFailureRetriesWithAUTS(t *testing.T) {
	auts := []byte{0x33, 0xd5, 0x8d, 0x39, 0x61, 0x9c, 0x21, 0x33, 0x67, 0xe3, 0x76, 0x11, 0x53, 0x15}
	nextNonce := base64.StdEncoding.EncodeToString(append(bytes.Repeat([]byte{0x05}, 16), bytes.Repeat([]byte{0x06}, 16)...))
	old := newTCPTransport(5062, 4060)
	nextOutbound := newTCPTransport(45000, 4060)
	nextInbound := newTCPTransport(5063, 45000)
	successAKA := usim.AKAResult{
		RES: []byte("password"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextOutbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nextInbound, nil
		},
	}, old, &sequenceAKACard{
		results: []usim.AKAResult{
			successAKA,
			{AUTS: auts},
			successAKA,
		},
	})
	if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
		t.Fatalf("applyRegisterChallenge() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.sess.Run(runCtx)
	}()
	if err := svc.sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	old.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(old) {
		case 1:
			old.queue(newUnauthorizedRegisterResponse(req, testNonce, 4600))
		case 2:
			auth := req.Header("Authorization")
			if !strings.Contains(auth, `response=""`) {
				t.Fatalf("synchronization failure Authorization = %q, want empty response", auth)
			}
			if !strings.Contains(auth, `auts="`+base64.StdEncoding.EncodeToString(auts)+`"`) {
				t.Fatalf("synchronization failure Authorization = %q, want auts", auth)
			}
			old.queue(newUnauthorizedRegisterResponse(req, nextNonce, 4600))
		default:
			t.Fatalf("unexpected old write count %d", countWrites(old))
		}
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if countWrites(nextOutbound) != 1 {
			t.Fatalf("unexpected next outbound write count %d", countWrites(nextOutbound))
		}
		if strings.Contains(req.Header("Authorization"), "auts=") {
			t.Fatalf("recovered Authorization = %q, want no auts", req.Header("Authorization"))
		}
		nextInbound.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "600"}))
	}

	if err := svc.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if got := countWrites(old); got != 2 {
		t.Fatalf("old write count = %d, want refresh and synchronization failure REGISTER", got)
	}
	if got := countWrites(nextOutbound); got != 1 {
		t.Fatalf("next outbound write count = %d, want recovered SM7 on new outbound SA", got)
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestRegistrationProcedureRejectsConcurrentRefresh(t *testing.T) {
	transport := newTCPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})

	started := make(chan struct{})
	unblock := make(chan struct{})
	var startedOnce sync.Once
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		switch countWrites(transport) {
		case 1:
			startedOnce.Do(func() { close(started) })
			<-unblock
			transport.queue(newUnauthorizedRegisterResponse(req, testNonce, 4060))
		case 2:
			transport.queue(newResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write count %d", countWrites(transport))
		}
	}

	registerErr := make(chan error, 1)
	go func() {
		registerErr <- svc.Register(context.Background())
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	err := svc.Refresh(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Refresh() error = %v, want %v", err, context.DeadlineExceeded)
	}
	close(unblock)
	if err := <-registerErr; err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if got := countWrites(transport); got != 2 {
		t.Fatalf("write count = %d, want only Register writes", got)
	}
}

func TestMaintainRefreshesOnInterval(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{RegisterExpires: 2 * time.Second}, transport, stubCard{})
	registerService(t, svc, transport)

	refreshed := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		transport.queue(newResponse(req, 200, "OK"))
		if req.Method() == "REGISTER" && countWrites(transport) >= 3 {
			refreshed <- struct{}{}
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Maintain(ctx)
	}()

	select {
	case <-refreshed:
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for refresh")
	}
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Fatalf("Maintain() error = %v", err)
	}
}

func TestMaintainRefreshesRegistrationEventSubscription(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setSubscribeExpires(2 * time.Second)

	refreshed := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			refreshed <- struct{}{}
		}
		transport.queue(newResponse(req, 200, "OK", sip.Header{Name: "Expires", Value: "2"}))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Maintain(ctx)
	}()

	select {
	case <-refreshed:
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for subscription refresh")
	}
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Fatalf("Maintain() error = %v", err)
	}
}

func TestMaintainIgnoresRegistrationEventSubscriptionRefreshError(t *testing.T) {
	transport := newUDPTransport(5062, 5060)
	svc := newTestService(t, Config{}, transport, stubCard{})
	svc.setSubscribeExpires(2 * time.Second)

	attempted := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() == "SUBSCRIBE" {
			attempted <- struct{}{}
			transport.queue(newResponse(req, 500, "Server Internal Error"))
			return
		}
		transport.queue(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- svc.Maintain(ctx)
	}()

	select {
	case <-attempted:
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for subscription refresh")
	}

	select {
	case err := <-errCh:
		t.Fatalf("Maintain() returned after subscription refresh error: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	cancel()
	if err := <-errCh; err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Fatalf("Maintain() error = %v", err)
	}
}

func TestRefreshIntervalFollowsIMSRegistrationExpiryRules(t *testing.T) {
	tests := []struct {
		name    string
		expires time.Duration
		want    time.Duration
	}{
		{name: "minimum interval", expires: 500 * time.Millisecond, want: time.Second},
		{name: "half below threshold", expires: 2 * time.Second, want: time.Second},
		{name: "half at threshold", expires: 1200 * time.Second, want: 600 * time.Second},
		{name: "six hundred seconds before expiry above threshold", expires: 1201 * time.Second, want: 601 * time.Second},
		{name: "default ims expiry", expires: 600000 * time.Second, want: 599400 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, Config{RegisterExpires: tt.expires}, newUDPTransport(5062, 5060), stubCard{})
			if got := svc.refreshInterval(); got != tt.want {
				t.Fatalf("refreshInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}
