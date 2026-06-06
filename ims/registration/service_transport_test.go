package registration

import (
	"bytes"
	"context"
	"errors"
	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSecureResponseTransportSkipsDuplicateSessionEndpoint(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "duplicates session udp endpoint"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newUDPTransport(10553, 6000)
			outboundTCP := newTCPTransport(10553, 6000)
			responseUDP := newUDPTransport(10553, 6000)
			dialUDPCount := 0
			svc := newTestService(t, Config{
				DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
					dialUDPCount++
					return responseUDP, nil
				},
			}, primary, stubCard{})
			verify := security.Param{Alg: "hmac-sha-1-96", EAlg: "aes-cbc", PortS: 6000, SPIS: 20}
			flow := Flow{
				SecurityClient: security.Param{PortC: 10553, SPIC: 10},
				SecurityVerify: &verify,
			}

			attachments, err := svc.startSecureResponseTransportsWithKeys(context.Background(), &verify, flow, outboundTCP, []session.Transport{newUDPTransport(28789, 32813)}, []byte("ck"), []byte("ik"))
			if err != nil {
				t.Fatalf("startSecureResponseTransportsWithKeys() error = %v", err)
			}
			if len(attachments) != 0 {
				t.Fatalf("attachments = %d, want 0", len(attachments))
			}
			if dialUDPCount != 0 {
				t.Fatalf("DialSecureUDP calls = %d, want 0", dialUDPCount)
			}
			responseUDP.mu.Lock()
			closeCount := responseUDP.closeCount
			responseUDP.mu.Unlock()
			if closeCount != 0 {
				t.Fatalf("response transport closes = %d, want 0", closeCount)
			}
		})
	}
}

func TestSecureTransportConfigExpandsHMACSHA1IntegrityKey(t *testing.T) {
	ik := []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F}
	ck := []byte{0x20, 0x21, 0x22, 0x23}
	tests := []struct {
		name string
		alg  string
		want []byte
	}{
		{
			name: "spec spelling",
			alg:  "hmac-sha-1-96",
			want: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0, 0, 0, 0},
		},
		{
			name: "codec spelling",
			alg:  "hmac-sha1-96",
			want: []byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0, 0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := secureTransportConfigWithKeys(&security.Param{Alg: tt.alg, EAlg: "null"}, 40000, 5060, 1111, 2222, ck, ik)
			if !bytes.Equal(cfg.IntegrityKey, tt.want) {
				t.Fatalf("IntegrityKey = %X, want %X", cfg.IntegrityKey, tt.want)
			}
			if !bytes.Equal(cfg.EncryptionKey, ck) {
				t.Fatalf("EncryptionKey = %X, want %X", cfg.EncryptionKey, ck)
			}
			cfg.IntegrityKey[0] = 0
			if ik[0] == 0 {
				t.Fatal("input IK was mutated")
			}
		})
	}
}

func TestRegisterRebuildsSecureTransportAfterProtectedRechallenge(t *testing.T) {
	initial := newUDPTransport(5062, 5060)
	firstOutbound := newUDPTransport(45000, 4060)
	firstInbound := newUDPTransport(5063, 45000)
	nextOutbound := newUDPTransport(45001, 4600)
	nextInbound := newUDPTransport(5063, 45001)

	dialed := 0
	listened := 0
	var secondDialCfg session.SecureUDPConfig
	var secondListenCfg session.SecureUDPConfig
	svc := newTestService(t, Config{
		DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			dialed++
			if dialed == 2 {
				secondDialCfg = cfg
				return nextOutbound, nil
			}
			return firstOutbound, nil
		},
		ListenSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			listened++
			if listened == 2 {
				secondListenCfg = cfg
				return nextInbound, nil
			}
			return firstInbound, nil
		},
	}, initial, stubCard{})

	firstNonce := "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI="
	secondNonce := "AgICAgICAgICAgICAgICAQMDAwMDAwMDAwMDAwMDAwM="
	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, firstNonce, 4060))
	}
	firstOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "REGISTER" {
			t.Fatalf("first secure method = %q, want REGISTER", req.Method())
		}
		firstInbound.queue(newUnauthorizedRegisterResponse(req, secondNonce, 4600))
	}
	nextOutbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if got := req.Header("Authorization"); !strings.Contains(got, `nonce="`+secondNonce+`"`) {
			t.Fatalf("Authorization = %q, want second nonce", got)
		}
		if got := req.Header("Security-Verify"); !strings.Contains(got, "port-c=4600") {
			t.Fatalf("Security-Verify = %q, want refreshed Security-Server", got)
		}
		nextInbound.queue(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := svc.Register(ctx); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	if dialed != 2 || listened != 2 {
		t.Fatalf("secure transports dialed/listened = %d/%d, want 2/2", dialed, listened)
	}
	if secondDialCfg.RemotePort != 4060 {
		t.Fatalf("second dial remote port = %d, want P-CSCF protected server port 4060", secondDialCfg.RemotePort)
	}
	if secondListenCfg.RemotePort != 4600 {
		t.Fatalf("second listen remote port = %d, want refreshed P-CSCF protected client port 4600", secondListenCfg.RemotePort)
	}
	if got := countWrites(firstOutbound); got != 1 {
		t.Fatalf("first outbound writes = %d, want 1", got)
	}
	if got := countWrites(nextOutbound); got != 1 {
		t.Fatalf("next outbound writes = %d, want 1", got)
	}
}

func TestRegisterSuccessMaintainsSecureAssociationLifetime(t *testing.T) {
	tests := []struct {
		name          string
		initial       time.Duration
		response      time.Duration
		wantZero      bool
		wantUnchanged bool
		wantExtended  bool
	}{
		{
			name:         "authenticated success starts lifetime",
			response:     time.Minute,
			wantExtended: true,
		},
		{
			name:          "shorter unauthenticated refresh does not decrease lifetime",
			initial:       10 * time.Minute,
			response:      time.Second,
			wantUnchanged: true,
		},
		{
			name:         "longer unauthenticated refresh extends lifetime",
			initial:      time.Minute,
			response:     10 * time.Minute,
			wantExtended: true,
		},
		{
			name:     "unsecured success does not start lifetime",
			response: time.Minute,
			wantZero: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 4060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			defer svc.closeSecureResources()
			if !tt.wantZero {
				if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
					t.Fatalf("applyRegisterChallenge() error = %v", err)
				}
			}
			var initialExpiresAt time.Time
			if tt.initial > 0 {
				initialExpiresAt = time.Now().Add(tt.initial)
				svc.extendActiveSecureAssociationLifetime(initialExpiresAt)
			}

			resp := newResponse(svc.buildRegister(nil, nil), 200, "OK", sip.Header{Name: "Expires", Value: strconv.Itoa(int(tt.response / time.Second))})
			svc.applyRegisterSuccess(resp)
			got := svc.currentSecureAssociationExpiresAt()

			switch {
			case tt.wantZero:
				if !got.IsZero() {
					t.Fatalf("secure association expires at = %v, want zero", got)
				}
			case tt.wantUnchanged:
				if !got.Equal(initialExpiresAt) {
					t.Fatalf("secure association expires at = %v, want unchanged %v", got, initialExpiresAt)
				}
			case tt.wantExtended:
				if got.IsZero() {
					t.Fatal("secure association expires at is zero, want scheduled lifetime")
				}
				if !initialExpiresAt.IsZero() && !got.After(initialExpiresAt) {
					t.Fatalf("secure association expires at = %v, want after %v", got, initialExpiresAt)
				}
			}
		})
	}
}

func TestSecureAssociationLifetimeUsesIMSGrace(t *testing.T) {
	tests := []struct {
		name    string
		secured bool
		expires time.Duration
		want    time.Duration
	}{
		{name: "secured registration lifetime adds ims grace", secured: true, expires: 2 * time.Minute, want: 2*time.Minute + secureAssociationLifetimeGrace},
		{name: "unsecured registration has no secure lifetime", expires: 2 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newTCPTransport(5062, 4060)
			svc := newTestService(t, Config{}, transport, stubCard{})
			if tt.secured {
				if _, err := svc.applyRegisterChallenge(newUnauthorizedRegisterResponse(svc.buildRegister(nil, nil), testNonce, 4060)); err != nil {
					t.Fatalf("applyRegisterChallenge() error = %v", err)
				}
			}
			svc.setRegisterExpires(tt.expires)

			now := time.Unix(1000, 0)
			got := svc.secureAssociationExpiresAt(now)
			if tt.want == 0 {
				if !got.IsZero() {
					t.Fatalf("secureAssociationExpiresAt() = %v, want zero", got)
				}
				return
			}
			want := now.Add(tt.want)
			if !got.Equal(want) {
				t.Fatalf("secureAssociationExpiresAt() = %v, want %v", got, want)
			}
		})
	}
}

func TestSecureAssociationLifetimeExpiryClosesSecureResources(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "active secure resources close and registration event is published"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newTCPTransport(5062, 4060)
			activeInbound := newTCPTransport(5063, 4060)
			sess, err := session.Open(session.Config{}, primary)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			activeAttachment, err := sess.AddTransport(activeInbound)
			if err != nil {
				t.Fatalf("AddTransport(active) error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			svc.setRegistered(true)
			svc.replaceSecureServerAttachments([]session.Attachment{activeAttachment})
			svc.extendActiveSecureAssociationLifetime(time.Now().Add(10 * time.Millisecond))

			select {
			case err := <-svc.registrationEvents:
				if !errors.Is(err, errSecureSAExpired) {
					t.Fatalf("registration event = %v, want %v", err, errSecureSAExpired)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for secure association expiry event")
			}

			waitForCloseCount(t, activeInbound, 1)
			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
			if got := svc.currentSecureAssociationExpiresAt(); !got.IsZero() {
				t.Fatalf("secure association expires at = %v, want zero", got)
			}
			if got := closeCount(primary); got != 0 {
				t.Fatalf("primary closeCount = %d, want 0", got)
			}
		})
	}
}

func TestSecureAssociationLifetimeExtensionCancelsStaleExpiry(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "extended lifetime keeps resources active"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newTCPTransport(5062, 4060)
			activeInbound := newTCPTransport(5063, 4060)
			sess, err := session.Open(session.Config{}, primary)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			activeAttachment, err := sess.AddTransport(activeInbound)
			if err != nil {
				t.Fatalf("AddTransport(active) error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer svc.closeSecureResources()

			svc.setRegistered(true)
			svc.replaceSecureServerAttachments([]session.Attachment{activeAttachment})
			svc.extendActiveSecureAssociationLifetime(time.Now().Add(20 * time.Millisecond))
			svc.extendActiveSecureAssociationLifetime(time.Now().Add(time.Hour))

			select {
			case err := <-svc.registrationEvents:
				t.Fatalf("registration event = %v, want none", err)
			case <-time.After(80 * time.Millisecond):
			}
			if !svc.State().Registered {
				t.Fatal("Registered = false, want true")
			}
			if got := closeCount(activeInbound); got != 0 {
				t.Fatalf("active inbound closeCount = %d, want 0", got)
			}
		})
	}
}

func TestSADrainDelayBeforeLifetimeExpiry(t *testing.T) {
	timers := session.TransactionTimers{
		T4: 100 * time.Millisecond,
		TB: 100 * time.Millisecond,
		TD: 100 * time.Millisecond,
		TF: 100 * time.Millisecond,
		TH: 100 * time.Millisecond,
		TJ: 100 * time.Millisecond,
	}
	tests := []struct {
		name      string
		expiresAt time.Time
		want      time.Duration
	}{
		{name: "no lifetime uses transaction drain", want: 100 * time.Millisecond},
		{name: "expired lifetime closes immediately", expiresAt: time.Now().Add(-time.Second), want: 0},
		{name: "later lifetime keeps transaction drain", expiresAt: time.Now().Add(time.Second), want: 100 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := saDrainDelayBefore(tt.expiresAt, timers); got != tt.want {
				t.Fatalf("saDrainDelayBefore() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCloseClosesSecureResources(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "active and draining secure attachments are closed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newTCPTransport(5062, 4060)
			activeInbound := newTCPTransport(5063, 4060)
			drainingInbound := newTCPTransport(5064, 4060)
			sess, err := session.Open(session.Config{}, primary)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			activeAttachment, err := sess.AddTransport(activeInbound)
			if err != nil {
				t.Fatalf("AddTransport(active) error = %v", err)
			}
			drainAttachment, err := sess.AddTransport(drainingInbound)
			if err != nil {
				t.Fatalf("AddTransport(draining) error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			svc.setRegistered(true)
			svc.replaceSecureServerAttachments([]session.Attachment{activeAttachment})
			svc.closeAttachmentsAfter([]session.Attachment{drainAttachment}, time.Hour)

			if err := svc.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}

			if svc.State().Registered {
				t.Fatal("Registered = true, want false")
			}
			if got := closeCount(primary); got != 0 {
				t.Fatalf("primary closeCount = %d, want 0", got)
			}
			if got := closeCount(activeInbound); got != 1 {
				t.Fatalf("active inbound closeCount = %d, want 1", got)
			}
			if got := closeCount(drainingInbound); got != 1 {
				t.Fatalf("draining inbound closeCount = %d, want 1", got)
			}
			svc.mu.Lock()
			gotActive := len(svc.secureServerAttachments)
			gotDrains := len(svc.drainTimers)
			svc.mu.Unlock()
			if gotActive != 0 || gotDrains != 0 {
				t.Fatalf("secure resources = active %d drains %d, want 0", gotActive, gotDrains)
			}
		})
	}
}

func TestCloseAttachmentsAfterClosedServiceClosesImmediately(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "closed service"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			primary := newTCPTransport(5062, 4060)
			draining := newTCPTransport(5064, 4060)
			sess, err := session.Open(session.Config{}, primary)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			attachment, err := sess.AddTransport(draining)
			if err != nil {
				t.Fatalf("AddTransport() error = %v", err)
			}
			svc, err := New(Config{Logger: testLogger()}, sess, stubCard{})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			if err := svc.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
			svc.closeAttachmentsAfter([]session.Attachment{attachment}, time.Hour)
			svc.extendActiveSecureAssociationLifetime(time.Now().Add(time.Hour))

			if got := closeCount(draining); got != 1 {
				t.Fatalf("draining closeCount = %d, want 1", got)
			}
			svc.mu.Lock()
			gotDrains := len(svc.drainTimers)
			expiry := svc.activeSecureSAExpiry
			expiresAt := svc.activeSecureSAExpiresAt
			closed := svc.closed
			svc.mu.Unlock()
			if !closed {
				t.Fatal("closed = false, want true")
			}
			if gotDrains != 0 {
				t.Fatalf("drainTimers = %d, want 0", gotDrains)
			}
			if expiry != nil {
				t.Fatal("activeSecureSAExpiry != nil, want nil")
			}
			if !expiresAt.IsZero() {
				t.Fatalf("activeSecureSAExpiresAt = %v, want zero", expiresAt)
			}
		})
	}
}

func TestEstablishUpgradesSecureTransport(t *testing.T) {
	initial := newTCPTransport(5062, 5060)
	secure := newTCPTransport(45000, 5060)
	serverTCP := newTCPTransport(5063, 45000)
	serverUDP := newUDPTransport(5063, 45000)

	var dialCfg session.SecureTCPConfig
	var listenTCPCfg session.SecureTCPConfig
	var listenUDPCfg session.SecureUDPConfig

	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			dialCfg = cfg
			return secure, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			listenTCPCfg = cfg
			return serverTCP, nil
		},
		ListenSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			listenUDPCfg = cfg
			return serverUDP, nil
		},
	}, initial, stubCard{})

	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=", 4060))
	}
	secure.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "REGISTER" {
			t.Fatalf("unexpected method %q", req.Method())
		}
		secure.queue(newResponse(req, 200, "OK"))
	}

	if err := svc.Establish(context.Background()); err != nil {
		t.Fatalf("Establish() error = %v", err)
	}
	if dialCfg.LocalPort == 0 || listenTCPCfg.LocalPort == 0 || listenUDPCfg.LocalPort == 0 {
		t.Fatalf("secure transport configs not captured: %+v %+v %+v", dialCfg, listenTCPCfg, listenUDPCfg)
	}
	if initial.closeCount != 1 {
		t.Fatalf("initial closeCount = %d, want 1", initial.closeCount)
	}
}

func TestEstablishKeepsPlainTransportWhenSecureInboundSetupFails(t *testing.T) {
	initial := newTCPTransport(5062, 5060)
	secure := newTCPTransport(45000, 5060)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return secure, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return nil, errors.New("listen rejected")
		},
	}, initial, stubCard{})

	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, testNonce, 4060))
	}

	err := svc.Establish(context.Background())
	if err == nil {
		t.Fatal("Establish() error = nil, want secure inbound setup error")
	}
	if !strings.Contains(err.Error(), "listen rejected") {
		t.Fatalf("Establish() error = %v, want listen rejected", err)
	}
	if svc.sess.LocalAddr() != initial.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want initial transport %v", svc.sess.LocalAddr(), initial.LocalAddr())
	}
	if got := closeCount(initial); got != 0 {
		t.Fatalf("initial closeCount = %d, want 0", got)
	}
	if got := closeCount(secure); got != 1 {
		t.Fatalf("secure closeCount = %d, want 1", got)
	}
}

func TestRegisterFailureDeletesIncompleteSecurityAssociations(t *testing.T) {
	initial := newTCPTransport(5062, 5060)
	outbound := newTCPTransport(45000, 4060)
	inbound := newTCPTransport(5063, 45000)
	svc := newTestService(t, Config{
		DialSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return outbound, nil
		},
		ListenSecureTCP: func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error) {
			return inbound, nil
		},
	}, initial, stubCard{})

	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, testNonce, 4060))
	}
	outbound.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		outbound.queue(newResponse(req, 403, "Forbidden"))
	}

	err := svc.Register(context.Background())
	if err == nil {
		t.Fatal("Register() error = nil, want registration failure")
	}
	if !errors.Is(err, errInitialRegistrationNeeded) {
		t.Fatalf("Register() error = %v, want %v", err, errInitialRegistrationNeeded)
	}
	if got := closeCount(outbound); got != 1 {
		t.Fatalf("outbound closeCount = %d, want incomplete SA closed", got)
	}
	if got := closeCount(inbound); got != 1 {
		t.Fatalf("inbound closeCount = %d, want incomplete SA closed", got)
	}
	if got := closeCount(initial); got != 0 {
		t.Fatalf("initial closeCount = %d, want plain transport retained", got)
	}
	if svc.sess.LocalAddr() != initial.LocalAddr() {
		t.Fatalf("LocalAddr() = %v, want initial transport %v", svc.sess.LocalAddr(), initial.LocalAddr())
	}
}

func TestEstablishUpgradesSecureUDPTransport(t *testing.T) {
	initial := newUDPTransport(5062, 5060)
	secure := newUDPTransport(45000, 5060)
	serverUDP := newUDPTransport(5063, 45000)

	var dialCfg session.SecureUDPConfig
	var listenUDPCfg session.SecureUDPConfig

	svc := newTestService(t, Config{
		DialSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			dialCfg = cfg
			return secure, nil
		},
		ListenSecureUDP: func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error) {
			listenUDPCfg = cfg
			return serverUDP, nil
		},
	}, initial, stubCard{})

	initial.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		initial.queue(newUnauthorizedRegisterResponse(req, "AQEBAQEBAQEBAQEBAQEBAgICAgICAgICAgICAgICAgI=", 4060))
	}
	secure.onWrite = func(data []byte) {
		req := mustParseMessage(t, data)
		if req.Method() != "REGISTER" {
			t.Fatalf("unexpected method %q", req.Method())
		}
		serverUDP.queue(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := svc.Establish(ctx); err != nil {
		t.Fatalf("Establish() error = %v", err)
	}
	if dialCfg.LocalPort == 0 || listenUDPCfg.LocalPort == 0 {
		t.Fatalf("secure UDP configs not captured: %+v %+v", dialCfg, listenUDPCfg)
	}
	if initial.closeCount != 1 {
		t.Fatalf("initial closeCount = %d, want 1", initial.closeCount)
	}
}
