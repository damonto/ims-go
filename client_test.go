package ims

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	imssession "github.com/damonto/ims-go/ims/session"
	imssip "github.com/damonto/ims-go/ims/sip"
	imssms "github.com/damonto/ims-go/ims/sms"
	imsussd "github.com/damonto/ims-go/ims/ussd"
	imsvoice "github.com/damonto/ims-go/ims/voice"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
	usim "github.com/damonto/wwan-go/sim"
	usimcard "github.com/damonto/wwan-go/sim/card"
	"github.com/damonto/wwan-go/sim/simfile"
)

type stubCard struct{}

type plmnTestCard struct {
	stubCard
	mcc string
	mnc string
}

func (c plmnTestCard) MCC() string { return c.mcc }
func (c plmnTestCard) MNC() string { return c.mnc }
func (c plmnTestCard) MNCLength() int {
	return len(c.mnc)
}

type testTunnelBackoffError struct {
	delay       time.Duration
	deactivated bool
	scope       swutunnel.BackoffScope
}

type testTunnelBackoffDeactivatedError struct{}

type testTransportFailure struct {
	err error
}

func (e testTunnelBackoffError) Error() string {
	return "ePDG backoff"
}

func (e testTunnelBackoffError) BackoffDelay() time.Duration {
	return e.delay
}

func (e testTunnelBackoffError) BackoffDeactivated() bool {
	return e.deactivated
}

func (e testTunnelBackoffError) BackoffPolicy() swutunnel.BackoffPolicy {
	return swutunnel.BackoffPolicy{
		Delay:       e.delay,
		Deactivated: e.deactivated,
		Scope:       e.scope,
	}
}

func (testTunnelBackoffDeactivatedError) Error() string {
	return "ePDG backoff deactivated"
}

func (testTunnelBackoffDeactivatedError) BackoffDeactivated() bool {
	return true
}

func (testTunnelBackoffDeactivatedError) BackoffPolicy() swutunnel.BackoffPolicy {
	return swutunnel.BackoffPolicy{
		Deactivated: true,
		Scope:       swutunnel.BackoffScopeEPDG,
	}
}

func (e testTransportFailure) Error() string {
	return e.err.Error()
}

func (e testTransportFailure) Unwrap() error {
	return e.err
}

func (testTransportFailure) TransportFailed() bool {
	return true
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func testRegistrationConfig(transport imssession.Transport) registration.Config {
	return registration.Config{
		Logger:                    testLogger(),
		IPSecIntegrityAlgorithms:  []string{"hmac-sha-1-96"},
		IPSecEncryptionAlgorithms: []string{"null", "aes-cbc"},
		IPSecModes:                []string{"trans", "UDP-enc-tun"},
		DialSecureUDP: func(ctx context.Context, cfg imssession.SecureUDPConfig) (imssession.Transport, error) {
			return transport, nil
		},
		DialSecureTCP: func(ctx context.Context, cfg imssession.SecureTCPConfig) (imssession.Transport, error) {
			return transport, nil
		},
	}
}

func (stubCard) ICCID() string  { return "8986000000000000000" }
func (stubCard) IMSI() string   { return "001010123456789" }
func (stubCard) MCC() string    { return "001" }
func (stubCard) MNC() string    { return "001" }
func (stubCard) MNCLength() int { return 3 }
func (stubCard) GID1() string   { return "" }
func (stubCard) GID2() string   { return "" }
func (stubCard) SPN() string    { return "" }
func (stubCard) SMSC() string   { return "+8613800000000" }
func (stubCard) AKA(_ context.Context, _, _ []byte) (usim.AKAResult, error) {
	return usim.AKAResult{
		RES: []byte("12345678"),
		CK:  []byte("client-test-ck"),
		IK:  []byte("client-test-ik"),
	}, nil
}

func (stubCard) EAPAKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error) {
	return stubCard{}.AKA(ctx, rand, autn)
}

type readerStub struct {
	closeCalls        int
	closeErr          error
	listApplications  func(context.Context) ([]usimcard.Application, error)
	getFileAttributes func(context.Context, usimcard.FileRef) (usimcard.FileAttributes, error)
	readTransparent   func(context.Context, usimcard.TransparentRead) ([]byte, error)
	readRecord        func(context.Context, usimcard.RecordRead) ([]byte, error)
	authenticate3G    func(context.Context, usimcard.AuthenticateRequest) ([]byte, error)
	smsPPDownload     func(context.Context, usimcard.SMSPPDownloadRequest) (usimcard.SMSPPDownloadResponse, error)
}

type clientTestPacketConn struct {
	local net.Addr
}

type pcscfReselectingAccessStub struct {
	openErrors  []error
	openCalls   int
	selectCalls int
	selectErr   error
	closeErr    error
}

func (s *pcscfReselectingAccessStub) OpenIMS(context.Context, accessIMSConfig) (imsAccess, error) {
	err := s.openErrors[s.openCalls]
	s.openCalls++
	return imsAccess{}, err
}

func (s *pcscfReselectingAccessStub) Close() error { return s.closeErr }

func (s *pcscfReselectingAccessStub) PCSCFCandidateCount() int { return len(s.openErrors) }

func (s *pcscfReselectingAccessStub) SelectNextPCSCF() error {
	s.selectCalls++
	return s.selectErr
}

func (c *clientTestPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, errors.New("ReadFrom was not expected")
}

func (c *clientTestPacketConn) WriteTo([]byte, net.Addr) (int, error) {
	return 0, errors.New("WriteTo was not expected")
}

func (c *clientTestPacketConn) Close() error { return nil }

func (c *clientTestPacketConn) LocalAddr() net.Addr { return c.local }

func (c *clientTestPacketConn) SetDeadline(time.Time) error { return nil }

func (c *clientTestPacketConn) SetReadDeadline(time.Time) error { return nil }

func (c *clientTestPacketConn) SetWriteDeadline(time.Time) error { return nil }

func (r *readerStub) ListApplications(ctx context.Context) ([]usimcard.Application, error) {
	if r.listApplications == nil {
		return nil, errors.New("ListApplications was not expected")
	}
	return r.listApplications(ctx)
}

func (r *readerStub) FileAttributes(ctx context.Context, file usimcard.FileRef) (usimcard.FileAttributes, error) {
	if r.getFileAttributes == nil {
		return usimcard.FileAttributes{}, errors.New("FileAttributes was not expected")
	}
	return r.getFileAttributes(ctx, file)
}

func (r *readerStub) ReadTransparent(ctx context.Context, req usimcard.TransparentRead) ([]byte, error) {
	if r.readTransparent == nil {
		return nil, errors.New("ReadTransparent was not expected")
	}
	return r.readTransparent(ctx, req)
}

func (r *readerStub) ReadRecord(ctx context.Context, req usimcard.RecordRead) ([]byte, error) {
	if r.readRecord == nil {
		return nil, errors.New("ReadRecord was not expected")
	}
	return r.readRecord(ctx, req)
}

func (r *readerStub) Authenticate3G(ctx context.Context, req usimcard.AuthenticateRequest) ([]byte, error) {
	if r.authenticate3G == nil {
		return nil, errors.New("Authenticate3G was not expected")
	}
	return r.authenticate3G(ctx, req)
}

func (r *readerStub) SMSPPDownload(ctx context.Context, req usimcard.SMSPPDownloadRequest) (usimcard.SMSPPDownloadResponse, error) {
	if r.smsPPDownload == nil {
		return usimcard.SMSPPDownloadResponse{}, errors.New("SMSPPDownload was not expected")
	}
	return r.smsPPDownload(ctx, req)
}

func (r *readerStub) Close() error {
	r.closeCalls++
	return r.closeErr
}

func TestOpenIMSWithPCSCFFailover(t *testing.T) {
	tests := []struct {
		name            string
		firstErr        error
		secondErr       error
		selectErr       error
		wantOpenCalls   int
		wantSelectCalls int
		wantSecondErr   bool
	}{
		{
			name:            "Timer F selects next P-CSCF",
			firstErr:        &imssession.TransactionTimeoutError{Method: "REGISTER", Timer: "F"},
			wantOpenCalls:   2,
			wantSelectCalls: 1,
			wantSecondErr:   true,
		},
		{
			name:            "fatal transport failure selects next P-CSCF",
			firstErr:        testTransportFailure{err: errors.New("peer reset connection")},
			wantOpenCalls:   2,
			wantSelectCalls: 1,
			wantSecondErr:   true,
		},
		{
			name:            "504 selects next P-CSCF",
			firstErr:        fmt.Errorf("registering IMS: %w", &imssip.ResponseError{StatusCode: 504, ReasonPhrase: "Server Time-out"}),
			wantOpenCalls:   2,
			wantSelectCalls: 1,
			wantSecondErr:   true,
		},
		{
			name:            "503 without Retry-After selects next P-CSCF",
			firstErr:        fmt.Errorf("registering IMS: %w", &imssip.ResponseError{StatusCode: 503, ReasonPhrase: "Service Unavailable"}),
			wantOpenCalls:   2,
			wantSelectCalls: 1,
			wantSecondErr:   true,
		},
		{
			name:            "500 without Retry-After selects next P-CSCF",
			firstErr:        fmt.Errorf("registering IMS: %w", &imssip.ResponseError{StatusCode: 500, ReasonPhrase: "Server Internal Error"}),
			wantOpenCalls:   2,
			wantSelectCalls: 1,
			wantSecondErr:   true,
		},
		{
			name:          "ordinary error keeps current P-CSCF",
			firstErr:      errors.New("opening SIP transport"),
			wantOpenCalls: 1,
		},
		{
			name:            "last candidate timeout does not wrap to first P-CSCF",
			firstErr:        &imssession.TransactionTimeoutError{Method: "REGISTER", Timer: "F"},
			secondErr:       &imssession.TransactionTimeoutError{Method: "REGISTER", Timer: "F"},
			wantOpenCalls:   2,
			wantSelectCalls: 1,
			wantSecondErr:   true,
		},
		{
			name:            "P-CSCF selection error stops retry",
			firstErr:        &imssession.TransactionTimeoutError{Method: "REGISTER", Timer: "F"},
			selectErr:       errors.New("closing previous LTE IPsec session"),
			wantOpenCalls:   1,
			wantSelectCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lastErr := tt.secondErr
			if lastErr == nil {
				lastErr = errors.New("second P-CSCF rejected registration")
			}
			access := &pcscfReselectingAccessStub{
				openErrors: []error{tt.firstErr, lastErr},
				selectErr:  tt.selectErr,
			}
			setup := &connectSetup{access: access}

			err := (&Client{}).openIMSWithPCSCFFailover(context.Background(), setup)
			if tt.wantSecondErr && !errors.Is(err, lastErr) {
				t.Fatalf("openIMSWithPCSCFFailover() error = %v, want second P-CSCF error", err)
			}
			if tt.selectErr != nil && !errors.Is(err, tt.selectErr) {
				t.Fatalf("openIMSWithPCSCFFailover() error = %v, want selection error", err)
			}
			if !errors.Is(err, tt.firstErr) {
				t.Fatalf("openIMSWithPCSCFFailover() error = %v, want first error", err)
			}
			if tt.wantOpenCalls > 1 {
				for attempt := 1; attempt <= tt.wantOpenCalls; attempt++ {
					want := fmt.Sprintf("connecting P-CSCF attempt %d", attempt)
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("openIMSWithPCSCFFailover() error = %v, want %q", err, want)
					}
				}
			}
			if access.openCalls != tt.wantOpenCalls {
				t.Fatalf("OpenIMS() calls = %d, want %d", access.openCalls, tt.wantOpenCalls)
			}
			if access.selectCalls != tt.wantSelectCalls {
				t.Fatalf("SelectNextPCSCF() calls = %d, want %d", access.selectCalls, tt.wantSelectCalls)
			}
		})
	}
}

func TestRestoreIMSWithNextLTEPCSCFTriesAllRemainingCandidates(t *testing.T) {
	tests := []struct {
		name               string
		remaining          int
		wantOpenCalls      int
		wantSelectionCalls int
	}{
		{name: "three remaining candidates", remaining: 3, wantOpenCalls: 3, wantSelectionCalls: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			openErrors := make([]error, tt.remaining)
			for i := range openErrors {
				openErrors[i] = &imssession.TransactionTimeoutError{Method: "REGISTER", Timer: "F"}
			}
			access := &pcscfReselectingAccessStub{openErrors: openErrors}
			client := newClient(Config{Logger: slog.Default()})
			active := &activeConn{scope: newConnectionScope(), access: access}

			if _, err := client.restoreIMSWithNextLTEPCSCF(active, access); err == nil {
				t.Fatal("restoreIMSWithNextLTEPCSCF() error = nil, want exhausted candidates error")
			}
			if access.openCalls != tt.wantOpenCalls {
				t.Fatalf("OpenIMS() calls = %d, want %d", access.openCalls, tt.wantOpenCalls)
			}
			if access.selectCalls != tt.wantSelectionCalls {
				t.Fatalf("SelectNextPCSCF() calls = %d, want %d", access.selectCalls, tt.wantSelectionCalls)
			}
		})
	}
}

func TestConnectSetupRollbackReturnsCleanupErrors(t *testing.T) {
	imsErr := errors.New("closing IMS transport")
	accessErr := errors.New("closing access")
	tests := []struct {
		name      string
		imsErr    error
		accessErr error
	}{
		{name: "clean rollback"},
		{name: "joins IMS and access errors", imsErr: imsErr, accessErr: accessErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newGatedCancelTransport(5062, 5060)
			transport.closeErr = tt.imsErr
			sess, err := imssession.Open(imssession.Config{}, transport)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			scope := newConnectionScope()
			setup := &connectSetup{
				scope:  scope,
				access: &pcscfReselectingAccessStub{closeErr: tt.accessErr},
				ims:    imsStack{sip: sess},
			}

			err = setup.rollback()
			for _, want := range []error{tt.imsErr, tt.accessErr} {
				if want != nil && !errors.Is(err, want) {
					t.Fatalf("rollback() error = %v, want wrapped %v", err, want)
				}
			}
			if tt.imsErr == nil && tt.accessErr == nil && err != nil {
				t.Fatalf("rollback() error = %v, want nil", err)
			}
			if !scope.stopped() {
				t.Fatal("rollback() left connection scope running")
			}
		})
	}
}

func TestConnectSetupCloseIMSAfterFailurePreservesCause(t *testing.T) {
	cause := errors.New("opening IMS endpoints")
	cleanupErr := errors.New("closing IMS transport")
	tests := []struct {
		name       string
		cleanupErr error
	}{
		{name: "clean close keeps original cause"},
		{name: "failed close joins cleanup error", cleanupErr: cleanupErr},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newGatedCancelTransport(5062, 5060)
			transport.closeErr = tt.cleanupErr
			sess, err := imssession.Open(imssession.Config{}, transport)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			setup := &connectSetup{ims: imsStack{sip: sess}}

			err = setup.closeIMSAfterFailure(cause)
			if !errors.Is(err, cause) {
				t.Fatalf("closeIMSAfterFailure() error = %v, want original cause", err)
			}
			if tt.cleanupErr != nil && !errors.Is(err, tt.cleanupErr) {
				t.Fatalf("closeIMSAfterFailure() error = %v, want cleanup error", err)
			}
		})
	}
}

func TestCurrentServicesReturnConnectionErrorStatus(t *testing.T) {
	tests := []struct {
		name         string
		status       ClientStatus
		lastErr      error
		connecting   bool
		reconnecting bool
		closed       bool
		active       bool
		wantErr      error
		call         func(*Client) error
	}{
		{
			name:         "sms",
			status:       StatusReconnecting,
			lastErr:      errors.New("transport dropped"),
			reconnecting: true,
			wantErr:      ErrClientReconnecting,
			call: func(client *Client) error {
				_, err := client.currentSMSClient()
				return err
			},
		},
		{
			name:       "ussd",
			status:     StatusFailed,
			lastErr:    errors.New("registration failed"),
			connecting: true,
			wantErr:    ErrClientConnecting,
			call: func(client *Client) error {
				_, err := client.currentUSSDClient()
				return err
			},
		},
		{
			name:    "voice",
			status:  StatusClosed,
			closed:  true,
			wantErr: ErrClientClosed,
			call: func(client *Client) error {
				_, err := client.currentVoiceClient()
				return err
			},
		},
		{
			name:    "active missing sms service",
			status:  StatusRegistered,
			active:  true,
			wantErr: ErrClientNotConnected,
			call: func(client *Client) error {
				_, err := client.currentSMSClient()
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newClient(Config{Logger: testLogger()})
			client.emitStatusError(tt.status, tt.lastErr)
			setClientState(t, client, clientStateSetup{
				connecting:   tt.connecting,
				reconnecting: tt.reconnecting,
				closed:       tt.closed,
				active:       tt.active,
			})

			err := tt.call(client)
			if !errors.Is(err, ErrClientNotConnected) {
				t.Fatalf("error = %v, want ErrClientNotConnected", err)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", err, tt.wantErr)
			}
			var connErr *ConnectionError
			if !errors.As(err, &connErr) {
				t.Fatalf("error type = %T, want *ConnectionError", err)
			}
			if connErr.Status() != tt.status {
				t.Fatalf("ConnectionError.Status() = %s, want %s", connErr.Status(), tt.status)
			}
			if connErr.State.Status != tt.status {
				t.Fatalf("ConnectionError.State.Status = %s, want %s", connErr.State.Status, tt.status)
			}
			if !errors.Is(connErr.State.LastError, tt.lastErr) {
				t.Fatalf("ConnectionError.State.LastError = %v, want %v", connErr.State.LastError, tt.lastErr)
			}
			if connErr.State.Connecting != tt.connecting {
				t.Fatalf("ConnectionError.State.Connecting = %v, want %v", connErr.State.Connecting, tt.connecting)
			}
			if connErr.State.Reconnecting != tt.reconnecting {
				t.Fatalf("ConnectionError.State.Reconnecting = %v, want %v", connErr.State.Reconnecting, tt.reconnecting)
			}
			if connErr.State.Closed != tt.closed {
				t.Fatalf("ConnectionError.State.Closed = %v, want %v", connErr.State.Closed, tt.closed)
			}
		})
	}
}

func TestCurrentVoiceClientRejectsInactiveTunnel(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "active tunnel is not connected"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newClient(Config{Logger: testLogger()})
			session, err := swutunnel.Dial(context.Background(), swutunnel.Config{
				RemoteAddr: "198.51.100.1",
				PacketConn: &clientTestPacketConn{
					local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				},
				Logger: testLogger(),
			})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			client.emitStatus(StatusRegistered)
			setClientActive(t, client, &activeConn{
				tunnel: session,
				ims: imsStack{
					voice: new(imsvoice.Endpoint),
				},
			})

			_, err = client.currentVoiceClient()
			if !errors.Is(err, ErrClientNotConnected) {
				t.Fatalf("currentVoiceClient() error = %v, want ErrClientNotConnected", err)
			}
			if !strings.Contains(err.Error(), "tunnel not ready") || !strings.Contains(err.Error(), "child sa is unavailable") {
				t.Fatalf("currentVoiceClient() error = %v, want tunnel not ready cause", err)
			}
		})
	}
}

func TestEmitStatusErrorRecordsStateAndPublishesEvents(t *testing.T) {
	tests := []struct {
		name   string
		status ClientStatus
		err    error
	}{
		{
			name:   "failed",
			status: StatusFailed,
			err:    errors.New("registration dropped"),
		},
		{
			name:   "reconnecting",
			status: StatusReconnecting,
			err:    errors.New("transport dropped"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newClient(Config{Logger: testLogger()})
			events := client.Events()
			defer events.Close()

			client.emitStatusError(tt.status, tt.err)

			state := client.State()
			if state.Status != tt.status {
				t.Fatalf("State().Status = %s, want %s", state.Status, tt.status)
			}
			if !errors.Is(state.LastError, tt.err) {
				t.Fatalf("State().LastError = %v, want %v", state.LastError, tt.err)
			}

			select {
			case got := <-events.Errors:
				if !errors.Is(got, tt.err) {
					t.Fatalf("error event = %v, want %v", got, tt.err)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for error event")
			}

			select {
			case got := <-events.State:
				if got.Status != tt.status {
					t.Fatalf("state event status = %s, want %s", got.Status, tt.status)
				}
				if !errors.Is(got.LastError, tt.err) {
					t.Fatalf("state event LastError = %v, want %v", got.LastError, tt.err)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out waiting for state event")
			}
		})
	}
}

type gatedCancelTransport struct {
	local  net.Addr
	remote net.Addr

	mu                sync.Mutex
	writes            [][]byte
	onWrite           func([]byte)
	readCh            chan []byte
	readErrCh         chan error
	cancelReadRelease chan struct{}
	closed            bool
	closeErr          error
}

func newGatedCancelTransport(localPort, remotePort int) *gatedCancelTransport {
	return &gatedCancelTransport{
		local:             &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote:            &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh:            make(chan []byte, 16),
		readErrCh:         make(chan error, 1),
		cancelReadRelease: make(chan struct{}),
	}
}

func (t *gatedCancelTransport) LocalAddr() net.Addr  { return t.local }
func (t *gatedCancelTransport) RemoteAddr() net.Addr { return t.remote }

func (t *gatedCancelTransport) WritePacket(_ context.Context, data []byte) error {
	t.mu.Lock()
	closed := t.closed
	if !closed {
		t.writes = append(t.writes, append([]byte(nil), data...))
	}
	onWrite := t.onWrite
	t.mu.Unlock()
	if closed {
		return net.ErrClosed
	}
	if onWrite != nil {
		onWrite(data)
	}
	return nil
}

func (t *gatedCancelTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	case err := <-t.readErrCh:
		return nil, nil, err
	case <-ctx.Done():
		<-t.cancelReadRelease
		return nil, nil, ctx.Err()
	}
}

func (t *gatedCancelTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	err := t.closeErr
	t.mu.Unlock()
	select {
	case <-t.cancelReadRelease:
	default:
		close(t.cancelReadRelease)
	}
	return err
}

func (t *gatedCancelTransport) queueRead(msg imssip.Message) {
	t.readCh <- marshalSIPMessageForTest(msg)
}

func marshalSIPMessageForTest(msg imssip.Message) []byte {
	data, err := msg.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return data
}

func (t *gatedCancelTransport) failRead(err error) {
	t.readErrCh <- err
}

func (t *gatedCancelTransport) writeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}

const (
	testIMEI              = "356789012345678"
	fakeIMSSecurityServer = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5063;prot=esp;spi-c=0000000310;spi-s=0000000320"
)

func newStandaloneClient(t *testing.T) *Client {
	t.Helper()
	return newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
		IMS: IMSConfig{
			RegisterExpires: time.Minute,
		},
	})
}

func newReadyClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	cfg = withTestIPSecAlgorithms(cfg)
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	client := newClient(cfg)
	normalized, err := cfg.normalized(stubCard{})
	if err != nil {
		t.Fatalf("Config.normalized() error = %v", err)
	}
	client.card = stubCard{}
	client.cfg = normalized
	client.logger = normalized.Logger.With("component", "ims-go")
	return client
}

type clientStateSetup struct {
	connecting   bool
	reconnecting bool
	closed       bool
	active       bool
}

func setClientState(t *testing.T, client *Client, setup clientStateSetup) {
	t.Helper()
	client.state.mu.Lock()
	client.state.connecting = setup.connecting
	client.state.reconnecting = setup.reconnecting
	client.state.closed = setup.closed
	if setup.active {
		client.state.active = &activeConn{}
	}
	client.state.mu.Unlock()
}

func setClientActive(t *testing.T, client *Client, active *activeConn) {
	t.Helper()
	client.state.mu.Lock()
	client.state.active = active
	client.state.mu.Unlock()
}

func currentClientActive(t *testing.T, client *Client) *activeConn {
	t.Helper()
	client.state.mu.Lock()
	active := client.state.active
	client.state.mu.Unlock()
	return active
}

func clientDone(t *testing.T, client *Client) <-chan struct{} {
	t.Helper()
	client.state.mu.Lock()
	done := client.state.done
	client.state.mu.Unlock()
	return done
}

func testNonce() string {
	return base64.StdEncoding.EncodeToString(append(bytesOf(0x01, 16), bytesOf(0x02, 16)...))
}

func newIMSResponse(req imssip.Message, code int, reason string) imssip.Message {
	res := imssip.NewResponse(code, reason)
	res.Headers = responseHeaders(req)
	return res
}

func newUnauthorizedRegisterResponse(req imssip.Message, nonce string) imssip.Message {
	res := newIMSResponse(req, 401, "Unauthorized")
	res.Headers.Add("WWW-Authenticate", fmt.Sprintf(`Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="%s",algorithm=AKAv1-MD5`, nonce))
	res.Headers.Add("Security-Server", fakeIMSSecurityServer)
	return res
}

func newRegisteredIMS(t *testing.T, transport *gatedCancelTransport, registerExpires time.Duration) (*imssession.Session, *registration.Registrar) {
	t.Helper()
	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	cfg := testRegistrationConfig(transport)
	cfg.RegisterExpires = registerExpires
	reg, err := registration.New(cfg, sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}
	return sess, reg
}

func TestSMSEventsFanOut(t *testing.T) {
	client := newStandaloneClient(t)

	smsEventsA := client.SMS().Events()
	defer smsEventsA.Close()
	smsEventsB := client.SMS().Events()
	defer smsEventsB.Close()

	client.handleSMS(imssms.Incoming{CallID: "sms-call-id", From: "+1", FromURI: "sip:+1@example.net", To: "+2", ToURI: "sip:+2@example.net", ServiceCenter: "+3", Text: "hello"})

	for i, events := range []*SMSEvents{smsEventsA, smsEventsB} {
		select {
		case msg := <-events.Incoming:
			if msg.Text != "hello" {
				t.Fatalf("subscriber %d msg = %+v", i, msg)
			}
			if msg.CallID != "sms-call-id" {
				t.Fatalf("subscriber %d msg.CallID = %q, want sms-call-id", i, msg.CallID)
			}
			if msg.From != "+1" || msg.FromURI != "sip:+1@example.net" {
				t.Fatalf("subscriber %d sender = %q/%q, want +1/sip:+1@example.net", i, msg.From, msg.FromURI)
			}
			if msg.To != "+2" || msg.ToURI != "sip:+2@example.net" {
				t.Fatalf("subscriber %d recipient = %q/%q, want +2/sip:+2@example.net", i, msg.To, msg.ToURI)
			}
		case <-time.After(time.Second):
			t.Fatalf("waiting for sms subscriber %d", i)
		}
	}
}

func TestBroadcasterConcurrentPublishAndClose(t *testing.T) {
	for range 100 {
		b := newBroadcaster[int]()
		subs := make([]broadcastSubscription[int], 64)
		for i := range subs {
			subs[i] = b.subscribe(1)
		}

		start := make(chan struct{})
		var wg sync.WaitGroup
		for range 16 {
			wg.Go(func() {
				<-start
				for n := range 50 {
					b.publish(n, nil)
				}
			})
		}
		for _, sub := range subs[:len(subs)/2] {
			wg.Add(1)
			go func(sub broadcastSubscription[int]) {
				defer wg.Done()
				<-start
				sub.close()
			}(sub)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			b.close()
		}()

		close(start)
		done := make(chan struct{})
		go func() {
			wg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("waiting for concurrent broadcaster close")
		}
	}
}

type eventCounts struct {
	state       int
	errors      int
	smsIncoming int
	smsReports  int
	ussd        int
	voiceIn     int
	voiceEvents int
}

func TestEventsUseRequestedBroadcasters(t *testing.T) {
	tests := []struct {
		name string
		open func(*Client) func()
		want eventCounts
	}{
		{
			name: "client events",
			open: func(c *Client) func() {
				events := c.Events()
				return events.Close
			},
			want: eventCounts{state: 1, errors: 1},
		},
		{
			name: "sms events",
			open: func(c *Client) func() {
				events := c.SMS().Events()
				return events.Close
			},
			want: eventCounts{smsIncoming: 1, smsReports: 1},
		},
		{
			name: "ussd events",
			open: func(c *Client) func() {
				events := c.USSD().Events()
				return events.Close
			},
			want: eventCounts{ussd: 1},
		},
		{
			name: "voice events",
			open: func(c *Client) func() {
				events := c.Voice().Events()
				return events.Close
			},
			want: eventCounts{voiceIn: 1, voiceEvents: 1},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newStandaloneClient(t)
			closeEvents := tt.open(client)
			if got := eventSubscriberCounts(t, client); got != tt.want {
				t.Fatalf("subscriber counts = %+v, want %+v", got, tt.want)
			}

			closeEvents()
			if got := eventSubscriberCounts(t, client); got != (eventCounts{}) {
				t.Fatalf("subscriber counts after close = %+v, want zero", got)
			}
		})
	}
}

func eventSubscriberCounts(t *testing.T, c *Client) eventCounts {
	t.Helper()
	return eventCounts{
		state:       broadcasterSubscriberCount(t, &c.events.state),
		errors:      broadcasterSubscriberCount(t, &c.events.errors),
		smsIncoming: broadcasterSubscriberCount(t, &c.events.smsIncoming),
		smsReports:  broadcasterSubscriberCount(t, &c.events.smsReports),
		ussd:        broadcasterSubscriberCount(t, &c.events.ussd),
		voiceIn:     broadcasterSubscriberCount(t, &c.events.voiceIn),
		voiceEvents: broadcasterSubscriberCount(t, &c.events.voiceEvents),
	}
}

func broadcasterSubscriberCount[T any](t *testing.T, b *broadcaster[T]) int {
	t.Helper()
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

func TestHandleUSSDEventFanOutUsesWrapper(t *testing.T) {
	client := newStandaloneClient(t)

	eventsA := client.USSD().Events()
	defer eventsA.Close()
	eventsB := client.USSD().Events()
	defer eventsB.Close()

	low := &imsussd.Session{}
	client.handleUSSD(low, imsussd.Message{Text: "Enter PIN", Language: "en", Request: true})

	var first *IncomingUSSD
	for i, events := range []*USSDEvents{eventsA, eventsB} {
		select {
		case event := <-events.Incoming:
			if event.Message.Text != "Enter PIN" || !event.Message.Request {
				t.Fatalf("event.Message = %+v", event.Message)
			}
			if event.Session == nil {
				t.Fatalf("subscriber %d session = nil", i)
			}
			if first == nil {
				first = &event
				continue
			}
			if event.Session != first.Session {
				t.Fatal("subscribers received different session wrappers")
			}
		case <-time.After(time.Second):
			t.Fatalf("waiting for ussd subscriber %d", i)
		}
	}

	client.handleUSSD(low, imsussd.Message{Text: "Next", Language: "en", Request: true})
	select {
	case event := <-eventsA.Incoming:
		if event.Session != first.Session {
			t.Fatal("reused low session did not reuse wrapper")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for second ussd event")
	}
}

func TestHandleSMSStatusReportEvent(t *testing.T) {
	client := newStandaloneClient(t)
	events := client.SMS().Events()
	defer events.Close()
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-7",
		SegmentCount: 2,
		Segments: []SMSSubmissionSegment{
			{Index: 0, Recipient: "+15550000006", ServiceCenter: "+15550000000", TPReference: 6},
			{Index: 1, Recipient: "+15551234567", ServiceCenter: "+15550000000", TPReference: 7},
		},
	}, nil)

	report := imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		Recipient:        "+15551234567",
		MessageReference: 7,
		Status:           0x00,
	}
	client.handleSMSStatusReport(report)

	select {
	case event := <-events.Reports:
		if event.SubmissionID != "sms-7" {
			t.Fatalf("event.SubmissionID = %q, want sms-7", event.SubmissionID)
		}
		if event.SegmentIndex != 1 {
			t.Fatalf("event.SegmentIndex = %d, want 1", event.SegmentIndex)
		}
		if event.SegmentCount != 2 {
			t.Fatalf("event.SegmentCount = %d, want 2", event.SegmentCount)
		}
		if event.ServiceCenter != report.ServiceCenter {
			t.Fatalf("event.ServiceCenter = %q, want %q", event.ServiceCenter, report.ServiceCenter)
		}
		if event.Recipient != report.Recipient {
			t.Fatalf("event.Recipient = %q, want %q", event.Recipient, report.Recipient)
		}
		if event.MessageReference != report.MessageReference {
			t.Fatalf("event.MessageReference = %d, want %d", event.MessageReference, report.MessageReference)
		}
		if event.Status != report.Status {
			t.Fatalf("event.Status = 0x%02X, want 0x%02X", event.Status, report.Status)
		}
		if !event.Status.Delivered() {
			t.Fatalf("event.Status.Delivered() = false, want true")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for SMS status report event")
	}
}

func TestSMSStatusReportRoutesToSubmissionUpdates(t *testing.T) {
	client := newStandaloneClient(t)
	sink := newSMSSubmissionSink(1, true)
	t.Cleanup(sink.cancel)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-7",
		SegmentCount: 1,
		Segments: []SMSSubmissionSegment{
			{Index: 0, Recipient: "+15551234567", ServiceCenter: "+15550000000", CallID: "call-7", RPReference: 3, TPReference: 7},
		},
	}, sink)
	sink.completeSubmit()

	report := imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		Recipient:        "+15551234567",
		MessageReference: 7,
		Status:           imssms.ReportStatusReceivedBySME,
	}
	client.handleSMSStatusReport(report)

	select {
	case update := <-sink.updates:
		if update.SubmissionID != "sms-7" {
			t.Fatalf("update.SubmissionID = %q, want sms-7", update.SubmissionID)
		}
		if update.State != SMSDelivered {
			t.Fatalf("update.State = %q, want %q", update.State, SMSDelivered)
		}
		if !update.HasStatus || update.Status != report.Status {
			t.Fatalf("update status = has %t status %v, want %v", update.HasStatus, update.Status, report.Status)
		}
		if update.CallID != "call-7" || update.RPReference != 3 || update.TPReference != 7 {
			t.Fatalf("update route = call %q rp %d tp %d", update.CallID, update.RPReference, update.TPReference)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for submission update")
	}

	select {
	case _, ok := <-sink.updates:
		if ok {
			t.Fatal("updates channel open after final status report")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for updates channel close")
	}
}

func TestSMSStatusReportLinkIgnoresServiceCenterMismatch(t *testing.T) {
	client := newStandaloneClient(t)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-7",
		SegmentCount: 1,
		Segments: []SMSSubmissionSegment{
			{Index: 0, Recipient: "+15551234567", ServiceCenter: "+15550000000", TPReference: 7},
		},
	}, nil)

	link, ok := client.smsReportLink(imssms.StatusReport{
		ServiceCenter:    "+15559999999",
		Recipient:        "+15551234567",
		MessageReference: 7,
	})
	if !ok {
		t.Fatal("smsReportLink() ok = false")
	}
	if link.submissionID != "sms-7" {
		t.Fatalf("submissionID = %q, want sms-7", link.submissionID)
	}
}

func TestSMSSubmissionSinkDrainsQueuedUpdates(t *testing.T) {
	tests := []struct {
		name  string
		count int
	}{
		{name: "more than channel buffer", count: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sink := newSMSSubmissionSink(1, false)

			for i := range tt.count {
				sink.publish(SMSSubmissionUpdate{SegmentIndex: i})
			}
			sink.finish()

			got := make([]int, 0, tt.count)
			for update := range sink.updates {
				got = append(got, update.SegmentIndex)
			}
			want := make([]int, 0, tt.count)
			for i := range tt.count {
				want = append(want, i)
			}
			if !slices.Equal(got, want) {
				t.Fatalf("update indexes = %v, want %v", got, want)
			}
		})
	}
}

func TestSMSSubmissionSinkWaitsForSubmitUpdatesBeforeFinish(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "delivery finishes before submit stream closes"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newStandaloneClient(t)
			sink := newSMSSubmissionSink(1, true)
			t.Cleanup(sink.cancel)
			lowUpdates := make(chan imssms.SubmissionUpdate, 1)
			forwardDone := make(chan struct{})
			go func() {
				client.forwardSMSSubmitUpdates("sms-1", lowUpdates, sink)
				close(forwardDone)
			}()

			sink.publish(SMSSubmissionUpdate{State: SMSDelivered})
			sink.completeDeliverySegment(0)
			lowUpdates <- imssms.SubmissionUpdate{State: imssms.SubmissionSubmittedToIMS}
			close(lowUpdates)

			var states []SMSSubmissionState
			for update := range sink.updates {
				states = append(states, update.State)
			}
			if !slices.Contains(states, SMSDelivered) {
				t.Fatalf("states = %v, want %s", states, SMSDelivered)
			}
			if !slices.Contains(states, SMSSubmittedToIMS) {
				t.Fatalf("states = %v, want %s", states, SMSSubmittedToIMS)
			}
			select {
			case <-forwardDone:
			case <-time.After(time.Second):
				t.Fatal("waiting for submit forwarder")
			}
		})
	}
}

func TestSMSSubmissionDeliveryTimeoutPublishesUnknownAndCleansTracking(t *testing.T) {
	client := newStandaloneClient(t)
	sink := newSMSSubmissionSink(1, true)
	t.Cleanup(sink.cancel)
	sink.setDeliveryTimeout(20 * time.Millisecond)
	submission := SMSSubmission{
		ID:           "sms-1",
		SegmentCount: 1,
		Segments: []SMSSubmissionSegment{
			{Index: 0, Recipient: "+15551234567", ServiceCenter: "+15550000000", CallID: "call-1", RPReference: 3, TPReference: 8},
		},
		Updates: sink.updates,
	}
	sink.onClose = func() {
		client.untrackSMSSubmission(submission.ID, sink)
	}
	client.trackSMSSubmission(submission, sink)
	sink.completeSubmit()

	select {
	case update := <-submission.Updates:
		if update.State != SMSDeliveryUnknown {
			t.Fatalf("update.State = %q, want %q", update.State, SMSDeliveryUnknown)
		}
		if update.SubmissionID != "sms-1" || update.SegmentIndex != 0 || update.CallID != "call-1" {
			t.Fatalf("update route = %+v", update)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for delivery timeout update")
	}
	select {
	case _, ok := <-submission.Updates:
		if ok {
			t.Fatal("submission.Updates open after delivery timeout")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for submission updates close")
	}

	_, ok := client.smsReportLink(imssms.StatusReport{
		Recipient:        "+15551234567",
		MessageReference: 8,
	})
	if ok {
		t.Fatal("smsReportLink() ok = true after delivery timeout")
	}
}

func TestSMSSubmissionStateString(t *testing.T) {
	tests := []struct {
		name  string
		state SMSSubmissionState
		want  string
	}{
		{name: "submitted to IMS", state: SMSSubmittedToIMS, want: "submitted_to_ims"},
		{name: "accepted by SMSC", state: SMSAcceptedBySMSC, want: "accepted_by_smsc"},
		{name: "rejected by SMSC", state: SMSRejectedBySMSC, want: "rejected_by_smsc"},
		{name: "submit unknown", state: SMSSubmitUnknown, want: "submit_unknown"},
		{name: "delivered", state: SMSDelivered, want: "delivered"},
		{name: "delivery completed", state: SMSDeliveryCompleted, want: "delivery_completed"},
		{name: "delivery retrying", state: SMSDeliveryRetrying, want: "delivery_retrying"},
		{name: "delivery failed", state: SMSDeliveryFailed, want: "delivery_failed"},
		{name: "delivery unknown", state: SMSDeliveryUnknown, want: "delivery_unknown"},
		{name: "unknown", state: SMSSubmissionState(255), want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Fatalf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSMSSubmissionTrackingCleanup(t *testing.T) {
	tests := []struct {
		name   string
		action func(SMSSubmission, *smsSubmissionSink)
	}{
		{
			name: "final state",
			action: func(_ SMSSubmission, sink *smsSubmissionSink) {
				sink.finish()
			},
		},
		{
			name: "caller close",
			action: func(submission SMSSubmission, _ *smsSubmissionSink) {
				submission.Close()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newStandaloneClient(t)
			sink := newSMSSubmissionSink(1, true)
			submission := SMSSubmission{
				ID:           "sms-1",
				SegmentCount: 1,
				Segments: []SMSSubmissionSegment{
					{Index: 0, Recipient: "+15551234567", ServiceCenter: "+15550000000", TPReference: 8},
				},
				Updates: sink.updates,
			}
			sink.onClose = func() {
				client.untrackSMSSubmission(submission.ID, sink)
			}
			submission.closeFn = func() {
				sink.cancel()
			}
			client.trackSMSSubmission(submission, sink)

			report := imssms.StatusReport{
				ServiceCenter:    "+15550000000",
				Recipient:        "+15551234567",
				MessageReference: 8,
			}
			if _, ok := client.smsReportLink(report); !ok {
				t.Fatal("smsReportLink() ok = false before cleanup")
			}

			tt.action(submission, sink)

			if _, ok := client.smsReportLink(report); ok {
				t.Fatal("smsReportLink() ok = true after cleanup")
			}
			select {
			case _, ok := <-submission.Updates:
				if ok {
					t.Fatal("submission.Updates open after cleanup")
				}
			case <-time.After(time.Second):
				t.Fatal("waiting for submission updates close")
			}
		})
	}
}

func TestSMSStatusReportLinkKeepsRetryingReports(t *testing.T) {
	tests := []struct {
		name       string
		status     imssms.ReportStatus
		wantLinked bool
	}{
		{
			name:       "temporary retrying keeps link",
			status:     imssms.ReportStatusRetryingSMEBusy,
			wantLinked: true,
		},
		{
			name:       "final delivered removes link after report",
			status:     imssms.ReportStatusReceivedBySME,
			wantLinked: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newStandaloneClient(t)
			client.trackSMSSubmission(SMSSubmission{
				ID:           "sms-1",
				SegmentCount: 1,
				Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15551234567", ServiceCenter: "+15550000000", TPReference: 8}},
			}, nil)
			report := imssms.StatusReport{
				ServiceCenter:    "+15550000000",
				Recipient:        "+15551234567",
				MessageReference: 8,
				Status:           tt.status,
			}
			client.handleSMSStatusReport(report)
			_, gotLinked := client.smsReportLink(report)
			if gotLinked != tt.wantLinked {
				t.Fatalf("smsReportLink() = %t, want %t", gotLinked, tt.wantLinked)
			}
		})
	}
}

func TestSMSStatusReportSkipsAmbiguousSubmissionUpdates(t *testing.T) {
	client := newStandaloneClient(t)
	first := newSMSSubmissionSink(1, true)
	second := newSMSSubmissionSink(1, true)
	t.Cleanup(first.cancel)
	t.Cleanup(second.cancel)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-1",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15551234567", ServiceCenter: "+15550000000", TPReference: 9}},
	}, first)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-2",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15551234567", ServiceCenter: "+15550000000", TPReference: 9}},
	}, second)

	client.handleSMSStatusReport(imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		Recipient:        "+15551234567",
		MessageReference: 9,
		Status:           imssms.ReportStatusReceivedBySME,
	})

	select {
	case update := <-first.updates:
		t.Fatalf("first update = %+v, want none for ambiguous report", update)
	case update := <-second.updates:
		t.Fatalf("second update = %+v, want none for ambiguous report", update)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestSMSStatusReportLinkMatchesReferenceCollisionsByRoute(t *testing.T) {
	client := newStandaloneClient(t)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-1",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15550000001", ServiceCenter: "+15550000000", TPReference: 9}},
	}, nil)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-2",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15550000002", ServiceCenter: "+15550000000", TPReference: 9}},
	}, nil)

	link, ok := client.smsReportLink(imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		Recipient:        "+15550000002",
		MessageReference: 9,
	})
	if !ok {
		t.Fatal("smsReportLink() ok = false")
	}
	if link.submissionID != "sms-2" {
		t.Fatalf("submissionID = %q, want sms-2", link.submissionID)
	}
}

func TestSMSStatusReportLinkSkipsAmbiguousReferenceCollision(t *testing.T) {
	client := newStandaloneClient(t)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-1",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15550000001", ServiceCenter: "+15550000000", TPReference: 9}},
	}, nil)
	client.trackSMSSubmission(SMSSubmission{
		ID:           "sms-2",
		SegmentCount: 1,
		Segments:     []SMSSubmissionSegment{{Index: 0, Recipient: "+15550000002", ServiceCenter: "+15550000000", TPReference: 9}},
	}, nil)

	_, ok := client.smsReportLink(imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		MessageReference: 9,
	})
	if ok {
		t.Fatal("smsReportLink() ok = true, want false for ambiguous TP-MR collision")
	}
}

func TestUSSDSessionStateErrors(t *testing.T) {
	client := newStandaloneClient(t)
	session := newSession(client)

	replyResult, err := session.Reply(context.Background(), "1")
	if err == nil || !errors.Is(err, ErrUSSDNotStarted) {
		t.Fatalf("Reply() error = %v, want ErrUSSDNotStarted", err)
	}
	if replyResult != (USSDResult{}) {
		t.Fatalf("Reply() result = %+v, want zero value", replyResult)
	}

	closeResult, err := session.Close(context.Background())
	if err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !closeResult.Closed || closeResult.HasMessage {
		t.Fatalf("Close() result = %+v", closeResult)
	}

	if _, err := session.Send(context.Background(), "*100#"); err == nil || !errors.Is(err, ErrUSSDClosed) {
		t.Fatalf("Send(after Close) error = %v, want ErrUSSDClosed", err)
	}

	started := newSession(client)
	if err := started.attachLowSession(&imsussd.Session{}, false); err != nil {
		t.Fatalf("attachLowSession() error = %v", err)
	}
	if _, err := started.Send(context.Background(), "*100#"); err == nil || !errors.Is(err, ErrUSSDAlreadyStarted) {
		t.Fatalf("second Send() error = %v, want ErrUSSDAlreadyStarted", err)
	}

	busy := newSession(client)
	busy.busy = true
	if _, err := busy.Reply(context.Background(), "1"); err == nil || !errors.Is(err, ErrUSSDInProgress) {
		t.Fatalf("Reply(busy) error = %v, want ErrUSSDInProgress", err)
	}
}

func responseHeaders(req imssip.Message) imssip.Headers {
	return imssip.Headers{
		{Name: "Via", Value: req.Header("Via")},
		{Name: "From", Value: req.Header("From")},
		{Name: "To", Value: req.Header("To")},
		{Name: "Call-ID", Value: req.Header("Call-ID")},
		{Name: "CSeq", Value: req.Header("CSeq")},
	}
}

func bytesOf(value byte, count int) []byte {
	out := make([]byte, count)
	for i := range count {
		out[i] = value
	}
	return out
}

func TestNewNilDriver(t *testing.T) {
	_, err := New(nil, nil)
	if err == nil {
		t.Fatal("New() error = nil, want non-nil")
	}
}

func TestConnectReportsUSIMLoadError(t *testing.T) {
	reader := &readerStub{
		listApplications: func(context.Context) ([]usimcard.Application, error) {
			return nil, errors.New("boom")
		},
	}

	client, err := New(reader, &Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = client.Connect(context.Background())
	if err == nil {
		t.Fatal("Connect() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Connect() error = %v, want load error text", err)
	}
	if reader.closeCalls != 0 {
		t.Fatalf("reader Close() calls = %d, want 0 before Close", reader.closeCalls)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1 after Close", reader.closeCalls)
	}
}

func TestConnectUsesContextForUSIMLoad(t *testing.T) {
	tests := []struct {
		name string
		ctx  func() context.Context
	}{
		{
			name: "canceled before connect",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := &readerStub{
				listApplications: func(ctx context.Context) ([]usimcard.Application, error) {
					return nil, ctx.Err()
				},
			}
			client, err := New(reader, &Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{}),
			})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}
			defer client.Close()
			err = client.Connect(tt.ctx())
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("Connect() error = %v, want context.Canceled", err)
			}
		})
	}
}

func TestCloseCancelsUSIMLoadDuringConnect(t *testing.T) {
	started := make(chan struct{})
	reader := &readerStub{
		listApplications: func(ctx context.Context) ([]usimcard.Application, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	client, err := New(reader, &Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	connectErr := make(chan error, 1)
	go func() {
		connectErr <- client.Connect(context.Background())
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("waiting for USIM load to start")
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	select {
	case err := <-connectErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Connect() error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for Connect to exit")
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1", reader.closeCalls)
	}
}

func TestConnectLeavesReaderOwnedAfterUSIMLoadError(t *testing.T) {
	reader := &readerStub{
		closeErr: errors.New("close boom"),
		listApplications: func(context.Context) ([]usimcard.Application, error) {
			return nil, errors.New("load boom")
		},
	}

	client, err := New(reader, &Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	err = client.Connect(context.Background())
	if err == nil {
		t.Fatal("Connect() error = nil, want non-nil")
	}
	if !strings.Contains(err.Error(), "load boom") {
		t.Fatalf("Connect() error = %v, want load error text", err)
	}
	if err := client.Close(); err == nil || !strings.Contains(err.Error(), "close boom") {
		t.Fatalf("Close() error = %v, want close boom", err)
	}
}

func TestNewClosesReaderOnConfigError(t *testing.T) {
	reader := newReaderStubForUSIMLoad()

	_, err := New(reader, &Config{})
	if err == nil {
		t.Fatal("New() error = nil, want non-nil")
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1", reader.closeCalls)
	}
}

func TestClientCloseClosesOwnedReaderOnce(t *testing.T) {
	client := newStandaloneClient(t)
	reader := &readerStub{}
	client.reader = reader

	if err := client.Close(); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if reader.closeCalls != 1 {
		t.Fatalf("reader Close() calls = %d, want 1", reader.closeCalls)
	}
}

func TestClientCloseDeregistersOnlyMultipleRegistrationFlow(t *testing.T) {
	tests := []struct {
		name          string
		multiple      bool
		outbound      bool
		setupRollback bool
		wantWrites    int
	}{
		{name: "single registration keeps existing close behavior", wantWrites: 2},
		{name: "outbound registration removes its flow", multiple: true, outbound: true, wantWrites: 3},
		{name: "single-flow fallback removes only its contact", multiple: true, wantWrites: 3},
		{name: "failed setup removes outbound flow", multiple: true, outbound: true, setupRollback: true, wantWrites: 3},
		{name: "failed setup removes single-flow fallback", multiple: true, setupRollback: true, wantWrites: 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newGatedCancelTransport(5062, 5060)
			nonce := testNonce()
			var group *RegistrationGroup
			if tt.multiple {
				group = NewRegistrationGroup()
			}
			transport.onWrite = func(data []byte) {
				req, err := imssip.ParseMessage(data)
				if err != nil {
					t.Errorf("ParseMessage() error = %v", err)
					return
				}
				switch transport.writeCount() {
				case 1:
					transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
				case 2:
					resp := newIMSResponse(req, 200, "OK")
					if tt.multiple {
						if tt.outbound {
							resp.Headers.Add("Require", "outbound")
						}
						resp.Headers.Add("Contact", req.Header("Contact")+";expires=60")
					}
					transport.queueRead(resp)
				case 3:
					if !tt.multiple {
						t.Fatalf("unexpected deregistration for a single registration")
					}
					if got := req.Header("Contact"); got == "*" {
						t.Fatal("deregister Contact = *, want current flow only")
					}
					_, params := imssip.AddressURIAndParams(req.Header("Contact"))
					wantRegID := ""
					if tt.outbound {
						wantRegID = "1"
					}
					if got := imssip.HeaderParam(params, "reg-id"); got != wantRegID {
						t.Fatalf("deregister reg-id = %q, want %q", got, wantRegID)
					}
					if got := imssip.HeaderParam(params, "expires"); got != "0" {
						t.Fatalf("deregister expires = %q, want 0", got)
					}
					transport.queueRead(newIMSResponse(req, 200, "OK"))
				default:
					t.Fatalf("unexpected write count %d", transport.writeCount())
				}
			}

			sess, err := imssession.Open(imssession.Config{}, transport)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			regCfg := testRegistrationConfig(transport)
			if tt.multiple {
				regCfg.RegistrationGroup = group
				regCfg.RegistrationID = 1
				regCfg.RegistrationPreference = 1000
				regCfg.IMEI = testIMEI
			}
			reg, err := registration.New(regCfg, sess, stubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			if err := reg.Register(context.Background()); err != nil {
				t.Fatalf("Register() error = %v", err)
			}

			if tt.setupRollback {
				setup := &connectSetup{
					imsCfg: IMSConfig{RegistrationGroup: group},
					ims:    imsStack{sip: sess, reg: reg},
				}
				if err := setup.closeIMS(); err != nil {
					t.Fatalf("closeIMS() error = %v", err)
				}
			} else {
				client := newReadyClient(t, Config{
					Terminal: TerminalInfo{ID: testIMEI},
					Access:   VoWiFi(VoWiFiConfig{}),
					IMS:      IMSConfig{RegistrationGroup: group},
				})
				setClientActive(t, client, &activeConn{
					scope: newConnectionScope(),
					ims:   imsStack{sip: sess, reg: reg},
				})
				if err := client.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
			}
			if got := transport.writeCount(); got != tt.wantWrites {
				t.Fatalf("write count = %d, want %d", got, tt.wantWrites)
			}
		})
	}
}

func TestCancelConnectStartWaitsForIMSLoopExitBeforeCleanup(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		case 3:
			if got := req.Header("Expires"); got != "0" {
				t.Errorf("Expires = %q, want 0", got)
			}
			if got := req.Header("Contact"); got != "*" {
				t.Errorf("Contact = %q, want *", got)
			}
			resp := newIMSResponse(req, 401, "Unauthorized")
			resp.Headers.Add("WWW-Authenticate", fmt.Sprintf(`Digest realm="ims.mnc001.mcc001.3gppnetwork.org",nonce="%s",algorithm=AKAv1-MD5,qop="auth"`, nonce))
			transport.queueRead(resp)
		case 4:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	client := newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
		IMS: IMSConfig{
			RegisterExpires: time.Minute,
		},
	})
	defer client.Close()

	scope := newConnectionScope()
	active := &activeConn{
		scope: scope,
		ims: imsStack{
			sip: sess,
			reg: reg,
		},
	}

	setClientActive(t, client, active)

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := client.startConnectionRunner(active, done)
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	cleanupDone := make(chan struct{})
	go func() {
		client.cancelConnectStart(active, runDone)
		close(cleanupDone)
	}()

	close(transport.cancelReadRelease)

	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("cancelConnectStart() did not finish after IMS loop exit")
	}
	if got := transport.writeCount(); got != 2 {
		t.Fatalf("write count after cleanup = %d, want 2", got)
	}
	if reg.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func TestCloseActiveConnectionSkipsDeregister(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected write during scope cleanup: %s", req.StartLine)
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	ussdSvc, err := imsussd.New(imsussd.Config{Logger: testLogger()}, sess, reg)
	if err != nil {
		t.Fatalf("ussd.New() error = %v", err)
	}

	client := newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	})
	active := &activeConn{ims: imsStack{sip: sess, reg: reg, ussd: ussdSvc}}
	if err := client.closeActiveConnection(active); err != nil {
		t.Fatalf("closeActiveConnection() error = %v", err)
	}
	if got := transport.writeCount(); got != 2 {
		t.Fatalf("write count = %d, want registration only", got)
	}
	if reg.State().Registered {
		t.Fatal("Registered = true, want local registration state cleared")
	}
}

func TestIMSRunnerMaintainsRegistration(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	refreshed := make(chan struct{}, 1)
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		default:
			if req.Method() == "REGISTER" && req.Header("Expires") != "0" && transport.writeCount() >= 3 {
				select {
				case refreshed <- struct{}{}:
				default:
				}
			}
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(func() registration.Config {
		cfg := testRegistrationConfig(transport)
		cfg.RegisterExpires = 2 * time.Second
		return cfg
	}(), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	client := newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	})
	defer client.Close()

	scope := newConnectionScope()
	active := &activeConn{
		scope: scope,
		ims: imsStack{
			sip: sess,
			reg: reg,
		},
	}
	setClientActive(t, client, active)

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := client.startConnectionRunner(active, done)
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	select {
	case <-refreshed:
	case <-time.After(2 * time.Second):
		t.Fatal("waiting for registration refresh")
	}

	scope.stop()
	close(transport.cancelReadRelease)
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("IMS runner did not stop")
	}
}

func TestIMSRunnerReconnectsAfterPrimaryTransportFailure(t *testing.T) {
	oldTransport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	oldTransport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch oldTransport.writeCount() {
		case 1:
			oldTransport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			oldTransport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected old transport write after failure: %s", req.StartLine)
		}
	}
	oldSess, oldReg := newRegisteredIMS(t, oldTransport, time.Minute)

	newTransport := newGatedCancelTransport(5072, 5060)
	newTransport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch newTransport.writeCount() {
		case 1:
			newTransport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			newTransport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			newTransport.queueRead(newIMSResponse(req, 200, "OK"))
		}
	}
	newSess, newReg := newRegisteredIMS(t, newTransport, time.Minute)

	client := newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	})
	defer client.Close()
	events := client.Events()
	defer events.Close()

	oldActive := &activeConn{scope: newConnectionScope(), ims: imsStack{sip: oldSess, reg: oldReg}}
	newActive := &activeConn{scope: newConnectionScope(), ims: imsStack{sip: newSess, reg: newReg}}
	defer newActive.scope.stop()

	reconnected := make(chan struct{})
	reconnect := func(error) (*activeConn, error) {
		setClientActive(t, client, newActive)
		close(reconnected)
		return newActive, nil
	}
	setClientActive(t, client, oldActive)

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := connectionRunner{
		client:    client,
		active:    oldActive,
		done:      done,
		reconnect: reconnect,
	}.start()
	if err := oldSess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("old WaitStarted() error = %v", err)
	}

	readErr := errors.New("primary transport read failed")
	oldTransport.failRead(readErr)

	select {
	case err := <-events.Errors:
		if !strings.Contains(err.Error(), "running IMS loop") || !errors.Is(err, readErr) {
			t.Fatalf("error event = %v, want IMS loop wrapping read failure", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for IMS loop error event")
	}
	select {
	case state := <-events.State:
		if state.Status != StatusReconnecting {
			t.Fatalf("state event status = %s, want %s", state.Status, StatusReconnecting)
		}
		if !state.Reconnecting {
			t.Fatal("state event Reconnecting = false, want true")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for reconnecting state event")
	}
	select {
	case <-reconnected:
	case <-time.After(time.Second):
		t.Fatal("waiting for reconnect")
	}
	select {
	case state := <-events.State:
		if state.Status != StatusRegistered {
			t.Fatalf("state event status = %s, want %s", state.Status, StatusRegistered)
		}
		if state.Reconnecting {
			t.Fatal("registered state event Reconnecting = true")
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for registered state event")
	}
	state := client.State()
	if state.Reconnecting {
		t.Fatal("State().Reconnecting = true after registered reconnect event")
	}
	if state.Status != StatusRegistered {
		t.Fatalf("State().Status = %s, want %s", state.Status, StatusRegistered)
	}
	if err := newSess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("new WaitStarted() error = %v", err)
	}
	if currentClientActive(t, client) != newActive {
		t.Fatal("client active connection was not replaced after reconnect")
	}
	if oldReg.State().Registered {
		t.Fatal("old registration state still registered after scope abort")
	}

	newActive.scope.stop()
	close(newTransport.cancelReadRelease)
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("IMS runner did not stop after replacement context cancellation")
	}
}

func TestIMSRunnerPassesRetryAfterToReconnect(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		case 3:
			resp := newIMSResponse(req, 500, "Server Internal Error")
			resp.Headers.Add("Retry-After", "45")
			transport.queueRead(resp)
		default:
			t.Fatalf("unexpected transport write: %s", req.StartLine)
		}
	}
	sess, reg := newRegisteredIMS(t, transport, 2*time.Second)

	client := newReadyClient(t, Config{
		Terminal:       TerminalInfo{ID: testIMEI},
		Access:         VoWiFi(VoWiFiConfig{}),
		ReconnectDelay: 3 * time.Second,
		IMS: IMSConfig{
			RegistrationRetryBase: 20 * time.Second,
			RegistrationRetryMax:  80 * time.Second,
		},
	})
	defer client.Close()
	delayCh := make(chan time.Duration, 1)
	reconnect := func(cause error) (*activeConn, error) {
		delay := client.reconnectDelay(
			cause,
			newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
			newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
		)
		delayCh <- delay
		return nil, context.Canceled
	}

	active := &activeConn{scope: newConnectionScope(), ims: imsStack{sip: sess, reg: reg}}
	defer active.scope.stop()
	setClientActive(t, client, active)

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := connectionRunner{
		client:    client,
		active:    active,
		done:      done,
		reconnect: reconnect,
	}.start()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	select {
	case delay := <-delayCh:
		if delay != 45*time.Second {
			t.Fatalf("reconnect delay = %v, want Retry-After", delay)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for reconnect delay")
	}
	select {
	case <-runDone:
	case <-time.After(time.Second):
		t.Fatal("IMS runner did not stop after reconnect cancellation")
	}
}

func TestCloseCancelsIMSRunnerReconnect(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			t.Fatalf("unexpected transport write after failure: %s", req.StartLine)
		}
	}
	sess, reg := newRegisteredIMS(t, transport, time.Minute)

	client := newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{}),
	})
	reconnectStarted := make(chan struct{})
	doneCh := clientDone(t, client)
	reconnect := func(error) (*activeConn, error) {
		close(reconnectStarted)
		<-doneCh
		return nil, context.Canceled
	}

	active := &activeConn{scope: newConnectionScope(), ims: imsStack{sip: sess, reg: reg}}
	setClientActive(t, client, active)

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	connectionRunner{
		client:    client,
		active:    active,
		done:      done,
		reconnect: reconnect,
	}.start()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	transport.failRead(errors.New("primary transport read failed"))
	select {
	case <-reconnectStarted:
	case <-time.After(time.Second):
		t.Fatal("waiting for reconnect to start")
	}

	if err := client.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestReconnectBackoff(t *testing.T) {
	tests := []struct {
		name  string
		first time.Duration
		max   time.Duration
		steps int
		want  []time.Duration
	}{
		{
			name:  "doubles until capped",
			first: 3 * time.Second,
			max:   20 * time.Second,
			steps: 5,
			want:  []time.Duration{3 * time.Second, 6 * time.Second, 12 * time.Second, 20 * time.Second, 20 * time.Second},
		},
		{
			name:  "zero delay stays immediate",
			first: 0,
			max:   time.Minute,
			steps: 3,
			want:  []time.Duration{0, 0, 0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backoff := newReconnectBackoff(tt.first, tt.max)
			got := make([]time.Duration, 0, tt.steps)
			for range tt.steps {
				got = append(got, backoff.Next())
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("backoff sequence = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReconnectDelayHonorsIMSRegistrationRetryPolicy(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		resp := newIMSResponse(req, 500, "Server Internal Error")
		resp.Headers.Add("Retry-After", "45")
		transport.queueRead(resp)
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	registerErr := reg.Register(context.Background())
	if registerErr == nil {
		t.Fatal("Register() error = nil, want Retry-After registration error")
	}
	if retryAfter, ok := registration.InitialRegistrationRetryAfter(registerErr); !ok || retryAfter != 45*time.Second {
		t.Fatalf("InitialRegistrationRetryAfter() = %v, %v; want 45s, true", retryAfter, ok)
	}

	client := newReadyClient(t, Config{
		Terminal:       TerminalInfo{ID: testIMEI},
		Access:         VoWiFi(VoWiFiConfig{}),
		ReconnectDelay: 3 * time.Second,
		IMS: IMSConfig{
			RegistrationRetryBase: 20 * time.Second,
			RegistrationRetryMax:  80 * time.Second,
		},
	})
	defer client.Close()
	got := client.reconnectDelay(
		fmt.Errorf("running IMS loop: %w", registerErr),
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 45*time.Second {
		t.Fatalf("reconnectDelay() = %v, want Retry-After", got)
	}

	registrationErr := fmt.Errorf("running IMS loop: %w", registrationTestInitialRequiredError(t))
	registrationBackoff := newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax)
	got = client.reconnectDelay(
		registrationErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		registrationBackoff,
	)
	if got != 20*time.Second {
		t.Fatalf("first registration reconnect delay = %v, want IMS retry base", got)
	}
	got = client.reconnectDelay(
		registrationErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		registrationBackoff,
	)
	if got != 40*time.Second {
		t.Fatalf("second registration reconnect delay = %v, want IMS retry backoff", got)
	}

	genericBackoff := newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay)
	got = client.reconnectDelay(
		errors.New("tcp transport closed"),
		genericBackoff,
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 3*time.Second {
		t.Fatalf("generic reconnect delay = %v, want generic base", got)
	}
	got = client.reconnectDelay(
		errors.New("tcp transport closed"),
		genericBackoff,
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 6*time.Second {
		t.Fatalf("second generic reconnect delay = %v, want generic backoff", got)
	}

	tunnelBackoffErr := fmt.Errorf("connecting swu: %w", testTunnelBackoffError{delay: 2 * time.Minute})
	if delay, ok := swutunnel.BackoffDelay(tunnelBackoffErr); !ok || delay != 2*time.Minute {
		t.Fatalf("swutunnel.BackoffDelay() = %v, %v; want 2m, true", delay, ok)
	}
	got = client.reconnectDelay(
		tunnelBackoffErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 2*time.Minute {
		t.Fatalf("tunnel backoff reconnect delay = %v, want ePDG backoff timer", got)
	}

	reactivationErr := fmt.Errorf("running IMS loop: %w", swutunnel.ErrReactivationRequested)
	if !swutunnel.ReactivationRequested(reactivationErr) {
		t.Fatalf("swutunnel.ReactivationRequested() = false for %v", reactivationErr)
	}
	got = client.reconnectDelay(
		reactivationErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 0 {
		t.Fatalf("reactivation reconnect delay = %v, want immediate retry", got)
	}

	pcscfReselectionErr := fmt.Errorf("running IMS loop: %w", swutunnel.ErrPCSCFReselectionRequested)
	if !swutunnel.PCSCFReselectionRequested(pcscfReselectionErr) {
		t.Fatalf("swutunnel.PCSCFReselectionRequested() = false for %v", pcscfReselectionErr)
	}
	got = client.reconnectDelay(
		pcscfReselectionErr,
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 0 {
		t.Fatalf("p-cscf reselection reconnect delay = %v, want immediate retry", got)
	}
}

func TestReconnectDelayHonorsIMSSubscribeRetryAfter(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		if req.Method() != "SUBSCRIBE" {
			t.Fatalf("method = %q, want SUBSCRIBE", req.Method())
		}
		resp := newIMSResponse(req, 503, "Service Unavailable")
		resp.Headers.Add("Retry-After", "75")
		transport.queueRead(resp)
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	subscribeErr := reg.Subscribe(context.Background())
	if subscribeErr == nil {
		t.Fatal("Subscribe() error = nil, want Retry-After subscription error")
	}
	if retryAfter, ok := registration.RetryAfterDelay(subscribeErr); !ok || retryAfter != 75*time.Second {
		t.Fatalf("RetryAfterDelay() = %v, %v; want 75s, true", retryAfter, ok)
	}

	client := newReadyClient(t, Config{
		Terminal:       TerminalInfo{ID: testIMEI},
		Access:         VoWiFi(VoWiFiConfig{}),
		ReconnectDelay: 3 * time.Second,
		IMS: IMSConfig{
			RegistrationRetryBase: 20 * time.Second,
			RegistrationRetryMax:  80 * time.Second,
		},
	})
	defer client.Close()
	got := client.reconnectDelay(
		fmt.Errorf("starting IMS: %w", subscribeErr),
		newReconnectBackoff(client.cfg.ReconnectDelay, client.cfg.ReconnectMaxDelay),
		newReconnectBackoff(client.cfg.IMS.RegistrationRetryBase, client.cfg.IMS.RegistrationRetryMax),
	)
	if got != 75*time.Second {
		t.Fatalf("reconnectDelay() = %v, want Subscribe Retry-After", got)
	}
}

func TestReconnectStopsOnAccessRejectedCause(t *testing.T) {
	client := newReadyClient(t, Config{
		Terminal:       TerminalInfo{ID: testIMEI},
		Access:         VoWiFi(VoWiFiConfig{}),
		ReconnectDelay: time.Hour,
	})
	defer client.Close()

	cause := fmt.Errorf("connecting swu: %w", swutunnel.ErrAccessRejected)
	done := make(chan error, 1)
	go func() {
		_, err := client.reconnect(cause)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, swutunnel.ErrAccessRejected) {
			t.Fatalf("reconnect() error = %v, want access rejected", err)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("reconnect() slept or retried after access rejection")
	}
}

func TestSWUBackoffGateScopesPolicy(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name      string
		recordErr error
		cfg       Config
		card      Card
		wantDelay time.Duration
		wantBlock bool
	}{
		{
			name:      "network failure blocks same epdg",
			recordErr: testTunnelBackoffError{delay: 2 * time.Minute, scope: swutunnel.BackoffScopeEPDG},
			cfg:       testVoWiFiConfig("epdg.example", swutunnel.Config{}),
			card:      stubCard{},
			wantDelay: 2 * time.Minute,
		},
		{
			name:      "network failure does not block different epdg",
			recordErr: testTunnelBackoffError{delay: 2 * time.Minute, scope: swutunnel.BackoffScopeEPDG},
			cfg:       testVoWiFiConfig("other.example", swutunnel.Config{}),
			card:      stubCard{},
		},
		{
			name:      "no apn subscription blocks same plmn apn across epdgs",
			recordErr: testTunnelBackoffError{delay: 3 * time.Minute, scope: swutunnel.BackoffScopePLMNAPN},
			cfg:       testVoWiFiConfig("other.example", swutunnel.Config{}),
			card:      stubCard{},
			wantDelay: 3 * time.Minute,
		},
		{
			name:      "no apn subscription does not block different plmn",
			recordErr: testTunnelBackoffError{delay: 3 * time.Minute, scope: swutunnel.BackoffScopePLMNAPN},
			cfg:       testVoWiFiConfig("epdg.example", swutunnel.Config{}),
			card:      plmnTestCard{mcc: "002", mnc: "001"},
		},
		{
			name:      "no apn subscription does not block different apn",
			recordErr: testTunnelBackoffError{delay: 3 * time.Minute, scope: swutunnel.BackoffScopePLMNAPN},
			cfg:       testVoWiFiConfig("other.example", swutunnel.Config{APN: "internet"}),
			card:      stubCard{},
		},
		{
			name:      "deactivated blocks terminally",
			recordErr: testTunnelBackoffError{deactivated: true, scope: swutunnel.BackoffScopeEPDG},
			cfg:       testVoWiFiConfig("epdg.example", swutunnel.Config{}),
			card:      stubCard{},
			wantBlock: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newReadyClient(t, Config{
				Access:   VoWiFi(VoWiFiConfig{EPDG: "epdg.example"}),
				Terminal: TerminalInfo{ID: testIMEI},
			})
			defer client.Close()
			client.recordSWUBackoff(tt.recordErr, now)
			client.cfg.Access.VoWiFi.EPDG = configEPDG(tt.cfg)
			client.cfg.Access.VoWiFi.Tunnel.APN = configTunnel(tt.cfg).APN
			client.card = tt.card

			gotDelay, gotBlock, gotActive := client.swuBackoffDelay(now)
			if gotActive != (tt.wantDelay > 0 || tt.wantBlock) {
				t.Fatalf("swuBackoffDelay() active = %t, want %t", gotActive, tt.wantDelay > 0 || tt.wantBlock)
			}
			if gotBlock != tt.wantBlock {
				t.Fatalf("swuBackoffDelay() deactivated = %t, want %t", gotBlock, tt.wantBlock)
			}
			if gotDelay != tt.wantDelay {
				t.Fatalf("swuBackoffDelay() delay = %v, want %v", gotDelay, tt.wantDelay)
			}
		})
	}
}

func TestSWUBackoffGateRecordsImplementationSpecificPolicy(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name      string
		err       error
		cfg       Config
		card      Card
		wantDelay time.Duration
	}{
		{
			name:      "network failure without timer blocks same epdg",
			err:       fmt.Errorf("connecting swu: %w", swutunnel.ErrNetworkFailure),
			cfg:       testVoWiFiConfig("epdg.example", swutunnel.Config{}),
			card:      stubCard{},
			wantDelay: 5 * time.Second,
		},
		{
			name: "network failure without timer does not block different epdg",
			err:  fmt.Errorf("connecting swu: %w", swutunnel.ErrNetworkFailure),
			cfg:  testVoWiFiConfig("other.example", swutunnel.Config{}),
			card: stubCard{},
		},
		{
			name:      "no apn subscription without timer blocks same plmn apn",
			err:       fmt.Errorf("connecting swu: %w", swutunnel.ErrNoAPNSubscription),
			cfg:       testVoWiFiConfig("other.example", swutunnel.Config{}),
			card:      stubCard{},
			wantDelay: 5 * time.Second,
		},
		{
			name: "no apn subscription without timer does not block different apn",
			err:  fmt.Errorf("connecting swu: %w", swutunnel.ErrNoAPNSubscription),
			cfg:  testVoWiFiConfig("other.example", swutunnel.Config{APN: "internet"}),
			card: stubCard{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newReadyClient(t, Config{
				Access:         VoWiFi(VoWiFiConfig{EPDG: "epdg.example"}),
				ReconnectDelay: 5 * time.Second,
				Terminal:       TerminalInfo{ID: testIMEI},
			})
			defer client.Close()
			client.recordSWUBackoff(tt.err, now)
			client.cfg.Access.VoWiFi.EPDG = configEPDG(tt.cfg)
			client.cfg.Access.VoWiFi.Tunnel.APN = configTunnel(tt.cfg).APN
			client.card = tt.card

			gotDelay, gotBlock, gotActive := client.swuBackoffDelay(now)
			if gotActive != (tt.wantDelay > 0) {
				t.Fatalf("swuBackoffDelay() active = %t, want %t", gotActive, tt.wantDelay > 0)
			}
			if gotBlock {
				t.Fatal("swuBackoffDelay() deactivated = true, want false")
			}
			if gotDelay != tt.wantDelay {
				t.Fatalf("swuBackoffDelay() delay = %v, want %v", gotDelay, tt.wantDelay)
			}
		})
	}
}

func TestSWUBackoffGateClearsExplicitZeroPolicy(t *testing.T) {
	client := newReadyClient(t, Config{
		Access:         VoWiFi(VoWiFiConfig{EPDG: "epdg.example"}),
		ReconnectDelay: 5 * time.Second,
		Terminal:       TerminalInfo{ID: testIMEI},
	})
	defer client.Close()

	now := time.Unix(100, 0)
	client.recordSWUBackoff(testTunnelBackoffError{delay: time.Minute, scope: swutunnel.BackoffScopeEPDG}, now)
	if delay, deactivated, active := client.swuBackoffDelay(now); !active || deactivated || delay != time.Minute {
		t.Fatalf("swuBackoffDelay(before zero) = %v, %t, %t; want 1m, false, true", delay, deactivated, active)
	}

	client.recordSWUBackoff(testTunnelBackoffError{scope: swutunnel.BackoffScopeEPDG}, now)
	if delay, deactivated, active := client.swuBackoffDelay(now); active || deactivated || delay != 0 {
		t.Fatalf("swuBackoffDelay(after zero) = %v, %t, %t; want inactive", delay, deactivated, active)
	}
}

func TestSWUBackoffGateExpiresAndClears(t *testing.T) {
	client := newReadyClient(t, Config{
		Access:   VoWiFi(VoWiFiConfig{EPDG: "epdg.example"}),
		Terminal: TerminalInfo{ID: testIMEI},
	})
	defer client.Close()

	now := time.Unix(100, 0)
	client.recordSWUBackoff(testTunnelBackoffError{delay: time.Minute, scope: swutunnel.BackoffScopeEPDG}, now)

	if delay, deactivated, active := client.swuBackoffDelay(now.Add(30 * time.Second)); !active || deactivated || delay != 30*time.Second {
		t.Fatalf("swuBackoffDelay(before expiry) = %v, %t, %t; want 30s, false, true", delay, deactivated, active)
	}
	if delay, deactivated, active := client.swuBackoffDelay(now.Add(time.Minute)); active || deactivated || delay != 0 {
		t.Fatalf("swuBackoffDelay(after expiry) = %v, %t, %t; want inactive", delay, deactivated, active)
	}

	client.recordSWUBackoff(testTunnelBackoffError{delay: time.Minute, scope: swutunnel.BackoffScopeEPDG}, now)
	client.clearCurrentSWUBackoff()
	if delay, deactivated, active := client.swuBackoffDelay(now); active || deactivated || delay != 0 {
		t.Fatalf("swuBackoffDelay(after clear) = %v, %t, %t; want inactive", delay, deactivated, active)
	}
}

func TestSWUPDNTypeRestrictionGateAppliesPLMNAPN(t *testing.T) {
	tests := []struct {
		name    string
		apn     string
		card    Card
		initial swutunnel.PDNType
		want    swutunnel.PDNType
	}{
		{
			name: "same plmn apn applies restriction",
			apn:  "IMS",
			card: stubCard{},
			want: swutunnel.PDNTypeIPv6,
		},
		{
			name: "different apn does not apply restriction",
			apn:  "internet",
			card: stubCard{},
		},
		{
			name: "different plmn does not apply restriction",
			apn:  "ims",
			card: plmnTestCard{mcc: "002", mnc: "001"},
		},
		{
			name:    "explicit conflicting request is restricted",
			apn:     "ims",
			card:    stubCard{},
			initial: swutunnel.PDNTypeIPv4,
			want:    swutunnel.PDNTypeIPv6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newReadyClient(t, Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{Tunnel: swutunnel.Config{APN: "ims"}}),
			})
			defer client.Close()
			client.recordSWUPDNTypeRestriction(swutunnel.Info{PDNTypeRestriction: swutunnel.PDNTypeIPv6})
			client.card = tt.card
			cfg := swutunnel.Config{APN: tt.apn, PDNType: tt.initial}

			client.applySWUPDNTypeRestriction(&cfg)

			if cfg.PDNType != tt.want {
				t.Fatalf("PDNType = %d, want %d", cfg.PDNType, tt.want)
			}
		})
	}
}

func TestSWUPDNTypeRestrictionGateIgnoresUnrestrictedInfo(t *testing.T) {
	client := newReadyClient(t, Config{
		Terminal: TerminalInfo{ID: testIMEI},
		Access:   VoWiFi(VoWiFiConfig{Tunnel: swutunnel.Config{APN: "ims"}}),
	})
	defer client.Close()

	client.recordSWUPDNTypeRestriction(swutunnel.Info{PDNTypeRestriction: swutunnel.PDNTypeUnspecified})
	cfg := swutunnel.Config{APN: "ims"}
	client.applySWUPDNTypeRestriction(&cfg)
	if cfg.PDNType != swutunnel.PDNTypeUnspecified {
		t.Fatalf("PDNType = %d, want unspecified", cfg.PDNType)
	}
}

func TestSWUPDNTypeRestrictionGateClearsAfterPDNDeactivation(t *testing.T) {
	tests := []struct {
		name  string
		cause error
		want  swutunnel.PDNType
	}{
		{
			name:  "network deactivation clears restriction",
			cause: fmt.Errorf("running IMS loop: %w", swutunnel.ErrPDNDeactivated),
		},
		{
			name:  "reactivation requested keeps restriction",
			cause: errors.Join(swutunnel.ErrPDNDeactivated, swutunnel.ErrReactivationRequested),
			want:  swutunnel.PDNTypeIPv6,
		},
		{
			name:  "other disconnect keeps restriction",
			cause: errors.New("transport closed"),
			want:  swutunnel.PDNTypeIPv6,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := newReadyClient(t, Config{
				Terminal: TerminalInfo{ID: testIMEI},
				Access:   VoWiFi(VoWiFiConfig{Tunnel: swutunnel.Config{APN: "ims"}}),
			})
			defer client.Close()

			client.recordSWUPDNTypeRestriction(swutunnel.Info{PDNTypeRestriction: swutunnel.PDNTypeIPv6})
			client.clearSWUPDNTypeRestrictionAfterDisconnect(tt.cause)
			cfg := swutunnel.Config{APN: "ims"}
			client.applySWUPDNTypeRestriction(&cfg)

			if cfg.PDNType != tt.want {
				t.Fatalf("PDNType = %d, want %d", cfg.PDNType, tt.want)
			}
		})
	}
}

func TestTerminalReconnectError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "access rejected", err: fmt.Errorf("connecting swu: %w", swutunnel.ErrAccessRejected), want: true},
		{name: "backoff deactivated", err: fmt.Errorf("connecting swu: %w", testTunnelBackoffDeactivatedError{}), want: true},
		{name: "swu backoff deactivated", err: fmt.Errorf("preparing connect: %w", errSWUBackoffDeactivated), want: true},
		{name: "transport closed", err: errors.New("tcp transport closed")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := terminalReconnectError(tt.err); got != tt.want {
				t.Fatalf("terminalReconnectError() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestPCSCFCandidateIPs(t *testing.T) {
	tests := []struct {
		name string
		info swutunnel.Info
		want []net.IP
	}{
		{
			name: "ordered list deduplicated",
			info: swutunnel.Info{
				PCSCFIPs: []net.IP{
					net.IPv4(10, 0, 0, 1),
					net.IPv4(10, 0, 0, 2),
					net.IPv4(10, 0, 0, 1),
				},
			},
			want: []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)},
		},
		{
			name: "single source list",
			info: swutunnel.Info{
				PCSCFIPs: []net.IP{
					net.IPv4(10, 0, 0, 9),
				},
			},
			want: []net.IP{net.IPv4(10, 0, 0, 9)},
		},
		{
			name: "empty",
			info: swutunnel.Info{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pcscfCandidateIPs(tt.info)
			if len(got) != len(tt.want) {
				t.Fatalf("candidate count = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if !got[i].Equal(tt.want[i]) {
					t.Fatalf("candidate[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
			if len(got) != 0 && &got[0][0] == &tt.want[0][0] {
				t.Fatal("candidate IP aliases input")
			}
		})
	}
}

func TestNextPCSCFInfoMarksCurrentUnavailable(t *testing.T) {
	tests := []struct {
		name    string
		ips     []net.IP
		current net.IP
		want    []net.IP
		wantOK  bool
	}{
		{
			name: "removes actual current address and selects following address",
			ips: []net.IP{
				net.IPv4(10, 0, 0, 1),
				net.IPv4(10, 0, 0, 2),
				net.IPv4(10, 0, 0, 3),
			},
			current: net.IPv4(10, 0, 0, 2),
			want:    []net.IP{net.IPv4(10, 0, 0, 3), net.IPv4(10, 0, 0, 1)},
			wantOK:  true,
		},
		{
			name:    "missing current address does not remove a candidate",
			ips:     []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)},
			current: net.IPv4(10, 0, 0, 9),
			want:    []net.IP{net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2)},
		},
		{
			name:    "single address requires new discovery",
			ips:     []net.IP{net.IPv4(10, 0, 0, 1)},
			current: net.IPv4(10, 0, 0, 1),
			want:    []net.IP{net.IPv4(10, 0, 0, 1)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := swutunnel.Info{PCSCFIPs: tt.ips}
			got, ok := nextPCSCFInfo(info, tt.current)
			if ok != tt.wantOK {
				t.Fatalf("nextPCSCFInfo() ok = %v, want %v", ok, tt.wantOK)
			}
			gotIPs := got.PCSCFAddresses()
			if len(gotIPs) != len(tt.want) {
				t.Fatalf("PCSCFAddresses() length = %d, want %d", len(gotIPs), len(tt.want))
			}
			for i := range tt.want {
				if !gotIPs[i].Equal(tt.want[i]) {
					t.Fatalf("PCSCFAddresses()[%d] = %s, want %s", i, gotIPs[i], tt.want[i])
				}
			}
		})
	}
}

func TestVoWiFiAccessSelectNextPCSCF(t *testing.T) {
	tests := []struct {
		name      string
		ips       []net.IP
		current   net.IP
		want      []net.IP
		wantError bool
	}{
		{
			name: "removes selected address",
			ips: []net.IP{
				net.IPv4(10, 0, 0, 1),
				net.IPv4(10, 0, 0, 2),
				net.IPv4(10, 0, 0, 3),
			},
			current: net.IPv4(10, 0, 0, 2),
			want:    []net.IP{net.IPv4(10, 0, 0, 3), net.IPv4(10, 0, 0, 1)},
		},
		{
			name:      "last address requires discovery",
			ips:       []net.IP{net.IPv4(10, 0, 0, 1)},
			current:   net.IPv4(10, 0, 0, 1),
			want:      []net.IP{net.IPv4(10, 0, 0, 1)},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			access := &voWiFiAccess{
				info:    swutunnel.Info{PCSCFIPs: tt.ips},
				current: tt.current,
			}
			err := access.SelectNextPCSCF()
			if (err != nil) != tt.wantError {
				t.Fatalf("SelectNextPCSCF() error = %v, wantError %v", err, tt.wantError)
			}
			got := access.pcscfInfo().PCSCFAddresses()
			if len(got) != len(tt.want) {
				t.Fatalf("PCSCFAddresses() length = %d, want %d", len(got), len(tt.want))
			}
			for i := range tt.want {
				if !got[i].Equal(tt.want[i]) {
					t.Fatalf("PCSCFAddresses()[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func registrationTestInitialRequiredError(t *testing.T) error {
	t.Helper()

	transport := newGatedCancelTransport(5062, 5060)
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		transport.queueRead(newIMSResponse(req, 500, "Server Internal Error"))
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	err = reg.Register(context.Background())
	if err == nil {
		t.Fatal("Register() error = nil, want initial registration required")
	}
	if !registration.InitialRegistrationRequired(err) {
		t.Fatalf("InitialRegistrationRequired() = false for %v", err)
	}
	return err
}

func TestConnectionRunnerRunIMSKeepsParentContextOnRegistrationRefreshError(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	released := make(chan struct{})
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		default:
			transport.queueRead(newIMSResponse(req, 500, "Server Internal Error"))
			select {
			case <-released:
			default:
				close(released)
				close(transport.cancelReadRelease)
			}
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(func() registration.Config {
		cfg := testRegistrationConfig(transport)
		cfg.RegisterExpires = 2 * time.Second
		return cfg
	}(), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	scope := newConnectionScope()
	defer scope.stop()
	active := &activeConn{
		scope: scope,
		ims: imsStack{
			sip: sess,
			reg: reg,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		runner := connectionRunner{active: active}
		errCh <- runner.runIMS()
	}()

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("connectionRunner.runIMS() error = nil, want refresh error")
		}
		if !strings.Contains(err.Error(), "maintaining IMS registration") {
			t.Fatalf("connectionRunner.runIMS() error = %v, want maintaining IMS registration", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("waiting for connectionRunner.runIMS refresh error")
	}
	if scope.stopped() {
		t.Fatal("scope stopped, want active")
	}
}

func TestConnectionRunnerRunIMSReturnsRegistrationEventTermination(t *testing.T) {
	transport := newGatedCancelTransport(5062, 5060)
	nonce := testNonce()
	var registerContact string
	transport.onWrite = func(data []byte) {
		req, err := imssip.ParseMessage(data)
		if err != nil {
			t.Errorf("ParseMessage() error = %v", err)
			return
		}
		if !req.IsRequest() || req.Method() != "REGISTER" {
			return
		}
		switch transport.writeCount() {
		case 1:
			transport.queueRead(newUnauthorizedRegisterResponse(req, nonce))
		case 2:
			registerContact = req.Header("Contact")
			transport.queueRead(newIMSResponse(req, 200, "OK"))
		}
	}

	sess, err := imssession.Open(imssession.Config{}, transport)
	if err != nil {
		t.Fatalf("session.Open() error = %v", err)
	}
	reg, err := registration.New(testRegistrationConfig(transport), sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	scope := newConnectionScope()
	defer scope.stop()
	active := &activeConn{
		scope: scope,
		ims: imsStack{
			sip: sess,
			reg: reg,
		},
	}

	errCh := make(chan error, 1)
	go func() {
		runner := connectionRunner{active: active}
		errCh <- runner.runIMS()
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	state := reg.State()
	contactURI := imssip.AddressURI(registerContact)
	notify := imssip.NewRequest("NOTIFY", "sip:user@example.com")
	notify.Headers.Add("Via", "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-registration-terminated")
	notify.Headers.Add("Max-Forwards", "70")
	notify.Headers.Add("From", "<sip:registrar@example.com>;tag=registrar")
	notify.Headers.Add("To", "<sip:user@example.com>;tag=user")
	notify.Headers.Add("Call-ID", "registration-terminated@example.com")
	notify.Headers.Add("CSeq", "1 NOTIFY")
	notify.Headers.Add("Event", "reg")
	notify.Headers.Add("Content-Type", "application/reginfo+xml")
	notify.Body = fmt.Appendf(nil, `<?xml version="1.0"?>
	<reginfo xmlns="urn:ietf:params:xml:ns:reginfo" version="1" state="full">
	  <registration aor="%s" id="reg-1" state="active">
	    <contact id="contact-1" state="terminated" event="deactivated">
	      <uri>%s</uri>
	    </contact>
	  </registration>
	</reginfo>`, state.PublicIdentity, contactURI)
	transport.queueRead(notify)

	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("connectionRunner.runIMS() error = nil, want registration event termination")
		}
		if !strings.Contains(err.Error(), "ims registration terminated by network") {
			t.Fatalf("connectionRunner.runIMS() error = %v, want network deregistration", err)
		}
	case <-time.After(time.Second):
		scope.stop()
		close(transport.cancelReadRelease)
		t.Fatal("waiting for connectionRunner.runIMS registration event termination")
	}
	if scope.stopped() {
		t.Fatal("scope stopped, want active")
	}
	if reg.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func newReaderStubForUSIMLoad() *readerStub {
	usimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}

	return &readerStub{
		listApplications: func(context.Context) ([]usimcard.Application, error) {
			return []usimcard.Application{{
				AID:   append([]byte(nil), usimAID...),
				Label: "USIM",
			}}, nil
		},
		getFileAttributes: func(_ context.Context, file usimcard.FileRef) (usimcard.FileAttributes, error) {
			switch {
			case len(file.AID) == 0 && slices.Equal(file.Path, []byte{0x2F, 0xE2}):
				return usimcard.FileAttributes{FileStructure: simfile.StructureTransparent, FileSize: 10}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0x07}):
				return usimcard.FileAttributes{FileStructure: simfile.StructureTransparent, FileSize: 9}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0xAD}):
				return usimcard.FileAttributes{FileStructure: simfile.StructureTransparent, FileSize: 4}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0x42}):
				return usimcard.FileAttributes{FileStructure: simfile.StructureLinearFixed, RecordSize: 32, RecordCount: 0}, nil
			default:
				return usimcard.FileAttributes{}, errors.New("file not found")
			}
		},
		readTransparent: func(_ context.Context, req usimcard.TransparentRead) ([]byte, error) {
			switch {
			case len(req.File.AID) == 0 && slices.Equal(req.File.Path, []byte{0x2F, 0xE2}):
				return []byte{0x98, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0}, nil
			case slices.Equal(req.File.AID, usimAID) && slices.Equal(req.File.Path, []byte{0x6F, 0x07}):
				return []byte{0x08, 0x09, 0x10, 0x10, 0x10, 0x32, 0x54, 0x76, 0x98}, nil
			case slices.Equal(req.File.AID, usimAID) && slices.Equal(req.File.Path, []byte{0x6F, 0xAD}):
				return []byte{0x00, 0x00, 0x00, 0x02}, nil
			default:
				return nil, errors.New("transparent file not found")
			}
		},
	}
}
