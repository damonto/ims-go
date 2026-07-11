package tunnel

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/ipsec/packet"
	"github.com/damonto/ims-go/swu/ike"
	"github.com/damonto/uicc-go/usim"
)

type sessionTestCard struct{}

func (sessionTestCard) IMSI() string { return "001010123456789" }
func (sessionTestCard) MCC() string  { return "001" }
func (sessionTestCard) MNC() string  { return "001" }

func (sessionTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, nil
}

type readResult struct {
	data []byte
	addr net.Addr
	err  error
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type fakePacketConn struct {
	mu sync.Mutex

	local net.Addr

	readResults []readResult
	readIndex   int

	writeErr     error
	writeBlock   <-chan struct{}
	writeStarted chan struct{}
	writeOnce    sync.Once
	writes       [][]byte

	closed bool
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, nil, net.ErrClosed
	}
	if c.readIndex >= len(c.readResults) {
		return 0, nil, timeoutError{}
	}
	result := c.readResults[c.readIndex]
	c.readIndex++
	if result.err != nil {
		return 0, nil, result.err
	}
	copy(p, result.data)
	return len(result.data), result.addr, nil
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.writeOnce.Do(func() {
		if c.writeStarted != nil {
			close(c.writeStarted)
		}
	})
	if c.writeBlock != nil {
		<-c.writeBlock
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *fakePacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *fakePacketConn) LocalAddr() net.Addr { return c.local }

func (c *fakePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *fakePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fakePacketConn) SetWriteDeadline(time.Time) error { return nil }

type serializedWritePacketConn struct {
	*fakePacketConn

	mu             sync.Mutex
	deadlineCalls  int
	secondDeadline chan struct{}
}

func (c *serializedWritePacketConn) SetWriteDeadline(time.Time) error {
	c.mu.Lock()
	c.deadlineCalls++
	if c.deadlineCalls == 2 {
		close(c.secondDeadline)
	}
	c.mu.Unlock()
	return nil
}

type recordingInnerHandler struct {
	errCh chan error
}

func (h *recordingInnerHandler) HandleInnerPacket(packet.InnerPacket) bool { return false }

func (h *recordingInnerHandler) HandleError(err error) {
	select {
	case h.errCh <- err:
	default:
	}
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustDialSession(t *testing.T, conn net.PacketConn) *Session {
	t.Helper()
	session, err := Dial(context.Background(), Config{
		RemoteAddr: "127.0.0.1:4500",
		PacketConn: conn,
		Logger:     testLogger(),
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	return session
}

func TestWriteOuterSerializesDeadlineAndWrite(t *testing.T) {
	releaseWrite := make(chan struct{})
	writeStarted := make(chan struct{})
	conn := &serializedWritePacketConn{
		fakePacketConn: &fakePacketConn{
			local:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
			writeBlock:   releaseWrite,
			writeStarted: writeStarted,
		},
		secondDeadline: make(chan struct{}),
	}
	sess := newSession(
		Config{Logger: testLogger()},
		conn,
		false,
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	errs := make(chan error, 2)
	go func() {
		errs <- sess.writeOuter(ctx, []byte("first"), sess.outerRemote)
	}()

	select {
	case <-writeStarted:
	case <-time.After(time.Second):
		t.Fatal("first WriteTo did not start")
	}

	go func() {
		errs <- sess.writeOuter(ctx, []byte("second"), sess.outerRemote)
	}()

	select {
	case <-conn.secondDeadline:
		t.Fatal("second SetWriteDeadline ran while first WriteTo was blocked")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseWrite)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("writeOuter() error = %v", err)
		}
	}

	select {
	case <-conn.secondDeadline:
	case <-time.After(time.Second):
		t.Fatal("second SetWriteDeadline did not run after first WriteTo completed")
	}
}

func TestConnectRejectsConcurrentConnect(t *testing.T) {
	block := make(chan struct{})
	started := make(chan struct{})
	conn := &fakePacketConn{
		local:        &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
		writeErr:     errors.New("write failed"),
		writeBlock:   block,
		writeStarted: started,
	}
	session := mustDialSession(t, conn)

	firstResult := make(chan error, 1)
	go func() {
		firstResult <- session.Connect(context.Background(), "356789012345678", sessionTestCard{})
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("first Connect() did not reach write path")
	}

	err := session.Connect(context.Background(), "356789012345678", sessionTestCard{})
	if err == nil || !strings.Contains(err.Error(), "connect already in progress") {
		t.Fatalf("concurrent Connect() error = %v, want in-progress error", err)
	}

	close(block)

	if err := <-firstResult; err == nil || !strings.Contains(err.Error(), "write failed") {
		t.Fatalf("first Connect() error = %v, want wrapped write failure", err)
	}

	err = session.Connect(context.Background(), "356789012345678", sessionTestCard{})
	if err == nil {
		t.Fatal("Connect() after failed in-flight attempt error = nil, want non-nil")
	}
	if strings.Contains(err.Error(), "connect already in progress") {
		t.Fatalf("Connect() after failed in-flight attempt still reports in-progress: %v", err)
	}
}

func TestDiscardChildSecurityAssociationsKeepsIKESessionOpen(t *testing.T) {
	conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
	session := mustDialSession(t, conn)
	session.mu.Lock()
	session.connected = true
	session.innerLocal = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062}
	session.innerRemote = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060}
	session.tunnel = Info{
		InnerIPv4:       net.IPv4(10, 0, 0, 1),
		PCSCFIPs:        []net.IP{net.IPv4(10, 0, 0, 2)},
		ESPInitiatorSPI: 101,
		ESPResponderSPI: 202,
	}
	session.outboundESP = esp.Codec{SPI: 202}
	session.inboundESP = esp.Codec{SPI: 101}
	session.ike = &ikeCrypto{}
	session.tunnelErr = nil
	session.initiatorSPI = 1
	session.responderSPI = 2
	session.deviceIdentity = "urn:gsma:imei:356789012345678"
	session.nextMessageID = 9
	session.livenessTimeout = time.Minute
	session.natKeepaliveInterval = 20 * time.Second
	session.mu.Unlock()

	handler := &recordingInnerHandler{errCh: make(chan error, 1)}
	if _, err := session.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	cause := errors.New("peer deleted child SA")
	session.discardChildSecurityAssociations(cause)

	select {
	case err := <-handler.errCh:
		if !errors.Is(err, cause) {
			t.Fatalf("HandleError() error = %v, want wrapped %v", err, cause)
		}
	case <-time.After(time.Second):
		t.Fatal("HandleError() was not called")
	}

	if session.isClosed() {
		t.Fatal("session is closed, want active")
	}
	if conn.closed {
		t.Fatal("packet conn was closed")
	}

	session.mu.RLock()
	connected := session.connected
	ikeState := session.ike
	initiatorSPI := session.initiatorSPI
	responderSPI := session.responderSPI
	nextMessageID := session.nextMessageID
	innerLocal := session.innerLocal
	innerRemote := session.innerRemote
	info := session.tunnel
	tunnelErr := session.tunnelErr
	session.mu.RUnlock()

	if connected {
		t.Fatal("connected = true, want false")
	}
	if ikeState == nil {
		t.Fatal("ike = nil, want preserved IKE state")
	}
	if initiatorSPI != 1 || responderSPI != 2 {
		t.Fatalf("IKE SPIs = (%d, %d), want (1, 2)", initiatorSPI, responderSPI)
	}
	if nextMessageID != 9 {
		t.Fatalf("nextMessageID = %d, want 9", nextMessageID)
	}
	if innerLocal != nil || innerRemote != nil {
		t.Fatalf("inner addrs = (%v, %v), want nil", innerLocal, innerRemote)
	}
	if info.HasInnerAddress() || len(info.PCSCFAddresses()) != 0 || info.ESPInitiatorSPI != 0 || info.ESPResponderSPI != 0 || info.Encryption != 0 || info.EncryptionKeyLen != 0 || info.Integrity != 0 {
		t.Fatalf("Info = %+v, want zero value", info)
	}
	if !errors.Is(tunnelErr, cause) {
		t.Fatalf("tunnelErr = %v, want wrapped %v", tunnelErr, cause)
	}
	if !session.currentInformationalState().canSendDelete() {
		t.Fatal("currentInformationalState().canSendDelete() = false, want true")
	}

	if err := session.WritePacket(context.Background(), []byte("ping")); !errors.Is(err, cause) {
		t.Fatalf("WritePacket() error = %v, want wrapped %v", err, cause)
	}
	for range 2 {
		_, _, err := session.ReadPacket(context.Background())
		if !errors.Is(err, cause) {
			t.Fatalf("ReadPacket() error = %v, want wrapped %v", err, cause)
		}
	}
	if _, err := session.beginConnect(); err == nil || !strings.Contains(err.Error(), "close and redial") {
		t.Fatalf("beginConnect() error = %v, want close-and-redial error", err)
	}
}

func TestReadyInfoReportsTunnelState(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(*Session)
		wantErr error
		wantMsg string
	}{
		{
			name: "connected",
			setup: func(session *Session) {
				session.mu.Lock()
				session.connected = true
				session.tunnel = Info{InnerIPv4: net.IPv4(10, 0, 0, 1)}
				session.mu.Unlock()
			},
		},
		{
			name: "connected without inner ip",
			setup: func(session *Session) {
				session.mu.Lock()
				session.connected = true
				session.mu.Unlock()
			},
			wantMsg: "tunnel inner ip is empty",
		},
		{
			name: "child sa unavailable",
			setup: func(session *Session) {
				session.mu.Lock()
				session.ike = &ikeCrypto{}
				session.tunnelErr = errChildSAUnavailable
				session.mu.Unlock()
			},
			wantErr: errChildSAUnavailable,
		},
		{
			name: "child sa expired",
			setup: func(session *Session) {
				session.mu.Lock()
				session.ike = &ikeCrypto{}
				session.tunnelErr = errChildSAExpired
				session.mu.Unlock()
			},
			wantErr: errChildSAExpired,
		},
		{
			name: "closed",
			setup: func(session *Session) {
				session.closeSession()
			},
			wantErr: errSessionClosed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			tt.setup(session)

			info, err := session.ReadyInfo()
			if tt.wantErr == nil {
				if tt.wantMsg != "" {
					if err == nil || !strings.Contains(err.Error(), tt.wantMsg) {
						t.Fatalf("ReadyInfo() error = %v, want %q", err, tt.wantMsg)
					}
					return
				}
				if err != nil {
					t.Fatalf("ReadyInfo() error = %v", err)
				}
				if !info.DefaultInnerIP().Equal(net.IPv4(10, 0, 0, 1)) {
					t.Fatalf("ReadyInfo().DefaultInnerIP() = %v, want 10.0.0.1", info.DefaultInnerIP())
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ReadyInfo() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyPCSCFReselectionUpdatesTunnelAndSignalsReader(t *testing.T) {
	conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
	session := mustDialSession(t, conn)
	session.mu.Lock()
	session.connected = true
	session.tunnel = Info{
		InnerIPv4:        net.IPv4(10, 0, 0, 1),
		PCSCFIPs:         []net.IP{net.IPv4(10, 0, 0, 2)},
		ESPInitiatorSPI:  101,
		ESPResponderSPI:  202,
		Encryption:       transformENCRAESCBC,
		EncryptionKeyLen: 128,
		Integrity:        transformINTEGHMACSHA256,
	}
	session.mu.Unlock()

	want := Info{
		InnerIPv4:        net.IPv4(10, 0, 0, 1),
		PCSCFIPs:         []net.IP{net.IPv4(10, 9, 8, 7), net.IPv4(10, 9, 8, 8)},
		ESPInitiatorSPI:  101,
		ESPResponderSPI:  202,
		Encryption:       transformENCRAESCBC,
		EncryptionKeyLen: 128,
		Integrity:        transformINTEGHMACSHA256,
	}
	session.applyPCSCFReselection(want)

	info := session.Info()
	if !info.DefaultPCSCFIP().Equal(want.DefaultPCSCFIP()) {
		t.Fatalf("DefaultPCSCFIP() = %s, want %s", info.DefaultPCSCFIP(), want.DefaultPCSCFIP())
	}
	if !ipListEqual(info.PCSCFIPs, want.PCSCFIPs) {
		t.Fatalf("PCSCFIPs = %v, want %v", info.PCSCFIPs, want.PCSCFIPs)
	}
	select {
	case inbound := <-session.readCh:
		if !PCSCFReselectionRequested(inbound.err) {
			t.Fatalf("readCh err = %v, want P-CSCF reselection", inbound.err)
		}
		got, ok := PCSCFReselectionInfo(inbound.err)
		if !ok {
			t.Fatal("PCSCFReselectionInfo() ok = false")
		}
		if !ipListEqual(got.PCSCFIPs, want.PCSCFIPs) {
			t.Fatalf("PCSCFReselectionInfo().PCSCFIPs = %v, want %v", got.PCSCFIPs, want.PCSCFIPs)
		}
	default:
		t.Fatal("readCh empty, want P-CSCF reselection signal")
	}
}

func TestDiscardChildSecurityAssociationsUnblocksConnectedRead(t *testing.T) {
	session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
	session.mu.Lock()
	session.connected = true
	session.ike = &ikeCrypto{}
	session.tunnelErr = nil
	session.dataPlaneDone = make(chan struct{})
	session.mu.Unlock()

	result := make(chan error, 1)
	go func() {
		_, _, err := session.readConnectedPacket(context.Background())
		result <- err
	}()

	select {
	case err := <-result:
		t.Fatalf("readConnectedPacket() returned early with %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cause := errors.New("peer deleted child SA")
	session.discardChildSecurityAssociations(cause)

	select {
	case err := <-result:
		if !errors.Is(err, cause) {
			t.Fatalf("readConnectedPacket() error = %v, want wrapped %v", err, cause)
		}
	case <-time.After(time.Second):
		t.Fatal("readConnectedPacket() did not unblock")
	}
}

func TestLivenessLoopDoesNotConfirmPeerDuringIKESARekey(t *testing.T) {
	conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
	session := mustDialSession(t, conn)
	oldRx := time.Now().Add(-time.Hour)
	session.mu.Lock()
	session.ike = &ikeCrypto{}
	session.ikeSARekeying = true
	session.livenessTimeout = time.Nanosecond
	session.lastProtectedRx = oldRx
	session.mu.Unlock()

	session.wg.Add(1)
	go session.livenessLoop()
	time.Sleep(1100 * time.Millisecond)
	session.closeSession()
	session.wg.Wait()

	session.mu.RLock()
	got := session.lastProtectedRx
	session.mu.RUnlock()
	if !got.Equal(oldRx) {
		t.Fatalf("lastProtectedRx = %s, want unchanged %s while rekey blocks DPD", got, oldRx)
	}
}

func TestLivenessLoopFailsSecurityAssociationsAfterDPDTimeout(t *testing.T) {
	conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
	session := mustDialSession(t, conn)
	session.cfg.IKERetransmitDelays = []time.Duration{10 * time.Millisecond}
	session.mu.Lock()
	session.connected = true
	session.ike = testIKECrypto()
	session.ikeLocalInitiator = true
	session.initiatorSPI = session.ike.initiatorSPI
	session.responderSPI = session.ike.responderSPI
	session.livenessTimeout = 10 * time.Millisecond
	session.lastProtectedRx = time.Now().Add(-20 * time.Millisecond)
	session.dataPlaneDone = make(chan struct{})
	session.mu.Unlock()

	session.wg.Add(1)
	go session.livenessLoop()
	defer func() {
		session.closeSession()
		session.wg.Wait()
	}()

	errCh := make(chan error, 1)
	go func() {
		_, _, err := session.readConnectedPacket(context.Background())
		errCh <- err
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, errIKERequestIncomplete) || !strings.Contains(err.Error(), "liveness check") {
			t.Fatalf("readConnectedPacket() error = %v, want liveness incomplete request", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("liveness DPD timeout did not unblock connected read")
	}
}

func TestSARekeyTimeAppliesJitterInsideRekeyMargin(t *testing.T) {
	tests := []struct {
		name          string
		lifetime      time.Duration
		margin        time.Duration
		jitter        time.Duration
		wantWindow    time.Duration
		wantAfterBase time.Duration
	}{
		{name: "child and ike sa soft lifetime jitter", lifetime: time.Hour, margin: 10 * time.Minute, jitter: 2 * time.Minute, wantWindow: 5 * time.Minute, wantAfterBase: 2 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previous := saRekeyJitter
			saRekeyJitter = func(maxDelay time.Duration) time.Duration {
				if maxDelay != tt.wantWindow {
					t.Fatalf("jitter window = %s, want %s", maxDelay, tt.wantWindow)
				}
				return tt.jitter
			}
			t.Cleanup(func() {
				saRekeyJitter = previous
			})

			now := time.Unix(1000, 0)
			got := childSARekeyTime(now, tt.lifetime, tt.margin)
			want := now.Add(tt.lifetime - tt.margin + tt.wantAfterBase)
			if !got.Equal(want) {
				t.Fatalf("childSARekeyTime() = %s, want %s", got, want)
			}
			if !got.Before(now.Add(tt.lifetime)) {
				t.Fatalf("childSARekeyTime() = %s, want before hard lifetime", got)
			}
		})
	}
}

func TestRekeyReleaseWakesStateWaiters(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Session)
		begin   func(*Session) (func(), error)
	}{
		{
			name: "ike sa rekey release",
			prepare: func(session *Session) {
				session.mu.Lock()
				session.ike = testIKECrypto()
				session.initiatorSPI = 0x0102030405060708
				session.responderSPI = 0x1112131415161718
				session.mu.Unlock()
			},
			begin: func(session *Session) (func(), error) {
				_, release, err := session.beginIKESARekey()
				return release, err
			},
		},
		{
			name: "child sa rekey release",
			prepare: func(session *Session) {
				tsi, tsr := testChildSATrafficSelectors()
				session.mu.Lock()
				session.connected = true
				session.ike = testIKECrypto()
				session.initiatorSPI = 0x0102030405060708
				session.responderSPI = 0x1112131415161718
				session.tunnel = Info{
					InnerIPv4:                 net.IPv4(10, 0, 0, 1),
					PCSCFIPs:                  []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI:           0x01020304,
					ESPResponderSPI:           0x10203040,
					InitiatorTrafficSelectors: tsi,
					ResponderTrafficSelectors: tsr,
				}
				session.mu.Unlock()
			},
			begin: func(session *Session) (func(), error) {
				_, release, err := session.beginChildSARekey()
				return release, err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			tt.prepare(session)
			release, err := tt.begin(session)
			if err != nil {
				t.Fatalf("begin rekey error = %v", err)
			}

			started := make(chan struct{})
			woke := make(chan bool, 1)
			go func() {
				close(started)
				woke <- session.waitForRekeyStateChange()
			}()
			<-started
			release()

			select {
			case ok := <-woke:
				if !ok {
					t.Fatal("waitForRekeyStateChange() = false, want true")
				}
			case <-time.After(time.Second):
				t.Fatal("rekey release did not wake state waiter")
			}
		})
	}
}

func TestIKESAState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Session)
		want    ikeSAState
	}{
		{
			name: "none without ike crypto",
			want: ikeSAStateNone,
		},
		{
			name: "active",
			prepare: func(session *Session) {
				session.ike = testIKECrypto()
			},
			want: ikeSAStateActive,
		},
		{
			name: "rekeying",
			prepare: func(session *Session) {
				session.ike = testIKECrypto()
				session.ikeSARekeying = true
			},
			want: ikeSAStateRekeying,
		},
		{
			name: "pending install wins over rekeying",
			prepare: func(session *Session) {
				session.ike = testIKECrypto()
				session.ikeSARekeying = true
				session.pendingIKESAReady = true
			},
			want: ikeSAStatePendingInstall,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}
			if tt.prepare != nil {
				tt.prepare(session)
			}
			if got := session.ikeSAState(); got != tt.want {
				t.Fatalf("ikeSAState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestChildSAState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Session)
		want    childSAState
	}{
		{
			name: "none without connected child sa",
			want: childSAStateNone,
		},
		{
			name: "active",
			prepare: func(session *Session) {
				session.connected = true
			},
			want: childSAStateActive,
		},
		{
			name: "rekeying",
			prepare: func(session *Session) {
				session.connected = true
				session.childSARekeying = true
			},
			want: childSAStateRekeying,
		},
		{
			name: "pending outbound wins over rekeying",
			prepare: func(session *Session) {
				session.connected = true
				session.childSARekeying = true
				session.pendingChildSA.ready = true
			},
			want: childSAStatePendingOutbound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}
			if tt.prepare != nil {
				tt.prepare(session)
			}
			if got := session.childSAState(); got != tt.want {
				t.Fatalf("childSAState() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBeginRekeyRejectsPendingState(t *testing.T) {
	tests := []struct {
		name    string
		prepare func(*Session)
		begin   func(*Session) (func(), error)
		wantErr error
	}{
		{
			name: "ike rekey rejects pending ike install",
			prepare: func(session *Session) {
				session.ike = testIKECrypto()
				session.pendingIKESAReady = true
			},
			begin: func(session *Session) (func(), error) {
				_, release, err := session.beginIKESARekey()
				return release, err
			},
			wantErr: errIKESARekeyInProgress,
		},
		{
			name: "ike rekey rejects pending child outbound",
			prepare: func(session *Session) {
				session.ike = testIKECrypto()
				session.connected = true
				session.pendingChildSA.ready = true
			},
			begin: func(session *Session) (func(), error) {
				_, release, err := session.beginIKESARekey()
				return release, err
			},
			wantErr: errChildSARekeyInProgress,
		},
		{
			name: "child rekey rejects pending ike install",
			prepare: func(session *Session) {
				session.ike = testIKECrypto()
				session.pendingIKESAReady = true
			},
			begin: func(session *Session) (func(), error) {
				_, release, err := session.beginChildSARekey()
				return release, err
			},
			wantErr: errIKESARekeyInProgress,
		},
		{
			name: "child rekey rejects pending child outbound",
			prepare: func(session *Session) {
				session.ike = testIKECrypto()
				session.connected = true
				session.pendingChildSA.ready = true
			},
			begin: func(session *Session) (func(), error) {
				_, release, err := session.beginChildSARekey()
				return release, err
			},
			wantErr: errChildSARekeyInProgress,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			tt.prepare(session)
			session.mu.Unlock()

			release, err := tt.begin(session)
			if release != nil {
				release()
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("begin rekey error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestNextRekeyLoopDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	tests := []struct {
		name             string
		rekeyAt          time.Time
		expiresAt        time.Time
		temporaryFailure rekeyTemporaryFailureBackoff
		want             time.Time
	}{
		{name: "no lifetime state", want: time.Time{}},
		{name: "soft rekey before hard lifetime", rekeyAt: now.Add(time.Minute), expiresAt: now.Add(time.Hour), want: now.Add(time.Minute)},
		{name: "hard lifetime without soft rekey", expiresAt: now.Add(time.Hour), want: now.Add(time.Hour)},
		{
			name:             "temporary failure waits until retry",
			rekeyAt:          now.Add(-time.Second),
			expiresAt:        now.Add(time.Hour),
			temporaryFailure: rekeyTemporaryFailureBackoff{retryAt: now.Add(30 * time.Second)},
			want:             now.Add(30 * time.Second),
		},
		{
			name:             "hard lifetime wins over retry backoff",
			rekeyAt:          now.Add(-time.Second),
			expiresAt:        now.Add(10 * time.Second),
			temporaryFailure: rekeyTemporaryFailureBackoff{retryAt: now.Add(30 * time.Second)},
			want:             now.Add(10 * time.Second),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nextRekeyLoopDeadline(tt.rekeyAt, tt.expiresAt, tt.temporaryFailure, now)
			if !got.Equal(tt.want) {
				t.Fatalf("nextRekeyLoopDeadline() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestDeferRekeyAfterErrorMovesExpiredSoftDeadline(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	oldRetryDelay := rekeyTemporaryFailureRetryDelay
	rekeyTemporaryFailureRetryDelay = 30 * time.Second
	defer func() { rekeyTemporaryFailureRetryDelay = oldRetryDelay }()

	tests := []struct {
		name      string
		prepare   func(*Session)
		deferFunc func(*Session, time.Time, time.Time) time.Time
		check     func(*testing.T, *Session, time.Time)
		expiresAt time.Time
		want      time.Time
	}{
		{
			name: "ike sa",
			prepare: func(session *Session) {
				session.ikeSARekeyAt = now.Add(-time.Second)
			},
			deferFunc: func(session *Session, now, expiresAt time.Time) time.Time {
				return session.deferIKESARekey(now, expiresAt)
			},
			check: func(t *testing.T, session *Session, want time.Time) {
				if !session.ikeSARekeyAt.Equal(want) {
					t.Fatalf("ikeSARekeyAt = %s, want %s", session.ikeSARekeyAt, want)
				}
			},
			want: now.Add(30 * time.Second),
		},
		{
			name: "child sa hard lifetime caps retry",
			prepare: func(session *Session) {
				session.childSARekeyAt = now.Add(-time.Second)
			},
			deferFunc: func(session *Session, now, expiresAt time.Time) time.Time {
				return session.deferChildSARekey(now, expiresAt)
			},
			check: func(t *testing.T, session *Session, want time.Time) {
				if !session.childSARekeyAt.Equal(want) {
					t.Fatalf("childSARekeyAt = %s, want %s", session.childSARekeyAt, want)
				}
			},
			expiresAt: now.Add(10 * time.Second),
			want:      now.Add(10 * time.Second),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}
			tt.prepare(session)
			got := tt.deferFunc(session, now, tt.expiresAt)
			if !got.Equal(tt.want) {
				t.Fatalf("defer retry = %s, want %s", got, tt.want)
			}
			tt.check(t, session, tt.want)
		})
	}
}

func TestByteSoftRekeyWakesRekeyLoops(t *testing.T) {
	tests := []struct {
		name string
		run  func(*Session, time.Time)
	}{
		{
			name: "ike outbound byte soft lifetime",
			run: func(session *Session, now time.Time) {
				session.mu.Lock()
				session.ike = &ikeCrypto{}
				session.ikeSAByteRekeyAt = 10
				session.ikeSARekeyAt = now.Add(time.Hour)
				session.mu.Unlock()
				session.addIKESAOutboundBytes(10, now)
			},
		},
		{
			name: "child outbound byte soft lifetime",
			run: func(session *Session, now time.Time) {
				session.mu.Lock()
				session.connected = true
				session.childSAByteRekeyAt = 10
				session.childSARekeyAt = now.Add(time.Hour)
				session.mu.Unlock()
				session.addCurrentChildSAOutboundBytes(10, now)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			tt.run(session, time.Unix(1_700_000_000, 0))

			select {
			case <-session.rekeyWake:
			default:
				t.Fatal("rekeyWake was not signaled")
			}
		})
	}
}

func TestChildSARekeyRequestPayloads(t *testing.T) {
	tests := []struct {
		name          string
		oldInboundSPI uint32
		newInboundSPI uint32
		nonce         []byte
		addKE         bool
	}{
		{
			name:          "rekey notify identifies old inbound spi",
			oldInboundSPI: 0x01020304,
			newInboundSPI: 0x11121314,
			nonce:         testNonce("child rekey"),
		},
		{
			name:          "rekey includes pfs key exchange",
			oldInboundSPI: 0x01020304,
			newInboundSPI: 0x11121314,
			nonce:         testNonce("child rekey pfs"),
			addKE:         true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pfs *ikeCrypto
			if tt.addKE {
				var err error
				pfs, err = newIKECrypto(transformDH2048MODP)
				if err != nil {
					t.Fatalf("newIKECrypto() error = %v", err)
				}
			}
			payloads := childSARekeyRequestPayloads(handshakeConfig(Config{}), tt.oldInboundSPI, tt.newInboundSPI, tt.nonce, pfs)
			wantPayloadCount := 5
			if tt.addKE {
				wantPayloadCount = 6
			}
			if len(payloads) != wantPayloadCount {
				t.Fatalf("payload count = %d, want %d", len(payloads), wantPayloadCount)
			}
			notify, ok := payloads[0].(*ike.NotifyPayload)
			if !ok {
				t.Fatalf("payload[0] = %T, want *ike.NotifyPayload", payloads[0])
			}
			if notify.ProtocolID != protocolIDESP || notify.NotifyType != notifyTypeRekeySA {
				t.Fatalf("notify = protocol %d type %d, want ESP REKEY_SA", notify.ProtocolID, notify.NotifyType)
			}
			if got := binary.BigEndian.Uint32(notify.SPI); got != tt.oldInboundSPI {
				t.Fatalf("notify spi = %#x, want %#x", got, tt.oldInboundSPI)
			}
			sa := ike.FindSAPayload(payloads)
			if sa == nil || len(sa.Proposals) == 0 {
				t.Fatal("SA payload is missing")
			}
			if got := binary.BigEndian.Uint32(sa.Proposals[0].SPI); got != tt.newInboundSPI {
				t.Fatalf("new child spi = %#x, want %#x", got, tt.newInboundSPI)
			}
			if tt.addKE {
				ke := ike.FindKEPayload(payloads, transformDH2048MODP)
				if ke == nil {
					t.Fatal("KE payload is missing")
				}
				if got := proposalTransformID(sa.Proposals[0], transformTypeDH); got != transformDH2048MODP {
					t.Fatalf("proposal dh group = %d, want %d", got, transformDH2048MODP)
				}
			}
			nonce := ike.FindNoncePayload(payloads)
			if nonce == nil || !bytes.Equal(nonce.Data, tt.nonce) {
				t.Fatalf("nonce = %x, want %x", nonce.Data, tt.nonce)
			}
			tt.nonce[0] ^= 0xff
			if bytes.Equal(nonce.Data, tt.nonce) {
				t.Fatal("nonce payload aliases caller buffer")
			}
			if ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi) == nil || ike.FindTrafficSelectorPayload(payloads, payloadTypeTSr) == nil {
				t.Fatal("traffic selectors are missing")
			}
		})
	}
}

func TestChildSARekeyRequestPayloadsUseCurrentSAProposal(t *testing.T) {
	singleIPv4Selector := func(ip net.IP) ike.TrafficSelector {
		selector := ike.TrafficSelectorsAny()[0]
		ip4 := ip.To4()
		copy(selector.Data[4:8], ip4)
		copy(selector.Data[8:12], ip4)
		return selector
	}
	trafficSelectorsEqual := func(a, b []ike.TrafficSelector) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i].Type != b[i].Type || a[i].ProtocolID != b[i].ProtocolID || !bytes.Equal(a[i].Data, b[i].Data) {
				return false
			}
		}
		return true
	}
	currentTSi := []ike.TrafficSelector{singleIPv4Selector(net.IPv4(10, 0, 0, 1))}
	currentTSr := []ike.TrafficSelector{singleIPv4Selector(net.IPv4(10, 0, 0, 2))}
	state := childSARekeyState{
		cfg: handshakeConfig(Config{
			ChildEncryptionKeyLens: []uint16{256},
			ChildIntegrity:         []uint16{transformINTEGHMACSHA256},
		}),
		info: Info{
			Encryption:                transformENCRAESCBC,
			EncryptionKeyLen:          128,
			Integrity:                 transformINTEGHMACSHA196,
			InitiatorTrafficSelectors: currentTSi,
			ResponderTrafficSelectors: currentTSr,
		},
		inboundSPI: 0x01020304,
	}
	pfs, err := newIKECrypto(transformDH2048MODP)
	if err != nil {
		t.Fatalf("newIKECrypto() error = %v", err)
	}

	payloads := state.childSARekeyRequestPayloads(0x11121314, testNonce("child rekey current proposal"), pfs)

	sa := ike.FindSAPayload(payloads)
	if sa == nil || len(sa.Proposals) != 1 {
		t.Fatalf("SA payload = %+v, want one current proposal", sa)
	}
	proposal := sa.Proposals[0]
	if got := proposal.Number; got != 1 {
		t.Fatalf("proposal number = %d, want 1", got)
	}
	encr := proposal.Transforms[0]
	keyLen, ok := transformKeyLength(encr)
	if !ok || keyLen != 128 {
		t.Fatalf("encryption key length = %d/%t, want current 128", keyLen, ok)
	}
	if got := proposalTransformIDValue(proposal, transformTypeINTEG); got != transformINTEGHMACSHA196 {
		t.Fatalf("integrity transform = %d, want current %d", got, transformINTEGHMACSHA196)
	}
	if got := proposalTransformIDValue(proposal, transformTypeDH); got != transformDH2048MODP {
		t.Fatalf("dh transform = %d, want %d", got, transformDH2048MODP)
	}
	tsi := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi)
	tsr := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSr)
	if tsi == nil || tsr == nil {
		t.Fatal("traffic selector payloads are missing")
	}
	if !trafficSelectorsEqual(tsi.Selectors, currentTSi) {
		t.Fatalf("TSi = %+v, want current %+v", tsi.Selectors, currentTSi)
	}
	if !trafficSelectorsEqual(tsr.Selectors, currentTSr) {
		t.Fatalf("TSr = %+v, want current %+v", tsr.Selectors, currentTSr)
	}
}

func TestChildSACreateRequestPayloads(t *testing.T) {
	tests := []struct {
		name          string
		newInboundSPI uint32
		nonce         []byte
	}{
		{name: "new child sa without rekey notify", newInboundSPI: 0x11121314, nonce: testNonce("child create")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payloads := childSACreateRequestPayloads(handshakeConfig(Config{}), tt.newInboundSPI, tt.nonce)
			if ike.FindNotifyPayload(payloads, notifyTypeRekeySA) != nil {
				t.Fatal("REKEY_SA notify is present in fresh Child SA create")
			}
			sa := ike.FindSAPayload(payloads)
			if sa == nil || len(sa.Proposals) == 0 {
				t.Fatal("SA payload is missing")
			}
			if got := binary.BigEndian.Uint32(sa.Proposals[0].SPI); got != tt.newInboundSPI {
				t.Fatalf("new child spi = %#x, want %#x", got, tt.newInboundSPI)
			}
			nonce := ike.FindNoncePayload(payloads)
			if nonce == nil || !bytes.Equal(nonce.Data, tt.nonce) {
				t.Fatalf("nonce = %x, want %x", nonce.Data, tt.nonce)
			}
			if ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi) == nil || ike.FindTrafficSelectorPayload(payloads, payloadTypeTSr) == nil {
				t.Fatal("traffic selectors are missing")
			}
		})
	}
}

func TestIKESARekeyRequestPayloads(t *testing.T) {
	tests := []struct {
		name         string
		initiatorSPI uint64
		nonce        []byte
		public       []byte
	}{
		{
			name:         "new ike spi nonce and ke",
			initiatorSPI: 0x0102030405060708,
			nonce:        testNonce("ike rekey"),
			public:       []byte{0x11, 0x22, 0x33},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := &ikeCrypto{
				dhGroup:      transformDH2048MODP,
				initiatorSPI: tt.initiatorSPI,
				nonceI:       append([]byte(nil), tt.nonce...),
				public:       append([]byte(nil), tt.public...),
			}
			current := testIKESARekeyCrypto(transformDH2048MODP, transformPRFHMACSHA1)
			payloads := ikeSARekeyRequestPayloads(current, next)
			if len(payloads) != 3 {
				t.Fatalf("payload count = %d, want 3", len(payloads))
			}
			if ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi) != nil || ike.FindTrafficSelectorPayload(payloads, payloadTypeTSr) != nil {
				t.Fatal("IKE SA rekey request unexpectedly included traffic selectors")
			}
			sa := ike.FindSAPayload(payloads)
			if sa == nil || len(sa.Proposals) == 0 {
				t.Fatal("SA payload is missing")
			}
			if got := binary.BigEndian.Uint64(sa.Proposals[0].SPI); got != tt.initiatorSPI {
				t.Fatalf("new ike spi = %#x, want %#x", got, tt.initiatorSPI)
			}
			if got := proposalTransformIDValue(sa.Proposals[0], transformTypeINTEG); got != current.integ {
				t.Fatalf("integrity transform = %d, want current %d", got, current.integ)
			}
			if got := proposalTransformIDValue(sa.Proposals[0], transformTypePRF); got != current.prf {
				t.Fatalf("prf transform = %d, want current %d", got, current.prf)
			}
			nonce := ike.FindNoncePayload(payloads)
			if nonce == nil || !bytes.Equal(nonce.Data, tt.nonce) {
				t.Fatalf("nonce = %x, want %x", nonce.Data, tt.nonce)
			}
			ke := ike.FindKEPayload(payloads, transformDH2048MODP)
			if ke == nil || !bytes.Equal(ke.Data, tt.public) {
				t.Fatalf("ke = %x, want %x", ke.Data, tt.public)
			}
		})
	}
}

func TestInitiatedIKESARekeyResultRetriesInvalidKEPayload(t *testing.T) {
	tests := []struct {
		name       string
		initialDH  uint16
		retryDH    uint16
		wantGroups []uint16
	}{
		{
			name:       "retries with responder preferred group",
			initialDH:  transformDH1024MODP,
			retryDH:    transformDH2048MODP,
			wantGroups: []uint16{transformDH1024MODP, transformDH2048MODP},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotGroups []uint16
			session := &Session{}
			state := ikeSARekeyState{
				ike: testIKESARekeyCrypto(tt.initialDH, transformPRFHMACSHA1),
			}
			exchange := func(_ context.Context, _ ikeSARekeyState, next *ikeCrypto) ([]ike.Payload, error) {
				gotGroups = append(gotGroups, next.dhGroup)
				data := make([]byte, 2)
				binary.BigEndian.PutUint16(data, tt.retryDH)
				return []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeInvalidKEPayload, Data: data}}, nil
			}

			_, err := session.initiatedIKESARekeyResult(context.Background(), state, exchange)
			if err == nil || !strings.Contains(err.Error(), "repeated INVALID_KE_PAYLOAD group") {
				t.Fatalf("initiatedIKESARekeyResult() error = %v, want repeated INVALID_KE_PAYLOAD group", err)
			}
			if !slices.Equal(gotGroups, tt.wantGroups) {
				t.Fatalf("rekey dh groups = %v, want %v", gotGroups, tt.wantGroups)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsRejectsPeerChildCreate(t *testing.T) {
	tests := []struct {
		name           string
		peerInboundSPI uint32
	}{
		{name: "peer creates additional child sa", peerInboundSPI: 0x50607080},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := createChildSARequestState{
				ike: &ikeCrypto{
					prf: transformPRFHMACSHA1,
					keys: ikeKeys{
						SKD: bytes.Repeat([]byte{0x11}, 20),
					},
				},
				cfg: Config{
					ChildEncryptionKeyLens: []uint16{128},
					ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
				},
				info: Info{
					InnerIPv4:        net.IPv4(10, 0, 0, 1),
					PCSCFIPs:         []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI:  0x01020304,
					ESPResponderSPI:  0x10203040,
					Encryption:       transformENCRAESCBC,
					EncryptionKeyLen: 128,
					Integrity:        transformINTEGHMACSHA196,
				},
				inboundSPI:  0x01020304,
				outboundSPI: 0x10203040,
			}
			payloads := childSACreateRequestPayloads(handshakeConfig(state.cfg), tt.peerInboundSPI, testNonce("peer nonce"))

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if action.installChild || action.installIKE || action.simultaneousChild || action.simultaneousIKE {
				t.Fatalf("action = %+v, want no state install for unsupported additional child sa", action)
			}
			notify := ike.FindNotifyPayload(responsePayloads, notifyTypeNoAdditionalSAs)
			if notify == nil {
				t.Fatalf("response payloads = %#v, want NO_ADDITIONAL_SAS", responsePayloads)
			}
			if notify.ProtocolID != 0 || len(notify.SPI) != 0 {
				t.Fatalf("notify protocol/spi = %d/%x, want 0/empty", notify.ProtocolID, notify.SPI)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsClassifiesByFirstSAProposal(t *testing.T) {
	tests := []struct {
		name     string
		state    func(t *testing.T) createChildSARequestState
		payloads func(t *testing.T, state createChildSARequestState) []ike.Payload
		check    func(t *testing.T, responsePayloads []ike.Payload, action createChildSAAction)
	}{
		{
			name: "ike rekey ignores stray child rekey notify and selectors",
			state: func(t *testing.T) createChildSARequestState {
				t.Helper()
				old := testIKESARekeyCrypto(transformDH1024MODP, transformPRFHMACSHA1)
				return createChildSARequestState{
					ike: old,
					cfg: Config{
						DHGroups:             []uint16{transformDH1024MODP},
						IKEEncryptionKeyLens: []uint16{128},
						IKEIntegrity:         []uint16{transformINTEGHMACSHA196},
						IKEPRF:               []uint16{transformPRFHMACSHA1},
					},
					outboundSPI: 0x10203040,
				}
			},
			payloads: func(t *testing.T, state createChildSARequestState) []ike.Payload {
				t.Helper()
				peer, err := newIKECrypto(transformDH1024MODP)
				if err != nil {
					t.Fatalf("newIKECrypto() peer error = %v", err)
				}
				peer.SetSPIs(0x0102030405060708, 0)
				peer.SetNonces(testNonce("peer nonce"), nil)
				payloads := ikeSARekeyRequestPayloads(state.ike, peer)
				payloads = append(payloads,
					&ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeRekeySA, SPI: uint32Bytes(state.outboundSPI)},
					&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
					&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
				)
				return payloads
			},
			check: func(t *testing.T, responsePayloads []ike.Payload, action createChildSAAction) {
				t.Helper()
				if !action.installIKE || action.installChild {
					t.Fatalf("action = %+v, want IKE SA rekey only", action)
				}
				if ike.FindTrafficSelectorPayload(responsePayloads, payloadTypeTSi) != nil || ike.FindTrafficSelectorPayload(responsePayloads, payloadTypeTSr) != nil {
					t.Fatal("IKE SA rekey response unexpectedly included traffic selectors")
				}
				if ike.FindNotifyPayload(responsePayloads, notifyTypeChildSANotFound) != nil {
					t.Fatal("IKE SA rekey was misclassified as Child SA rekey")
				}
			},
		},
		{
			name: "esp proposal without selectors is still additional child create",
			state: func(t *testing.T) createChildSARequestState {
				t.Helper()
				return createChildSARequestState{
					cfg: Config{
						ChildEncryptionKeyLens: []uint16{128},
						ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
					},
				}
			},
			payloads: func(t *testing.T, state createChildSARequestState) []ike.Payload {
				t.Helper()
				return []ike.Payload{
					&ike.SecurityAssociationPayload{Proposals: childSAProposals(handshakeConfig(state.cfg), 0x50607080)},
					&ike.NoncePayload{Data: testNonce("peer nonce")},
				}
			},
			check: func(t *testing.T, responsePayloads []ike.Payload, action createChildSAAction) {
				t.Helper()
				if action.installChild || action.installIKE {
					t.Fatalf("action = %+v, want no SA install", action)
				}
				if notify := ike.FindNotifyPayload(responsePayloads, notifyTypeNoAdditionalSAs); notify == nil {
					t.Fatalf("response payloads = %#v, want NO_ADDITIONAL_SAS", responsePayloads)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := tt.state(t)
			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, tt.payloads(t, state))
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			tt.check(t, responsePayloads, action)
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsRejectsMissingSAAsInvalidSyntax(t *testing.T) {
	tests := []struct {
		name     string
		payloads []ike.Payload
	}{
		{
			name: "missing SA in create_child_sa request",
			payloads: []ike.Payload{
				&ike.NoncePayload{Data: testNonce("peer nonce")},
				&ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
			},
		},
		{
			name: "rekey notify without SA",
			payloads: []ike.Payload{
				&ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeRekeySA, SPI: uint32Bytes(0x10203040)},
				&ike.NoncePayload{Data: testNonce("peer nonce")},
				&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
				&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responsePayloads, action, err := buildCreateChildSAResponsePayloads(createChildSARequestState{}, tt.payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if !action.fatalIKE {
				t.Fatal("fatalIKE = false, want true for invalid CREATE_CHILD_SA syntax")
			}
			var syntax ike.InvalidSyntaxError
			if !errors.As(action.fatalErr, &syntax) {
				t.Fatalf("fatalErr = %v, want InvalidSyntaxError", action.fatalErr)
			}
			notify := ike.FindNotifyPayload(responsePayloads, notifyTypeInvalidSyntax)
			if notify == nil {
				t.Fatalf("response payloads = %#v, want INVALID_SYNTAX", responsePayloads)
			}
			if notify.ProtocolID != 0 || len(notify.SPI) != 0 || len(notify.Data) != 0 {
				t.Fatalf("INVALID_SYNTAX notify = protocol %d spi %x data %x, want empty protocol/spi/data", notify.ProtocolID, notify.SPI, notify.Data)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsRejectsInvalidProposalNumbering(t *testing.T) {
	payloads := childSARekeyRequestPayloads(handshakeConfig(Config{}), 0x10203040, 0x50607080, testNonce("peer nonce"), nil)
	proposals := ike.FindSAPayload(payloads).Proposals
	proposals[0].Number = 2

	responsePayloads, action, err := buildCreateChildSAResponsePayloads(createChildSARequestState{}, payloads)
	if err != nil {
		t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
	}
	if !action.fatalIKE {
		t.Fatal("fatalIKE = false, want true for invalid CREATE_CHILD_SA syntax")
	}
	var syntax ike.InvalidSyntaxError
	if !errors.As(action.fatalErr, &syntax) {
		t.Fatalf("fatalErr = %v, want InvalidSyntaxError", action.fatalErr)
	}
	if notify := ike.FindNotifyPayload(responsePayloads, notifyTypeInvalidSyntax); notify == nil {
		t.Fatalf("response payloads = %#v, want INVALID_SYNTAX", responsePayloads)
	}
}

func TestHandleCreateChildSARequestMissingSAClosesIKESA(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "missing SA is fatal syntax error"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			wire := protectedIKEWire(t, crypto, exchangeTypeCreateChildSA, 0, 0, []ike.Payload{
				&ike.NoncePayload{Data: testNonce("peer nonce")},
				&ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: bytes.Repeat([]byte{0x01}, 256)},
			}, false)
			var packet ike.IKEPacket
			if err := packet.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			session.mu.Lock()
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.initiatorSPI = packet.Header.InitiatorSPI
			session.responderSPI = packet.Header.ResponderSPI
			session.outerNAT = peer
			session.mu.Unlock()
			state := createChildSARequestState{
				ike:            crypto,
				localInitiator: true,
				useNATT:        true,
				initiatorSPI:   packet.Header.InitiatorSPI,
				responderSPI:   packet.Header.ResponderSPI,
				peer:           peer,
			}

			handled, err := session.handleCreateChildSARequest(state, packet, peer)

			if !handled || err != nil {
				t.Fatalf("handleCreateChildSARequest() = (%t, %v), want handled without direct error", handled, err)
			}
			if got := len(conn.writes); got != 1 {
				t.Fatalf("writes = %d, want INVALID_SYNTAX response", got)
			}
			var response ike.IKEPacket
			if err := response.UnmarshalBinary(conn.writes[0][4:]); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			payloads, err := crypto.OpenIKE(response, true)
			if err != nil {
				t.Fatalf("response OpenIKE() error = %v", err)
			}
			if notify := ike.FindNotifyPayload(payloads, notifyTypeInvalidSyntax); notify == nil {
				t.Fatalf("response payloads = %#v, want INVALID_SYNTAX", payloads)
			}
			if !session.isClosed() {
				t.Fatal("session is active, want closed after fatal syntax error")
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsForPeerChildRekey(t *testing.T) {
	tests := []struct {
		name           string
		oldOutboundSPI uint32
		peerInboundSPI uint32
		addKE          bool
	}{
		{name: "peer initiated child rekey", oldOutboundSPI: 0x10203040, peerInboundSPI: 0x50607080},
		{name: "peer initiated child rekey with pfs", oldOutboundSPI: 0x10203040, peerInboundSPI: 0x50607080, addKE: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := createChildSARequestState{
				ike: &ikeCrypto{
					prf: transformPRFHMACSHA1,
					keys: ikeKeys{
						SKD: bytes.Repeat([]byte{0x11}, 20),
					},
				},
				cfg: Config{
					ChildEncryptionKeyLens: []uint16{128},
					ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
				},
				info: Info{
					InnerIPv4:                 net.IPv4(10, 0, 0, 1),
					PCSCFIPs:                  []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI:           0x01020304,
					ESPResponderSPI:           tt.oldOutboundSPI,
					Encryption:                transformENCRAESCBC,
					EncryptionKeyLen:          128,
					Integrity:                 transformINTEGHMACSHA196,
					InitiatorTrafficSelectors: ike.TrafficSelectorsAny()[:1],
					ResponderTrafficSelectors: ike.TrafficSelectorsAny()[:1],
				},
				inboundSPI:  0x01020304,
				outboundSPI: tt.oldOutboundSPI,
			}
			var pfs *ikeCrypto
			if tt.addKE {
				var err error
				pfs, err = newIKECrypto(transformDH2048MODP)
				if err != nil {
					t.Fatalf("newIKECrypto() error = %v", err)
				}
			}
			payloads := childSARekeyRequestPayloads(handshakeConfig(state.cfg), tt.oldOutboundSPI, tt.peerInboundSPI, testNonce("peer nonce"), pfs)

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if !action.installChild {
				t.Fatal("installChild = false, want true")
			}
			if action.child.info.ESPResponderSPI != tt.peerInboundSPI {
				t.Fatalf("peer inbound spi = %#x, want %#x", action.child.info.ESPResponderSPI, tt.peerInboundSPI)
			}
			if action.child.info.ESPInitiatorSPI == 0 || action.child.info.ESPInitiatorSPI == state.inboundSPI {
				t.Fatalf("local inbound spi = %#x, want new nonzero spi", action.child.info.ESPInitiatorSPI)
			}
			if action.child.outbound.SPI != tt.peerInboundSPI {
				t.Fatalf("outbound spi = %#x, want peer inbound %#x", action.child.outbound.SPI, tt.peerInboundSPI)
			}
			if !bytes.Equal(action.child.outbound.EncryptionKey, action.child.keys.EncryptionResponder) {
				t.Fatal("outbound key does not use responder-to-initiator KEYMAT")
			}
			if action.child.inbound.SPI != action.child.info.ESPInitiatorSPI {
				t.Fatalf("inbound spi = %#x, want %#x", action.child.inbound.SPI, action.child.info.ESPInitiatorSPI)
			}
			if !bytes.Equal(action.child.inbound.EncryptionKey, action.child.keys.EncryptionInitiator) {
				t.Fatal("inbound key does not use initiator-to-responder KEYMAT")
			}
			if ike.FindSAPayload(responsePayloads) == nil || ike.FindNoncePayload(responsePayloads) == nil {
				t.Fatalf("response payloads = %T, want SA and Nonce", responsePayloads)
			}
			responseSA := ike.FindSAPayload(responsePayloads)
			responseDH := proposalTransformID(responseSA.Proposals[0], transformTypeDH)
			responseKE := ike.FindKEPayload(responsePayloads, transformDH2048MODP)
			if tt.addKE {
				if responseDH != transformDH2048MODP {
					t.Fatalf("response dh group = %d, want %d", responseDH, transformDH2048MODP)
				}
				if responseKE == nil {
					t.Fatal("response KE payload is missing")
				}
			} else if responseDH != 0 || responseKE != nil {
				t.Fatalf("unexpected pfs response: dh=%d ke=%v", responseDH, responseKE != nil)
			}
			tsi := ike.FindTrafficSelectorPayload(responsePayloads, payloadTypeTSi)
			tsr := ike.FindTrafficSelectorPayload(responsePayloads, payloadTypeTSr)
			if tsi == nil || tsr == nil {
				t.Fatal("response traffic selectors are missing")
			}
			if len(tsi.Selectors) != 1 || len(tsr.Selectors) != 1 {
				t.Fatalf("response traffic selector counts = %d/%d, want current child sa selectors", len(tsi.Selectors), len(tsr.Selectors))
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsPreservesAcceptedChildProposalNumber(t *testing.T) {
	state := createChildSARequestState{
		ike: &ikeCrypto{
			prf: transformPRFHMACSHA1,
			keys: ikeKeys{
				SKD: bytes.Repeat([]byte{0x11}, 20),
			},
		},
		cfg: Config{
			ChildEncryptionKeyLens: []uint16{128},
			ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
		},
		info: Info{
			InnerIPv4:                 net.IPv4(10, 0, 0, 1),
			PCSCFIPs:                  []net.IP{net.IPv4(10, 0, 0, 2)},
			ESPInitiatorSPI:           0x01020304,
			ESPResponderSPI:           0x10203040,
			Encryption:                transformENCRAESCBC,
			EncryptionKeyLen:          128,
			Integrity:                 transformINTEGHMACSHA196,
			InitiatorTrafficSelectors: ike.TrafficSelectorsAny()[:1],
			ResponderTrafficSelectors: ike.TrafficSelectorsAny()[:1],
		},
		inboundSPI:  0x01020304,
		outboundSPI: 0x10203040,
	}
	proposals := childSAProposals(handshakeConfig(state.cfg), 0x50607080)
	proposals = append([]ike.Proposal{
		{
			Number:     1,
			ProtocolID: proposalProtocolESP,
			SPI:        uint64Bytes(0x0102030405060708),
			Transforms: proposals[0].Transforms,
		},
	}, proposals[0])
	proposals[1].Number = 2
	payloads := childSARekeyRequestPayloads(handshakeConfig(state.cfg), state.outboundSPI, 0x50607080, testNonce("peer nonce"), nil)
	ike.FindSAPayload(payloads).Proposals = proposals

	responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
	if err != nil {
		t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
	}
	if !action.installChild {
		t.Fatal("installChild = false, want true")
	}
	responseSA := ike.FindSAPayload(responsePayloads)
	if responseSA == nil || len(responseSA.Proposals) != 1 {
		t.Fatalf("response SA = %+v, want one proposal", responseSA)
	}
	if responseSA.Proposals[0].Number != 2 {
		t.Fatalf("response proposal number = %d, want accepted proposal number 2", responseSA.Proposals[0].Number)
	}
}

func TestBuildCreateChildSAResponsePayloadsRejectsChildRekeyAlgorithmChange(t *testing.T) {
	state := createChildSARequestState{
		ike: &ikeCrypto{
			prf: transformPRFHMACSHA1,
			keys: ikeKeys{
				SKD: bytes.Repeat([]byte{0x11}, 20),
			},
		},
		info: Info{
			ESPInitiatorSPI:           0x01020304,
			ESPResponderSPI:           0x10203040,
			Encryption:                transformENCRAESCBC,
			EncryptionKeyLen:          128,
			Integrity:                 transformINTEGHMACSHA196,
			InitiatorTrafficSelectors: ike.TrafficSelectorsAny()[:1],
			ResponderTrafficSelectors: ike.TrafficSelectorsAny()[:1],
		},
		inboundSPI:  0x01020304,
		outboundSPI: 0x10203040,
	}
	requestCfg := Config{
		ChildEncryptionKeyLens: []uint16{256},
		ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
	}
	payloads := childSARekeyRequestPayloads(handshakeConfig(requestCfg), state.outboundSPI, 0x50607080, testNonce("peer nonce"), nil)

	responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
	if err != nil {
		t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
	}
	if action.installChild {
		t.Fatal("installChild = true, want NO_PROPOSAL_CHOSEN")
	}
	if notify := ike.FindNotifyPayload(responsePayloads, notifyTypeNoProposalChosen); notify == nil {
		t.Fatalf("response payloads = %#v, want NO_PROPOSAL_CHOSEN", responsePayloads)
	}
}

func TestBuildCreateChildSAResponsePayloadsRejectsNarrowRekeySelectors(t *testing.T) {
	state := createChildSARequestState{
		ike: &ikeCrypto{
			prf: transformPRFHMACSHA1,
			keys: ikeKeys{
				SKD: bytes.Repeat([]byte{0x11}, 20),
			},
		},
		cfg: Config{
			ChildEncryptionKeyLens: []uint16{128},
			ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
		},
		info: Info{
			ESPResponderSPI:           0x10203040,
			Encryption:                transformENCRAESCBC,
			EncryptionKeyLen:          128,
			Integrity:                 transformINTEGHMACSHA196,
			InitiatorTrafficSelectors: ike.TrafficSelectorsAny(),
			ResponderTrafficSelectors: ike.TrafficSelectorsAny(),
		},
		inboundSPI:  0x01020304,
		outboundSPI: 0x10203040,
	}
	payloads := childSARekeyRequestPayloads(handshakeConfig(state.cfg), state.outboundSPI, 0x50607080, testNonce("peer nonce"), nil)
	tsi := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi)
	tsi.Selectors = tsi.Selectors[:1]

	responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
	if err != nil {
		t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
	}
	if action.installChild {
		t.Fatal("installChild = true, want TS_UNACCEPTABLE response")
	}
	if notify := ike.FindNotifyPayload(responsePayloads, notifyTypeTSUnacceptable); notify == nil {
		t.Fatalf("response payloads = %#v, want TS_UNACCEPTABLE", responsePayloads)
	}
}

func TestBuildCreateChildSAResponsePayloadsInvalidKEPayload(t *testing.T) {
	tests := []struct {
		name        string
		keGroup     uint16
		proposalDHs []uint16
		preferredDH uint16
	}{
		{name: "unsupported ke group", keGroup: 999, proposalDHs: []uint16{transformDH2048MODP}, preferredDH: transformDH2048MODP},
		{name: "proposal uses different supported group", keGroup: transformDH1024MODP, proposalDHs: []uint16{transformDH2048MODP}, preferredDH: transformDH2048MODP},
		{name: "ke group outside local policy with acceptable alternative", keGroup: transformDH1024MODP, proposalDHs: []uint16{transformDH1024MODP, transformDH2048MODP}, preferredDH: transformDH2048MODP},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := createChildSARequestState{
				cfg: Config{
					DHGroups:               []uint16{tt.preferredDH},
					ChildEncryptionKeyLens: []uint16{128},
					ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
				},
				info: Info{
					Encryption:       transformENCRAESCBC,
					EncryptionKeyLen: 128,
					Integrity:        transformINTEGHMACSHA196,
				},
				outboundSPI: 0x10203040,
			}
			proposal := childSAProposalsWithDH(handshakeConfig(state.cfg), 0x50607080, 0)[0]
			for _, dhGroup := range tt.proposalDHs {
				proposal.Transforms = slices.Insert(proposal.Transforms, len(proposal.Transforms)-1, ike.Transform{TransformType: transformTypeDH, ID: dhGroup})
			}
			payloads := []ike.Payload{
				&ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeRekeySA, SPI: uint32Bytes(state.outboundSPI)},
				&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{proposal}},
				&ike.NoncePayload{Data: testNonce("peer nonce")},
				&ike.KeyExchangePayload{DHGroup: tt.keGroup, Data: []byte{0x01}},
				&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
				&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
			}

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if action.installChild || action.installIKE {
				t.Fatal("action installs SA for INVALID_KE_PAYLOAD")
			}
			notify := ike.FindNotifyPayload(responsePayloads, notifyTypeInvalidKEPayload)
			if notify == nil {
				t.Fatal("INVALID_KE_PAYLOAD notify is missing")
			}
			if notify.ProtocolID != 0 || len(notify.SPI) != 0 {
				t.Fatalf("INVALID_KE_PAYLOAD protocol/spi = %d/%x, want 0/empty", notify.ProtocolID, notify.SPI)
			}
			if len(notify.Data) != 2 {
				t.Fatalf("INVALID_KE_PAYLOAD data length = %d, want 2", len(notify.Data))
			}
			if got := binary.BigEndian.Uint16(notify.Data); got != tt.preferredDH {
				t.Fatalf("INVALID_KE_PAYLOAD group = %d, want %d", got, tt.preferredDH)
			}
		})
	}
}

func TestInitiatedChildSARekeyRetriesInvalidKEPayloadGroup(t *testing.T) {
	tests := []struct {
		name      string
		responses func(*testing.T, uint32) []ike.Payload
		wantCalls int
		wantErr   string
	}{
		{
			name: "retries with preferred pfs group",
			responses: func(t *testing.T, peerInboundSPI uint32) []ike.Payload {
				t.Helper()
				responderDH, err := newIKECrypto(transformDH2048MODP)
				if err != nil {
					t.Fatalf("newIKECrypto() error = %v", err)
				}
				return []ike.Payload{
					&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{
						childSAResponseProposal(acceptedChildSA{
							Info:           Info{EncryptionKeyLen: 128, Integrity: transformINTEGHMACSHA196},
							DHGroup:        transformDH2048MODP,
							ProposalNumber: 1,
						}, peerInboundSPI),
					}},
					&ike.NoncePayload{Data: testNonce("responder nonce")},
					&ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: responderDH.PublicKey()},
					&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
					&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
				}
			},
			wantCalls: 2,
		},
		{
			name: "rejects repeated invalid ke group",
			responses: func(t *testing.T, _ uint32) []ike.Payload {
				t.Helper()
				return createChildSAInvalidKEPayloadNotify(transformDH2048MODP)
			},
			wantCalls: 2,
			wantErr:   "repeated INVALID_KE_PAYLOAD group",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := &Session{}
			state := childSARekeyState{
				ike: &ikeCrypto{
					prf:  transformPRFHMACSHA1,
					keys: ikeKeys{SKD: bytes.Repeat([]byte{0x11}, 20)},
				},
				cfg: handshakeConfig(Config{
					DHGroups:               []uint16{transformDH1024MODP, transformDH2048MODP},
					ChildEncryptionKeyLens: []uint16{128},
					ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
				}),
				info: Info{
					InnerIPv4:        net.IPv4(10, 0, 0, 1),
					PCSCFIPs:         []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI:  0x01020304,
					ESPResponderSPI:  0x10203040,
					Encryption:       transformENCRAESCBC,
					EncryptionKeyLen: 128,
					Integrity:        transformINTEGHMACSHA196,
				},
				inboundSPI:  0x01020304,
				outboundSPI: 0x10203040,
				addKE:       true,
			}
			pfs, err := newIKECrypto(transformDH1024MODP)
			if err != nil {
				t.Fatalf("newIKECrypto() error = %v", err)
			}

			var calls int
			gotGroups := make([]uint16, 0, tt.wantCalls)
			exchange := func(_ context.Context, state childSARekeyState, newInboundSPI uint32, nonceI []byte, pfs *ikeCrypto) ([]ike.Payload, error) {
				calls++
				gotGroups = append(gotGroups, pfs.dhGroup)
				request := state.childSARekeyRequestPayloads(newInboundSPI, nonceI, pfs)
				sa := ike.FindSAPayload(request)
				if sa == nil || len(sa.Proposals) == 0 {
					t.Fatal("rekey request SA payload is missing")
				}
				if got := proposalTransformIDValue(sa.Proposals[0], transformTypeDH); got != pfs.dhGroup {
					t.Fatalf("request proposal dh group = %d, want %d", got, pfs.dhGroup)
				}
				if ke := ike.FindKEPayload(request, pfs.dhGroup); ke == nil {
					t.Fatalf("request KE payload for group %d is missing", pfs.dhGroup)
				}
				if calls == 1 {
					return createChildSAInvalidKEPayloadNotify(transformDH2048MODP), nil
				}
				return tt.responses(t, 0x50607080), nil
			}

			result, err := session.initiatedChildSARekeyResult(context.Background(), state, pfs, exchange)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("initiatedChildSARekeyResult() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("initiatedChildSARekeyResult() error = %v", err)
			}
			if calls != tt.wantCalls {
				t.Fatalf("exchange calls = %d, want %d", calls, tt.wantCalls)
			}
			wantGroups := []uint16{transformDH1024MODP, transformDH2048MODP}
			if !slices.Equal(gotGroups, wantGroups) {
				t.Fatalf("pfs groups = %v, want %v", gotGroups, wantGroups)
			}
			if result.info.ESPInitiatorSPI == 0 || result.info.ESPResponderSPI != 0x50607080 {
				t.Fatalf("result child SPI = (%#x, %#x), want nonzero local and peer 0x50607080", result.info.ESPInitiatorSPI, result.info.ESPResponderSPI)
			}
			if !bytes.Equal(result.nonceR, testNonce("responder nonce")) {
				t.Fatalf("result nonceR = %x, want responder nonce", result.nonceR)
			}
		})
	}
}

func TestAcceptedChildSARequestProposalValidation(t *testing.T) {
	current := Info{
		Encryption:       transformENCRAESCBC,
		EncryptionKeyLen: 128,
		Integrity:        transformINTEGHMACSHA196,
	}
	validProposal := func(dhGroup uint16) ike.Proposal {
		return childSAProposalsWithDH(handshakeConfig(Config{
			ChildEncryptionKeyLens: []uint16{128},
			ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
		}), 0x50607080, dhGroup)[0]
	}
	tests := []struct {
		name     string
		proposal ike.Proposal
		dhGroup  uint16
		wantDH   uint16
		wantErr  string
	}{
		{
			name:     "valid without pfs",
			proposal: validProposal(0),
		},
		{
			name:     "valid with pfs",
			proposal: validProposal(transformDH2048MODP),
			dhGroup:  transformDH2048MODP,
			wantDH:   transformDH2048MODP,
		},
		{
			name: "proposal with alternative dh selects matching ke group",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.Transforms = append(
					proposal.Transforms,
					ike.Transform{TransformType: transformTypeDH, ID: transformDH1024MODP},
					ike.Transform{TransformType: transformTypeDH, ID: transformDH2048MODP},
				)
				return proposal
			}(),
			dhGroup: transformDH2048MODP,
			wantDH:  transformDH2048MODP,
		},
		{
			name: "proposal with alternative suite selects current child sa transforms",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.Transforms = []ike.Transform{
					aesCBCTransform(256),
					aesCBCTransform(128),
					{TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA256},
					{TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196},
					{TransformType: transformTypeESN, ID: transformESNNoESN},
				}
				return proposal
			}(),
		},
		{
			name: "wrong protocol",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.ProtocolID = proposalProtocolIKE
				return proposal
			}(),
			wantErr: "invalid proposal protocol id",
		},
		{
			name: "reserved peer esp spi",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.SPI = uint32Bytes(255)
				return proposal
			}(),
			wantErr: "invalid peer esp spi 255",
		},
		{
			name: "missing esn",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.Transforms = proposal.Transforms[:2]
				return proposal
			}(),
			wantErr: "proposal transform is incomplete",
		},
		{
			name: "unsupported esn",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.Transforms[len(proposal.Transforms)-1].ID = 1
				return proposal
			}(),
			wantErr: "proposal transform is incomplete",
		},
		{
			name: "unsupported protocol transform",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.Transforms = append(proposal.Transforms, ike.Transform{TransformType: transformTypePRF, ID: transformPRFHMACSHA1})
				return proposal
			}(),
			wantErr: "unsupported proposal transform type",
		},
		{
			name: "dh transform without pfs",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.Transforms = append(proposal.Transforms, ike.Transform{TransformType: transformTypeDH, ID: transformDH2048MODP})
				return proposal
			}(),
			wantErr: "unexpected dh group",
		},
		{
			name:     "pfs proposal omits matching dh",
			proposal: validProposal(transformDH1024MODP),
			dhGroup:  transformDH2048MODP,
			wantErr:  "dh group = 0, want 14",
		},
		{
			name: "unsupported encryption only",
			proposal: func() ike.Proposal {
				proposal := validProposal(0)
				proposal.Transforms[0] = ike.Transform{TransformType: transformTypeENCR, ID: 999}
				return proposal
			}(),
			wantErr: "proposal transform is incomplete",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := acceptedChildSARequestProposal(tt.proposal, current, tt.dhGroup)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("acceptedChildSARequestProposal() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("acceptedChildSARequestProposal() error = %v", err)
			}
			if got.DHGroup != tt.wantDH {
				t.Fatalf("DHGroup = %d, want %d", got.DHGroup, tt.wantDH)
			}
			if got.Encryption != current.Encryption || got.EncryptionKeyLen != current.EncryptionKeyLen || got.Integrity != current.Integrity {
				t.Fatalf("accepted suite = encr %d/%d integ %d, want current %d/%d/%d", got.Encryption, got.EncryptionKeyLen, got.Integrity, current.Encryption, current.EncryptionKeyLen, current.Integrity)
			}
			if got.ESPResponderSPI != 0x50607080 {
				t.Fatalf("ESPResponderSPI = %#x, want 0x50607080", got.ESPResponderSPI)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsChildNotFound(t *testing.T) {
	tests := []struct {
		name           string
		oldOutboundSPI uint32
		rekeySPI       uint32
	}{
		{name: "unknown child sa", oldOutboundSPI: 0x10203040, rekeySPI: 0x50607080},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := createChildSARequestState{outboundSPI: tt.oldOutboundSPI}
			payloads := childSARekeyRequestPayloads(handshakeConfig(Config{}), tt.rekeySPI, 0x11121314, testNonce("peer nonce"), nil)

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if action.installChild || action.installIKE {
				t.Fatal("action installs SA for CHILD_SA_NOT_FOUND")
			}
			notify := ike.FindNotifyPayload(responsePayloads, notifyTypeChildSANotFound)
			if notify == nil {
				t.Fatal("CHILD_SA_NOT_FOUND notify is missing")
			}
			if got := binary.BigEndian.Uint32(notify.SPI); got != tt.rekeySPI {
				t.Fatalf("notify spi = %#x, want %#x", got, tt.rekeySPI)
			}
		})
	}
}

func TestCreateChildSAResponseParsersReturnErrorNotify(t *testing.T) {
	tests := []struct {
		name      string
		payloads  []ike.Payload
		parse     func([]ike.Payload) error
		wantError error
	}{
		{
			name:     "child rekey temporary failure",
			payloads: []ike.Payload{&ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeTemporaryFailure}},
			parse: func(payloads []ike.Payload) error {
				_, _, _, err := childSAFromCreateChildResponse(payloads, Info{}, 0x01020304, 0)
				return err
			},
			wantError: errIKETemporaryFailure,
		},
		{
			name:     "ike rekey temporary failure",
			payloads: []ike.Payload{&ike.NotifyPayload{ProtocolID: protocolIDIKE, NotifyType: notifyTypeTemporaryFailure}},
			parse: func(payloads []ike.Payload) error {
				_, _, _, _, err := negotiatedIKESARekeyFromPayloads(payloads, transformDH2048MODP)
				return err
			},
			wantError: errIKETemporaryFailure,
		},
		{
			name:     "child rekey child sa not found",
			payloads: []ike.Payload{&ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeChildSANotFound, SPI: uint32Bytes(0x01020304)}},
			parse: func(payloads []ike.Payload) error {
				_, _, _, err := childSAFromCreateChildResponse(payloads, Info{}, 0x01020304, 0)
				return err
			},
			wantError: errChildSANotFound,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.parse(tt.payloads)
			if !errors.Is(err, tt.wantError) {
				t.Fatalf("parser error = %v, want %v", err, tt.wantError)
			}
		})
	}
}

func TestChildSAFromCreateChildResponseValidatesNegotiatedProposal(t *testing.T) {
	validProposal := func(dhGroup uint16) ike.Proposal {
		return childSAResponseProposal(acceptedChildSA{
			Info: Info{
				EncryptionKeyLen: 128,
				Integrity:        transformINTEGHMACSHA196,
			},
			DHGroup: dhGroup,
		}, 0x50607080)
	}
	payloads := func(proposals []ike.Proposal, ke *ike.KeyExchangePayload) []ike.Payload {
		out := []ike.Payload{
			&ike.SecurityAssociationPayload{Proposals: proposals},
			&ike.NoncePayload{Data: testNonce("responder nonce")},
			&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
			&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
		}
		if ke != nil {
			out = append(out, ke)
		}
		return out
	}
	tests := []struct {
		name      string
		proposals []ike.Proposal
		ke        *ike.KeyExchangePayload
		dhGroup   uint16
		wantErr   string
	}{
		{
			name:      "valid without pfs",
			proposals: []ike.Proposal{validProposal(0)},
		},
		{
			name:      "valid with pfs",
			proposals: []ike.Proposal{validProposal(transformDH2048MODP)},
			ke:        &ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
			dhGroup:   transformDH2048MODP,
		},
		{
			name:      "multiple negotiated proposals",
			proposals: []ike.Proposal{validProposal(0), validProposal(0)},
			wantErr:   "negotiated proposal count 2",
		},
		{
			name: "ike proposal",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal(0)
					proposal.ProtocolID = proposalProtocolIKE
					return proposal
				}(),
			},
			wantErr: "invalid negotiated protocol id",
		},
		{
			name: "reserved responder esp spi",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal(0)
					proposal.SPI = uint32Bytes(255)
					return proposal
				}(),
			},
			wantErr: "invalid responder esp spi 255",
		},
		{
			name: "dh transform without pfs",
			proposals: []ike.Proposal{
				validProposal(transformDH2048MODP),
			},
			wantErr: "unexpected dh group",
		},
		{
			name: "pfs proposal omits dh transform",
			proposals: []ike.Proposal{
				validProposal(0),
			},
			ke:      &ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
			dhGroup: transformDH2048MODP,
			wantErr: "dh group = 0, want",
		},
		{
			name: "pfs proposal uses wrong dh transform",
			proposals: []ike.Proposal{
				validProposal(transformDH1024MODP),
			},
			ke:      &ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
			dhGroup: transformDH2048MODP,
			wantErr: "dh group = 2, want 14",
		},
		{
			name: "pfs proposal omits ke payload",
			proposals: []ike.Proposal{
				validProposal(transformDH2048MODP),
			},
			dhGroup: transformDH2048MODP,
			wantErr: "key exchange payload is missing",
		},
		{
			name: "ke payload without pfs",
			proposals: []ike.Proposal{
				validProposal(0),
			},
			ke:      &ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
			wantErr: "unexpected key exchange payload",
		},
		{
			name: "missing esn",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal(0)
					proposal.Transforms = proposal.Transforms[:2]
					return proposal
				}(),
			},
			wantErr: "negotiated esp transform is incomplete",
		},
		{
			name: "unsupported esn",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal(0)
					proposal.Transforms[len(proposal.Transforms)-1].ID = 1
					return proposal
				}(),
			},
			wantErr: "unsupported esn transform 1",
		},
		{
			name: "duplicate encryption",
			proposals: []ike.Proposal{
				func() ike.Proposal {
					proposal := validProposal(0)
					proposal.Transforms = append(proposal.Transforms, aesCBCTransform(256))
					return proposal
				}(),
			},
			wantErr: "duplicate encryption transform",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := childSAFromCreateChildResponse(payloads(tt.proposals, tt.ke), Info{}, 0x01020304, tt.dhGroup)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("childSAFromCreateChildResponse() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("childSAFromCreateChildResponse() error = %v", err)
			}
		})
	}
}

func TestChildSAFromCreateChildResponseValidatesNegotiatedProposalNumberAgainstRequest(t *testing.T) {
	const newInboundSPI = 0x01020304
	requestProposals := childSAProposals(handshakeConfig(Config{
		ChildEncryptionKeyLens: []uint16{128},
		ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
	}), newInboundSPI)
	responseProposal := childSAResponseProposal(acceptedChildSA{
		Info: Info{
			EncryptionKeyLen: 128,
			Integrity:        transformINTEGHMACSHA196,
		},
		ProposalNumber: 2,
	}, 0x50607080)
	payloads := []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{responseProposal}},
		&ike.NoncePayload{Data: testNonce("responder nonce")},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
	}

	_, _, _, err := childSAFromCreateChildResponseWithRequests(payloads, Info{}, newInboundSPI, 0, requestProposals)

	if err == nil || !strings.Contains(err.Error(), "invalid negotiated proposal number 2") {
		t.Fatalf("childSAFromCreateChildResponseWithRequests() error = %v, want invalid proposal number", err)
	}
}

func TestChildSAFromCreateChildResponseRejectsNarrowTrafficSelectors(t *testing.T) {
	proposal := childSAResponseProposal(acceptedChildSA{
		Info: Info{
			EncryptionKeyLen: 128,
			Integrity:        transformINTEGHMACSHA196,
		},
	}, 0x50607080)
	payloads := []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{proposal}},
		&ike.NoncePayload{Data: testNonce("responder nonce")},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()[:1]},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
	}
	previous := Info{
		InitiatorTrafficSelectors: ike.TrafficSelectorsAny(),
		ResponderTrafficSelectors: ike.TrafficSelectorsAny(),
	}

	_, _, _, err := childSAFromCreateChildResponse(payloads, previous, 0x01020304, 0)
	if err == nil || !strings.Contains(err.Error(), "initiator traffic selectors are narrower than current child sa") {
		t.Fatalf("childSAFromCreateChildResponse() error = %v, want narrow traffic selector error", err)
	}
}

func TestRekeyChildSACreatesReplacementAfterChildSANotFound(t *testing.T) {
	tests := []struct {
		name           string
		peerInboundSPI uint32
	}{
		{name: "child not found falls back to fresh create", peerInboundSPI: 0x50607080},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			crypto.keys.SKD = bytes.Repeat([]byte{0x55}, 20)
			tsi, tsr := testChildSATrafficSelectors()
			session.mu.Lock()
			session.cfg.IKERetransmitDelays = []time.Duration{100 * time.Millisecond}
			session.cfg.ChildSALifetime = time.Hour
			session.cfg.ChildSARekeyMargin = 10 * time.Minute
			session.cfg.ChildEncryptionKeyLens = []uint16{128}
			session.cfg.ChildIntegrity = []uint16{transformINTEGHMACSHA196}
			session.connected = true
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.outerNAT = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.tunnel = Info{
				InnerIPv4:                 net.IPv4(10, 0, 0, 1),
				PCSCFIPs:                  []net.IP{net.IPv4(10, 0, 0, 2)},
				ESPInitiatorSPI:           0x01020304,
				ESPResponderSPI:           0x10203040,
				Encryption:                transformENCRAESCBC,
				EncryptionKeyLen:          128,
				Integrity:                 transformINTEGHMACSHA196,
				InitiatorTrafficSelectors: tsi,
				ResponderTrafficSelectors: tsr,
			}
			session.outboundESP = esp.Codec{SPI: 0x10203040}
			session.inboundESP = esp.Codec{SPI: 0x01020304}
			session.mu.Unlock()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- session.RekeyChildSA(ctx)
			}()

			waitForWrites(t, conn, 1)
			session.deliverInformationalWaiter(ikeMessageKeyForSPIs(0x0102030405060708, 0x1112131415161718, exchangeTypeCreateChildSA, flagResponse, 0), inboundIKE{
				data: sealCreateChildSAResponse(t, crypto, false, 0, []ike.Payload{
					&ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeChildSANotFound, SPI: uint32Bytes(0x01020304)},
				}),
				addr: cloneUDPAddr(session.outerNAT),
			})

			waitForWrites(t, conn, 2)
			session.deliverInformationalWaiter(ikeMessageKeyForSPIs(0x0102030405060708, 0x1112131415161718, exchangeTypeCreateChildSA, flagResponse, 1), inboundIKE{
				data: sealCreateChildSAResponse(t, crypto, false, 1, []ike.Payload{
					&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{childSAResponseProposal(acceptedChildSA{Info: Info{
						EncryptionKeyLen: 128,
						Integrity:        transformINTEGHMACSHA196,
					}, ProposalNumber: 1}, tt.peerInboundSPI)}},
					&ike.NoncePayload{Data: testNonce("replacement nonce")},
					&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
					&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
				}),
				addr: cloneUDPAddr(session.outerNAT),
			})

			if err := <-errCh; err != nil {
				t.Fatalf("RekeyChildSA() error = %v", err)
			}
			session.mu.RLock()
			outboundSPI := session.outboundESP.SPI
			nextMessageID := session.nextMessageID
			retired := append([]retiredChildSA(nil), session.retiredChildSAs...)
			session.mu.RUnlock()
			if outboundSPI != tt.peerInboundSPI {
				t.Fatalf("outbound SPI = %#x, want replacement peer SPI %#x", outboundSPI, tt.peerInboundSPI)
			}
			if nextMessageID != 2 {
				t.Fatalf("nextMessageID = %d, want 2 after rekey failure and create replacement", nextMessageID)
			}
			if len(retired) != 1 || retired[0].inbound.SPI != 0x01020304 {
				t.Fatalf("retired child SAs = %+v, want old inbound SPI 0x01020304", retired)
			}
		})
	}
}

func TestRekeyChildSAIgnoresChildSANotFoundAfterSimultaneousRekey(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "simultaneous child rekey already known"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			crypto.keys.SKD = bytes.Repeat([]byte{0x55}, 20)
			tsi, tsr := testChildSATrafficSelectors()
			session.mu.Lock()
			session.cfg.IKERetransmitDelays = []time.Duration{100 * time.Millisecond}
			session.cfg.ChildSALifetime = time.Hour
			session.cfg.ChildSARekeyMargin = 10 * time.Minute
			session.connected = true
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.outerNAT = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.tunnel = Info{
				InnerIPv4:                 net.IPv4(10, 0, 0, 1),
				PCSCFIPs:                  []net.IP{net.IPv4(10, 0, 0, 2)},
				ESPInitiatorSPI:           0x01020304,
				ESPResponderSPI:           0x10203040,
				Encryption:                transformENCRAESCBC,
				EncryptionKeyLen:          128,
				Integrity:                 transformINTEGHMACSHA196,
				InitiatorTrafficSelectors: tsi,
				ResponderTrafficSelectors: tsr,
			}
			session.outboundESP = esp.Codec{SPI: 0x10203040}
			session.inboundESP = esp.Codec{SPI: 0x01020304}
			session.mu.Unlock()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			errCh := make(chan error, 1)
			go func() {
				errCh <- session.RekeyChildSA(ctx)
			}()

			waitForWrites(t, conn, 1)
			session.noteSimultaneousChildSARekey(childSARekeyResult{
				info:   Info{ESPInitiatorSPI: 0x20304050},
				nonceI: []byte{0x20},
				nonceR: []byte{0x30},
			})
			session.deliverInformationalWaiter(ikeMessageKeyForSPIs(0x0102030405060708, 0x1112131415161718, exchangeTypeCreateChildSA, flagResponse, 0), inboundIKE{
				data: sealCreateChildSAResponse(t, crypto, false, 0, []ike.Payload{
					&ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeChildSANotFound, SPI: uint32Bytes(0x01020304)},
				}),
				addr: cloneUDPAddr(session.outerNAT),
			})

			if err := <-errCh; err != nil {
				t.Fatalf("RekeyChildSA() error = %v", err)
			}
			conn.mu.Lock()
			writeCount := len(conn.writes)
			conn.mu.Unlock()
			if writeCount != 1 {
				t.Fatalf("write count = %d, want no fresh child create after simultaneous CHILD_SA_NOT_FOUND", writeCount)
			}
			session.mu.RLock()
			nextMessageID := session.nextMessageID
			session.mu.RUnlock()
			if nextMessageID != 1 {
				t.Fatalf("nextMessageID = %d, want only original rekey exchange", nextMessageID)
			}
		})
	}
}

func waitForWrites(t *testing.T, conn *fakePacketConn, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn.mu.Lock()
		got := len(conn.writes)
		conn.mu.Unlock()
		if got >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	conn.mu.Lock()
	got := len(conn.writes)
	conn.mu.Unlock()
	t.Fatalf("write count = %d, want at least %d", got, want)
}

func sealCreateChildSAResponse(t *testing.T, crypto *ikeCrypto, senderInitiator bool, messageID uint32, payloads []ike.Payload) []byte {
	t.Helper()
	flags := flagResponse
	if senderInitiator {
		flags |= flagInitiator
	}
	wire, err := crypto.SealIKE(ike.IKEHeader{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeCreateChildSA,
		Flags:        flags,
		MessageID:    messageID,
	}, payloads, senderInitiator)
	if err != nil {
		t.Fatalf("SealIKE() error = %v", err)
	}
	return wire
}

func TestRekeyTemporaryFailureBackoff(t *testing.T) {
	oldRetryDelay := rekeyTemporaryFailureRetryDelay
	oldMaxDuration := rekeyTemporaryFailureMaxDuration
	rekeyTemporaryFailureRetryDelay = 10 * time.Second
	rekeyTemporaryFailureMaxDuration = 30 * time.Second
	t.Cleanup(func() {
		rekeyTemporaryFailureRetryDelay = oldRetryDelay
		rekeyTemporaryFailureMaxDuration = oldMaxDuration
	})

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "waits until retry delay",
			run: func(t *testing.T) {
				now := time.Unix(1_700_000_000, 0)
				var backoff rekeyTemporaryFailureBackoff

				if !backoff.record(now) {
					t.Fatal("record() = false, want true")
				}
				if !backoff.waiting(now.Add(9 * time.Second)) {
					t.Fatal("waiting() = false before retry delay")
				}
				if backoff.waiting(now.Add(10 * time.Second)) {
					t.Fatal("waiting() = true at retry delay")
				}
			},
		},
		{
			name: "expires after sustained temporary failure",
			run: func(t *testing.T) {
				now := time.Unix(1_700_000_000, 0)
				var backoff rekeyTemporaryFailureBackoff

				if !backoff.record(now) {
					t.Fatal("first record() = false, want true")
				}
				if backoff.record(now.Add(30 * time.Second)) {
					t.Fatal("record() = true after max duration")
				}
			},
		},
		{
			name: "reset clears retry window",
			run: func(t *testing.T) {
				now := time.Unix(1_700_000_000, 0)
				var backoff rekeyTemporaryFailureBackoff

				if !backoff.record(now) {
					t.Fatal("record() = false, want true")
				}
				backoff.reset()
				if backoff.waiting(now.Add(time.Second)) {
					t.Fatal("waiting() = true after reset")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestRekeyParsersRejectInvalidNonceLengths(t *testing.T) {
	tests := []struct {
		name string
		act  func() error
	}{
		{
			name: "ike sa init response",
			act: func() error {
				_, _, _, err := negotiatedIKESAFromPayloads([]ike.Payload{
					&ike.NoncePayload{Data: bytes.Repeat([]byte{0x01}, ikeNonceMinLen-1)},
					&ike.SecurityAssociationPayload{Proposals: ikeSAProposals(handshakeConfig(Config{}), transformDH2048MODP)[:1]},
					&ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
				}, transformDH2048MODP, nil)
				return err
			},
		},
		{
			name: "child sa rekey response",
			act: func() error {
				_, _, _, err := childSAFromCreateChildResponse([]ike.Payload{
					&ike.NoncePayload{Data: bytes.Repeat([]byte{0x01}, ikeNonceMaxLen+1)},
					&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{childSAResponseProposal(acceptedChildSA{Info: Info{EncryptionKeyLen: 128, Integrity: transformINTEGHMACSHA196}}, 0x01020304)}},
					&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: ike.TrafficSelectorsAny()},
					&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: ike.TrafficSelectorsAny()},
				}, Info{}, 0x01020304, 0)
				return err
			},
		},
		{
			name: "ike sa rekey response",
			act: func() error {
				_, _, _, _, err := negotiatedIKESARekeyFromPayloads([]ike.Payload{
					&ike.NoncePayload{Data: bytes.Repeat([]byte{0x01}, ikeNonceMinLen-1)},
					&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{ikeSARekeyResponseProposal(acceptedIKESAProposal{
						negotiatedIKESA: negotiatedIKESA{EncryptionKeyLen: 128, Integrity: transformINTEGHMACSHA196, PRF: transformPRFHMACSHA1},
						DHGroup:         transformDH2048MODP,
					}, 0x0102030405060708)}},
					&ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
				}, transformDH2048MODP)
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.act()
			if err == nil || !strings.Contains(err.Error(), "invalid nonce length") {
				t.Fatalf("parser error = %v, want invalid nonce length", err)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsDuringLocalChildRekeyRespondsAsUsual(t *testing.T) {
	tests := []struct {
		name           string
		oldOutboundSPI uint32
		peerInboundSPI uint32
	}{
		{name: "simultaneous child rekey", oldOutboundSPI: 0x10203040, peerInboundSPI: 0x50607080},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := createChildSARequestState{
				ike: &ikeCrypto{
					prf: transformPRFHMACSHA1,
					keys: ikeKeys{
						SKD: bytes.Repeat([]byte{0x11}, 20),
					},
				},
				childRekeying: true,
				cfg: Config{
					ChildEncryptionKeyLens: []uint16{128},
					ChildIntegrity:         []uint16{transformINTEGHMACSHA196},
				},
				info: Info{
					InnerIPv4:        net.IPv4(10, 0, 0, 1),
					PCSCFIPs:         []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI:  0x01020304,
					ESPResponderSPI:  tt.oldOutboundSPI,
					Encryption:       transformENCRAESCBC,
					EncryptionKeyLen: 128,
					Integrity:        transformINTEGHMACSHA196,
				},
				inboundSPI:  0x01020304,
				outboundSPI: tt.oldOutboundSPI,
			}
			payloads := childSARekeyRequestPayloads(handshakeConfig(state.cfg), tt.oldOutboundSPI, tt.peerInboundSPI, testNonce("peer nonce"), nil)

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if notify := ike.FindNotifyPayload(responsePayloads, notifyTypeTemporaryFailure); notify != nil {
				t.Fatal("TEMPORARY_FAILURE returned for simultaneous Child SA rekey")
			}
			if !action.installChild || !action.simultaneousChild {
				t.Fatalf("action = %+v, want simultaneous child install", action)
			}
			if !bytes.Equal(action.child.nonceI, testNonce("peer nonce")) || len(action.child.nonceR) == 0 {
				t.Fatalf("child rekey nonces = (%x, %x), want peer nonce and generated response nonce", action.child.nonceI, action.child.nonceR)
			}
		})
	}
}

func TestFinishInitiatedChildSARekeyResolvesSimultaneousRekeyByLowestNonce(t *testing.T) {
	tests := []struct {
		name        string
		local       childSARekeyResult
		peer        childSARekeyResult
		wantInstall bool
		wantDelete  uint32
	}{
		{
			name: "peer created sa loses when peer exchange has lowest nonce",
			local: childSARekeyResult{
				info:       Info{ESPInitiatorSPI: 0x11121314},
				oldInbound: 0x01020304,
				nonceI:     []byte{0x20},
				nonceR:     []byte{0x21},
			},
			peer: childSARekeyResult{
				nonceI: []byte{0x01},
				nonceR: []byte{0x22},
			},
			wantInstall: true,
			wantDelete:  0x01020304,
		},
		{
			name: "local created sa loses when local exchange has lowest nonce",
			local: childSARekeyResult{
				info:       Info{ESPInitiatorSPI: 0x11121314},
				oldInbound: 0x01020304,
				nonceI:     []byte{0x01},
				nonceR:     []byte{0x21},
			},
			peer: childSARekeyResult{
				nonceI: []byte{0x20},
				nonceR: []byte{0x22},
			},
			wantDelete: 0x11121314,
		},
		{
			name: "shorter equal prefix nonce is lower",
			local: childSARekeyResult{
				info:       Info{ESPInitiatorSPI: 0x11121314},
				oldInbound: 0x01020304,
				nonceI:     []byte{0x10, 0x00},
				nonceR:     []byte{0x20},
			},
			peer: childSARekeyResult{
				nonceI: []byte{0x10},
				nonceR: []byte{0x30},
			},
			wantInstall: true,
			wantDelete:  0x01020304,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.simultaneousChildSA = simultaneousChildSARekey{ready: true, peer: tt.peer}
			session.mu.Unlock()

			decision := session.finishInitiatedChildSARekey(tt.local)
			if decision.installLocal != tt.wantInstall || decision.deleteSPI != tt.wantDelete {
				t.Fatalf("finishInitiatedChildSARekey() = %+v, want install=%t delete=%#x", decision, tt.wantInstall, tt.wantDelete)
			}
		})
	}
}

func TestInstallLocalChildSAAfterSimultaneousRekeyRetiresPeerCreatedSAWithPendingOutboundSPI(t *testing.T) {
	tests := []struct {
		name             string
		oldInbound       uint32
		oldOutbound      uint32
		peerNewInbound   uint32
		peerNewOutbound  uint32
		localNewInbound  uint32
		localNewOutbound uint32
	}{
		{
			name:             "local created sa survives peer created sa loses",
			oldInbound:       0x01020304,
			oldOutbound:      0x10203040,
			peerNewInbound:   0x11121314,
			peerNewOutbound:  0x50607080,
			localNewInbound:  0x21222324,
			localNewOutbound: 0x61626364,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			session.tunnel = Info{
				InnerIPv4:       net.IPv4(10, 0, 0, 1),
				PCSCFIPs:        []net.IP{net.IPv4(10, 0, 0, 2)},
				ESPInitiatorSPI: tt.oldInbound,
				ESPResponderSPI: tt.oldOutbound,
			}
			session.inboundESP = esp.Codec{SPI: tt.oldInbound}
			session.outboundESP = esp.Codec{SPI: tt.oldOutbound}
			session.mu.Unlock()

			session.stageResponderChildSecurityAssociations(childSARekeyResult{
				info: Info{
					InnerIPv4:       net.IPv4(10, 0, 0, 1),
					PCSCFIPs:        []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI: tt.peerNewInbound,
					ESPResponderSPI: tt.peerNewOutbound,
				},
				inbound:    esp.Codec{SPI: tt.peerNewInbound},
				outbound:   esp.Codec{SPI: tt.peerNewOutbound},
				oldInbound: tt.oldInbound,
			})
			session.installChildSecurityAssociations(childSARekeyResult{
				info: Info{
					InnerIPv4:       net.IPv4(10, 0, 0, 1),
					PCSCFIPs:        []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI: tt.localNewInbound,
					ESPResponderSPI: tt.localNewOutbound,
				},
				inbound:    esp.Codec{SPI: tt.localNewInbound},
				outbound:   esp.Codec{SPI: tt.localNewOutbound},
				oldInbound: tt.oldInbound,
			})

			responsePayloads, action, ok, err := buildDeleteResponsePayloads(session.currentInformationalState(), []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{uint32Bytes(tt.peerNewOutbound)}},
			})
			if err != nil {
				t.Fatalf("buildDeleteResponsePayloads() error = %v", err)
			}
			if !ok {
				t.Fatal("delete payload not handled")
			}
			if !slices.Equal(action.deleteRetiredChildSPIs, []uint32{tt.peerNewInbound}) {
				t.Fatalf("deleteRetiredChildSPIs = %#x, want peer-created inbound %#x", action.deleteRetiredChildSPIs, []uint32{tt.peerNewInbound})
			}
			if len(responsePayloads) != 1 {
				t.Fatalf("response payload count = %d, want 1", len(responsePayloads))
			}
			deletePayload, ok := responsePayloads[0].(*ike.DeletePayload)
			if !ok {
				t.Fatalf("response payload = %T, want *ike.DeletePayload", responsePayloads[0])
			}
			if got := binary.BigEndian.Uint32(deletePayload.SPIs[0]); got != tt.peerNewInbound {
				t.Fatalf("response delete SPI = %#x, want peer-created inbound %#x", got, tt.peerNewInbound)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsForPeerIKESARekey(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "peer initiated ike rekey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := testIKESARekeyCrypto(transformDH1024MODP, transformPRFHMACSHA1)
			peer, err := newIKECrypto(transformDH1024MODP)
			if err != nil {
				t.Fatalf("newIKECrypto() peer error = %v", err)
			}
			peer.SetSPIs(0x0102030405060708, 0)
			peer.SetNonces(testNonce("peer nonce"), nil)
			state := createChildSARequestState{
				ike: old,
				cfg: Config{
					DHGroups:             []uint16{transformDH1024MODP},
					IKEEncryptionKeyLens: []uint16{128},
					IKEIntegrity:         []uint16{transformINTEGHMACSHA196},
					IKEPRF:               []uint16{transformPRFHMACSHA1},
				},
			}
			payloads := ikeSARekeyRequestPayloads(state.ike, peer)

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if !action.installIKE {
				t.Fatal("installIKE = false, want true")
			}
			if action.ike.initiatorSPI != peer.initiatorSPI {
				t.Fatalf("new ike initiator spi = %#x, want %#x", action.ike.initiatorSPI, peer.initiatorSPI)
			}
			if action.ike.responderSPI == 0 {
				t.Fatal("new ike responder spi = 0")
			}
			if action.ike.crypto == nil || len(action.ike.crypto.keys.SKD) == 0 {
				t.Fatal("new ike keys were not derived")
			}
			if !bytes.Equal(action.ike.nonceI, testNonce("peer nonce")) || len(action.ike.nonceR) == 0 {
				t.Fatalf("ike rekey nonces = (%x, %x), want peer nonce and generated response nonce", action.ike.nonceI, action.ike.nonceR)
			}
			if ike.FindTrafficSelectorPayload(responsePayloads, payloadTypeTSi) != nil || ike.FindTrafficSelectorPayload(responsePayloads, payloadTypeTSr) != nil {
				t.Fatal("IKE SA rekey response unexpectedly included traffic selectors")
			}
			if ike.FindSAPayload(responsePayloads) == nil || ike.FindNoncePayload(responsePayloads) == nil || ike.FindKEPayload(responsePayloads, transformDH1024MODP) == nil {
				t.Fatal("IKE SA rekey response missing SA, Nonce, or KE")
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsPreservesAcceptedIKESARekeyProposalNumber(t *testing.T) {
	old := testIKESARekeyCrypto(transformDH1024MODP, transformPRFHMACSHA1)
	peer, err := newIKECrypto(transformDH1024MODP)
	if err != nil {
		t.Fatalf("newIKECrypto() peer error = %v", err)
	}
	peer.SetSPIs(0x0102030405060708, 0)
	peer.SetNonces(testNonce("peer nonce"), nil)
	state := createChildSARequestState{
		ike: old,
		cfg: Config{
			DHGroups:             []uint16{transformDH1024MODP},
			IKEEncryptionKeyLens: []uint16{128},
			IKEIntegrity:         []uint16{transformINTEGHMACSHA196},
			IKEPRF:               []uint16{transformPRFHMACSHA1},
		},
	}
	proposals := currentIKESARekeyProposals(state.ike, transformDH1024MODP, peer.initiatorSPI)
	proposals = append([]ike.Proposal{
		{
			Number:     1,
			ProtocolID: proposalProtocolIKE,
			SPI:        uint32Bytes(0x50607080),
			Transforms: proposals[0].Transforms,
		},
	}, proposals[0])
	proposals[1].Number = 2
	payloads := ikeSARekeyRequestPayloads(state.ike, peer)
	ike.FindSAPayload(payloads).Proposals = proposals

	responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
	if err != nil {
		t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
	}
	if !action.installIKE {
		t.Fatal("installIKE = false, want true")
	}
	responseSA := ike.FindSAPayload(responsePayloads)
	if responseSA == nil || len(responseSA.Proposals) != 1 {
		t.Fatalf("response SA = %+v, want one proposal", responseSA)
	}
	if responseSA.Proposals[0].Number != 2 {
		t.Fatalf("response proposal number = %d, want accepted proposal number 2", responseSA.Proposals[0].Number)
	}
}

func TestNegotiatedIKESARekeyFromPayloadsValidatesProposalNumberAgainstRequest(t *testing.T) {
	current := testIKESARekeyCrypto(transformDH2048MODP, transformPRFHMACSHA1)
	requestProposals := currentIKESARekeyProposals(current, transformDH2048MODP, 0x0102030405060708)
	responseProposal := ikeSARekeyResponseProposal(acceptedIKESAProposal{
		negotiatedIKESA: negotiatedIKESA{
			EncryptionKeyLen: 128,
			Integrity:        transformINTEGHMACSHA196,
			PRF:              transformPRFHMACSHA1,
		},
		DHGroup:        transformDH2048MODP,
		ProposalNumber: 2,
	}, 0x1112131415161718)
	payloads := []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{responseProposal}},
		&ike.NoncePayload{Data: testNonce("responder nonce")},
		&ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
	}

	_, _, _, _, err := negotiatedIKESARekeyFromPayloadsWithRequests(payloads, transformDH2048MODP, requestProposals)

	if err == nil || !strings.Contains(err.Error(), "invalid negotiated proposal number 2") {
		t.Fatalf("negotiatedIKESARekeyFromPayloadsWithRequests() error = %v, want invalid proposal number", err)
	}
}

func TestNegotiatedIKESARekeyFromPayloadsRejectsZeroResponderSPI(t *testing.T) {
	responseProposal := ikeSARekeyResponseProposal(acceptedIKESAProposal{
		negotiatedIKESA: negotiatedIKESA{
			EncryptionKeyLen: 128,
			Integrity:        transformINTEGHMACSHA196,
			PRF:              transformPRFHMACSHA1,
		},
		DHGroup:        transformDH2048MODP,
		ProposalNumber: 1,
	}, 0)
	payloads := []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{responseProposal}},
		&ike.NoncePayload{Data: testNonce("responder nonce")},
		&ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
	}

	_, _, _, _, err := negotiatedIKESARekeyFromPayloads(payloads, transformDH2048MODP)

	if err == nil || !strings.Contains(err.Error(), "responder ike spi is zero") {
		t.Fatalf("negotiatedIKESARekeyFromPayloads() error = %v, want zero responder spi", err)
	}
}

func TestAcceptedIKESARekeyProposalRejectsInvalidSPI(t *testing.T) {
	current := testIKESARekeyCrypto(transformDH2048MODP, transformPRFHMACSHA1)
	current.SetSPIs(0x0102030405060708, 0x1112131415161718)
	tests := []struct {
		name string
		spi  uint64
	}{
		{name: "zero", spi: 0},
		{name: "current initiator", spi: current.initiatorSPI},
		{name: "current responder", spi: current.responderSPI},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proposals := currentIKESARekeyProposals(current, transformDH2048MODP, tt.spi)

			_, _, err := acceptedIKESARekeyProposal(proposals, current)

			if err == nil || !strings.Contains(err.Error(), "no acceptable ike sa rekey proposal") {
				t.Fatalf("acceptedIKESARekeyProposal() error = %v, want no proposal", err)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsForPeerIKESARekeyRejectsMismatchedKEGroup(t *testing.T) {
	tests := []struct {
		name      string
		proposal  uint16
		ke        uint16
		wantGroup uint16
	}{
		{
			name:      "selected ike proposal group differs from kei",
			proposal:  transformDH2048MODP,
			ke:        transformDH1024MODP,
			wantGroup: transformDH2048MODP,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			current := testIKESARekeyCrypto(tt.wantGroup, transformPRFHMACSHA1)
			state := createChildSARequestState{
				ike: current,
				cfg: Config{
					DHGroups:             []uint16{tt.wantGroup},
					IKEEncryptionKeyLens: []uint16{128},
					IKEIntegrity:         []uint16{transformINTEGHMACSHA196},
					IKEPRF:               []uint16{transformPRFHMACSHA1},
				},
			}
			payloads := []ike.Payload{
				&ike.SecurityAssociationPayload{Proposals: currentIKESARekeyProposals(current, tt.proposal, 0x0102030405060708)},
				&ike.NoncePayload{Data: testNonce("peer nonce")},
				&ike.KeyExchangePayload{DHGroup: tt.ke, Data: []byte{0x01}},
			}

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if action.installIKE {
				t.Fatal("installIKE = true, want false")
			}
			notify := ike.FindNotifyPayload(responsePayloads, notifyTypeInvalidKEPayload)
			if notify == nil {
				t.Fatal("INVALID_KE_PAYLOAD notify is missing")
			}
			if got := binary.BigEndian.Uint16(notify.Data); got != tt.wantGroup {
				t.Fatalf("INVALID_KE_PAYLOAD group = %d, want %d", got, tt.wantGroup)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsForPeerIKESARekeyRejectsUnsupportedProposal(t *testing.T) {
	tests := []struct {
		name    string
		payload []ike.Proposal
	}{
		{
			name:    "unsupported prf",
			payload: currentIKESARekeyProposals(testIKESARekeyCrypto(transformDH2048MODP, transformPRFHMACSHA256), transformDH2048MODP, 0x0102030405060708),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := createChildSARequestState{
				ike: testIKESARekeyCrypto(transformDH2048MODP, transformPRFHMACSHA1),
				cfg: Config{
					DHGroups:             []uint16{transformDH2048MODP},
					IKEEncryptionKeyLens: []uint16{128},
					IKEIntegrity:         []uint16{transformINTEGHMACSHA196},
					IKEPRF:               []uint16{transformPRFHMACSHA1},
				},
			}
			payloads := []ike.Payload{
				&ike.SecurityAssociationPayload{Proposals: tt.payload},
				&ike.NoncePayload{Data: testNonce("peer nonce")},
				&ike.KeyExchangePayload{DHGroup: transformDH2048MODP, Data: []byte{0x01}},
			}

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if action.installIKE {
				t.Fatal("installIKE = true, want false")
			}
			if notify := ike.FindNotifyPayload(responsePayloads, notifyTypeNoProposalChosen); notify == nil {
				t.Fatalf("response payloads = %#v, want NO_PROPOSAL_CHOSEN", responsePayloads)
			}
		})
	}
}

func TestBuildCreateChildSAResponsePayloadsDuringLocalIKESARekeyRespondsAsUsual(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "simultaneous ike rekey"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			old := testIKESARekeyCrypto(transformDH1024MODP, transformPRFHMACSHA1)
			peer, err := newIKECrypto(transformDH1024MODP)
			if err != nil {
				t.Fatalf("newIKECrypto() peer error = %v", err)
			}
			peer.SetSPIs(0x0102030405060708, 0)
			peer.SetNonces(testNonce("peer nonce"), nil)
			state := createChildSARequestState{
				ike:         old,
				ikeRekeying: true,
				cfg: Config{
					DHGroups:             []uint16{transformDH1024MODP},
					IKEEncryptionKeyLens: []uint16{128},
					IKEIntegrity:         []uint16{transformINTEGHMACSHA196},
					IKEPRF:               []uint16{transformPRFHMACSHA1},
				},
			}
			payloads := ikeSARekeyRequestPayloads(state.ike, peer)

			responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
			if err != nil {
				t.Fatalf("buildCreateChildSAResponsePayloads() error = %v", err)
			}
			if notify := ike.FindNotifyPayload(responsePayloads, notifyTypeTemporaryFailure); notify != nil {
				t.Fatal("TEMPORARY_FAILURE returned for simultaneous IKE SA rekey")
			}
			if !action.installIKE || !action.simultaneousIKE {
				t.Fatalf("action = %+v, want simultaneous ike install", action)
			}
		})
	}
}

func TestFinishInitiatedIKESARekeyResolvesSimultaneousRekeyByLowestNonce(t *testing.T) {
	tests := []struct {
		name        string
		local       ikeSARekeyResult
		peer        ikeSARekeyResult
		wantInstall bool
		wantRetain  bool
	}{
		{
			name:        "peer created ike sa loses when peer exchange has lowest nonce",
			local:       ikeSARekeyResult{nonceI: []byte{0x20}, nonceR: []byte{0x21}},
			peer:        ikeSARekeyResult{nonceI: []byte{0x01}, nonceR: []byte{0x22}},
			wantInstall: true,
			wantRetain:  true,
		},
		{
			name:  "local created ike sa loses when local exchange has lowest nonce",
			local: ikeSARekeyResult{nonceI: []byte{0x01}, nonceR: []byte{0x21}},
			peer:  ikeSARekeyResult{nonceI: []byte{0x20}, nonceR: []byte{0x22}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.simultaneousIKESA = simultaneousIKESARekey{ready: true, peer: tt.peer}
			session.mu.Unlock()

			decision := session.finishInitiatedIKESARekey(tt.local)
			if decision.installLocal != tt.wantInstall {
				t.Fatalf("finishInitiatedIKESARekey() = %+v, want install=%t", decision, tt.wantInstall)
			}
			if decision.retainPeerCreatedLosingSA != tt.wantRetain {
				t.Fatalf("finishInitiatedIKESARekey() = %+v, want retain peer losing=%t", decision, tt.wantRetain)
			}
		})
	}
}

func TestInstallSurvivingIKESARekeyRetainsPeerCreatedLosingSA(t *testing.T) {
	const (
		oldInitiatorSPI     uint64 = 0x2122232425262728
		oldResponderSPI     uint64 = 0x3132333435363738
		localInitiatorSPI   uint64 = 0x4142434445464748
		localResponderSPI   uint64 = 0x5152535455565758
		peerLosingInitiator uint64 = 0x0102030405060708
		peerLosingResponder uint64 = 0x1112131415161718
		peerDeleteMessageID uint32 = 0
		outerNATPort               = 4500
		localPacketConnPort        = 40000
	)

	tests := []struct {
		name string
	}{
		{name: "peer delete on losing ike sa is acknowledged after local sa wins"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPacketConnPort}}
			session := mustDialSession(t, conn)
			old := testIKECrypto()
			localSurviving := testIKECrypto()
			peerLosing := testIKECrypto()
			peerAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: outerNATPort}

			session.mu.Lock()
			session.ike = old
			session.ikeLocalInitiator = true
			session.initiatorSPI = oldInitiatorSPI
			session.responderSPI = oldResponderSPI
			session.outerNAT = peerAddr
			session.simultaneousIKESA = simultaneousIKESARekey{
				ready: true,
				peer: ikeSARekeyResult{
					crypto:         peerLosing,
					initiatorSPI:   peerLosingInitiator,
					responderSPI:   peerLosingResponder,
					nonceI:         []byte{0x01},
					nonceR:         []byte{0x22},
					localInitiator: false,
				},
			}
			session.mu.Unlock()

			local := ikeSARekeyResult{
				crypto:         localSurviving,
				initiatorSPI:   localInitiatorSPI,
				responderSPI:   localResponderSPI,
				nonceI:         []byte{0x20},
				nonceR:         []byte{0x21},
				localInitiator: true,
			}
			decision := session.finishInitiatedIKESARekey(local)
			if !decision.installLocal || !decision.retainPeerCreatedLosingSA {
				t.Fatalf("finishInitiatedIKESARekey() = %+v, want local install and peer losing retention", decision)
			}

			session.installSurvivingIKESARekey(local, decision, peerAddr)

			wire, err := peerLosing.SealIKE(ike.IKEHeader{
				InitiatorSPI: peerLosingInitiator,
				ResponderSPI: peerLosingResponder,
				Version:      ikeVersion20,
				ExchangeType: exchangeTypeInformational,
				Flags:        flagInitiator,
				MessageID:    peerDeleteMessageID,
			}, []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}}, true)
			if err != nil {
				t.Fatalf("SealIKE() error = %v", err)
			}

			handled, err := session.handleIKEPacket(wire, peerAddr)
			if err != nil {
				t.Fatalf("handleIKEPacket() error = %v", err)
			}
			if !handled {
				t.Fatal("handleIKEPacket() = false, want true")
			}
			if len(conn.writes) != 1 {
				t.Fatalf("response writes = %d, want 1", len(conn.writes))
			}
			var responsePacket ike.IKEPacket
			if err := responsePacket.UnmarshalBinary(conn.writes[0][nonESPMarkerLen:]); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			responsePayloads, err := peerLosing.OpenIKE(responsePacket, false)
			if err != nil {
				t.Fatalf("response OpenIKE() error = %v", err)
			}
			if len(responsePayloads) != 0 {
				t.Fatalf("delete response payloads = %v, want empty response", responsePayloads)
			}

			session.mu.RLock()
			currentIKE := session.ike
			retired := append([]retiredIKESA(nil), session.retiredIKESAs...)
			session.mu.RUnlock()
			if currentIKE != localSurviving {
				t.Fatal("current IKE SA changed after peer deleted losing SA")
			}
			for _, sa := range retired {
				if retiredIKESAMatches(sa, peerLosingInitiator, peerLosingResponder) {
					t.Fatal("peer-created losing IKE SA still retired after peer delete")
				}
			}
		})
	}
}

func TestDeriveESPKeysWithNoncesUsesCreateChildNonces(t *testing.T) {
	tests := []struct {
		name   string
		nonceI []byte
		nonceR []byte
	}{
		{name: "fresh create child nonces", nonceI: []byte("create-child-ni"), nonceR: []byte("create-child-nr")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := &ikeCrypto{
				prf: transformPRFHMACSHA1,
				keys: ikeKeys{
					SKD: bytes.Repeat([]byte{0x11}, 20),
				},
			}
			crypto.SetNonces([]byte("old-ni"), []byte("old-nr"))
			oldKeys, err := crypto.DeriveESPKeys(128, transformINTEGHMACSHA196)
			if err != nil {
				t.Fatalf("DeriveESPKeys() error = %v", err)
			}
			newKeys, err := crypto.DeriveESPKeysWithNonces(128, transformINTEGHMACSHA196, tt.nonceI, tt.nonceR)
			if err != nil {
				t.Fatalf("DeriveESPKeysWithNonces() error = %v", err)
			}
			if bytes.Equal(newKeys.EncryptionInitiator, oldKeys.EncryptionInitiator) {
				t.Fatal("new key material reused IKE_SA_INIT nonces")
			}
			stream, err := crypto.prfPlus(crypto.keys.SKD, append(append([]byte(nil), tt.nonceI...), tt.nonceR...), 72)
			if err != nil {
				t.Fatalf("prfPlus() error = %v", err)
			}
			if !bytes.Equal(newKeys.EncryptionInitiator, stream[:16]) {
				t.Fatalf("initiator encryption key = %x, want %x", newKeys.EncryptionInitiator, stream[:16])
			}
		})
	}
}

func TestDeriveESPKeysWithDHUsesSharedSecret(t *testing.T) {
	tests := []struct {
		name   string
		nonceI []byte
		nonceR []byte
	}{
		{name: "create child pfs keymat", nonceI: []byte("create-child-ni"), nonceR: []byte("create-child-nr")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := &ikeCrypto{
				prf: transformPRFHMACSHA1,
				keys: ikeKeys{
					SKD: bytes.Repeat([]byte{0x11}, 20),
				},
			}
			initiatorDH, err := newIKECrypto(transformDH2048MODP)
			if err != nil {
				t.Fatalf("newIKECrypto() initiator error = %v", err)
			}
			responderDH, err := newIKECrypto(transformDH2048MODP)
			if err != nil {
				t.Fatalf("newIKECrypto() responder error = %v", err)
			}
			keys, err := crypto.DeriveESPKeysWithDH(128, transformINTEGHMACSHA196, tt.nonceI, tt.nonceR, initiatorDH, responderDH.PublicKey())
			if err != nil {
				t.Fatalf("DeriveESPKeysWithDH() error = %v", err)
			}
			shared, err := initiatorDH.sharedSecret(responderDH.PublicKey())
			if err != nil {
				t.Fatalf("sharedSecret() error = %v", err)
			}
			seed := make([]byte, 0, len(shared)+len(tt.nonceI)+len(tt.nonceR))
			seed = append(seed, shared...)
			seed = append(seed, tt.nonceI...)
			seed = append(seed, tt.nonceR...)
			stream, err := crypto.prfPlus(crypto.keys.SKD, seed, 72)
			if err != nil {
				t.Fatalf("prfPlus() error = %v", err)
			}
			if !bytes.Equal(keys.EncryptionInitiator, stream[:16]) {
				t.Fatalf("initiator encryption key = %x, want %x", keys.EncryptionInitiator, stream[:16])
			}
			withoutDH, err := crypto.DeriveESPKeysWithNonces(128, transformINTEGHMACSHA196, tt.nonceI, tt.nonceR)
			if err != nil {
				t.Fatalf("DeriveESPKeysWithNonces() error = %v", err)
			}
			if bytes.Equal(keys.EncryptionInitiator, withoutDH.EncryptionInitiator) {
				t.Fatal("pfs key material did not include dh shared secret")
			}
		})
	}
}

func TestSharedSecretRejectsInvalidMODPPublicKey(t *testing.T) {
	crypto, err := newIKECrypto(transformDH2048MODP)
	if err != nil {
		t.Fatalf("newIKECrypto() error = %v", err)
	}
	one := big.NewInt(1).FillBytes(make([]byte, crypto.groupByteSize))
	upper := new(big.Int).Sub(crypto.groupPrime, big.NewInt(1)).FillBytes(make([]byte, crypto.groupByteSize))

	tests := []struct {
		name string
		peer []byte
	}{
		{name: "empty", peer: nil},
		{name: "zero", peer: make([]byte, crypto.groupByteSize)},
		{name: "one", peer: one},
		{name: "prime minus one", peer: upper},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := crypto.sharedSecret(tt.peer); err == nil {
				t.Fatal("sharedSecret() error = nil, want invalid public key")
			}
		})
	}
}

func TestInstallIKESecurityAssociationSwitchesControlPlane(t *testing.T) {
	tests := []struct {
		name         string
		initiatorSPI uint64
		responderSPI uint64
	}{
		{name: "new ike sa resets message ids", initiatorSPI: 0x0102030405060708, responderSPI: 0x1112131415161718},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.cfg.IKESALifetime = time.Hour
			session.cfg.IKESARekeyMargin = 10 * time.Minute
			next := &ikeCrypto{keys: ikeKeys{SKD: []byte{0x01}}}
			session.mu.Lock()
			session.ike = &ikeCrypto{keys: ikeKeys{SKD: []byte{0x02}}}
			session.initiatorSPI = 1
			session.responderSPI = 2
			session.nextMessageID = 44
			session.nextPeerMessageID = 17
			waiter := make(chan inboundIKE, 1)
			session.informWaiters = map[ikeMessageKey]chan inboundIKE{
				ikeMessageKeyForSPIs(1, 2, exchangeTypeInformational, flagResponse, 44): waiter,
			}
			session.informResponses = map[uint32][][]byte{43: {[]byte("old")}}
			session.mu.Unlock()

			session.installIKESecurityAssociation(ikeSARekeyResult{crypto: next, initiatorSPI: tt.initiatorSPI, responderSPI: tt.responderSPI, localInitiator: true})

			session.mu.RLock()
			gotIKE := session.ike
			initiatorSPI := session.initiatorSPI
			responderSPI := session.responderSPI
			nextMessageID := session.nextMessageID
			nextPeerMessageID := session.nextPeerMessageID
			expiresAt := session.ikeSAExpiresAt
			rekeyAt := session.ikeSARekeyAt
			waiterCount := len(session.informWaiters)
			responseCount := len(session.informResponses)
			localInitiator := session.ikeLocalInitiator
			session.mu.RUnlock()

			if gotIKE != next {
				t.Fatal("ike state was not replaced")
			}
			if initiatorSPI != tt.initiatorSPI || responderSPI != tt.responderSPI {
				t.Fatalf("IKE SPIs = (%#x, %#x), want (%#x, %#x)", initiatorSPI, responderSPI, tt.initiatorSPI, tt.responderSPI)
			}
			if nextMessageID != 0 {
				t.Fatalf("nextMessageID = %d, want 0", nextMessageID)
			}
			if nextPeerMessageID != 0 {
				t.Fatalf("nextPeerMessageID = %d, want 0", nextPeerMessageID)
			}
			if waiterCount != 0 || responseCount != 0 {
				t.Fatalf("protected exchange caches = (%d, %d), want empty", waiterCount, responseCount)
			}
			select {
			case packet := <-waiter:
				if !errors.Is(packet.err, errIKESASuperseded) {
					t.Fatalf("waiter error = %v, want %v", packet.err, errIKESASuperseded)
				}
			default:
				t.Fatal("old IKE waiter was not notified")
			}
			if !localInitiator {
				t.Fatal("ikeLocalInitiator = false, want true for locally initiated rekey")
			}
			if expiresAt.IsZero() || rekeyAt.IsZero() || !rekeyAt.Before(expiresAt) {
				t.Fatalf("IKE lifetime state = rekey %s expires %s, want proactive rekey before expiry", rekeyAt, expiresAt)
			}
		})
	}
}

func TestPromotePendingIKESecurityAssociation(t *testing.T) {
	tests := []struct {
		name         string
		initiatorSPI uint64
		responderSPI uint64
	}{
		{name: "old ike delete activates staged rekey", initiatorSPI: 0x0102030405060708, responderSPI: 0x1112131415161718},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.cfg.IKESALifetime = time.Hour
			session.cfg.IKESARekeyMargin = 10 * time.Minute
			next := &ikeCrypto{keys: ikeKeys{SKD: []byte{0x01}}}
			session.mu.Lock()
			session.ikeSARekeying = true
			session.simultaneousIKESA = simultaneousIKESARekey{ready: true}
			session.mu.Unlock()

			session.stageIKESecurityAssociation(ikeSARekeyResult{crypto: next, initiatorSPI: tt.initiatorSPI, responderSPI: tt.responderSPI})
			if !session.promotePendingIKESecurityAssociation() {
				t.Fatal("promotePendingIKESecurityAssociation() = false, want true")
			}
			if session.promotePendingIKESecurityAssociation() {
				t.Fatal("second promotePendingIKESecurityAssociation() = true, want false")
			}

			session.mu.RLock()
			gotIKE := session.ike
			initiatorSPI := session.initiatorSPI
			responderSPI := session.responderSPI
			pending := session.pendingIKESAReady
			localInitiator := session.ikeLocalInitiator
			rekeying := session.ikeSARekeying
			simultaneous := session.simultaneousIKESA.ready
			session.mu.RUnlock()
			if gotIKE != next {
				t.Fatal("ike state was not promoted")
			}
			if initiatorSPI != tt.initiatorSPI || responderSPI != tt.responderSPI {
				t.Fatalf("IKE SPIs = (%#x, %#x), want (%#x, %#x)", initiatorSPI, responderSPI, tt.initiatorSPI, tt.responderSPI)
			}
			if pending {
				t.Fatal("pendingIKESAReady = true, want false")
			}
			if localInitiator {
				t.Fatal("ikeLocalInitiator = true, want false for peer initiated rekey")
			}
			if rekeying || simultaneous {
				t.Fatalf("IKE rekey flags = (%t, %t), want false", rekeying, simultaneous)
			}
		})
	}
}

func TestPendingIKESecurityAssociationPromotesOnValidNewIKERequest(t *testing.T) {
	tests := []struct {
		name         string
		initiatorSPI uint64
		responderSPI uint64
	}{
		{name: "peer sends informational on rekeyed ike sa", initiatorSPI: 0x0102030405060708, responderSPI: 0x1112131415161718},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			pending := testIKECrypto()
			session.mu.Lock()
			session.ike = testIKECrypto()
			session.ikeLocalInitiator = true
			session.initiatorSPI = 1
			session.responderSPI = 2
			session.outerNAT = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.pendingIKESA = ikeSARekeyResult{
				crypto:         pending,
				initiatorSPI:   tt.initiatorSPI,
				responderSPI:   tt.responderSPI,
				localInitiator: false,
			}
			session.pendingIKESAReady = true
			session.mu.Unlock()

			wire, err := pending.SealIKE(ike.IKEHeader{
				InitiatorSPI: tt.initiatorSPI,
				ResponderSPI: tt.responderSPI,
				Version:      ikeVersion20,
				ExchangeType: exchangeTypeInformational,
				Flags:        flagInitiator,
				MessageID:    0,
			}, nil, true)
			if err != nil {
				t.Fatalf("SealIKE() error = %v", err)
			}

			handled, err := session.handleIKEPacket(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500})
			if err != nil {
				t.Fatalf("handleIKEPacket() error = %v", err)
			}
			if !handled {
				t.Fatal("handleIKEPacket() = false, want true")
			}

			session.mu.RLock()
			gotIKE := session.ike
			initiatorSPI := session.initiatorSPI
			responderSPI := session.responderSPI
			localInitiator := session.ikeLocalInitiator
			pendingReady := session.pendingIKESAReady
			session.mu.RUnlock()
			if gotIKE != pending {
				t.Fatal("pending IKE SA was not promoted")
			}
			if initiatorSPI != tt.initiatorSPI || responderSPI != tt.responderSPI {
				t.Fatalf("IKE SPIs = (%#x, %#x), want (%#x, %#x)", initiatorSPI, responderSPI, tt.initiatorSPI, tt.responderSPI)
			}
			if localInitiator {
				t.Fatal("ikeLocalInitiator = true, want false for peer initiated rekey")
			}
			if pendingReady {
				t.Fatal("pendingIKESAReady = true, want false")
			}
			if len(conn.writes) != 1 {
				t.Fatalf("response writes = %d, want 1", len(conn.writes))
			}
		})
	}
}

func TestPendingIKESecurityAssociationCreateChildUsesNewMessageWindow(t *testing.T) {
	tests := []struct {
		name         string
		initiatorSPI uint64
		responderSPI uint64
	}{
		{name: "first request on rekeyed ike sa starts at zero", initiatorSPI: 0x0102030405060708, responderSPI: 0x1112131415161718},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			pending := testIKECrypto()
			session.mu.Lock()
			session.ike = testIKECrypto()
			session.ikeLocalInitiator = true
			session.initiatorSPI = 1
			session.responderSPI = 2
			session.nextPeerMessageID = 9
			session.informResponses = map[uint32][][]byte{0: {[]byte("old")}}
			session.pendingIKESA = ikeSARekeyResult{
				crypto:         pending,
				initiatorSPI:   tt.initiatorSPI,
				responderSPI:   tt.responderSPI,
				localInitiator: false,
			}
			session.pendingIKESAReady = true
			session.mu.Unlock()

			payloads := childSACreateRequestPayloads(handshakeConfig(Config{}), 0x50607080, testNonce("peer nonce"))
			wire, err := pending.SealIKE(ike.IKEHeader{
				InitiatorSPI: tt.initiatorSPI,
				ResponderSPI: tt.responderSPI,
				Version:      ikeVersion20,
				ExchangeType: exchangeTypeCreateChildSA,
				Flags:        flagInitiator,
				MessageID:    0,
			}, payloads, true)
			if err != nil {
				t.Fatalf("SealIKE() error = %v", err)
			}

			handled, err := session.handleIKEPacket(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500})
			if err != nil {
				t.Fatalf("handleIKEPacket() error = %v", err)
			}
			if !handled {
				t.Fatal("handleIKEPacket() = false, want true")
			}
			if len(conn.writes) != 1 {
				t.Fatalf("response writes = %d, want 1", len(conn.writes))
			}
			if bytes.Equal(conn.writes[0], []byte("old")) {
				t.Fatal("CREATE_CHILD_SA response reused old IKE SA response cache")
			}
			session.mu.RLock()
			nextPeerMessageID := session.nextPeerMessageID
			pendingReady := session.pendingIKESAReady
			session.mu.RUnlock()
			if nextPeerMessageID != 1 {
				t.Fatalf("nextPeerMessageID = %d, want 1", nextPeerMessageID)
			}
			if pendingReady {
				t.Fatal("pendingIKESAReady = true, want false")
			}
		})
	}
}

func TestRetiredIKESecurityAssociationHandlesLateOldIKEMessages(t *testing.T) {
	tests := []struct {
		name         string
		exchangeType byte
		payloads     func(t *testing.T) []ike.Payload
		assert       func(t *testing.T, session *Session, response []ike.Payload)
	}{
		{
			name:         "late old ike rekey gets temporary failure",
			exchangeType: exchangeTypeCreateChildSA,
			payloads: func(t *testing.T) []ike.Payload {
				t.Helper()
				peer, err := newIKECrypto(transformDH1024MODP)
				if err != nil {
					t.Fatalf("newIKECrypto() error = %v", err)
				}
				peer.SetSPIs(0x2122232425262728, 0)
				peer.SetNonces(testNonce("peer late ike rekey"), nil)
				return ikeSARekeyRequestPayloads(testIKESARekeyCrypto(transformDH1024MODP, transformPRFHMACSHA1), peer)
			},
			assert: func(t *testing.T, session *Session, response []ike.Payload) {
				t.Helper()
				if notify := ike.FindNotifyPayload(response, notifyTypeTemporaryFailure); notify == nil {
					t.Fatalf("response notify = %v, want TEMPORARY_FAILURE", response)
				}
				session.mu.RLock()
				retiredCount := len(session.retiredIKESAs)
				nextPeerMessageID := session.retiredIKESAs[0].nextPeerMessageID
				session.mu.RUnlock()
				if retiredCount != 1 {
					t.Fatalf("retired IKE SA count = %d, want 1", retiredCount)
				}
				if nextPeerMessageID != 1 {
					t.Fatalf("retired nextPeerMessageID = %d, want 1", nextPeerMessageID)
				}
			},
		},
		{
			name:         "old ike delete is acknowledged without closing current ike",
			exchangeType: exchangeTypeInformational,
			payloads: func(t *testing.T) []ike.Payload {
				t.Helper()
				return []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}}
			},
			assert: func(t *testing.T, session *Session, response []ike.Payload) {
				t.Helper()
				if len(response) != 0 {
					t.Fatalf("delete response payloads = %v, want empty response", response)
				}
				session.mu.RLock()
				retiredCount := len(session.retiredIKESAs)
				currentIKE := session.ike
				session.mu.RUnlock()
				if retiredCount != 0 {
					t.Fatalf("retired IKE SA count = %d, want 0 after delete", retiredCount)
				}
				if currentIKE == nil {
					t.Fatal("current IKE SA was cleared after retired delete")
				}
				if session.isClosed() {
					t.Fatal("session is closed, want active")
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			old := testIKECrypto()
			next := testIKECrypto()
			session.mu.Lock()
			session.ike = old
			session.ikeLocalInitiator = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.outerNAT = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.nextPeerMessageID = 0
			session.informResponses = make(map[uint32][][]byte)
			session.mu.Unlock()

			session.installIKESecurityAssociation(ikeSARekeyResult{
				crypto:         next,
				initiatorSPI:   0x3132333435363738,
				responderSPI:   0x4142434445464748,
				localInitiator: true,
			})

			wire := protectedIKEWire(t, old, tt.exchangeType, flagInitiator, 0, tt.payloads(t), false)
			handled, err := session.handleIKEPacket(wire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500})
			if err != nil {
				t.Fatalf("handleIKEPacket() error = %v", err)
			}
			if !handled {
				t.Fatal("handleIKEPacket() = false, want true")
			}
			if len(conn.writes) != 1 {
				t.Fatalf("response writes = %d, want 1", len(conn.writes))
			}
			var packet ike.IKEPacket
			if err := packet.UnmarshalBinary(conn.writes[0][4:]); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			response, err := old.OpenIKE(packet, true)
			if err != nil {
				t.Fatalf("response OpenIKE() error = %v", err)
			}
			tt.assert(t, session, response)
		})
	}
}

func TestProtectedRequestParseErrorsGetNotifyResponse(t *testing.T) {
	const (
		unsupportedPayloadType byte = 99
		notifyPayloadType      byte = 41
		deletePayloadType      byte = 42
	)
	tests := []struct {
		name           string
		exchangeType   byte
		firstPayload   byte
		plain          []byte
		wantNotifyType uint16
		wantNotifyData []byte
	}{
		{
			name:           "informational unsupported critical payload",
			exchangeType:   exchangeTypeInformational,
			firstPayload:   unsupportedPayloadType,
			plain:          []byte{0x00, 0x80, 0x00, 0x04},
			wantNotifyType: notifyTypeUnsupportedCriticalPayload,
			wantNotifyData: []byte{unsupportedPayloadType},
		},
		{
			name:           "create_child_sa unsupported critical payload",
			exchangeType:   exchangeTypeCreateChildSA,
			firstPayload:   unsupportedPayloadType,
			plain:          []byte{0x00, 0x80, 0x00, 0x04},
			wantNotifyType: notifyTypeUnsupportedCriticalPayload,
			wantNotifyData: []byte{unsupportedPayloadType},
		},
		{
			name:           "informational invalid syntax",
			exchangeType:   exchangeTypeInformational,
			firstPayload:   notifyPayloadType,
			plain:          []byte{0x00, 0x00, 0x00, 0x04},
			wantNotifyType: notifyTypeInvalidSyntax,
		},
		{
			name:           "create_child_sa invalid syntax",
			exchangeType:   exchangeTypeCreateChildSA,
			firstPayload:   notifyPayloadType,
			plain:          []byte{0x00, 0x00, 0x00, 0x04},
			wantNotifyType: notifyTypeInvalidSyntax,
		},
		{
			name:           "informational malformed ike delete",
			exchangeType:   exchangeTypeInformational,
			firstPayload:   deletePayloadType,
			plain:          append([]byte{0x00, 0x00, 0x00, 0x0c, protocolIDIKE, 0x04, 0x00, 0x01}, uint32Bytes(0x01020304)...),
			wantNotifyType: notifyTypeInvalidSyntax,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.mu.Lock()
			session.connected = true
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.outerNAT = peer
			session.nextPeerMessageID = 0
			session.mu.Unlock()

			wire := protectedIKERawPlain(t, crypto, tt.exchangeType, 0, 0, tt.firstPayload, tt.plain, false)

			handled, err := session.handleIKEPacket(wire, peer)

			if err != nil {
				t.Fatalf("handleIKEPacket() error = %v", err)
			}
			if !handled {
				t.Fatal("handleIKEPacket() = false, want true")
			}
			if len(conn.writes) != 1 {
				t.Fatalf("response writes = %d, want 1", len(conn.writes))
			}
			var response ike.IKEPacket
			if err := response.UnmarshalBinary(conn.writes[0][4:]); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			if response.Header.ExchangeType != tt.exchangeType || response.Header.MessageID != 0 {
				t.Fatalf("response header exchange=%d message_id=%d, want exchange=%d message_id=0", response.Header.ExchangeType, response.Header.MessageID, tt.exchangeType)
			}
			payloads, err := crypto.OpenIKE(response, true)
			if err != nil {
				t.Fatalf("OpenIKE(response) error = %v", err)
			}
			notify := ike.FindNotifyPayload(payloads, tt.wantNotifyType)
			if notify == nil {
				t.Fatalf("notify %d missing in %v", tt.wantNotifyType, payloads)
			}
			if !bytes.Equal(notify.Data, tt.wantNotifyData) {
				t.Fatalf("notify data = %x, want %x", notify.Data, tt.wantNotifyData)
			}
			session.mu.RLock()
			nextPeerMessageID := session.nextPeerMessageID
			session.mu.RUnlock()
			if nextPeerMessageID != 1 {
				t.Fatalf("nextPeerMessageID = %d, want 1", nextPeerMessageID)
			}
		})
	}
}

func testIKECrypto() *ikeCrypto {
	return &ikeCrypto{
		encr:        transformENCRAESCBC,
		encrKeyBits: 128,
		integ:       transformINTEGHMACSHA196,
		prf:         transformPRFHMACSHA1,
		dhGroup:     transformDH2048MODP,
		random:      bytes.NewReader(bytes.Repeat([]byte{0x42}, 1024)),
		keys: ikeKeys{
			SKD:  bytes.Repeat([]byte{0x55}, 20),
			SKAI: bytes.Repeat([]byte{0x11}, 20),
			SKAR: bytes.Repeat([]byte{0x22}, 20),
			SKEI: bytes.Repeat([]byte{0x33}, 16),
			SKER: bytes.Repeat([]byte{0x44}, 16),
		},
	}
}

func testIKESARekeyCrypto(dhGroup, prf uint16) *ikeCrypto {
	crypto := testIKECrypto()
	crypto.dhGroup = dhGroup
	crypto.prf = prf
	return crypto
}

func testChildSATrafficSelectors() ([]ike.TrafficSelector, []ike.TrafficSelector) {
	selectors := ike.TrafficSelectorsAny()
	return cloneTrafficSelectors(selectors[:1]), cloneTrafficSelectors(selectors[:1])
}

func TestOpenIKERejectsNestedEncryptedPayload(t *testing.T) {
	crypto := testIKECrypto()
	nested := testPayloadBlock(payloadTypeNone, []byte{0x01, 0x02})
	wire := protectedIKERawPlain(
		t,
		crypto,
		exchangeTypeInformational,
		flagResponse,
		1,
		payloadTypeEncrypted,
		nested,
		false,
	)
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	_, err := crypto.OpenIKE(packet, false)
	var syntax ike.InvalidSyntaxError
	if err == nil || !errors.As(err, &syntax) || !strings.Contains(err.Error(), "nested encrypted payload") {
		t.Fatalf("OpenIKE() error = %v, want nested encrypted InvalidSyntaxError", err)
	}
}

func testPayloadBlock(next byte, body []byte) []byte {
	const payloadHeaderSize = 4
	wire := make([]byte, payloadHeaderSize)
	wire[0] = next
	binary.BigEndian.PutUint16(wire[2:4], uint16(len(body)+payloadHeaderSize))
	return append(wire, body...)
}

func protectedIKEWire(t *testing.T, crypto *ikeCrypto, exchangeType byte, flags byte, messageID uint32, payloads []ike.Payload, senderInitiator bool) []byte {
	t.Helper()
	wire, err := crypto.SealIKE(ike.IKEHeader{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeType,
		Flags:        flags,
		MessageID:    messageID,
	}, payloads, senderInitiator)
	if err != nil {
		t.Fatalf("SealIKE() error = %v", err)
	}
	return wire
}

func protectedIKERawPlain(t *testing.T, crypto *ikeCrypto, exchangeType byte, flags byte, messageID uint32, firstPayload byte, plain []byte, senderInitiator bool) []byte {
	t.Helper()
	padLen := aes.BlockSize - ((len(plain) + 1) % aes.BlockSize)
	if padLen == aes.BlockSize {
		padLen = 0
	}
	padded := append([]byte(nil), plain...)
	padded = append(padded, make([]byte, padLen)...)
	padded = append(padded, byte(padLen))
	iv := bytes.Repeat([]byte{0x42}, aes.BlockSize)
	ciphertext, err := crypto.encryptCBC(crypto.encryptionKey(senderInitiator), iv, padded)
	if err != nil {
		t.Fatalf("encryptCBC() error = %v", err)
	}
	icvLen, err := integLength(crypto.integ)
	if err != nil {
		t.Fatalf("integLength() error = %v", err)
	}
	container := &ike.EncryptedPayload{NextPayload: firstPayload, Raw: append(append(iv, ciphertext...), make([]byte, icvLen)...)}
	packet := ike.IKEPacket{Header: ike.IKEHeader{
		InitiatorSPI: 0x0102030405060708,
		ResponderSPI: 0x1112131415161718,
		Version:      ikeVersion20,
		ExchangeType: exchangeType,
		Flags:        flags,
		MessageID:    messageID,
	}, Payloads: []ike.Payload{container}}
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	icv := crypto.integHMAC(crypto.integrityKey(senderInitiator), wire[:len(wire)-icvLen])
	copy(wire[len(wire)-icvLen:], icv)
	return wire
}

func testNonce(label string) []byte {
	nonce := make([]byte, 32)
	copy(nonce, label)
	return nonce
}

func TestStageResponderChildSecurityAssociationsDefersOutboundSwitch(t *testing.T) {
	tests := []struct {
		name        string
		oldInbound  uint32
		oldOutbound uint32
		newInbound  uint32
		newOutbound uint32
	}{
		{name: "peer initiated child rekey", oldInbound: 0x01020304, oldOutbound: 0x10203040, newInbound: 0x11121314, newOutbound: 0x50607080},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.cfg.ChildSALifetime = time.Hour
			session.cfg.ChildSARekeyMargin = 10 * time.Minute
			oldOutbound := esp.Codec{SPI: tt.oldOutbound}
			result := childSARekeyResult{
				info: Info{
					InnerIPv4:        net.IPv4(10, 0, 0, 1),
					PCSCFIPs:         []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI:  tt.newInbound,
					ESPResponderSPI:  tt.newOutbound,
					Encryption:       transformENCRAESCBC,
					EncryptionKeyLen: 128,
					Integrity:        transformINTEGHMACSHA196,
				},
				inbound:    esp.Codec{SPI: tt.newInbound},
				outbound:   esp.Codec{SPI: tt.newOutbound},
				oldInbound: tt.oldInbound,
			}
			session.mu.Lock()
			session.connected = true
			session.dataPlaneDone = make(chan struct{})
			session.tunnel = Info{
				InnerIPv4:       net.IPv4(10, 0, 0, 1),
				PCSCFIPs:        []net.IP{net.IPv4(10, 0, 0, 2)},
				ESPInitiatorSPI: tt.oldInbound,
				ESPResponderSPI: tt.oldOutbound,
			}
			session.inboundESP = esp.Codec{SPI: tt.oldInbound}
			session.outboundESP = oldOutbound
			session.mu.Unlock()

			session.stageResponderChildSecurityAssociations(result)

			session.mu.RLock()
			outboundSPI := session.outboundESP.SPI
			inboundSPI := session.inboundESP.SPI
			tunnelOutboundSPI := session.tunnel.ESPResponderSPI
			pending := session.pendingChildSA
			retired := append([]retiredChildSA(nil), session.retiredChildSAs...)
			session.mu.RUnlock()
			if outboundSPI != tt.oldOutbound || tunnelOutboundSPI != tt.oldOutbound {
				t.Fatalf("outbound SPI = (%#x, %#x), want old %#x before peer readiness", outboundSPI, tunnelOutboundSPI, tt.oldOutbound)
			}
			if inboundSPI != tt.newInbound {
				t.Fatalf("inbound SPI = %#x, want new %#x", inboundSPI, tt.newInbound)
			}
			if !pending.ready || pending.outbound.SPI != tt.newOutbound || pending.oldInbound != tt.oldInbound {
				t.Fatalf("pending child = %+v, want new outbound %#x old inbound %#x", pending, tt.newOutbound, tt.oldInbound)
			}
			if len(retired) != 1 || retired[0].inbound.SPI != tt.oldInbound {
				t.Fatalf("retired child SAs = %+v, want old inbound %#x", retired, tt.oldInbound)
			}

			if !session.promotePendingChildSecurityAssociation() {
				t.Fatal("promotePendingChildSecurityAssociation() = false, want true")
			}
			session.mu.RLock()
			outboundSPI = session.outboundESP.SPI
			tunnelOutboundSPI = session.tunnel.ESPResponderSPI
			pendingReady := session.pendingChildSA.ready
			session.mu.RUnlock()
			if outboundSPI != tt.newOutbound || tunnelOutboundSPI != tt.newOutbound {
				t.Fatalf("outbound SPI after promote = (%#x, %#x), want %#x", outboundSPI, tunnelOutboundSPI, tt.newOutbound)
			}
			if pendingReady {
				t.Fatal("pending child still ready after promote")
			}
		})
	}
}

func TestDeleteOldChildSAPromotesPendingOutbound(t *testing.T) {
	tests := []struct {
		name        string
		oldInbound  uint32
		oldOutbound uint32
	}{
		{name: "delete old peer inbound", oldInbound: 0x01020304, oldOutbound: 0x10203040},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state := informationalState{
				inboundSPI:    0x11121314,
				outboundSPI:   tt.oldOutbound,
				pendingChild:  true,
				oldInboundSPI: tt.oldInbound,
			}
			responsePayloads, action, ok, err := buildDeleteResponsePayloads(state, []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{uint32Bytes(tt.oldOutbound)}},
			})
			if err != nil {
				t.Fatalf("buildDeleteResponsePayloads() error = %v", err)
			}
			if !ok {
				t.Fatal("delete payload not handled")
			}
			if !action.promotePendingChild || action.deleteChild {
				t.Fatalf("action = %+v, want promote pending child only", action)
			}
			deletePayload, ok := responsePayloads[0].(*ike.DeletePayload)
			if !ok {
				t.Fatalf("response payload = %T, want *ike.DeletePayload", responsePayloads[0])
			}
			if got := binary.BigEndian.Uint32(deletePayload.SPIs[0]); got != tt.oldInbound {
				t.Fatalf("response delete SPI = %#x, want old inbound %#x", got, tt.oldInbound)
			}
		})
	}
}

func TestDeleteOldChildSAAfterPendingPromotionRespondsWithRetiredInbound(t *testing.T) {
	tests := []struct {
		name        string
		oldInbound  uint32
		oldOutbound uint32
		newInbound  uint32
		newOutbound uint32
	}{
		{name: "delete old peer inbound after responder promoted pending child", oldInbound: 0x01020304, oldOutbound: 0x10203040, newInbound: 0x11121314, newOutbound: 0x50607080},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			session.tunnel = Info{
				InnerIPv4:       net.IPv4(10, 0, 0, 1),
				PCSCFIPs:        []net.IP{net.IPv4(10, 0, 0, 2)},
				ESPInitiatorSPI: tt.oldInbound,
				ESPResponderSPI: tt.oldOutbound,
			}
			session.inboundESP = esp.Codec{SPI: tt.oldInbound}
			session.outboundESP = esp.Codec{SPI: tt.oldOutbound}
			session.mu.Unlock()

			session.stageResponderChildSecurityAssociations(childSARekeyResult{
				info: Info{
					InnerIPv4:       net.IPv4(10, 0, 0, 1),
					PCSCFIPs:        []net.IP{net.IPv4(10, 0, 0, 2)},
					ESPInitiatorSPI: tt.newInbound,
					ESPResponderSPI: tt.newOutbound,
				},
				inbound:    esp.Codec{SPI: tt.newInbound},
				outbound:   esp.Codec{SPI: tt.newOutbound},
				oldInbound: tt.oldInbound,
			})
			if !session.promotePendingChildSecurityAssociation() {
				t.Fatal("promotePendingChildSecurityAssociation() = false, want true")
			}

			state := session.currentInformationalState()
			responsePayloads, action, ok, err := buildDeleteResponsePayloads(state, []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{uint32Bytes(tt.oldOutbound)}},
			})
			if err != nil {
				t.Fatalf("buildDeleteResponsePayloads() error = %v", err)
			}
			if !ok {
				t.Fatal("delete payload not handled")
			}
			if action.deleteChild || action.promotePendingChild {
				t.Fatalf("action = %+v, want retired child cleanup only", action)
			}
			if !slices.Equal(action.deleteRetiredChildSPIs, []uint32{tt.oldInbound}) {
				t.Fatalf("deleteRetiredChildSPIs = %#x, want %#x", action.deleteRetiredChildSPIs, []uint32{tt.oldInbound})
			}
			if len(responsePayloads) != 1 {
				t.Fatalf("response payload count = %d, want 1", len(responsePayloads))
			}
			deletePayload, ok := responsePayloads[0].(*ike.DeletePayload)
			if !ok {
				t.Fatalf("response payload = %T, want *ike.DeletePayload", responsePayloads[0])
			}
			if got := binary.BigEndian.Uint32(deletePayload.SPIs[0]); got != tt.oldInbound {
				t.Fatalf("response delete SPI = %#x, want retired inbound %#x", got, tt.oldInbound)
			}
			for _, spi := range action.deleteRetiredChildSPIs {
				session.removeRetiredChildSA(spi)
			}
			session.mu.RLock()
			retiredCount := len(session.retiredChildSAs)
			session.mu.RUnlock()
			if retiredCount != 0 {
				t.Fatalf("retired child SA count = %d, want 0 after delete response action", retiredCount)
			}
		})
	}
}

func TestDeleteKnownChildSAsAggregatesResponse(t *testing.T) {
	tests := []struct {
		name             string
		state            informationalState
		payloads         []ike.Payload
		wantSPIs         []uint32
		wantDeleteChild  bool
		wantPromoteChild bool
		wantRetiredSPIs  []uint32
	}{
		{
			name: "active and retired child sas",
			state: informationalState{
				inboundSPI:  0x01020304,
				outboundSPI: 0x10203040,
				retiredChildSAs: []retiredChildSAState{{
					inboundSPI:  0x11121314,
					outboundSPI: 0x21222324,
				}},
			},
			payloads: []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{uint32Bytes(0x10203040)}},
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{uint32Bytes(0x21222324)}},
			},
			wantSPIs:        []uint32{0x01020304, 0x11121314},
			wantDeleteChild: true,
			wantRetiredSPIs: []uint32{0x11121314},
		},
		{
			name: "pending old and retired child sas",
			state: informationalState{
				inboundSPI:    0x11121314,
				outboundSPI:   0x10203040,
				pendingChild:  true,
				oldInboundSPI: 0x01020304,
				retiredChildSAs: []retiredChildSAState{{
					inboundSPI:  0x21222324,
					outboundSPI: 0x31323334,
				}},
			},
			payloads: []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{
					uint32Bytes(0x10203040),
					uint32Bytes(0x31323334),
				}},
			},
			wantSPIs:         []uint32{0x01020304, 0x21222324},
			wantPromoteChild: true,
			wantRetiredSPIs:  []uint32{0x01020304, 0x21222324},
		},
		{
			name: "mixed unknown and active child spi",
			state: informationalState{
				inboundSPI:  0x01020304,
				outboundSPI: 0x10203040,
			},
			payloads: []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{
					uint32Bytes(0x50607080),
					uint32Bytes(0x10203040),
				}},
			},
			wantSPIs:        []uint32{0x01020304},
			wantDeleteChild: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responsePayloads, action, ok, err := buildDeleteResponsePayloads(tt.state, tt.payloads)
			if err != nil {
				t.Fatalf("buildDeleteResponsePayloads() error = %v", err)
			}
			if !ok {
				t.Fatal("delete payload not handled")
			}
			if action.deleteChild != tt.wantDeleteChild || action.promotePendingChild != tt.wantPromoteChild {
				t.Fatalf("action = %+v, want deleteChild=%t promotePendingChild=%t", action, tt.wantDeleteChild, tt.wantPromoteChild)
			}
			if !slices.Equal(action.deleteRetiredChildSPIs, tt.wantRetiredSPIs) {
				t.Fatalf("deleteRetiredChildSPIs = %#x, want %#x", action.deleteRetiredChildSPIs, tt.wantRetiredSPIs)
			}
			if len(responsePayloads) != 1 {
				t.Fatalf("response payload count = %d, want 1", len(responsePayloads))
			}
			deletePayload, ok := responsePayloads[0].(*ike.DeletePayload)
			if !ok {
				t.Fatalf("response payload = %T, want *ike.DeletePayload", responsePayloads[0])
			}
			if deletePayload.ProtocolID != protocolIDESP {
				t.Fatalf("response protocol id = %d, want %d", deletePayload.ProtocolID, protocolIDESP)
			}
			gotSPIs := make([]uint32, 0, len(deletePayload.SPIs))
			for _, spi := range deletePayload.SPIs {
				gotSPIs = append(gotSPIs, binary.BigEndian.Uint32(spi))
			}
			if !slices.Equal(gotSPIs, tt.wantSPIs) {
				t.Fatalf("response delete SPIs = %#x, want %#x", gotSPIs, tt.wantSPIs)
			}
		})
	}
}

func TestDeleteUnknownChildSARespondsEmpty(t *testing.T) {
	tests := []struct {
		name       string
		state      informationalState
		deleteSPIs [][]byte
	}{
		{
			name: "unknown current child spi",
			state: informationalState{
				inboundSPI:  0x01020304,
				outboundSPI: 0x10203040,
			},
			deleteSPIs: [][]byte{uint32Bytes(0x50607080)},
		},
		{
			name:       "no active child state",
			state:      informationalState{},
			deleteSPIs: [][]byte{uint32Bytes(0x50607080)},
		},
		{
			name:       "zero spi without active child state",
			state:      informationalState{},
			deleteSPIs: [][]byte{uint32Bytes(0)},
		},
		{
			name: "zero spi with partial child state",
			state: informationalState{
				inboundSPI: 0x01020304,
			},
			deleteSPIs: [][]byte{uint32Bytes(0)},
		},
		{
			name: "reserved spi with partial child state",
			state: informationalState{
				inboundSPI:  0x01020304,
				outboundSPI: 255,
			},
			deleteSPIs: [][]byte{uint32Bytes(255)},
		},
		{
			name: "pending child without old inbound spi",
			state: informationalState{
				outboundSPI:  0x10203040,
				pendingChild: true,
			},
			deleteSPIs: [][]byte{uint32Bytes(0x10203040)},
		},
		{
			name: "not a retired child spi",
			state: informationalState{
				inboundSPI:  0x01020304,
				outboundSPI: 0x10203040,
				retiredChildSAs: []retiredChildSAState{{
					inboundSPI:  0x11121314,
					outboundSPI: 0x21222324,
				}},
			},
			deleteSPIs: [][]byte{uint32Bytes(0x50607080)},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responsePayloads, action, ok, err := buildDeleteResponsePayloads(tt.state, []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: tt.deleteSPIs},
			})
			if err != nil {
				t.Fatalf("buildDeleteResponsePayloads() error = %v", err)
			}
			if !ok {
				t.Fatal("delete payload not handled")
			}
			if action.deleteIKE || action.deleteChild || action.promotePendingChild || len(action.deleteRetiredChildSPIs) != 0 {
				t.Fatalf("action = %+v, want no state change for unknown spi", action)
			}
			if len(responsePayloads) != 0 {
				t.Fatalf("response payload count = %d, want 0", len(responsePayloads))
			}
		})
	}
}

func TestAHDeletePayloadsAreIgnored(t *testing.T) {
	tests := []struct {
		name            string
		payloads        []ike.Payload
		wantResponseSPI uint32
		wantDeleteChild bool
	}{
		{
			name: "ah delete",
			payloads: []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDAH, SPIs: [][]byte{uint32Bytes(0x10203040)}},
			},
		},
		{
			name: "mixed ah and esp delete",
			payloads: []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDAH, SPIs: [][]byte{uint32Bytes(0x10203040)}},
				&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{uint32Bytes(0x50607080)}},
			},
			wantResponseSPI: 0x01020304,
			wantDeleteChild: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responsePayloads, action, ok, err := buildDeleteResponsePayloads(informationalState{
				inboundSPI:  0x01020304,
				outboundSPI: 0x50607080,
			}, tt.payloads)
			if err != nil {
				t.Fatalf("buildDeleteResponsePayloads() error = %v", err)
			}
			if !ok {
				t.Fatal("delete payload not handled")
			}
			if action.deleteIKE || action.deleteChild != tt.wantDeleteChild || action.promotePendingChild || len(action.deleteRetiredChildSPIs) != 0 {
				t.Fatalf("action = %+v, want deleteChild=%t", action, tt.wantDeleteChild)
			}
			if tt.wantResponseSPI == 0 {
				if len(responsePayloads) != 0 {
					t.Fatalf("response payload count = %d, want 0", len(responsePayloads))
				}
				return
			}
			if len(responsePayloads) != 1 {
				t.Fatalf("response payload count = %d, want 1", len(responsePayloads))
			}
			deletePayload, ok := responsePayloads[0].(*ike.DeletePayload)
			if !ok {
				t.Fatalf("response payload = %T, want *ike.DeletePayload", responsePayloads[0])
			}
			if deletePayload.ProtocolID != protocolIDESP {
				t.Fatalf("response protocol id = %d, want %d", deletePayload.ProtocolID, protocolIDESP)
			}
			if len(deletePayload.SPIs) != 1 {
				t.Fatalf("response delete spi count = %d, want 1", len(deletePayload.SPIs))
			}
			if got := binary.BigEndian.Uint32(deletePayload.SPIs[0]); got != tt.wantResponseSPI {
				t.Fatalf("response delete SPI = %#x, want %#x", got, tt.wantResponseSPI)
			}
		})
	}
}

func TestInvalidDeleteProtocolRespondsInvalidSyntax(t *testing.T) {
	responsePayloads, action, ok, err := buildDeleteResponsePayloads(informationalState{
		inboundSPI:  0x01020304,
		outboundSPI: 0x50607080,
	}, []ike.Payload{
		&ike.DeletePayload{ProtocolID: 4, SPIs: [][]byte{uint32Bytes(0x10203040)}},
	})
	if err != nil {
		t.Fatalf("buildDeleteResponsePayloads() error = %v", err)
	}
	if !ok {
		t.Fatal("delete payload not handled")
	}
	if action.deleteIKE || action.deleteChild || action.promotePendingChild || len(action.deleteRetiredChildSPIs) != 0 {
		t.Fatalf("action = %+v, want no state change for invalid protocol", action)
	}
	if len(responsePayloads) != 1 {
		t.Fatalf("response payload count = %d, want 1", len(responsePayloads))
	}
	notifyPayload, ok := responsePayloads[0].(*ike.NotifyPayload)
	if !ok {
		t.Fatalf("response payload = %T, want *ike.NotifyPayload", responsePayloads[0])
	}
	if notifyPayload.NotifyType != notifyTypeInvalidSyntax {
		t.Fatalf("notify type = %d, want %d", notifyPayload.NotifyType, notifyTypeInvalidSyntax)
	}
}

func TestInstallChildSecurityAssociationsSwitchesESPState(t *testing.T) {
	tests := []struct {
		name string
		info Info
		keys ESPKeys
	}{
		{
			name: "new child sa replaces data plane",
			info: Info{
				InnerIPv4:        net.IPv4(10, 0, 0, 1),
				PCSCFIPs:         []net.IP{net.IPv4(10, 0, 0, 2)},
				ESPInitiatorSPI:  0x11121314,
				ESPResponderSPI:  0x21222324,
				Encryption:       transformENCRAESCBC,
				EncryptionKeyLen: 128,
				Integrity:        transformINTEGHMACSHA196,
			},
			keys: ESPKeys{
				EncryptionInitiator: bytes.Repeat([]byte{0x01}, 16),
				IntegrityInitiator:  bytes.Repeat([]byte{0x02}, 20),
				EncryptionResponder: bytes.Repeat([]byte{0x03}, 16),
				IntegrityResponder:  bytes.Repeat([]byte{0x04}, 20),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.cfg.ChildSALifetime = time.Hour
			session.cfg.ChildSARekeyMargin = 10 * time.Minute
			session.mu.Lock()
			session.connected = true
			session.dataPlaneDone = make(chan struct{})
			session.inboundESP = esp.Codec{SPI: 0x01020304}
			session.espSeq = 99
			session.inboundReplay.Accept(7)
			session.mu.Unlock()

			session.installChildSecurityAssociations(childSARekeyResult{
				info:       tt.info,
				keys:       tt.keys,
				outbound:   outboundESPCodec(tt.info, tt.keys),
				inbound:    inboundESPCodec(tt.info, tt.keys),
				oldInbound: 0x01020304,
			})

			session.mu.RLock()
			info := session.tunnel
			outbound := session.outboundESP
			inbound := session.inboundESP
			seq := session.espSeq
			expiresAt := session.childSAExpiresAt
			rekeyAt := session.childSARekeyAt
			retired := append([]retiredChildSA(nil), session.retiredChildSAs...)
			session.mu.RUnlock()

			if info.ESPInitiatorSPI != tt.info.ESPInitiatorSPI || info.ESPResponderSPI != tt.info.ESPResponderSPI {
				t.Fatalf("tunnel SPIs = (%#x, %#x), want (%#x, %#x)", info.ESPInitiatorSPI, info.ESPResponderSPI, tt.info.ESPInitiatorSPI, tt.info.ESPResponderSPI)
			}
			if outbound.SPI != tt.info.ESPResponderSPI || inbound.SPI != tt.info.ESPInitiatorSPI {
				t.Fatalf("codec SPIs = (%#x, %#x), want (%#x, %#x)", outbound.SPI, inbound.SPI, tt.info.ESPResponderSPI, tt.info.ESPInitiatorSPI)
			}
			if seq != 0 {
				t.Fatalf("espSeq = %d, want 0", seq)
			}
			if !session.acceptInboundESPSequence(7) {
				t.Fatal("inbound replay window was not reset")
			}
			if len(retired) != 1 || retired[0].inbound.SPI != 0x01020304 {
				t.Fatalf("retired child SAs = %+v, want old inbound SPI 0x01020304", retired)
			}
			if !session.acceptESPSequence(0x01020304, 7, 0).accepted {
				t.Fatal("retired child SA did not keep an independent replay window")
			}
			if expiresAt.IsZero() || rekeyAt.IsZero() || !rekeyAt.Before(expiresAt) {
				t.Fatalf("lifetime state = rekey %s expires %s, want proactive rekey before expiry", rekeyAt, expiresAt)
			}
		})
	}
}

func TestInboundPacketContextsPrunesExpiredRetiredChildSAs(t *testing.T) {
	tests := []struct {
		name        string
		expiresAt   time.Time
		wantContext bool
		wantRetired int
	}{
		{name: "expired retired child sa is not accepted", expiresAt: time.Now().Add(-time.Second), wantContext: false, wantRetired: 0},
		{name: "live retired child sa stays usable during drain", expiresAt: time.Now().Add(time.Hour), wantContext: true, wantRetired: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.cfg.LocalSIPPort = 5062
			session.mu.Lock()
			session.connected = true
			session.inboundESP = esp.Codec{SPI: 0x01020304}
			session.retiredChildSAs = []retiredChildSA{{
				inbound:   esp.Codec{SPI: 0x11121314},
				expiresAt: tt.expiresAt,
			}}
			session.mu.Unlock()

			contexts := session.inboundPacketContexts(0x11121314)

			if got := len(contexts) != 0; got != tt.wantContext {
				t.Fatalf("inboundPacketContexts() present = %t, want %t", got, tt.wantContext)
			}
			if tt.wantContext && contexts[0].localUDPPort != 5062 {
				t.Fatalf("local UDP port = %d, want 5062", contexts[0].localUDPPort)
			}
			session.mu.RLock()
			retiredCount := len(session.retiredChildSAs)
			session.mu.RUnlock()
			if retiredCount != tt.wantRetired {
				t.Fatalf("retired child SA count = %d, want %d", retiredCount, tt.wantRetired)
			}
		})
	}
}

func TestAcceptESPSequencePrunesExpiredRetiredChildSAs(t *testing.T) {
	tests := []struct {
		name        string
		expiresAt   time.Time
		wantAccept  bool
		wantRetired int
	}{
		{name: "expired retired child sa rejects replay check", expiresAt: time.Now().Add(-time.Second), wantAccept: false, wantRetired: 0},
		{name: "live retired child sa keeps independent replay window", expiresAt: time.Now().Add(time.Hour), wantAccept: true, wantRetired: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			session.inboundESP = esp.Codec{SPI: 0x01020304}
			session.retiredChildSAs = []retiredChildSA{{
				inbound:   esp.Codec{SPI: 0x11121314},
				expiresAt: tt.expiresAt,
			}}
			session.mu.Unlock()

			got := session.acceptESPSequence(0x11121314, 7, 0).accepted

			if got != tt.wantAccept {
				t.Fatalf("acceptESPSequence() = %t, want %t", got, tt.wantAccept)
			}
			session.mu.RLock()
			retiredCount := len(session.retiredChildSAs)
			session.mu.RUnlock()
			if retiredCount != tt.wantRetired {
				t.Fatalf("retired child SA count = %d, want %d", retiredCount, tt.wantRetired)
			}
		})
	}
}

func TestIKESAByteLifetimeTriggersSoftRekey(t *testing.T) {
	tests := []struct {
		name        string
		inbound     bool
		lifetime    uint64
		rekeyMargin uint64
		addBytes    uint64
	}{
		{name: "outbound protected bytes reach soft lifetime", lifetime: 64, rekeyMargin: 16, addBytes: 48},
		{name: "inbound protected bytes reach soft lifetime", inbound: true, lifetime: 80, rekeyMargin: 20, addBytes: 60},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			futureRekey := time.Now().Add(time.Hour)
			now := time.Now()
			session.mu.Lock()
			session.ike = &ikeCrypto{}
			session.ikeSAByteExpiresAt = saByteExpiry(tt.lifetime)
			session.ikeSAByteRekeyAt = saByteRekeyLimit(tt.lifetime, tt.rekeyMargin)
			session.ikeSARekeyAt = futureRekey
			session.mu.Unlock()

			if tt.inbound {
				accept := session.acceptIKESAInboundBytes(tt.addBytes, now)
				if !accept.accepted || accept.expired {
					t.Fatalf("acceptIKESAInboundBytes() = %+v, want accepted before hard byte lifetime", accept)
				}
			} else if expired := session.addIKESAOutboundBytes(tt.addBytes, now); expired {
				t.Fatal("addIKESAOutboundBytes() expired before hard byte lifetime")
			}

			session.mu.RLock()
			rekeyAt := session.ikeSARekeyAt
			inboundBytes := session.ikeSAInboundBytes
			outboundBytes := session.ikeSAOutboundBytes
			session.mu.RUnlock()
			if !rekeyAt.Before(futureRekey) {
				t.Fatalf("ikeSARekeyAt = %s, want before %s after byte soft lifetime", rekeyAt, futureRekey)
			}
			if !tt.inbound && outboundBytes != tt.addBytes {
				t.Fatalf("ikeSAOutboundBytes = %d, want %d", outboundBytes, tt.addBytes)
			}
			if tt.inbound && inboundBytes != tt.addBytes {
				t.Fatalf("ikeSAInboundBytes = %d, want %d", inboundBytes, tt.addBytes)
			}
		})
	}
}

func TestIKESAByteHardLifetimeRejectsOutboundBeforeOverflow(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "next outbound ike packet would exceed byte hard lifetime"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			wire := protectedIKEWire(t, crypto, exchangeTypeInformational, flagInitiator, 0, nil, true)
			nattWire := prependNonESPMarker(wire)
			protectedBytes, err := crypto.ProtectedBytes(nattWire)
			if err != nil {
				t.Fatalf("ProtectedBytes() error = %v", err)
			}
			if protectedBytes == 0 {
				t.Fatal("ProtectedBytes() = 0, want protected bytes for encrypted IKE packet")
			}

			session.mu.Lock()
			session.ike = crypto
			session.ikeSAByteExpiresAt = protectedBytes
			session.ikeSAOutboundBytes = 1
			session.mu.Unlock()

			err = session.writeProtectedWire(context.Background(), ikeActionTestSend, crypto, nattWire, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}, false)

			if !errors.Is(err, errIKESAExpired) {
				t.Fatalf("writeProtectedWire() error = %v, want %v", err, errIKESAExpired)
			}
			if len(conn.writes) != 0 {
				t.Fatalf("write count = %d, want 0 when packet exceeds IKE byte hard lifetime", len(conn.writes))
			}
		})
	}
}

func TestIKESAInboundByteHardLifetime(t *testing.T) {
	tests := []struct {
		name        string
		current     uint64
		limit       uint64
		add         uint64
		wantAccept  bool
		wantExpired bool
	}{
		{name: "exact hard byte boundary is accepted", current: 12, limit: 24, add: 12, wantAccept: true, wantExpired: true},
		{name: "past hard byte boundary is rejected", current: 20, limit: 24, add: 12, wantAccept: false, wantExpired: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.ike = &ikeCrypto{}
			session.ikeSAInboundBytes = tt.current
			session.ikeSAByteExpiresAt = tt.limit
			session.mu.Unlock()

			got := session.acceptIKESAInboundBytes(tt.add, time.Now())

			if got.accepted != tt.wantAccept || got.expired != tt.wantExpired {
				t.Fatalf("acceptIKESAInboundBytes() = %+v, want accepted=%t expired=%t", got, tt.wantAccept, tt.wantExpired)
			}
		})
	}
}

func TestInformationalRequestAtIKEByteHardBoundaryRepliesBeforeClosing(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "exact inbound hard byte boundary"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			crypto := testIKECrypto()
			wire := protectedIKEWire(t, crypto, exchangeTypeInformational, 0, 0, nil, false)
			var packet ike.IKEPacket
			if err := packet.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			protectedBytes, err := crypto.ProtectedBytes(wire)
			if err != nil {
				t.Fatalf("ProtectedBytes() error = %v", err)
			}
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.mu.Lock()
			session.connected = true
			session.ike = crypto
			session.ikeLocalInitiator = true
			session.initiatorSPI = 0x0102030405060708
			session.responderSPI = 0x1112131415161718
			session.outerNAT = peer
			session.nextPeerMessageID = 0
			session.ikeSAInboundBytes = protectedBytes
			session.ikeSAByteExpiresAt = protectedBytes * 2
			session.mu.Unlock()
			state := informationalState{
				connected:      true,
				ike:            crypto,
				localInitiator: true,
				initiatorSPI:   0x0102030405060708,
				responderSPI:   0x1112131415161718,
				peer:           peer,
			}

			ok, err := session.handleInformationalRequest(state, packet, peer)

			if !ok || err != nil {
				t.Fatalf("handleInformationalRequest() = (%t, %v), want handled without error", ok, err)
			}
			if len(conn.writes) != 1 {
				t.Fatalf("write count = %d, want response before closing IKE SA", len(conn.writes))
			}
			session.mu.RLock()
			ike := session.ike
			session.mu.RUnlock()
			if ike != nil {
				t.Fatal("ike SA still installed after exact hard byte boundary")
			}
		})
	}
}

func TestChildSAByteLifetimeTriggersSoftRekey(t *testing.T) {
	tests := []struct {
		name          string
		lifetime      uint64
		rekeyMargin   uint64
		payloadLength int
	}{
		{name: "outbound packet reaches byte soft lifetime", lifetime: 24, rekeyMargin: 12, payloadLength: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			futureRekey := time.Now().Add(time.Hour)
			session.mu.Lock()
			session.connected = true
			session.outerNAT = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.outboundESP = esp.Codec{SPI: 0x10203040, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: bytes.Repeat([]byte{0x11}, 20)}
			session.childSAByteExpiresAt = saByteExpiry(tt.lifetime)
			session.childSAByteRekeyAt = saByteRekeyLimit(tt.lifetime, tt.rekeyMargin)
			session.childSARekeyAt = futureRekey
			session.mu.Unlock()

			if err := session.writeInner(context.Background(), packet.InnerPacket{}, make([]byte, tt.payloadLength), packet.ProtocolUDP); err != nil {
				t.Fatalf("writeInner() error = %v", err)
			}

			session.mu.RLock()
			protectedBytes := session.childSAOutboundBytes
			rekeyAt := session.childSARekeyAt
			connected := session.connected
			session.mu.RUnlock()
			if protectedBytes != tt.lifetime-tt.rekeyMargin {
				t.Fatalf("childSAOutboundBytes = %d, want %d", protectedBytes, tt.lifetime-tt.rekeyMargin)
			}
			if !rekeyAt.Before(futureRekey) {
				t.Fatalf("childSARekeyAt = %s, want before %s after byte soft lifetime", rekeyAt, futureRekey)
			}
			if !connected {
				t.Fatal("connected = false, want true before hard byte lifetime")
			}
		})
	}
}

func TestChildSAByteHardLifetimeDiscardsBeforeOutboundOverflow(t *testing.T) {
	tests := []struct {
		name          string
		currentBytes  uint64
		hardBytes     uint64
		payloadLength int
	}{
		{name: "next outbound packet would exceed byte hard lifetime", currentBytes: 20, hardBytes: 24, payloadLength: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			session := mustDialSession(t, conn)
			session.mu.Lock()
			session.connected = true
			session.outerNAT = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.outboundESP = esp.Codec{SPI: 0x10203040, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: bytes.Repeat([]byte{0x11}, 20)}
			session.childSAOutboundBytes = tt.currentBytes
			session.childSAByteExpiresAt = tt.hardBytes
			session.dataPlaneDone = make(chan struct{})
			session.mu.Unlock()

			err := session.writeInner(context.Background(), packet.InnerPacket{}, make([]byte, tt.payloadLength), packet.ProtocolUDP)

			if !errors.Is(err, errChildSAExpired) {
				t.Fatalf("writeInner() error = %v, want %v", err, errChildSAExpired)
			}
			if len(conn.writes) != 0 {
				t.Fatalf("write count = %d, want 0 when packet exceeds byte hard lifetime", len(conn.writes))
			}
			session.mu.RLock()
			connected := session.connected
			tunnelErr := session.tunnelErr
			session.mu.RUnlock()
			if connected {
				t.Fatal("connected = true, want false after byte hard lifetime")
			}
			if !errors.Is(tunnelErr, errChildSAExpired) {
				t.Fatalf("tunnelErr = %v, want %v", tunnelErr, errChildSAExpired)
			}
		})
	}
}

func TestRetiredChildSAByteHardLifetimePrunesOnInbound(t *testing.T) {
	tests := []struct {
		name          string
		currentBytes  uint64
		hardBytes     uint64
		payloadLength int
	}{
		{name: "retired child sa rejects packet past byte hard lifetime", currentBytes: 20, hardBytes: 24, payloadLength: 10},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			session.retiredChildSAs = []retiredChildSA{{
				inbound:        esp.Codec{SPI: 0x11121314},
				protectedBytes: tt.currentBytes,
				byteExpiresAt:  tt.hardBytes,
			}}
			session.mu.Unlock()

			got := session.acceptESPSequence(0x11121314, 7, uint64(tt.payloadLength+2))

			if got.accepted {
				t.Fatal("acceptESPSequence() accepted retired packet past byte hard lifetime")
			}
			session.mu.RLock()
			retiredCount := len(session.retiredChildSAs)
			connected := session.connected
			session.mu.RUnlock()
			if retiredCount != 0 {
				t.Fatalf("retired child SA count = %d, want 0 after byte hard lifetime", retiredCount)
			}
			if !connected {
				t.Fatal("connected = false, want current child sa unaffected by retired byte expiry")
			}
		})
	}
}

func TestReplayedESPPacketDoesNotAdvanceChildSAByteLifetime(t *testing.T) {
	tests := []struct {
		name    string
		retired bool
	}{
		{name: "current child sa"},
		{name: "retired child sa", retired: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			if tt.retired {
				replay := esp.ReplayWindow{}
				if !replay.Accept(7) {
					t.Fatal("ReplayWindow.Accept(7) = false, want true")
				}
				session.retiredChildSAs = []retiredChildSA{{
					inbound:        esp.Codec{SPI: 0x11121314},
					replay:         replay,
					protectedBytes: 20,
					byteExpiresAt:  24,
				}}
			} else {
				session.inboundESP = esp.Codec{SPI: 0x01020304}
				session.childSAInboundBytes = 20
				session.childSAByteExpiresAt = 24
				if !session.inboundReplay.Accept(7) {
					t.Fatal("ReplayWindow.Accept(7) = false, want true")
				}
			}
			session.mu.Unlock()

			spi := uint32(0x01020304)
			if tt.retired {
				spi = 0x11121314
			}
			got := session.acceptESPSequence(spi, 7, 12)

			if got.accepted || got.expireCurrent {
				t.Fatalf("acceptESPSequence() = %+v, want replay rejected without expiry", got)
			}
			session.mu.RLock()
			currentBytes := session.childSAInboundBytes
			retiredCount := len(session.retiredChildSAs)
			retiredBytes := uint64(0)
			if retiredCount != 0 {
				retiredBytes = session.retiredChildSAs[0].protectedBytes
			}
			session.mu.RUnlock()
			if tt.retired {
				if retiredCount != 1 || retiredBytes != 20 {
					t.Fatalf("retired state = count %d bytes %d, want count 1 bytes 20", retiredCount, retiredBytes)
				}
				return
			}
			if currentBytes != 20 {
				t.Fatalf("childSAInboundBytes = %d, want unchanged 20", currentBytes)
			}
		})
	}
}

func TestHandleESPPacketValidatesTunnelNextHeader(t *testing.T) {
	inner := packet.InnerPacket{
		UDP: &packet.UDPSegment{
			Src:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060},
			Dst:     &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062},
			Payload: []byte("ping"),
		},
	}
	innerWire, err := inner.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	tests := []struct {
		name       string
		nextHeader byte
		payload    []byte
		wantRead   bool
	}{
		{name: "matching ipv4 inner packet is delivered", nextHeader: packet.OuterIPv4, payload: innerWire, wantRead: true},
		{name: "dummy packet is discarded", nextHeader: esp.NextHeaderNoNext},
		{name: "unsupported next header is discarded", nextHeader: packet.ProtocolTCP, payload: innerWire},
		{name: "mismatched inner ip version is discarded", nextHeader: packet.OuterIPv6, payload: innerWire},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := esp.Codec{SPI: 0x01020304, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: bytes.Repeat([]byte{0x11}, 20)}
			wire, err := codec.Encode(esp.ESPPacket{
				SPI:        codec.SPI,
				Sequence:   1,
				NextHeader: tt.nextHeader,
				Payload:    tt.payload,
			})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			session.cfg.LocalSIPPort = 5062
			session.inboundESP = codec
			oldRx := time.Now().Add(-time.Hour)
			session.lastProtectedRx = oldRx
			session.mu.Unlock()

			session.handleESPPacket(wire)

			session.mu.RLock()
			lastRx := session.lastProtectedRx
			session.mu.RUnlock()
			if !lastRx.After(oldRx) {
				t.Fatalf("lastProtectedRx = %s, want after %s for accepted protected ESP packet", lastRx, oldRx)
			}
			select {
			case inbound := <-session.readCh:
				if !tt.wantRead {
					t.Fatalf("readCh delivered %+v, want packet discarded", inbound)
				}
				if string(inbound.data) != "ping" {
					t.Fatalf("readCh payload = %q, want ping", inbound.data)
				}
			default:
				if tt.wantRead {
					t.Fatal("readCh empty, want delivered inner UDP payload")
				}
			}
		})
	}
}

func TestHandleESPPacketDropsPacketsOutsideTrafficSelectors(t *testing.T) {
	ipv4Selector := func(ip net.IP, port uint16) ike.TrafficSelector {
		selector := ike.TrafficSelectorsAny()[0]
		binary.BigEndian.PutUint16(selector.Data[0:2], port)
		binary.BigEndian.PutUint16(selector.Data[2:4], port)
		ip4 := ip.To4()
		copy(selector.Data[4:8], ip4)
		copy(selector.Data[8:12], ip4)
		return selector
	}
	innerPacket := func(src, dst net.IP) []byte {
		inner := packet.InnerPacket{
			UDP: &packet.UDPSegment{
				Src:     &net.UDPAddr{IP: src, Port: 5060},
				Dst:     &net.UDPAddr{IP: dst, Port: 5062},
				Payload: []byte("ping"),
			},
		}
		wire, err := inner.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary() error = %v", err)
		}
		return wire
	}
	tests := []struct {
		name     string
		src      net.IP
		dst      net.IP
		wantRead bool
	}{
		{name: "matching selectors is delivered", src: net.IPv4(10, 0, 0, 2), dst: net.IPv4(10, 0, 0, 1), wantRead: true},
		{name: "source outside responder selector is dropped", src: net.IPv4(10, 0, 0, 3), dst: net.IPv4(10, 0, 0, 1)},
		{name: "destination outside initiator selector is dropped", src: net.IPv4(10, 0, 0, 2), dst: net.IPv4(10, 0, 0, 4)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := esp.Codec{SPI: 0x01020304, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: bytes.Repeat([]byte{0x11}, 20)}
			wire, err := codec.Encode(esp.ESPPacket{
				SPI:        codec.SPI,
				Sequence:   1,
				NextHeader: packet.OuterIPv4,
				Payload:    innerPacket(tt.src, tt.dst),
			})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			session.cfg.LocalSIPPort = 5062
			session.inboundESP = codec
			session.tunnel = Info{
				ESPInitiatorSPI:           codec.SPI,
				InitiatorTrafficSelectors: []ike.TrafficSelector{ipv4Selector(net.IPv4(10, 0, 0, 1), 5062)},
				ResponderTrafficSelectors: []ike.TrafficSelector{ipv4Selector(net.IPv4(10, 0, 0, 2), 5060)},
			}
			session.mu.Unlock()

			session.handleESPPacket(wire)

			select {
			case inbound := <-session.readCh:
				if !tt.wantRead {
					t.Fatalf("readCh delivered %+v, want packet discarded", inbound)
				}
				if string(inbound.data) != "ping" {
					t.Fatalf("readCh payload = %q, want ping", inbound.data)
				}
			default:
				if tt.wantRead {
					t.Fatal("readCh empty, want delivered inner UDP payload")
				}
			}
		})
	}
}

func TestWriteInnerPacketRejectsPacketsOutsideTrafficSelectors(t *testing.T) {
	ipv4Selector := func(ip net.IP, port uint16) ike.TrafficSelector {
		selector := ike.TrafficSelectorsAny()[0]
		binary.BigEndian.PutUint16(selector.Data[0:2], port)
		binary.BigEndian.PutUint16(selector.Data[2:4], port)
		ip4 := ip.To4()
		copy(selector.Data[4:8], ip4)
		copy(selector.Data[8:12], ip4)
		return selector
	}
	innerPacket := func(src, dst net.IP) packet.InnerPacket {
		return packet.InnerPacket{
			UDP: &packet.UDPSegment{
				Src:     &net.UDPAddr{IP: src, Port: 5062},
				Dst:     &net.UDPAddr{IP: dst, Port: 5060},
				Payload: []byte("ping"),
			},
		}
	}
	tests := []struct {
		name      string
		src       net.IP
		dst       net.IP
		wantErr   string
		wantWrite bool
	}{
		{name: "matching selectors is written", src: net.IPv4(10, 0, 0, 1), dst: net.IPv4(10, 0, 0, 2), wantWrite: true},
		{name: "source outside initiator selector is rejected", src: net.IPv4(10, 0, 0, 3), dst: net.IPv4(10, 0, 0, 2), wantErr: "outside child sa traffic selectors"},
		{name: "destination outside responder selector is rejected", src: net.IPv4(10, 0, 0, 1), dst: net.IPv4(10, 0, 0, 4), wantErr: "outside child sa traffic selectors"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
			codec := esp.Codec{SPI: 0x10203040, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: bytes.Repeat([]byte{0x11}, 20)}
			session := mustDialSession(t, conn)
			session.mu.Lock()
			session.connected = true
			session.outerNAT = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}
			session.outboundESP = codec
			session.tunnel = Info{
				ESPResponderSPI:           codec.SPI,
				InitiatorTrafficSelectors: []ike.TrafficSelector{ipv4Selector(net.IPv4(10, 0, 0, 1), 5062)},
				ResponderTrafficSelectors: []ike.TrafficSelector{ipv4Selector(net.IPv4(10, 0, 0, 2), 5060)},
			}
			session.mu.Unlock()

			err := session.WriteInnerPacket(context.Background(), innerPacket(tt.src, tt.dst))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("WriteInnerPacket() error = %v, want %q", err, tt.wantErr)
				}
				if len(conn.writes) != 0 {
					t.Fatalf("writes = %d, want 0", len(conn.writes))
				}
				session.mu.RLock()
				seq := session.espSeq
				session.mu.RUnlock()
				if seq != 0 {
					t.Fatalf("espSeq = %d, want 0", seq)
				}
				return
			}
			if err != nil {
				t.Fatalf("WriteInnerPacket() error = %v", err)
			}
			if len(conn.writes) != 1 {
				t.Fatalf("writes = %d, want 1", len(conn.writes))
			}
			session.mu.RLock()
			seq := session.espSeq
			session.mu.RUnlock()
			if seq != 1 {
				t.Fatalf("espSeq = %d, want 1", seq)
			}
		})
	}
}

func TestActiveInboundChildSAByteHardLifetimeExpiresCurrentSA(t *testing.T) {
	tests := []struct {
		name         string
		inboundBytes uint64
		hardBytes    uint64
		packetBytes  uint64
	}{
		{name: "active inbound packet reaches byte hard lifetime", inboundBytes: 12, hardBytes: 24, packetBytes: 12},
		{name: "active inbound packet exceeds byte hard lifetime", inboundBytes: 20, hardBytes: 24, packetBytes: 12},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			session.inboundESP = esp.Codec{SPI: 0x01020304}
			session.childSAInboundBytes = tt.inboundBytes
			session.childSAByteExpiresAt = tt.hardBytes
			session.mu.Unlock()

			got := session.acceptESPSequence(0x01020304, 7, tt.packetBytes)

			if !got.expireCurrent {
				t.Fatal("acceptESPSequence() did not flag current child SA byte hard expiry")
			}
			if tt.inboundBytes+tt.packetBytes <= tt.hardBytes && !got.accepted {
				t.Fatal("acceptESPSequence() rejected packet that exactly reached byte hard lifetime")
			}
			if tt.inboundBytes+tt.packetBytes > tt.hardBytes && got.accepted {
				t.Fatal("acceptESPSequence() accepted packet past byte hard lifetime")
			}
		})
	}
}

func TestExpiredChildSAIsDiscardedBeforeUse(t *testing.T) {
	tests := []struct {
		name string
		act  func(*Session) error
	}{
		{
			name: "outbound write",
			act: func(session *Session) error {
				return session.WritePacket(context.Background(), []byte("ping"))
			},
		},
		{
			name: "inbound esp",
			act: func(session *Session) error {
				session.handleESPPacket([]byte{0x01, 0x02, 0x03, 0x04})
				if err := session.currentDisconnectedTunnelErr(); err != nil {
					return fmt.Errorf("reading packet: %w", err)
				}
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := mustDialSession(t, &fakePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}})
			session.mu.Lock()
			session.connected = true
			session.innerLocal = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5062}
			session.innerRemote = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 2), Port: 5060}
			session.outboundESP = esp.Codec{SPI: 202}
			session.inboundESP = esp.Codec{SPI: 101}
			session.ike = &ikeCrypto{}
			session.childSAExpiresAt = time.Now().Add(-time.Second)
			session.dataPlaneDone = make(chan struct{})
			session.mu.Unlock()

			err := tt.act(session)
			if !errors.Is(err, errChildSAExpired) {
				t.Fatalf("action error = %v, want %v", err, errChildSAExpired)
			}
			session.mu.RLock()
			connected := session.connected
			ikeState := session.ike
			tunnelErr := session.tunnelErr
			session.mu.RUnlock()
			if connected {
				t.Fatal("connected = true, want false")
			}
			if ikeState == nil {
				t.Fatal("ike = nil, want preserved IKE state")
			}
			if !errors.Is(tunnelErr, errChildSAExpired) {
				t.Fatalf("tunnelErr = %v, want %v", tunnelErr, errChildSAExpired)
			}
		})
	}
}
