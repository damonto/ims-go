package tunnel

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/packet"
	"github.com/damonto/vowifi-go/usim"
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
		InnerIP:         net.IPv4(10, 0, 0, 1),
		PCSCFIP:         net.IPv4(10, 0, 0, 2),
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

	if session.closeCtx.Err() != nil {
		t.Fatalf("closeCtx.Err() = %v, want nil", session.closeCtx.Err())
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
	if len(info.InnerIP) != 0 || len(info.PCSCFIP) != 0 || info.ESPInitiatorSPI != 0 || info.ESPResponderSPI != 0 || info.Encryption != 0 || info.EncryptionKeyLen != 0 || info.Integrity != 0 {
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
