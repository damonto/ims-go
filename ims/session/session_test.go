package session

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/damonto/ims-client/ims/sip"
)

type stubTransport struct {
	local  net.Addr
	remote net.Addr

	mu         sync.Mutex
	writes     [][]byte
	writeAddrs []net.Addr
	onWrite    func([]byte)
	readCh     chan []byte
	closed     chan struct{}
	closeCount int
}

type basicTransport struct{ stub *stubTransport }

type blockingWriteTransport struct {
	local      net.Addr
	remote     net.Addr
	entered    chan struct{}
	release    chan struct{}
	writeCount atomic.Int32
	active     atomic.Int32
	maxActive  atomic.Int32
}

type requestHandler struct {
	requests []string
	errs     []error
	handle   func(context.Context, Request) (bool, error)
}

func newStubTransport(localPort, remotePort int) *stubTransport {
	return &stubTransport{
		local:  &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh: make(chan []byte, 16),
		closed: make(chan struct{}),
	}
}

func newBlockingWriteTransport() *blockingWriteTransport {
	return &blockingWriteTransport{
		local:   &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5062},
		remote:  &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060},
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
}

func (t *stubTransport) LocalAddr() net.Addr  { return t.local }
func (t *stubTransport) RemoteAddr() net.Addr { return t.remote }

func (t *stubTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-t.closed:
		return nil, nil, errors.New("transport is closed")
	case pkt := <-t.readCh:
		return pkt, t.remote, nil
	}
}

func (t *stubTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.WritePacketTo(ctx, data, nil)
}

func (t *stubTransport) WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error {
	t.mu.Lock()
	t.writes = append(t.writes, append([]byte(nil), data...))
	t.writeAddrs = append(t.writeAddrs, cloneAddr(addr))
	onWrite := t.onWrite
	t.mu.Unlock()
	if onWrite != nil {
		onWrite(data)
	}
	return nil
}

func (t *stubTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	select {
	case <-t.closed:
	default:
		close(t.closed)
	}
	t.closeCount++
	return nil
}

func (t *stubTransport) queueRead(msg sip.Message) {
	t.readCh <- msg.Bytes()
}

func (t *blockingWriteTransport) LocalAddr() net.Addr  { return t.local }
func (t *blockingWriteTransport) RemoteAddr() net.Addr { return t.remote }

func (t *blockingWriteTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (t *blockingWriteTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.waitWrite(ctx)
}

func (t *blockingWriteTransport) waitWrite(ctx context.Context) error {
	active := t.active.Add(1)
	defer t.active.Add(-1)
	for {
		maxActive := t.maxActive.Load()
		if active <= maxActive || t.maxActive.CompareAndSwap(maxActive, active) {
			break
		}
	}
	select {
	case t.entered <- struct{}{}:
	default:
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.release:
		t.writeCount.Add(1)
		return nil
	}
}

func (t *blockingWriteTransport) Close() error { return nil }

func (t *basicTransport) LocalAddr() net.Addr  { return t.stub.LocalAddr() }
func (t *basicTransport) RemoteAddr() net.Addr { return t.stub.RemoteAddr() }
func (t *basicTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	return t.stub.ReadPacket(ctx)
}
func (t *basicTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.stub.WritePacket(ctx, data)
}
func (t *basicTransport) Close() error { return t.stub.Close() }

func (h *requestHandler) HandleRequest(ctx context.Context, req Request) (bool, error) {
	h.requests = append(h.requests, req.Message.Method())
	if h.handle != nil {
		return h.handle(ctx, req)
	}
	return false, nil
}

func (h *requestHandler) HandleError(err error) {
	h.errs = append(h.errs, err)
}

func TestExchangeBeforeRunSkipsRequestsAndProvisionalResponses(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	req := newRequest("MESSAGE", "call-1", "1 MESSAGE")
	transport.queueRead(newRequest("MESSAGE", "incoming-1", "1 MESSAGE"))
	transport.queueRead(newResponse(req, 100, "Trying"))
	transport.queueRead(newResponse(req, 200, "OK"))

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
	if len(transport.writes) != 1 {
		t.Fatalf("len(writes) = %d, want 1", len(transport.writes))
	}
}

func TestExchangeAfterRunUsesPendingCorrelation(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	req := newRequest("MESSAGE", "call-1", "1 MESSAGE")
	transport.onWrite = func(_ []byte) {
		transport.queueRead(newResponse(req, 100, "Trying"))
		transport.queueRead(newResponse(req, 200, "OK"))
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestWaitStartedReturnsWhenRunBegins(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := sess.WaitStarted(ctx); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}
	if !sess.isRunning() {
		t.Fatal("isRunning() = false, want true")
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestExchangeAfterRunExitFallsBackToSynchronousTransport(t *testing.T) {
	transport := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}
	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}

	req := newRequest("MESSAGE", "call-2", "1 MESSAGE")
	transport.onWrite = func(_ []byte) {
		transport.queueRead(newResponse(req, 200, "OK"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	resp, err := sess.Exchange(ctx, req)
	if err != nil {
		t.Fatalf("Exchange() error = %v", err)
	}
	if resp.StatusCode() != 200 {
		t.Fatalf("StatusCode() = %d, want 200", resp.StatusCode())
	}
}

func TestRunFansInMultipleTransports(t *testing.T) {
	primary := newStubTransport(5062, 5060)
	aux := newStubTransport(15062, 15060)
	sess, err := Open(Config{}, primary)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := sess.AddTransport(aux); err != nil {
		t.Fatalf("AddTransport() error = %v", err)
	}

	handledCh := make(chan string, 1)
	handler := &requestHandler{
		handle: func(ctx context.Context, req Request) (bool, error) {
			handledCh <- req.Transport.LocalAddr().String()
			return true, nil
		},
	}
	if _, err := sess.Attach(handler); err != nil {
		t.Fatalf("Attach() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()

	aux.queueRead(newInboundRequest("NOTIFY", "fan-in", "1 NOTIFY"))
	select {
	case got := <-handledCh:
		if got != aux.LocalAddr().String() {
			t.Fatalf("handled transport = %q, want %q", got, aux.LocalAddr().String())
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for handled request")
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
}

func TestSessionSerializesWrites(t *testing.T) {
	transport := newBlockingWriteTransport()
	sess, err := Open(Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	req := newRequest("MESSAGE", "call-1", "1 MESSAGE")
	inbound := Request{Message: newInboundRequest("NOTIFY", "call-2", "1 NOTIFY"), Transport: transport}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	sendErrCh := make(chan error, 1)
	go func() {
		sendErrCh <- sess.Send(ctx, req)
	}()

	select {
	case <-transport.entered:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("first write did not reach transport")
	}

	respErrCh := make(chan error, 1)
	go func() {
		respErrCh <- sess.WriteStatus(ctx, inbound, 200, "OK")
	}()

	select {
	case <-transport.entered:
		t.Fatal("second write entered transport before first completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(transport.release)
	if err := <-sendErrCh; err != nil {
		t.Fatalf("Send() error = %v", err)
	}
	if err := <-respErrCh; err != nil {
		t.Fatalf("WriteStatus() error = %v", err)
	}
	if got := transport.writeCount.Load(); got != 2 {
		t.Fatalf("write count = %d, want 2", got)
	}
	if got := transport.maxActive.Load(); got != 1 {
		t.Fatalf("max concurrent writes = %d, want 1", got)
	}
}

func TestWriteResponseTargetsUDPSourceAndFallsBack(t *testing.T) {
	tests := []struct {
		name      string
		transport Transport
		wantAddr  bool
	}{
		{name: "targeted writer", transport: newStubTransport(5062, 5060), wantAddr: true},
		{name: "fallback writer", transport: &basicTransport{stub: newStubTransport(5062, 5060)}, wantAddr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sess, err := Open(Config{}, tt.transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			req := Request{Message: newInboundRequest("MESSAGE", "call-1", "1 MESSAGE"), Transport: tt.transport}
			if err := sess.WriteStatus(context.Background(), req, 200, "OK"); err != nil {
				t.Fatalf("WriteStatus() error = %v", err)
			}

			stub := extractStubTransport(tt.transport)
			if len(stub.writeAddrs) != 1 {
				t.Fatalf("len(writeAddrs) = %d, want 1", len(stub.writeAddrs))
			}
			if got := stub.writeAddrs[0] != nil; got != tt.wantAddr {
				t.Fatalf("writeAddrs[0] set = %v, want %v", got, tt.wantAddr)
			}
		})
	}
}

func TestAttachmentOrderAndUnhandledBehavior(t *testing.T) {
	tests := []struct {
		name       string
		msg        sip.Message
		wantWrites int
		wantStatus int
	}{
		{name: "ack ignored", msg: newInboundRequest("ACK", "ack-1", "1 ACK"), wantWrites: 0},
		{name: "unhandled request gets 405", msg: newInboundRequest("OPTIONS", "options-1", "1 OPTIONS"), wantWrites: 1, wantStatus: 405},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newStubTransport(15062, 15060)
			sess, err := Open(Config{}, newStubTransport(5062, 5060))
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}

			first := &requestHandler{}
			second := &requestHandler{
				handle: func(ctx context.Context, req Request) (bool, error) {
					return req.Message.Method() == "NOTIFY", nil
				},
			}
			if _, err := sess.Attach(first); err != nil {
				t.Fatalf("Attach(first) error = %v", err)
			}
			if _, err := sess.Attach(second); err != nil {
				t.Fatalf("Attach(second) error = %v", err)
			}

			err = sess.handleRequest(context.Background(), Request{Message: tt.msg, Transport: transport})
			if err != nil {
				t.Fatalf("handleRequest() error = %v", err)
			}
			if got := len(first.requests); got != 1 {
				t.Fatalf("len(first.requests) = %d, want 1", got)
			}
			if got := len(second.requests); got != 1 {
				t.Fatalf("len(second.requests) = %d, want 1", got)
			}
			stub := extractStubTransport(transport)
			if got := len(stub.writes); got != tt.wantWrites {
				t.Fatalf("len(writes) = %d, want %d", got, tt.wantWrites)
			}
			if tt.wantWrites == 1 {
				resp, err := sip.ParseMessage(stub.writes[0])
				if err != nil {
					t.Fatalf("ParseMessage(response) error = %v", err)
				}
				if got := resp.StatusCode(); got != tt.wantStatus {
					t.Fatalf("StatusCode() = %d, want %d", got, tt.wantStatus)
				}
			}
		})
	}
}

func TestAddTransportAndReplacePrimaryRequirePreRun(t *testing.T) {
	primary := newStubTransport(5062, 5060)
	sess, err := Open(Config{}, primary)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- sess.Run(runCtx)
	}()
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	if _, err := sess.AddTransport(newStubTransport(15062, 15060)); err == nil {
		t.Fatal("AddTransport() error = nil, want non-nil")
	}
	if err := sess.ReplacePrimary(newStubTransport(25062, 25060)); err == nil {
		t.Fatal("ReplacePrimary() error = nil, want non-nil")
	}

	runCancel()
	if err := <-errCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v, want context.Canceled", err)
	}
	if _, err := sess.AddTransport(newStubTransport(35062, 35060)); err == nil {
		t.Fatal("AddTransport() after Run() error = nil, want non-nil")
	}
	if err := sess.ReplacePrimary(newStubTransport(45062, 45060)); err == nil {
		t.Fatal("ReplacePrimary() after Run() error = nil, want non-nil")
	}
}

func TestCloseContextClosesTransportsAndFansOutErrorOnce(t *testing.T) {
	primary := newStubTransport(5062, 5060)
	aux := newStubTransport(15062, 15060)
	sess, err := Open(Config{}, primary)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := sess.AddTransport(aux); err != nil {
		t.Fatalf("AddTransport() error = %v", err)
	}

	first := &requestHandler{}
	second := &requestHandler{}
	if _, err := sess.Attach(first); err != nil {
		t.Fatalf("Attach(first) error = %v", err)
	}
	if _, err := sess.Attach(second); err != nil {
		t.Fatalf("Attach(second) error = %v", err)
	}

	if err := sess.CloseContext(context.Background()); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
	}
	if primary.closeCount != 1 {
		t.Fatalf("primary closeCount = %d, want 1", primary.closeCount)
	}
	if aux.closeCount != 1 {
		t.Fatalf("aux closeCount = %d, want 1", aux.closeCount)
	}
	if len(first.errs) != 1 || len(second.errs) != 1 {
		t.Fatalf("fanout counts = %d, %d; want 1, 1", len(first.errs), len(second.errs))
	}
}

func newRequest(method, callID, cseq string) sip.Message {
	msg := sip.NewRequest(method, "sip:test@example.com")
	msg.Headers = sip.Headers{
		{Name: "Via", Value: "SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-1"},
		{Name: "From", Value: "<sip:alice@example.com>;tag=local"},
		{Name: "To", Value: "<sip:bob@example.com>"},
		{Name: "Call-ID", Value: callID},
		{Name: "CSeq", Value: cseq},
		{Name: "Content-Length", Value: "0"},
	}
	return msg
}

func newInboundRequest(method, callID, cseq string) sip.Message {
	return newRequest(method, callID, cseq)
}

func newResponse(req sip.Message, code int, reason string) sip.Message {
	resp := sip.NewResponse(code, reason)
	resp.Headers = sip.ResponseHeaders(req, code)
	return resp
}

func cloneAddr(addr net.Addr) net.Addr {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return &net.UDPAddr{IP: append(net.IP(nil), v.IP...), Port: v.Port, Zone: v.Zone}
	case *net.TCPAddr:
		return &net.TCPAddr{IP: append(net.IP(nil), v.IP...), Port: v.Port, Zone: v.Zone}
	default:
		return addr
	}
}

func extractStubTransport(t Transport) *stubTransport {
	switch v := t.(type) {
	case *stubTransport:
		return v
	case *basicTransport:
		return v.stub
	default:
		return nil
	}
}

func waitForCondition(t *testing.T, timeout time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("waiting for condition")
}
