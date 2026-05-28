package vowifi

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/vowifi-go/ims/registration"
	imssession "github.com/damonto/vowifi-go/ims/session"
	imssip "github.com/damonto/vowifi-go/ims/sip"
	imssms "github.com/damonto/vowifi-go/ims/sms"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
	"github.com/damonto/vowifi-go/usim"
	usimreader "github.com/damonto/vowifi-go/usim/reader"
)

type stubCard struct{}

func (stubCard) ICCID() string { return "8986000000000000000" }
func (stubCard) IMSI() string  { return "001010123456789" }
func (stubCard) MCC() string   { return "001" }
func (stubCard) MNC() string   { return "001" }
func (stubCard) SMSC() string  { return "+8613800000000" }
func (stubCard) AKA(_ context.Context, _, _ []byte) (usim.AKAResult, error) {
	return usim.AKAResult{RES: []byte("12345678")}, nil
}

type readerStub struct {
	closeCalls        int
	closeErr          error
	listApplications  func(context.Context) ([]usimreader.Application, error)
	getFileAttributes func(context.Context, usimreader.FileRef) (usimreader.FileAttributes, error)
	readTransparent   func(context.Context, usimreader.TransparentRead) ([]byte, error)
	readRecord        func(context.Context, usimreader.RecordRead) ([]byte, error)
	authenticate3G    func(context.Context, usimreader.AuthenticateRequest) ([]byte, error)
	smsPPDownload     func(context.Context, usimreader.SMSPPDownloadRequest) (usimreader.SMSPPDownloadResponse, error)
}

func (r *readerStub) ListApplications(ctx context.Context) ([]usimreader.Application, error) {
	if r.listApplications == nil {
		return nil, errors.New("ListApplications was not expected")
	}
	return r.listApplications(ctx)
}

func (r *readerStub) GetFileAttributes(ctx context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
	if r.getFileAttributes == nil {
		return usimreader.FileAttributes{}, errors.New("GetFileAttributes was not expected")
	}
	return r.getFileAttributes(ctx, file)
}

func (r *readerStub) ReadTransparent(ctx context.Context, req usimreader.TransparentRead) ([]byte, error) {
	if r.readTransparent == nil {
		return nil, errors.New("ReadTransparent was not expected")
	}
	return r.readTransparent(ctx, req)
}

func (r *readerStub) ReadRecord(ctx context.Context, req usimreader.RecordRead) ([]byte, error) {
	if r.readRecord == nil {
		return nil, errors.New("ReadRecord was not expected")
	}
	return r.readRecord(ctx, req)
}

func (r *readerStub) Authenticate3G(ctx context.Context, req usimreader.AuthenticateRequest) ([]byte, error) {
	if r.authenticate3G == nil {
		return nil, errors.New("Authenticate3G was not expected")
	}
	return r.authenticate3G(ctx, req)
}

func (r *readerStub) SMSPPDownload(ctx context.Context, req usimreader.SMSPPDownloadRequest) (usimreader.SMSPPDownloadResponse, error) {
	if r.smsPPDownload == nil {
		return usimreader.SMSPPDownloadResponse{}, errors.New("SMSPPDownload was not expected")
	}
	return r.smsPPDownload(ctx, req)
}

func (r *readerStub) Close() error {
	r.closeCalls++
	return r.closeErr
}

type gatedCancelTransport struct {
	local  net.Addr
	remote net.Addr

	mu                sync.Mutex
	writes            [][]byte
	onWrite           func([]byte)
	readCh            chan []byte
	cancelReadRelease chan struct{}
	closed            bool
}

func newGatedCancelTransport(localPort, remotePort int) *gatedCancelTransport {
	return &gatedCancelTransport{
		local:             &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: localPort},
		remote:            &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: remotePort},
		readCh:            make(chan []byte, 16),
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
	case <-ctx.Done():
		<-t.cancelReadRelease
		return nil, nil, ctx.Err()
	}
}

func (t *gatedCancelTransport) Close() error {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
	select {
	case <-t.cancelReadRelease:
	default:
		close(t.cancelReadRelease)
	}
	return nil
}

func (t *gatedCancelTransport) queueRead(msg imssip.Message) {
	t.readCh <- msg.Bytes()
}

func (t *gatedCancelTransport) writeCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.writes)
}

const (
	testIMEI              = "356789012345678"
	fakeIMSSecurityServer = "ipsec-3gpp;alg=hmac-sha-1-96;ealg=null;mod=trans;port-c=5062;port-s=5060;prot=esp;spi-c=10;spi-s=20"
)

func newStandaloneClient(t *testing.T) *Client {
	t.Helper()
	return newReadyClient(t, Config{
		IMEI: testIMEI,
		IMS: IMSConfig{
			RegisterExpires: time.Minute,
		},
	})
}

func newReadyClient(t *testing.T, cfg Config) *Client {
	t.Helper()
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
	client.logger = normalized.Logger.With("component", "vowifi-go")
	return client
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

func TestSMSEventsFanOutAndSubscribeError(t *testing.T) {
	client := newStandaloneClient(t)
	clientEvents := client.Events()
	defer clientEvents.Close()

	smsEventsA := client.SMS().Events()
	defer smsEventsA.Close()
	smsEventsB := client.SMS().Events()
	defer smsEventsB.Close()

	stop := client.SMS().Subscribe(func(msg SMS) error {
		if msg.Text != "hello" {
			t.Fatalf("msg.Text = %q, want hello", msg.Text)
		}
		return errors.New("boom")
	})
	defer stop()

	client.handleSMS(imssms.Incoming{CallID: "sms-call-id", From: "+1", To: "+2", ServiceCenter: "+3", Text: "hello"})

	for i, events := range []*SMSEvents{smsEventsA, smsEventsB} {
		select {
		case msg := <-events.Incoming:
			if msg.Text != "hello" {
				t.Fatalf("subscriber %d msg = %+v", i, msg)
			}
			if msg.CallID != "sms-call-id" {
				t.Fatalf("subscriber %d msg.CallID = %q, want sms-call-id", i, msg.CallID)
			}
		case <-time.After(time.Second):
			t.Fatalf("waiting for sms subscriber %d", i)
		}
	}

	select {
	case err := <-clientEvents.Errors:
		if !strings.Contains(err.Error(), "sms subscriber") {
			t.Fatalf("client error = %v, want sms subscriber callback error", err)
		}
	case <-time.After(time.Second):
		t.Fatal("waiting for callback error")
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

	report := imssms.StatusReport{
		ServiceCenter:    "+15550000000",
		Recipient:        "+15551234567",
		MessageReference: 7,
		Status:           0x00,
	}
	client.handleSMSStatusReport(report)

	select {
	case event := <-events.Reports:
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
	case <-time.After(time.Second):
		t.Fatal("waiting for SMS status report event")
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
		listApplications: func(context.Context) ([]usimreader.Application, error) {
			return nil, errors.New("boom")
		},
	}

	client, err := New(reader, &Config{IMEI: testIMEI})
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
				listApplications: func(ctx context.Context) ([]usimreader.Application, error) {
					return nil, ctx.Err()
				},
			}
			client, err := New(reader, &Config{IMEI: testIMEI})
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
		listApplications: func(ctx context.Context) ([]usimreader.Application, error) {
			close(started)
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}
	client, err := New(reader, &Config{IMEI: testIMEI})
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

	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := client.CloseContext(closeCtx); err != nil {
		t.Fatalf("CloseContext() error = %v", err)
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
		listApplications: func(context.Context) ([]usimreader.Application, error) {
			return nil, errors.New("load boom")
		},
	}

	client, err := New(reader, &Config{IMEI: testIMEI})
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

func TestAbortConnectStartWaitsForIMSLoopExitBeforeDeregister(t *testing.T) {
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
	reg, err := registration.New(registration.Config{}, sess, stubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	if err := reg.Register(context.Background()); err != nil {
		t.Fatalf("Register() error = %v", err)
	}

	client := newReadyClient(t, Config{
		IMEI: testIMEI,
		IMS: IMSConfig{
			RegisterExpires: time.Minute,
		},
	})
	defer client.Close()

	runCtx, cancelRun := context.WithCancel(context.Background())
	active := &activeConn{
		runCtx:     runCtx,
		cancel:     cancelRun,
		imsSession: sess,
		reg:        reg,
	}

	client.mu.Lock()
	client.active = active
	client.mu.Unlock()

	done, ok := client.reserveCloseTask()
	if !ok {
		t.Fatal("reserveCloseTask() = false, want true")
	}
	runDone := client.startIMSRunner(active, done)
	if err := sess.WaitStarted(context.Background()); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}

	cleanupDone := make(chan struct{})
	go func() {
		client.abortConnectStart(active, runDone)
		close(cleanupDone)
	}()

	close(transport.cancelReadRelease)

	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("abortConnectStart() did not finish after IMS loop exit")
	}
	if got := transport.writeCount(); got != 4 {
		t.Fatalf("write count after cleanup = %d, want 4", got)
	}
	if reg.State().Registered {
		t.Fatal("Registered = true, want false")
	}
}

func newReaderStubForUSIMLoad() *readerStub {
	const (
		fileStructureTransparent byte = 0x01
		fileStructureLinearFixed byte = 0x02
	)

	usimAID := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x02}

	return &readerStub{
		listApplications: func(context.Context) ([]usimreader.Application, error) {
			return []usimreader.Application{{
				AID:   append([]byte(nil), usimAID...),
				Label: "USIM",
			}}, nil
		},
		getFileAttributes: func(_ context.Context, file usimreader.FileRef) (usimreader.FileAttributes, error) {
			switch {
			case len(file.AID) == 0 && slices.Equal(file.Path, []byte{0x2F, 0xE2}):
				return usimreader.FileAttributes{FileStructure: fileStructureTransparent, FileSize: 10}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0x07}):
				return usimreader.FileAttributes{FileStructure: fileStructureTransparent, FileSize: 9}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0xAD}):
				return usimreader.FileAttributes{FileStructure: fileStructureTransparent, FileSize: 4}, nil
			case slices.Equal(file.AID, usimAID) && slices.Equal(file.Path, []byte{0x6F, 0x42}):
				return usimreader.FileAttributes{FileStructure: fileStructureLinearFixed, RecordSize: 32, RecordCount: 0}, nil
			default:
				return usimreader.FileAttributes{}, errors.New("file not found")
			}
		},
		readTransparent: func(_ context.Context, req usimreader.TransparentRead) ([]byte, error) {
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
