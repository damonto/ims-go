package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ElMostafaIdrassi/goscard"

	"github.com/damonto/ims-client"
	"github.com/damonto/ims-client/driver/at"
	"github.com/damonto/ims-client/driver/ccid"
	"github.com/damonto/ims-client/driver/mbim"
	"github.com/damonto/ims-client/driver/qmi"
	imssession "github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/swu/tunnel"
	"github.com/damonto/ims-client/usim"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

const (
	defaultAPDUTimeout    = 30 * time.Second
	maxTCPAPDUFrameLength = 64 * 1024
	wfcUserActionPoll     = 10 * time.Second
)

type options struct {
	debug          bool
	driverKind     string
	listReaders    bool
	readerName     string
	device         string
	ccidTCPListen  string
	apduTimeout    time.Duration
	slot           int
	imei           string
	epdgAddr       string
	transport      string
	expires        time.Duration
	privateID      string
	publicID       string
	homeDomain     string
	phoneContext   string
	userAgent      string
	pani           string
	wlanNodeID     string
	terminalVendor string
	terminalModel  string
	terminalSW     string
	sipPort        int
	sipT1          time.Duration
	sipT2          time.Duration
	sipT4          time.Duration
	sipTimerB      time.Duration
	sipTimerD      time.Duration
	sipTimerF      time.Duration
	sipTimerH      time.Duration
	sipTimerJ      time.Duration
	smsTR1         time.Duration
	nattKeepalive  time.Duration
	ikeRetransmit  string
	sendTo         string
	sendText       string
	ussdCode       string
}

func main() {
	opt := parseFlags()
	level := new(slog.LevelVar)
	level.Set(slog.LevelInfo)
	if opt.debug {
		level.Set(slog.LevelDebug)
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(logger)

	if err := run(opt); err != nil {
		logger.Error("running example", "err", err)
		os.Exit(1)
	}
}

func parseFlags() options {
	opt := options{}
	flag.BoolVar(&opt.debug, "debug", false, "enable verbose debug logs")
	flag.StringVar(&opt.driverKind, "driver", "pcsc", "driver kind: pcsc, ccid-tcp, at, qmi, qrtr, or mbim")
	flag.BoolVar(&opt.listReaders, "list-readers", false, "list available PC/SC readers and exit")
	flag.StringVar(&opt.readerName, "reader", "", "PC/SC reader name; required for -driver pcsc")
	flag.StringVar(&opt.device, "device", "", "AT+CSIM serial device, QMI/MBIM modem path, or ccid-tcp host:port")
	flag.StringVar(&opt.ccidTCPListen, "ccid-tcp-listen", "", "listen address for temporary CCID TCP APDU server, for example :9999")
	flag.DurationVar(&opt.apduTimeout, "apdu-timeout", defaultAPDUTimeout, "APDU TCP read/write timeout for -driver ccid-tcp")
	flag.IntVar(&opt.slot, "slot", 1, "physical SIM slot for -driver qmi or -driver mbim")
	flag.StringVar(&opt.imei, "imei", "", "UE IMEI used for SWu authentication")
	flag.StringVar(&opt.epdgAddr, "epdg", "", "optional ePDG host:port or host; default uses MCC/MNC from the card")
	flag.StringVar(&opt.transport, "transport", "", "IMS SIP transport override: tcp or udp")
	flag.DurationVar(&opt.expires, "register-expires", 0, "IMS registration expiration override, for example 1800s")
	flag.StringVar(&opt.privateID, "private-identity", "", "IMS private user identity override")
	flag.StringVar(&opt.publicID, "public-identity", "", "IMS public user identity override")
	flag.StringVar(&opt.homeDomain, "home-domain", "", "IMS home domain override")
	flag.StringVar(&opt.phoneContext, "phone-context", "", "phone-context domain override, maps ims.phone_context_domain_name_string")
	flag.StringVar(&opt.userAgent, "user-agent", "", "IMS User-Agent override")
	flag.StringVar(&opt.pani, "pani", "", "P-Access-Network-Info override")
	flag.StringVar(&opt.wlanNodeID, "wlan-node-id", "", "WLAN AP MAC for i-wlan-node-id")
	flag.StringVar(&opt.terminalVendor, "terminal-vendor", "", "TS.43 terminal_vendor for Wi-Fi Calling entitlement")
	flag.StringVar(&opt.terminalModel, "terminal-model", "", "TS.43 terminal_model for Wi-Fi Calling entitlement")
	flag.StringVar(&opt.terminalSW, "terminal-sw-version", "", "TS.43 terminal_sw_version for Wi-Fi Calling entitlement")
	flag.IntVar(&opt.sipPort, "sip-port", 0, "IMS SIP server port override, maps ims.sip_server_port_number_int")
	flag.DurationVar(&opt.sipT1, "sip-timer-t1", 0, "SIP timer T1 override, for example 500ms or 2s")
	flag.DurationVar(&opt.sipT2, "sip-timer-t2", 0, "SIP timer T2 override")
	flag.DurationVar(&opt.sipT4, "sip-timer-t4", 0, "SIP timer T4 override")
	flag.DurationVar(&opt.sipTimerB, "sip-timer-b", 0, "SIP timer B override")
	flag.DurationVar(&opt.sipTimerD, "sip-timer-d", 0, "SIP timer D override")
	flag.DurationVar(&opt.sipTimerF, "sip-timer-f", 0, "SIP timer F override")
	flag.DurationVar(&opt.sipTimerH, "sip-timer-h", 0, "SIP timer H override")
	flag.DurationVar(&opt.sipTimerJ, "sip-timer-j", 0, "SIP timer J override")
	flag.DurationVar(&opt.smsTR1, "sms-tr1", 0, "SMS submit report TR1 timeout override")
	flag.DurationVar(&opt.nattKeepalive, "natt-keepalive", 0, "IWLAN NAT-T keepalive override, maps iwlan.natt_keep_alive_timer_sec_int")
	flag.StringVar(&opt.ikeRetransmit, "ike-retransmit", "", "comma-separated IKE retransmit delays, for example 1s,2s,4s")
	flag.StringVar(&opt.sendTo, "send-to", "", "destination MSISDN for one test SMS")
	flag.StringVar(&opt.sendText, "send-text", "", "text body for one test SMS")
	flag.StringVar(&opt.ussdCode, "ussd", "", "USSD code to dial, for example *100#")
	flag.Parse()
	return opt
}

func sipTimersFromOptions(opt options) imssession.TransactionTimers {
	return imssession.TransactionTimers{
		T1: opt.sipT1,
		T2: opt.sipT2,
		T4: opt.sipT4,
		TB: opt.sipTimerB,
		TD: opt.sipTimerD,
		TF: opt.sipTimerF,
		TH: opt.sipTimerH,
		TJ: opt.sipTimerJ,
	}
}

func parseDurationList(value string) ([]time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	delays := make([]time.Duration, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, errors.New("parsing IKE retransmit delays: empty entry")
		}
		delay, err := time.ParseDuration(part)
		if err != nil {
			return nil, fmt.Errorf("parsing IKE retransmit delay %q: %w", part, err)
		}
		delays = append(delays, delay)
	}
	return delays, nil
}

func run(opt options) error {
	if opt.listReaders {
		if !strings.EqualFold(strings.TrimSpace(opt.driverKind), "pcsc") {
			return errors.New("listing readers: -list-readers requires -driver pcsc")
		}
		return listCCIDReaders()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if opt.ccidTCPListen != "" {
		return serveTCPAPDUServer(ctx, opt)
	}

	if opt.imei == "" {
		return errors.New("running example: -imei is required")
	}
	if (opt.sendTo == "") != (opt.sendText == "") {
		return errors.New("running example: -send-to and -send-text must be provided together")
	}
	if opt.sendTo != "" && opt.ussdCode != "" {
		return errors.New("running example: choose either SMS flags or -ussd")
	}
	ikeRetransmit, err := parseDurationList(opt.ikeRetransmit)
	if err != nil {
		return err
	}

	reader, err := openDriver(ctx, opt)
	if err != nil {
		return err
	}

	cfg := &imsclient.Config{
		IMEI:   opt.imei,
		EPDG:   opt.epdgAddr,
		Logger: slog.Default(),
		Tunnel: tunnel.Config{
			SIPPort:              opt.sipPort,
			NATKeepaliveInterval: opt.nattKeepalive,
			IKERetransmitDelays:  ikeRetransmit,
		},
		IMS: imsclient.IMSConfig{
			Transport:              opt.transport,
			PrivateIdentity:        opt.privateID,
			PublicIdentity:         opt.publicID,
			HomeDomain:             opt.homeDomain,
			PhoneContextDomain:     opt.phoneContext,
			UserAgent:              opt.userAgent,
			AccessNetworkInfo:      opt.pani,
			WLANNodeID:             opt.wlanNodeID,
			RegisterExpires:        opt.expires,
			SIPServerPort:          opt.sipPort,
			SIPTimers:              sipTimersFromOptions(opt),
			SMSSubmitReportTimeout: opt.smsTR1,
		},
		WFCEntitlement: imsclient.WFCEntitlementConfig{
			TerminalVendor:   opt.terminalVendor,
			TerminalModel:    opt.terminalModel,
			TerminalSoftware: opt.terminalSW,
		},
	}

	client, err := imsclient.New(reader, cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err := client.Close(); err != nil {
			slog.Warn("close client", "err", err)
		}
	}()

	clientEvents := client.Events()
	defer clientEvents.Close()
	go logClientEvents(clientEvents)

	smsEvents := client.SMS().Events()
	defer smsEvents.Close()
	go logSMSEvents(smsEvents)

	if err := connectWithWFCUserActionPolling(ctx, client.Connect, wfcUserActionPoll); err != nil {
		return fmt.Errorf("connecting client: %w", err)
	}
	slog.Info("registered to IMS")
	if tunnel := client.Tunnel(); len(tunnel.PCSCFIP) > 0 {
		slog.Info("tunnel ready", "inner_ip", tunnel.InnerIP.String(), "pcscf_ip", tunnel.PCSCFIP.String())
	}

	if opt.sendTo != "" {
		sendCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		submission, err := client.SMS().Send(sendCtx, opt.sendTo, opt.sendText)
		if err != nil {
			return fmt.Errorf("sending SMS: %w", err)
		}
		slog.Info("submitted SMS", "id", submission.ID, "to", submission.To, "segments", submission.SegmentCount)
	}
	if opt.ussdCode != "" {
		if err := runUSSD(ctx, client, opt.ussdCode); err != nil {
			return err
		}
		return nil
	}

	<-ctx.Done()
	return nil
}

func connectWithWFCUserActionPolling(ctx context.Context, connect func(context.Context) error, interval time.Duration) error {
	if interval <= 0 {
		interval = wfcUserActionPoll
	}

	var lastAction wfcUserAction
	var logged bool
	for {
		err := connect(ctx)
		if err == nil {
			return nil
		}

		action, ok := wfcUserActionFromError(err)
		if !ok {
			return err
		}
		if !logged || action != lastAction {
			logWFCUserAction(action)
			lastAction = action
			logged = true
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("waiting for wfc user action: %w", ctx.Err())
		case <-timer.C:
			slog.Info("polling wfc entitlement after user action", "interval", interval)
		}
	}
}

type wfcUserAction struct {
	Source     string
	Carrier    string
	URL        string
	Data       string
	Title      string
	ClientName string
}

func logWFCUserAction(action wfcUserAction) {
	slog.Error(
		"wfc entitlement requires user action",
		"source", action.Source,
		"carrier", action.Carrier,
		"url", action.URL,
		"data", action.Data,
		"open_url", wfcUserActionURL(action.URL, action.Data),
		"title", action.Title,
		"client", action.ClientName,
		"next", "complete the web flow; this process will keep polling",
	)
}

func wfcUserActionURL(rawURL, rawData string) string {
	rawURL = strings.TrimSpace(rawURL)
	rawData = strings.TrimSpace(rawData)
	if rawURL == "" || rawData == "" {
		return rawURL
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return appendRawQuery(rawURL, rawData)
	}
	data := strings.TrimLeft(rawData, "?&")
	values, err := url.ParseQuery(data)
	if err != nil {
		return appendRawQuery(rawURL, data)
	}
	query := parsed.Query()
	for key, items := range values {
		for _, item := range items {
			query.Add(key, item)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func appendRawQuery(rawURL, data string) string {
	separator := "?"
	if strings.Contains(rawURL, "?") {
		separator = "&"
	}
	return rawURL + separator + data
}

func wfcUserActionFromError(err error) (wfcUserAction, bool) {
	if !errors.Is(err, imsclient.ErrWFCEntitlementUserActionRequired) {
		return wfcUserAction{}, false
	}

	var nsdsErr *imsclient.NSDSWFCEntitlementError
	if errors.As(err, &nsdsErr) {
		return wfcUserAction{
			Source:     "nsds",
			Carrier:    nsdsErr.Carrier,
			URL:        nsdsErr.Websheet.URL,
			Data:       nsdsErr.Websheet.Data,
			Title:      nsdsErr.Websheet.Title,
			ClientName: nsdsErr.Websheet.ClientName,
		}, true
	}

	var ts43Err *imsclient.WFCEntitlementError
	if errors.As(err, &ts43Err) {
		return wfcUserAction{
			Source:  "ts43",
			Carrier: ts43Err.Config.CarrierName,
			URL:     ts43Err.Status.ServiceFlowURL,
			Data:    ts43Err.Status.ServiceFlowUserData,
			Title:   "Wi-Fi Calling",
		}, true
	}

	return wfcUserAction{Source: "unknown"}, true
}

func runUSSD(ctx context.Context, client *imsclient.Client, code string) error {
	session, err := client.USSD().Start()
	if err != nil {
		return fmt.Errorf("starting USSD: %w", err)
	}

	sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	result, err := session.Send(sendCtx, code)
	cancel()
	if err != nil {
		return fmt.Errorf("sending USSD: %w", err)
	}
	slog.Info("started USSD", "code", code)

	reader := bufio.NewReader(os.Stdin)
	for {
		logUSSDResult(result)
		if result.Closed {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		fmt.Fprint(os.Stdout, "ussd> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading USSD input: %w", err)
		}
		line = strings.TrimSpace(line)

		if line == "" || line == "/bye" || line == "/end" || line == "/quit" {
			closeCtx, closeCancel := context.WithTimeout(ctx, 15*time.Second)
			result, err = session.Close(closeCtx)
			closeCancel()
			if err != nil {
				return fmt.Errorf("closing USSD: %w", err)
			}
			continue
		}

		replyCtx, replyCancel := context.WithTimeout(ctx, 30*time.Second)
		result, err = session.Reply(replyCtx, line)
		replyCancel()
		if err != nil {
			return fmt.Errorf("replying USSD: %w", err)
		}
	}
}

func listCCIDReaders() error {
	readers, err := availableCCIDReaders()
	if err != nil {
		return err
	}
	if len(readers) == 0 {
		return errors.New("listing pcsc readers: no readers found")
	}
	for _, reader := range readers {
		if _, err := fmt.Fprintln(os.Stdout, reader); err != nil {
			return fmt.Errorf("printing reader %q: %w", reader, err)
		}
	}
	return nil
}

func availableCCIDReaders() ([]string, error) {
	readers, err := ccid.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("listing pcsc readers: %w", err)
	}
	return readers, nil
}

func openDriver(ctx context.Context, opt options) (usimreader.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(opt.driverKind)) {
	case "pcsc":
		if opt.readerName == "" {
			readers, err := ccid.ListReaders()
			if err != nil {
				return nil, fmt.Errorf("listing pcsc readers: %w", err)
			}
			if len(readers) == 0 {
				return nil, errors.New("opening pcsc driver: no readers found")
			}
			return nil, fmt.Errorf("opening pcsc driver: -reader is required; available readers: %s", strings.Join(readers, ", "))
		}
		drv, err := ccid.Open(opt.readerName)
		if err != nil {
			return nil, fmt.Errorf("opening pcsc driver: %w", err)
		}
		return drv, nil
	case "at", "at+csim", "serial":
		if opt.device == "" {
			return nil, errors.New("opening AT driver: -device is required")
		}
		drv, err := at.New(opt.device, 0)
		if err != nil {
			return nil, fmt.Errorf("opening AT driver: %w", err)
		}
		return drv, nil
	case "ccid-tcp", "tcp-ccid":
		if opt.device == "" {
			return nil, errors.New("opening CCID TCP driver: -device host:port is required")
		}
		drv, err := openTCPAPDUReader(ctx, opt.device, opt.apduTimeout)
		if err != nil {
			return nil, fmt.Errorf("opening CCID TCP driver: %w", err)
		}
		return drv, nil
	case "qmi":
		if opt.device == "" {
			return nil, errors.New("opening QMI driver: -device is required")
		}
		drv, err := qmi.Open(ctx, opt.device, opt.slot)
		if err != nil {
			return nil, fmt.Errorf("opening QMI driver: %w", err)
		}
		return drv, nil
	case "qrtr":
		drv, err := qmi.OpenQRTR(ctx, opt.slot)
		if err != nil {
			return nil, fmt.Errorf("opening QRTR driver: %w", err)
		}
		return drv, nil
	case "mbim":
		if opt.device == "" {
			return nil, errors.New("opening MBIM driver: -device is required")
		}
		drv, err := mbim.Open(ctx, opt.device, opt.slot)
		if err != nil {
			return nil, fmt.Errorf("opening MBIM driver: %w", err)
		}
		return drv, nil
	default:
		return nil, fmt.Errorf("opening driver: unsupported kind %q", opt.driverKind)
	}
}

type tcpAPDUTransmitter struct {
	conn    net.Conn
	timeout time.Duration

	mu     sync.Mutex
	closed bool
}

func openTCPAPDUReader(ctx context.Context, addr string, timeout time.Duration) (usimreader.Reader, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, errors.New("opening TCP APDU reader: address is empty")
	}
	if timeout <= 0 {
		timeout = defaultAPDUTimeout
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dialing %s: %w", addr, err)
	}
	return usim.New(&tcpAPDUTransmitter{
		conn:    conn,
		timeout: timeout,
	}), nil
}

func (t *tcpAPDUTransmitter) Transmit(ctx context.Context, req []byte) ([]byte, error) {
	if len(req) == 0 {
		return nil, errors.New("transmitting APDU: request is empty")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil, errors.New("transmitting APDU: reader is closed")
	}
	if err := t.setDeadline(ctx); err != nil {
		return nil, err
	}
	defer func() {
		_ = t.conn.SetDeadline(time.Time{})
	}()

	if err := writeTCPAPDUFrame(t.conn, req); err != nil {
		return nil, fmt.Errorf("writing APDU %X: %w", req, err)
	}
	resp, err := readTCPAPDUFrame(t.conn)
	if err != nil {
		if isCleanTCPAPDUClose(err) {
			return nil, fmt.Errorf("remote closed before APDU response for %X: %w", req, err)
		}
		return nil, fmt.Errorf("reading response for APDU %X: %w", req, err)
	}
	return resp, nil
}

func (t *tcpAPDUTransmitter) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return t.conn.Close()
}

func (t *tcpAPDUTransmitter) setDeadline(ctx context.Context) error {
	deadline := time.Now().Add(t.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := t.conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("setting APDU TCP deadline: %w", err)
	}
	return nil
}

func writeTCPAPDUFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return errors.New("writing APDU frame: payload is empty")
	}
	if len(payload) > maxTCPAPDUFrameLength {
		return fmt.Errorf("writing APDU frame: payload length %d exceeds limit %d", len(payload), maxTCPAPDUFrameLength)
	}

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return fmt.Errorf("writing APDU frame header: %w", err)
	}
	if err := writeAll(w, payload); err != nil {
		return fmt.Errorf("writing APDU frame payload: %w", err)
	}
	return nil
}

func readTCPAPDUFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, fmt.Errorf("reading APDU frame header: %w", err)
	}

	length := binary.BigEndian.Uint32(header[:])
	if length == 0 {
		return nil, errors.New("reading APDU frame: payload is empty")
	}
	if length > maxTCPAPDUFrameLength {
		return nil, fmt.Errorf("reading APDU frame: payload length %d exceeds limit %d", length, maxTCPAPDUFrameLength)
	}

	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("reading APDU frame payload: %w", err)
	}
	return payload, nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

var _ usimreader.Transmitter = (*tcpAPDUTransmitter)(nil)

type pcscAPDUTransmitter struct {
	ctx  *goscard.Context
	card *goscard.Card
}

var (
	examplePCSCInitOnce sync.Once
	examplePCSCInitErr  error
)

func serveTCPAPDUServer(ctx context.Context, opt options) error {
	addr := strings.TrimSpace(opt.ccidTCPListen)
	if addr == "" {
		return errors.New("serving CCID TCP: listen address is empty")
	}
	if strings.TrimSpace(opt.readerName) == "" {
		readers, err := availableCCIDReaders()
		if err != nil {
			return err
		}
		if len(readers) == 0 {
			return errors.New("serving CCID TCP: no pcsc readers found")
		}
		return fmt.Errorf("serving CCID TCP: -reader is required; available readers: %s", strings.Join(readers, ", "))
	}

	tx, err := openExamplePCSCTransmitter(opt.readerName)
	if err != nil {
		return fmt.Errorf("opening server pcsc reader: %w", err)
	}
	defer func() {
		if err := tx.Close(); err != nil {
			slog.Warn("close pcsc reader", "err", err)
		}
	}()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listening for CCID TCP: %w", err)
	}
	defer ln.Close()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	timeout := opt.apduTimeout
	if timeout <= 0 {
		timeout = defaultAPDUTimeout
	}
	slog.Info("ccid tcp server listening", "addr", ln.Addr().String(), "reader", opt.readerName)

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accepting CCID TCP connection: %w", err)
		}

		remote := conn.RemoteAddr().String()
		slog.Info("ccid tcp client connected", "remote", remote)
		if err := serveTCPAPDUConn(ctx, conn, tx, timeout); err != nil {
			slog.Error("ccid tcp client error", "remote", remote, "err", err)
		}
		slog.Info("ccid tcp client disconnected", "remote", remote)
	}
}

func serveTCPAPDUConn(ctx context.Context, conn net.Conn, tx usimreader.Transmitter, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = defaultAPDUTimeout
	}
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()
	defer close(done)
	defer conn.Close()

	for {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			if isCleanTCPAPDUClose(err) {
				return nil
			}
			return fmt.Errorf("setting CCID TCP deadline: %w", err)
		}
		req, err := readTCPAPDUFrame(conn)
		if err != nil {
			if isCleanTCPAPDUClose(err) {
				return nil
			}
			return fmt.Errorf("reading CCID TCP APDU: %w", err)
		}
		slog.Debug("ccid tcp apdu request", "apdu", fmt.Sprintf("%X", req))

		apduCtx, cancel := context.WithTimeout(ctx, timeout)
		resp, err := tx.Transmit(apduCtx, req)
		cancel()
		if err != nil {
			return fmt.Errorf("transmitting APDU to pcsc reader: %w", err)
		}

		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			if isCleanTCPAPDUClose(err) {
				return nil
			}
			return fmt.Errorf("setting CCID TCP deadline: %w", err)
		}
		if err := writeTCPAPDUFrame(conn, resp); err != nil {
			return fmt.Errorf("writing CCID TCP response: %w", err)
		}
		slog.Debug("ccid tcp apdu response", "apdu", fmt.Sprintf("%X", resp))
	}
}

func isCleanTCPAPDUClose(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed)
}

func openExamplePCSCTransmitter(readerName string) (usimreader.Transmitter, error) {
	readerName = strings.TrimSpace(readerName)
	if readerName == "" {
		return nil, errors.New("opening pcsc reader: reader name is empty")
	}

	ctx, err := newExamplePCSCContext()
	if err != nil {
		return nil, err
	}

	readers, _, err := ctx.ListReaders(nil)
	if err != nil {
		_, _ = ctx.Release()
		return nil, fmt.Errorf("listing pcsc readers: %w", err)
	}
	if !slices.Contains(readers, readerName) {
		_, _ = ctx.Release()
		return nil, fmt.Errorf("selecting %q: %w", readerName, ccid.ErrReaderNotFound)
	}

	card, _, err := ctx.Connect(readerName, goscard.SCardShareShared, goscard.SCardProtocolT0|goscard.SCardProtocolT1)
	if err != nil {
		_, _ = ctx.Release()
		return nil, fmt.Errorf("connecting to %s: %w", readerName, err)
	}

	return &pcscAPDUTransmitter{
		ctx:  &ctx,
		card: &card,
	}, nil
}

func newExamplePCSCContext() (goscard.Context, error) {
	examplePCSCInitOnce.Do(func() {
		examplePCSCInitErr = goscard.Initialize(goscard.NewDefaultLogger(goscard.LogLevelNone))
	})
	if examplePCSCInitErr != nil {
		return goscard.Context{}, fmt.Errorf("initializing pcsc: %w", examplePCSCInitErr)
	}

	ctx, _, err := goscard.NewContext(goscard.SCardScopeSystem, nil, nil)
	if err != nil {
		return goscard.Context{}, fmt.Errorf("creating pcsc context: %w", err)
	}
	return ctx, nil
}

func (p *pcscAPDUTransmitter) Transmit(ctx context.Context, req []byte) ([]byte, error) {
	if p.card == nil {
		return nil, errors.New("transmitting APDU: pcsc reader is closed")
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	pci := goscard.SCardIoRequestT1
	if p.card.ActiveProtocol() == goscard.SCardProtocolT0 {
		pci = goscard.SCardIoRequestT0
	}

	resp, _, err := p.card.Transmit(&pci, req, nil)
	if err != nil {
		return nil, fmt.Errorf("transmitting APDU %X: %w", req, err)
	}
	return resp, nil
}

func (p *pcscAPDUTransmitter) Close() error {
	var errs []error
	if p.card != nil {
		if _, err := p.card.Disconnect(goscard.SCardLeaveCard); err != nil {
			errs = append(errs, fmt.Errorf("disconnecting pcsc card: %w", err))
		}
		p.card = nil
	}
	if p.ctx != nil {
		if _, err := p.ctx.Release(); err != nil {
			errs = append(errs, fmt.Errorf("releasing pcsc context: %w", err))
		}
		p.ctx = nil
	}
	return errors.Join(errs...)
}

var _ usimreader.Transmitter = (*pcscAPDUTransmitter)(nil)

func logClientEvents(events *imsclient.Events) {
	for {
		select {
		case state, ok := <-events.State:
			if !ok {
				return
			}
			slog.Info("registration state", "state", state)
		case err, ok := <-events.Errors:
			if !ok {
				return
			}
			slog.Error("client error", "err", err)
		}
	}
}

func logSMSEvents(events *imsclient.SMSEvents) {
	for {
		select {
		case sms, ok := <-events.Incoming:
			if !ok {
				return
			}
			slog.Info("incoming sms", "from", sms.From, "to", sms.To, "service_center", sms.ServiceCenter, "text", sms.Text, "received_at", sms.ReceivedAt.Format(time.RFC3339))
		case report, ok := <-events.Reports:
			if !ok {
				return
			}
			slog.Info("sms status report", "recipient", report.Recipient, "service_center", report.ServiceCenter, "message_reference", report.MessageReference, "status", report.Status, "service_center_time", report.ServiceCenterTime.Format(time.RFC3339), "discharge_time", report.DischargeTime.Format(time.RFC3339), "received_at", report.ReceivedAt.Format(time.RFC3339))
		}
	}
}

func logUSSDResult(result imsclient.USSDResult) {
	if !result.HasMessage {
		slog.Info("ussd session updated", "closed", result.Closed, "received_at", result.ReceivedAt.Format(time.RFC3339))
		return
	}
	slog.Info("incoming ussd", "text", result.Message.Text, "language", result.Message.Language, "error_code", result.Message.ErrorCode, "final", result.Message.Final, "request", result.Message.Request, "notify", result.Message.Notify, "closed", result.Closed, "received_at", result.ReceivedAt.Format(time.RFC3339))
}
