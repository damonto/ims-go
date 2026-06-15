package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	uiccat "github.com/damonto/uicc-go/at"
	uiccccid "github.com/damonto/uicc-go/ccid"
	uiccqmi "github.com/damonto/uicc-go/qcom/qmi"
	uiccqrtr "github.com/damonto/uicc-go/qcom/qrtr"
	uiccuim "github.com/damonto/uicc-go/qcom/uim"
	"github.com/damonto/uicc-go/usim"
	usimcard "github.com/damonto/uicc-go/usim/card"
	"github.com/damonto/vowifi-go"
	imssession "github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/swu/tunnel"
	"github.com/damonto/vowifi-go/wfcsetup"
)

const (
	defaultAPDUTimeout    = 30 * time.Second
	maxTCPAPDUFrameLength = 64 * 1024
	wfcUserActionPoll     = 10 * time.Second
	wfcFlowRecheckDelay   = 5 * time.Second
	wfcFlowRecheckMax     = 6
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
	terminalBuild  string
	sipPort        int
	sipT1          time.Duration
	sipT2          time.Duration
	sipT4          time.Duration
	sipTimerB      time.Duration
	sipTimerD      time.Duration
	sipTimerF      time.Duration
	sipTimerH      time.Duration
	sipTimerJ      time.Duration
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
	flag.StringVar(&opt.driverKind, "driver", "pcsc", "driver kind: pcsc, ccid-tcp, at, qmi, or qrtr")
	flag.BoolVar(&opt.listReaders, "list-readers", false, "list available PC/SC readers and exit")
	flag.StringVar(&opt.readerName, "reader", "", "PC/SC reader name; required for -driver pcsc")
	flag.StringVar(&opt.device, "device", "", "AT+CSIM serial device, QMI modem path, or ccid-tcp host:port")
	flag.StringVar(&opt.ccidTCPListen, "ccid-tcp-listen", "", "listen address for temporary CCID TCP APDU server, for example :9999")
	flag.DurationVar(&opt.apduTimeout, "apdu-timeout", defaultAPDUTimeout, "APDU TCP read/write timeout for -driver ccid-tcp")
	flag.IntVar(&opt.slot, "slot", 1, "physical SIM slot for -driver qmi or -driver qrtr")
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
	flag.StringVar(&opt.terminalVendor, "terminal-vendor", "", "terminal vendor for TS.43 and generated IMS User-Agent")
	flag.StringVar(&opt.terminalModel, "terminal-model", "", "terminal model for TS.43 and generated IMS User-Agent")
	flag.StringVar(&opt.terminalSW, "terminal-sw-version", "", "terminal software version for TS.43 and generated IMS User-Agent")
	flag.StringVar(&opt.terminalBuild, "terminal-build", "", "terminal build string for generated IMS User-Agent")
	flag.IntVar(&opt.sipPort, "sip-port", 0, "IMS SIP server port override, maps ims.sip_server_port_number_int")
	flag.DurationVar(&opt.sipT1, "sip-timer-t1", 0, "SIP timer T1 override, for example 500ms or 2s")
	flag.DurationVar(&opt.sipT2, "sip-timer-t2", 0, "SIP timer T2 override")
	flag.DurationVar(&opt.sipT4, "sip-timer-t4", 0, "SIP timer T4 override")
	flag.DurationVar(&opt.sipTimerB, "sip-timer-b", 0, "SIP timer B override")
	flag.DurationVar(&opt.sipTimerD, "sip-timer-d", 0, "SIP timer D override")
	flag.DurationVar(&opt.sipTimerF, "sip-timer-f", 0, "SIP timer F override")
	flag.DurationVar(&opt.sipTimerH, "sip-timer-h", 0, "SIP timer H override")
	flag.DurationVar(&opt.sipTimerJ, "sip-timer-j", 0, "SIP timer J override")
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if opt.listReaders {
		if !strings.EqualFold(strings.TrimSpace(opt.driverKind), "pcsc") {
			return errors.New("listing readers: -list-readers requires -driver pcsc")
		}
		return listCCIDReaders(ctx)
	}

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

	cfg := &vowifi.Config{
		EPDG:   opt.epdgAddr,
		Logger: slog.Default(),
		Terminal: vowifi.TerminalInfo{
			ID:              opt.imei,
			Vendor:          opt.terminalVendor,
			Model:           opt.terminalModel,
			SoftwareVersion: opt.terminalSW,
			Build:           opt.terminalBuild,
		},
		Tunnel: tunnel.Config{
			SIPPort:              opt.sipPort,
			NATKeepaliveInterval: opt.nattKeepalive,
			IKERetransmitDelays:  ikeRetransmit,
		},
		IMS: vowifi.IMSConfig{
			Transport:          opt.transport,
			PrivateIdentity:    opt.privateID,
			PublicIdentity:     opt.publicID,
			HomeDomain:         opt.homeDomain,
			PhoneContextDomain: opt.phoneContext,
			UserAgent:          opt.userAgent,
			AccessNetworkInfo:  opt.pani,
			WLANNodeID:         opt.wlanNodeID,
			RegisterExpires:    opt.expires,
			SIPServerPort:      opt.sipPort,
			SIPTimers:          sipTimersFromOptions(opt),
		},
	}

	client, err := vowifi.New(reader, cfg)
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
	if tunnel := client.Tunnel(); len(tunnel.DefaultPCSCFIP()) > 0 {
		slog.Info("tunnel ready", "inner_ip", tunnel.DefaultInnerIP().String(), "pcscf_ip", tunnel.DefaultPCSCFIP().String())
	}

	if opt.sendTo != "" {
		sendCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		submission, err := client.SMS().Send(sendCtx, opt.sendTo, opt.sendText)
		if err != nil {
			return fmt.Errorf("sending SMS: %w", err)
		}
		defer submission.Close()
		go logSMSSubmissionUpdates(submission)
		slog.Info("submitted SMS", "id", submission.ID, "to", submission.To, "segments", submission.SegmentCount)
	}
	if opt.ussdCode != "" {
		if err := runUSSD(ctx, client, opt.ussdCode); err != nil {
			return err
		}
		return nil
	}

	<-ctx.Done()
	stop()
	return nil
}

func connectWithWFCUserActionPolling(ctx context.Context, connect func(context.Context) error, interval time.Duration) error {
	return connectWithWFCServiceFlow(ctx, connect, interval, consoleWFCServiceFlow)
}

func connectWithWFCServiceFlow(ctx context.Context, connect func(context.Context) error, interval time.Duration, serviceFlow func(context.Context, wfcUserAction) error) error {
	if interval <= 0 {
		interval = wfcUserActionPoll
	}

	var lastAction wfcUserAction
	var logged bool
	var completedFlow bool
	var rechecks int
	for {
		err := connect(ctx)
		if err == nil {
			return nil
		}

		if errors.Is(err, wfcsetup.ErrPending) {
			retryAfter := wfcRetryAfter(err, interval)
			slog.Info("wfc entitlement pending", "retry_after", retryAfter)
			if err := waitForWFCRetry(ctx, retryAfter); err != nil {
				return err
			}
			continue
		}

		action, ok := wfcUserActionFromError(err)
		if !ok {
			return err
		}
		if completedFlow {
			if rechecks >= wfcFlowRecheckMax {
				return fmt.Errorf("waiting for wfc entitlement update: %w", wfcsetup.ErrPending)
			}
			rechecks++
			if err := waitForWFCRetry(ctx, wfcFlowRecheckDelay); err != nil {
				return err
			}
			slog.Info("rechecking wfc entitlement after service flow", "attempt", rechecks, "max", wfcFlowRecheckMax)
			continue
		}
		if (!logged || action != lastAction) && serviceFlow == nil {
			logWFCUserAction(action)
			lastAction = action
			logged = true
		}
		if serviceFlow != nil {
			if err := serviceFlow(ctx, action); err != nil {
				return err
			}
			completedFlow = true
			rechecks = 0
			continue
		}
		if err := waitForWFCRetry(ctx, interval); err != nil {
			return err
		}
		slog.Info("polling wfc entitlement after user action", "interval", interval)
	}
}

func wfcRetryAfter(err error, fallback time.Duration) time.Duration {
	var setupErr *wfcsetup.Error
	if errors.As(err, &setupErr) && setupErr.Result.RetryAfter > 0 {
		return setupErr.Result.RetryAfter
	}
	return fallback
}

func waitForWFCRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return fmt.Errorf("waiting for wfc entitlement: %w", ctx.Err())
	case <-timer.C:
		return nil
	}
}

func consoleWFCServiceFlow(ctx context.Context, action wfcUserAction) error {
	logWFCUserAction(action)
	reader := bufio.NewReader(os.Stdin)
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("waiting for wfc service flow callback: %w", err)
		}
		fmt.Fprint(os.Stdout, "wfc-flow> ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("reading wfc service flow callback: %w", err)
		}
		done, err := parseWFCServiceFlowCallback(line)
		if err != nil {
			fmt.Fprintf(os.Stdout, "invalid wfc callback: %v\n", err)
			continue
		}
		if !done {
			return errors.New("wfc service flow dismissed")
		}
		slog.Info("wfc service flow completed; rechecking entitlement")
		return nil
	}
}

type wfcServiceFlowCallback struct {
	Event string `json:"event"`
}

func parseWFCServiceFlowCallback(line string) (bool, error) {
	line = strings.TrimSpace(line)
	if line == "" {
		return false, errors.New("wfc service flow callback is required")
	}
	line = trimWFCServiceFlowPrefix(line)
	if strings.HasPrefix(line, "{") {
		var payload wfcServiceFlowCallback
		if err := json.Unmarshal([]byte(line), &payload); err != nil {
			return false, fmt.Errorf("parse wfc service flow JSON callback: %w", err)
		}
		return wfcServiceFlowDone(payload.Event)
	}
	if strings.Contains(line, "VoWiFiWebServiceFlow.") {
		_, after, _ := strings.Cut(line, "VoWiFiWebServiceFlow.")
		name, _, ok := strings.Cut(after, "(")
		if !ok {
			return false, errors.New("wfc service flow callback argument list is required")
		}
		return wfcServiceFlowDone(name)
	}
	return wfcServiceFlowDone(line)
}

func trimWFCServiceFlowPrefix(line string) string {
	const prefix = "TS43_VOWIFI_CALLBACK"
	line = strings.TrimSpace(line)
	if !strings.HasPrefix(line, prefix) {
		return line
	}
	return strings.TrimSpace(strings.TrimPrefix(line, prefix))
}

func wfcServiceFlowDone(event string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(event)) {
	case "done", "entitlementchanged":
		return true, nil
	case "dismiss", "dismissflow":
		return false, nil
	default:
		return false, fmt.Errorf("unknown wfc service flow callback %q", event)
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
	method := "GET"
	if action.Data != "" {
		method = "POST"
	}
	slog.Error(
		"wfc entitlement requires user action",
		"source", action.Source,
		"carrier", action.Carrier,
		"method", method,
		"url", action.URL,
		"post_data", action.Data,
		"title", action.Title,
		"client", action.ClientName,
		"adapter", "examples/vowifi_service_flow.js",
		"next", "open the URL with the shown method; paste DONE or the VoWiFiWebServiceFlow callback when the page completes",
	)
}

func wfcUserActionFromError(err error) (wfcUserAction, bool) {
	if !errors.Is(err, wfcsetup.ErrUserActionRequired) {
		return wfcUserAction{}, false
	}

	var setupErr *wfcsetup.Error
	if errors.As(err, &setupErr) {
		websheet := setupErr.Result.Websheet
		if websheet == nil {
			return wfcUserAction{Source: string(setupErr.Result.Scheme), Carrier: setupErr.Result.Carrier}, true
		}
		return wfcUserAction{
			Source:     string(setupErr.Result.Scheme),
			Carrier:    setupErr.Result.Carrier,
			URL:        websheet.URL,
			Data:       websheet.Data,
			Title:      websheet.Title,
			ClientName: websheet.ClientName,
		}, true
	}

	return wfcUserAction{Source: "unknown"}, true
}

func runUSSD(ctx context.Context, client *vowifi.Client, code string) error {
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

func listCCIDReaders(ctx context.Context) error {
	readers, err := availableCCIDReaders(ctx)
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

func availableCCIDReaders(ctx context.Context) ([]string, error) {
	readers, err := uiccccid.ListReaders(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing pcsc readers: %w", err)
	}
	return readers, nil
}

func openDriver(ctx context.Context, opt options) (usimcard.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(opt.driverKind)) {
	case "pcsc":
		if opt.readerName == "" {
			readers, err := uiccccid.ListReaders(ctx)
			if err != nil {
				return nil, fmt.Errorf("listing pcsc readers: %w", err)
			}
			if len(readers) == 0 {
				return nil, errors.New("opening pcsc driver: no readers found")
			}
			return nil, fmt.Errorf("opening pcsc driver: -reader is required; available readers: %s", strings.Join(readers, ", "))
		}
		tx, err := uiccccid.Open(ctx, opt.readerName)
		if err != nil {
			return nil, fmt.Errorf("opening pcsc driver: %w", err)
		}
		return openAPDUReader(tx)
	case "at", "at+csim", "serial":
		if opt.device == "" {
			return nil, errors.New("opening AT driver: -device is required")
		}
		tx, err := uiccat.Open(ctx, opt.device, 0)
		if err != nil {
			return nil, fmt.Errorf("opening AT driver: %w", err)
		}
		return openAPDUReader(tx)
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
		drv, err := openQCOMQMIReader(ctx, opt.device, opt.slot)
		if err != nil {
			return nil, fmt.Errorf("opening QMI driver: %w", err)
		}
		return drv, nil
	case "qrtr":
		drv, err := openQCOMQRTRReader(ctx, opt.slot)
		if err != nil {
			return nil, fmt.Errorf("opening QRTR driver: %w", err)
		}
		return drv, nil
	default:
		return nil, fmt.Errorf("opening driver: unsupported kind %q", opt.driverKind)
	}
}

func openAPDUReader(tx usimcard.Transmitter) (usimcard.Reader, error) {
	reader, err := usim.NewReader(tx)
	if err != nil {
		return nil, errors.Join(err, tx.Close())
	}
	return reader, nil
}

func openQCOMQMIReader(ctx context.Context, device string, slot int) (usimcard.Reader, error) {
	qmiSlot, err := qcomSlot(slot)
	if err != nil {
		return nil, err
	}
	transport, err := uiccqmi.Open(ctx, uiccqmi.WithProxy(device))
	if err != nil {
		return nil, err
	}
	reader, err := uiccuim.New(ctx, transport, uiccuim.WithSlot(qmiSlot))
	if err != nil {
		return nil, err
	}
	if err := reader.ActivateSlot(ctx); err != nil {
		return nil, errors.Join(err, reader.Close())
	}
	return openQCOMAdapter(reader)
}

func openQCOMQRTRReader(ctx context.Context, slot int) (usimcard.Reader, error) {
	qmiSlot, err := qcomSlot(slot)
	if err != nil {
		return nil, err
	}
	transport, err := uiccqrtr.Open(ctx)
	if err != nil {
		return nil, err
	}
	reader, err := uiccuim.New(ctx, transport, uiccuim.WithSlot(qmiSlot))
	if err != nil {
		return nil, err
	}
	if err := reader.ActivateSlot(ctx); err != nil {
		return nil, errors.Join(err, reader.Close())
	}
	return openQCOMAdapter(reader)
}

func openQCOMAdapter(reader *uiccuim.Reader) (usimcard.Reader, error) {
	adapter, err := usim.NewQCOM(reader)
	if err != nil {
		return nil, errors.Join(err, reader.Close())
	}
	return adapter, nil
}

func qcomSlot(slot int) (uint8, error) {
	if slot < 1 || slot > 5 {
		return 0, fmt.Errorf("slot %d is out of range", slot)
	}
	return uint8(slot), nil
}

type tcpAPDUTransmitter struct {
	conn    net.Conn
	timeout time.Duration

	mu     sync.Mutex
	closed bool
}

func openTCPAPDUReader(ctx context.Context, addr string, timeout time.Duration) (usimcard.Reader, error) {
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
	return openAPDUReader(&tcpAPDUTransmitter{
		conn:    conn,
		timeout: timeout,
	})
}

func (t *tcpAPDUTransmitter) Transmit(ctx context.Context, req []byte) ([]byte, error) {
	if len(req) == 0 {
		return nil, errors.New("transmitting APDU: request is empty")
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

var _ usimcard.Transmitter = (*tcpAPDUTransmitter)(nil)

func serveTCPAPDUServer(ctx context.Context, opt options) error {
	addr := strings.TrimSpace(opt.ccidTCPListen)
	if addr == "" {
		return errors.New("serving CCID TCP: listen address is empty")
	}
	if strings.TrimSpace(opt.readerName) == "" {
		readers, err := availableCCIDReaders(ctx)
		if err != nil {
			return err
		}
		if len(readers) == 0 {
			return errors.New("serving CCID TCP: no pcsc readers found")
		}
		return fmt.Errorf("serving CCID TCP: -reader is required; available readers: %s", strings.Join(readers, ", "))
	}

	tx, err := uiccccid.Open(ctx, opt.readerName)
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

func serveTCPAPDUConn(ctx context.Context, conn net.Conn, tx usimcard.Transmitter, timeout time.Duration) error {
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

func logClientEvents(events *vowifi.Events) {
	for {
		select {
		case state, ok := <-events.State:
			if !ok {
				return
			}
			slog.Info("client state", "status", state.Status, "active", state.Active, "connecting", state.Connecting, "reconnecting", state.Reconnecting, "closed", state.Closed, "last_error", state.LastError)
		case err, ok := <-events.Errors:
			if !ok {
				return
			}
			slog.Error("client error", "err", err)
		}
	}
}

func logSMSEvents(events *vowifi.SMSEvents) {
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

func logSMSSubmissionUpdates(submission vowifi.SMSSubmission) {
	for update := range submission.Updates {
		attrs := []any{
			"id", update.SubmissionID,
			"segment", update.SegmentIndex + 1,
			"segments", update.SegmentCount,
			"state", update.State,
			"recipient", update.Recipient,
			"service_center", update.ServiceCenter,
			"rp_ref", update.RPReference,
			"tp_ref", update.TPReference,
			"received_at", update.ReceivedAt.Format(time.RFC3339),
		}
		if update.HasRPCause {
			attrs = append(attrs, "rp_cause", update.RPCause)
		}
		if update.HasStatus {
			attrs = append(attrs, "tp_status", update.Status)
		}
		slog.Info("sms submission update", attrs...)
	}
}

func logUSSDResult(result vowifi.USSDResult) {
	if !result.HasMessage {
		slog.Info("ussd session updated", "closed", result.Closed, "received_at", result.ReceivedAt.Format(time.RFC3339))
		return
	}
	slog.Info("incoming ussd", "text", result.Message.Text, "language", result.Message.Language, "error_code", result.Message.ErrorCode, "final", result.Message.Final, "request", result.Message.Request, "notify", result.Message.Notify, "closed", result.Closed, "received_at", result.ReceivedAt.Format(time.RFC3339))
}
