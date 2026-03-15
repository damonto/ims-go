package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	imsclient "github.com/damonto/ims-client"
	atdriver "github.com/damonto/ims-client/driver/at"
	cciddriver "github.com/damonto/ims-client/driver/ccid"
	qmidriver "github.com/damonto/ims-client/driver/qmi"
	swutunnel "github.com/damonto/ims-client/swu/tunnel"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

type options struct {
	debug       bool
	driverKind  string
	listReaders bool
	readerName  string
	device      string
	slot        int
	imei        string
	epdgAddr    string
	country     string
	sendTo      string
	sendText    string
	ussdCode    string
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
	flag.StringVar(&opt.driverKind, "driver", "pcsc", "driver kind: pcsc, at, qmi, or qrtr")
	flag.BoolVar(&opt.listReaders, "list-readers", false, "list available PC/SC readers and exit")
	flag.StringVar(&opt.readerName, "reader", "", "PC/SC reader name; required for -driver pcsc")
	flag.StringVar(&opt.device, "device", "", "AT+CSIM serial device or qmi-proxy modem path, for example /dev/ttyUSB7")
	flag.IntVar(&opt.slot, "slot", 1, "physical SIM slot for -driver qmi")
	flag.StringVar(&opt.imei, "imei", "", "UE IMEI used for SWu authentication")
	flag.StringVar(&opt.epdgAddr, "epdg", "", "optional ePDG host:port or host; default uses MCC/MNC from the card")
	flag.StringVar(&opt.country, "country", "IE", "PIDF civic country code, for example NZ")
	flag.StringVar(&opt.sendTo, "send-to", "", "destination MSISDN for one test SMS")
	flag.StringVar(&opt.sendText, "send-text", "", "text body for one test SMS")
	flag.StringVar(&opt.ussdCode, "ussd", "", "USSD code to dial, for example *100#")
	flag.Parse()
	return opt
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

	if opt.imei == "" {
		return errors.New("running example: -imei is required")
	}
	if (opt.sendTo == "") != (opt.sendText == "") {
		return errors.New("running example: -send-to and -send-text must be provided together")
	}
	if opt.sendTo != "" && opt.ussdCode != "" {
		return errors.New("running example: choose either SMS flags or -ussd")
	}

	reader, err := openDriver(ctx, opt)
	if err != nil {
		return err
	}

	cfg := &imsclient.Config{
		IMEI:   opt.imei,
		EPDG:   opt.epdgAddr,
		Logger: slog.Default(),
		Tunnel: swutunnel.Config{},
		IMS: imsclient.IMSConfig{
			Country: opt.country,
		},
	}

	client, err := imsclient.New(ctx, reader, cfg)
	if err != nil {
		if closeErr := reader.Close(); closeErr != nil {
			return errors.Join(fmt.Errorf("creating client: %w", err), fmt.Errorf("closing driver: %w", closeErr))
		}
		return fmt.Errorf("creating client: %w", err)
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

	if err := client.Connect(ctx); err != nil {
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
	readers, err := cciddriver.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("listing pcsc readers: %w", err)
	}
	return readers, nil
}

func openDriver(ctx context.Context, opt options) (usimreader.Reader, error) {
	switch strings.ToLower(strings.TrimSpace(opt.driverKind)) {
	case "pcsc":
		if opt.readerName == "" {
			readers, err := cciddriver.ListReaders()
			if err != nil {
				return nil, fmt.Errorf("listing pcsc readers: %w", err)
			}
			if len(readers) == 0 {
				return nil, errors.New("opening pcsc driver: no readers found")
			}
			return nil, fmt.Errorf("opening pcsc driver: -reader is required; available readers: %s", strings.Join(readers, ", "))
		}
		drv, err := cciddriver.Open(opt.readerName)
		if err != nil {
			return nil, fmt.Errorf("opening pcsc driver: %w", err)
		}
		return drv, nil
	case "at", "at+csim", "serial":
		if opt.device == "" {
			return nil, errors.New("opening AT driver: -device is required")
		}
		drv, err := atdriver.New(opt.device, 0)
		if err != nil {
			return nil, fmt.Errorf("opening AT driver: %w", err)
		}
		return drv, nil
	case "qmi":
		if opt.device == "" {
			return nil, errors.New("opening QMI driver: -device is required")
		}
		drv, err := qmidriver.Open(ctx, opt.device, opt.slot)
		if err != nil {
			return nil, fmt.Errorf("opening QMI driver: %w", err)
		}
		return drv, nil
	case "qrtr":
		drv, err := qmidriver.OpenQRTR(ctx, opt.slot)
		if err != nil {
			return nil, fmt.Errorf("opening QRTR driver: %w", err)
		}
		return drv, nil
	default:
		return nil, fmt.Errorf("opening driver: unsupported kind %q", opt.driverKind)
	}
}

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
