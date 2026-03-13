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
	"github.com/damonto/ims-client/apdu"
	"github.com/damonto/ims-client/driver"
	"github.com/damonto/ims-client/ims"
	"github.com/damonto/ims-client/swu"
)

type options struct {
	debug       bool
	driverKind  string
	listReaders bool
	readerName  string
	device      string
	imei        string
	epdgAddr    string
	pcscfAddr   string
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
	flag.StringVar(&opt.driverKind, "driver", "pcsc", "driver kind: pcsc or at")
	flag.BoolVar(&opt.listReaders, "list-readers", false, "list available PC/SC readers and exit")
	flag.StringVar(&opt.readerName, "reader", "", "PC/SC reader name; required for -driver pcsc")
	flag.StringVar(&opt.device, "device", "", "AT+CSIM serial device, for example /dev/ttyUSB7")
	flag.StringVar(&opt.imei, "imei", "", "UE IMEI used for SWu authentication")
	flag.StringVar(&opt.epdgAddr, "epdg", "", "ePDG host:port or host")
	flag.StringVar(&opt.pcscfAddr, "pcscf", "", "P-CSCF host:port or host; optional when -epdg is set")
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

	imsTransport := "udp"
	if opt.epdgAddr != "" {
		imsTransport = "tcp"
	}

	if opt.pcscfAddr == "" && opt.epdgAddr == "" {
		return errors.New("running example: -pcscf is required when -epdg is not set")
	}
	if opt.epdgAddr != "" && opt.imei == "" {
		return errors.New("running example: -imei is required when -epdg is set")
	}
	if (opt.sendTo == "") != (opt.sendText == "") {
		return errors.New("running example: -send-to and -send-text must be provided together")
	}
	if opt.sendTo != "" && opt.ussdCode != "" {
		return errors.New("running example: choose either SMS flags or -ussd")
	}

	drv, err := openDriver(opt)
	if err != nil {
		return err
	}
	defer func() {
		if err := drv.Close(); err != nil {
			slog.Warn("close driver", "err", err)
		}
	}()

	cfg := imsclient.Config{
		Logger:       slog.Default(),
		IMEI:         opt.imei,
		EPDGAddress:  opt.epdgAddr,
		PCSCFAddress: opt.pcscfAddr,
		Tunnel:       swu.Config{},
		IMS: ims.Config{
			Transport: imsTransport,
			Country:   opt.country,
			IMEI:      opt.imei,
		},
	}

	client, err := imsclient.NewClient(ctx, cfg, drv)
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			slog.Warn("close client", "err", err)
		}
	}()

	events := client.Events()
	go logEvents(events)

	if err := client.Connect(ctx); err != nil {
		return fmt.Errorf("connecting client: %w", err)
	}
	slog.Info("registered to IMS")
	if tunnel := client.Tunnel(); len(tunnel.PCSCFIP) > 0 {
		slog.Info("tunnel ready", "inner_ip", tunnel.InnerIP.String(), "pcscf_ip", tunnel.PCSCFIP.String())
	}

	if opt.sendTo != "" {
		sendCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		if err := client.SendSMS(sendCtx, opt.sendTo, opt.sendText); err != nil {
			return fmt.Errorf("sending SMS: %w", err)
		}
		slog.Info("sent SMS", "to", opt.sendTo)
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
	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	session, err := client.StartUSSD(dialCtx, code)
	if err != nil {
		return fmt.Errorf("starting USSD: %w", err)
	}
	slog.Info("started USSD", "code", code)
	reader := bufio.NewReader(os.Stdin)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-session.Events():
			if !ok {
				return nil
			}
			slog.Info("incoming ussd", "text", msg.Text, "language", msg.Language, "error_code", msg.ErrorCode, "final", msg.Final, "request", msg.Request, "notify", msg.Notify)
			if msg.Final {
				return nil
			}
			fmt.Fprint(os.Stdout, "ussd> ")
			line, err := reader.ReadString('\n')
			if err != nil {
				return fmt.Errorf("reading USSD input: %w", err)
			}
			line = strings.TrimSpace(line)
			if line == "" || line == "/bye" || line == "/end" || line == "/quit" {
				endCtx, endCancel := context.WithTimeout(ctx, 15*time.Second)
				defer endCancel()
				if err := session.End(endCtx, ""); err != nil {
					return fmt.Errorf("ending USSD: %w", err)
				}
				return nil
			}
			replyCtx, replyCancel := context.WithTimeout(ctx, 30*time.Second)
			if err := session.Reply(replyCtx, line); err != nil {
				replyCancel()
				return fmt.Errorf("replying USSD: %w", err)
			}
			replyCancel()
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
	drv, err := driver.NewCCID()
	if err != nil {
		return nil, fmt.Errorf("opening pcsc driver: %w", err)
	}
	defer func() {
		if err := drv.Close(); err != nil {
			slog.Warn("close pcsc driver", "err", err)
		}
	}()

	readers, err := drv.ListReaders()
	if err != nil {
		return nil, fmt.Errorf("listing pcsc readers: %w", err)
	}
	return readers, nil
}

func openDriver(opt options) (apdu.Driver, error) {
	switch strings.ToLower(strings.TrimSpace(opt.driverKind)) {
	case "pcsc":
		drv, err := driver.NewCCID()
		if err != nil {
			return nil, fmt.Errorf("opening pcsc driver: %w", err)
		}
		if opt.readerName == "" {
			readers, err := drv.ListReaders()
			if closeErr := drv.Close(); closeErr != nil {
				slog.Warn("close pcsc driver", "err", closeErr)
			}
			if err != nil {
				return nil, fmt.Errorf("listing pcsc readers: %w", err)
			}
			if len(readers) == 0 {
				return nil, errors.New("opening pcsc driver: no readers found")
			}
			return nil, fmt.Errorf("opening pcsc driver: -reader is required; available readers: %s", strings.Join(readers, ", "))
		}
		if err := drv.SetReader(opt.readerName); err != nil {
			if closeErr := drv.Close(); closeErr != nil {
				slog.Warn("close pcsc driver", "err", closeErr)
			}
			return nil, fmt.Errorf("opening pcsc driver: %w", err)
		}
		return drv, nil
	case "at", "at+csim", "serial":
		if opt.device == "" {
			return nil, errors.New("opening AT driver: -device is required")
		}
		drv, err := driver.NewAT(opt.device, 0, nil)
		if err != nil {
			return nil, fmt.Errorf("opening AT driver: %w", err)
		}
		return drv, nil
	default:
		return nil, fmt.Errorf("opening driver: unsupported kind %q", opt.driverKind)
	}
}

func logEvents(events imsclient.Events) {
	for {
		select {
		case state, ok := <-events.State:
			if !ok {
				return
			}
			slog.Info("registration state", "state", state)
		case sms, ok := <-events.SMS:
			if !ok {
				return
			}
			slog.Info("incoming sms", "from", sms.From, "to", sms.To, "service_center", sms.ServiceCenter, "text", sms.Text, "received_at", sms.ReceivedAt.Format(time.RFC3339))
		case err, ok := <-events.Errors:
			if !ok {
				return
			}
			slog.Error("event error", "err", err)
		}
	}
}
