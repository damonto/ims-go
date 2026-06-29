package vowifi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/damonto/uicc-go/usim"
	usimcard "github.com/damonto/uicc-go/usim/card"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
)

type Card interface {
	ICCID() string
	IMSI() string
	MCC() string
	MNC() string
	SMSC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type Client struct {
	cfg    Config
	card   Card
	reader usimcard.Reader
	logger *slog.Logger

	state clientState

	events       eventHub
	sms          SMSClient
	ussd         USSDClient
	voice        VoiceClient
	smsSeq       atomic.Uint64
	smsReportsMu sync.Mutex
	smsReports   map[byte][]smsReportLink
	ussdSessions map[*imsussd.Session]*USSDSession
}

// New takes ownership of reader. The SIM state is loaded by Connect(ctx), so
// callers can cancel the first connect attempt with ctx.
// On construction failure it closes reader before returning the error.
// The returned Client closes the underlying reader when Close is called.
func New(reader usimcard.Reader, cfg *Config) (*Client, error) {
	if reader == nil {
		return nil, errors.New("creating client: reader is nil")
	}
	raw := cloneConfig(cfg)
	if raw.Logger == nil {
		raw.Logger = slog.Default()
	}
	raw = raw.trimmed()
	if err := raw.validate(); err != nil {
		return nil, errors.Join(fmt.Errorf("creating client: %w", err), wrapCloseError(closeActionReader, reader.Close()))
	}
	raw.Terminal = raw.Terminal.trimmed()
	if raw.Terminal.ID == "" {
		return nil, errors.Join(errors.New("creating client: terminal id is empty"), wrapCloseError(closeActionReader, reader.Close()))
	}
	client := newClient(raw)
	client.reader = reader
	return client, nil
}

func newClient(cfg Config) *Client {
	client := &Client{
		cfg:    cfg,
		logger: cfg.Logger.With("component", "vowifi-go"),
		state: clientState{
			done:   make(chan struct{}),
			status: StatusIdle,
		},
		events:       newEventHub(),
		smsReports:   make(map[byte][]smsReportLink),
		ussdSessions: make(map[*imsussd.Session]*USSDSession),
	}
	client.sms.client = client
	client.ussd.client = client
	client.voice.client = client
	return client
}

func (c *Client) SMS() *SMSClient {
	return &c.sms
}

func (c *Client) USSD() *USSDClient {
	return &c.ussd
}

func (c *Client) Voice() *VoiceClient {
	return &c.voice
}
