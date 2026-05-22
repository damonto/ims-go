package imsclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	imssession "github.com/damonto/ims-client/ims/session"
	imsussd "github.com/damonto/ims-client/ims/ussd"
	swutunnel "github.com/damonto/ims-client/swu/tunnel"
	"github.com/damonto/ims-client/usim"
	usimreader "github.com/damonto/ims-client/usim/reader"
)

type Config struct {
	IMEI           string
	EPDG           string
	Logger         *slog.Logger
	ReconnectDelay time.Duration
	Tunnel         swutunnel.Config
	IMS            IMSConfig
}

type IMSConfig struct {
	Transport         string
	PrivateIdentity   string
	PublicIdentity    string
	HomeDomain        string
	USSDLanguage      string
	UserAgent         string
	AccessNetworkInfo string
	WLANNodeID        string
	RegisterExpires   time.Duration
	ServiceCenter     string
	IMEI              string

	dialSecureTCP   func(context.Context, imssession.SecureTCPConfig) (imssession.Transport, error)
	dialSecureUDP   func(context.Context, imssession.SecureUDPConfig) (imssession.Transport, error)
	listenSecureTCP func(context.Context, imssession.SecureTCPConfig) (imssession.Transport, error)
	listenSecureUDP func(context.Context, imssession.SecureUDPConfig) (imssession.Transport, error)
}

type Card interface {
	ICCID() string
	IMSI() string
	MCC() string
	MNC() string
	SMSC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type RegistrationState string

const (
	StateConnecting     RegistrationState = "connecting"
	StateAuthenticating RegistrationState = "authenticating"
	StateRegistered     RegistrationState = "registered"
	StateClosed         RegistrationState = "closed"
	StateFailed         RegistrationState = "failed"
)

var (
	ErrClientClosed       = errors.New("client is closed")
	ErrClientNotConnected = errors.New("client is not connected")
	ErrUSSDNotStarted     = errors.New("ussd session is not started")
	ErrUSSDAlreadyStarted = errors.New("ussd session is already started")
	ErrUSSDClosed         = errors.New("ussd session is closed")
	ErrUSSDInProgress     = errors.New("ussd session operation in progress")
)

type SMS struct {
	From          string
	To            string
	ServiceCenter string
	Text          string
	ReceivedAt    time.Time
}

type SMSReport struct {
	ServiceCenter         string
	Recipient             string
	MessageReference      byte
	Status                byte
	MoreMessagesWaiting   bool
	LoopPrevention        bool
	FromCommand           bool
	HasUserDataHeader     bool
	ServiceCenterTime     time.Time
	DischargeTime         time.Time
	ProtocolIdentifier    byte
	HasProtocolIdentifier bool
	DataCodingScheme      byte
	HasDataCodingScheme   bool
	UserData              []byte
	ReceivedAt            time.Time
}

type SMSSubmission struct {
	ID           string
	To           string
	Text         string
	SubmittedAt  time.Time
	SegmentCount int
	Segments     []SMSSubmissionSegment
}

type SMSSubmissionSegment struct {
	Index       int
	SubmittedAt time.Time
	CallID      string
	RPReference byte
	TPReference byte
}

type USSDMessage = imsussd.Message

type USSDResult struct {
	Message    USSDMessage
	HasMessage bool
	Closed     bool
	ReceivedAt time.Time
}

type IncomingUSSD struct {
	Session    *Session
	Message    USSDMessage
	ReceivedAt time.Time
}

type Events struct {
	State  <-chan RegistrationState
	Errors <-chan error

	closeOnce sync.Once
	closeFn   func()
}

func (e *Events) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		if e.closeFn != nil {
			e.closeFn()
		}
	})
}

type SMSEvents struct {
	Incoming <-chan SMS
	Reports  <-chan SMSReport

	closeOnce sync.Once
	closeFn   func()
}

func (e *SMSEvents) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		if e.closeFn != nil {
			e.closeFn()
		}
	})
}

type USSDEvents struct {
	Incoming <-chan IncomingUSSD

	closeOnce sync.Once
	closeFn   func()
}

func (e *USSDEvents) Close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		if e.closeFn != nil {
			e.closeFn()
		}
	})
}

type Client struct {
	cfg    Config
	card   Card
	reader io.Closer
	logger *slog.Logger

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	mu           sync.Mutex
	closed       bool
	connecting   bool
	reconnecting bool
	active       *activeConn
	closeWG      sync.WaitGroup
	close        sync.Once

	events       eventHub
	sms          SMSService
	ussd         USSDService
	smsSeq       atomic.Uint64
	ussdSessions map[*imsussd.Session]*Session
}

type SMSService struct {
	client *Client
}

type USSDService struct {
	client *Client
}

type Session struct {
	client *Client

	mu      sync.Mutex
	low     *imsussd.Session
	results chan USSDResult
	started bool
	closed  bool
	busy    bool

	watchOnce sync.Once
}

// New loads the SIM state and takes ownership of reader.
// On failure it closes reader before returning the error.
// The returned Client closes the underlying reader when Close is called.
func New(ctx context.Context, reader usimreader.Reader, cfg *Config) (*Client, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	client, err := buildClient(ctx, reader, cfg)
	if err != nil {
		if reader != nil {
			err = errors.Join(err, wrapCloseError("closing reader", reader.Close()))
		}
		return nil, err
	}
	return client, nil
}

func buildClient(ctx context.Context, reader usimreader.Reader, cfg *Config) (*Client, error) {
	raw := cloneConfig(cfg)
	logger := raw.Logger
	if logger == nil {
		logger = slog.Default()
	}

	card, err := usim.Load(ctx, reader, logger)
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	raw.Logger = logger
	client, err := newClient(raw, card)
	if err != nil {
		return nil, err
	}
	client.reader = reader
	return client, nil
}

func newClient(cfg Config, card Card) (*Client, error) {
	if card == nil {
		return nil, errors.New("creating client: card is nil")
	}

	normalized, err := cfg.normalized(card)
	if err != nil {
		return nil, fmt.Errorf("creating client: %w", err)
	}

	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	client := &Client{
		cfg:             normalized,
		card:            card,
		logger:          normalized.Logger.With("component", "ims-client"),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		events:          newEventHub(),
		ussdSessions:    make(map[*imsussd.Session]*Session),
	}
	client.sms.client = client
	client.ussd.client = client
	return client, nil
}

func (c *Client) SMS() *SMSService {
	return &c.sms
}

func (c *Client) USSD() *USSDService {
	return &c.ussd
}
