package vowifi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/uicc-go/usim"
	usimcard "github.com/damonto/uicc-go/usim/card"
	imssession "github.com/damonto/vowifi-go/ims/session"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
	imsvoice "github.com/damonto/vowifi-go/ims/voice"
	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
)

type Config struct {
	EPDG              string
	Logger            *slog.Logger
	ReconnectDelay    time.Duration
	ReconnectMaxDelay time.Duration
	Terminal          TerminalInfo
	Tunnel            swutunnel.Config
	IMS               IMSConfig

	smsRequestStatusReport bool
}

type TerminalInfo struct {
	ID              string
	Vendor          string
	Model           string
	SoftwareVersion string
	Build           string
	Type            string
	HardwareSKU     string
}

type IMSConfig struct {
	Transport                string
	PrivateIdentity          string
	PublicIdentity           string
	HomeDomain               string
	PhoneContextDomain       string
	USSDLanguage             string
	USSDDomain               string
	UserAgent                string
	AccessNetworkInfo        string
	WLANNodeID               string
	RegisterExpires          time.Duration
	AuthAlgorithm            string
	RegistrationRetryBase    time.Duration
	RegistrationRetryMax     time.Duration
	ServiceCenter            string
	IMEI                     string
	GeolocationPIDFRegister  []int
	GeolocationCountry       string
	UseTelURIForPIDFXML      bool
	SIPServerPort            int
	SIPTimers                imssession.TransactionTimers
	TCPDataACKTimeouts       []time.Duration
	SMSDeliveryReportTimeout time.Duration
	Voice                    imsvoice.Config

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

type ClientStatus string

const (
	StatusIdle           ClientStatus = "idle"
	StatusConnecting     ClientStatus = "connecting"
	StatusAuthenticating ClientStatus = "authenticating"
	StatusRegistered     ClientStatus = "registered"
	StatusReconnecting   ClientStatus = "reconnecting"
	StatusClosed         ClientStatus = "closed"
	StatusFailed         ClientStatus = "failed"
)

var (
	ErrClientClosed       = errors.New("client is closed")
	ErrClientConnecting   = errors.New("client is connecting")
	ErrClientReconnecting = errors.New("client is reconnecting")
	ErrClientFailed       = errors.New("client failed")
	ErrClientNotConnected = errors.New("client is not connected")
	ErrUSSDNotStarted     = errors.New("ussd session is not started")
	ErrUSSDAlreadyStarted = errors.New("ussd session is already started")
	ErrUSSDClosed         = errors.New("ussd session is closed")
	ErrUSSDInProgress     = errors.New("ussd session operation in progress")
)

type clientState struct {
	done         chan struct{}
	mu           sync.Mutex
	status       ClientStatus
	lastErr      error
	closed       bool
	connecting   bool
	reconnecting bool
	active       *activeConn
	closeWG      sync.WaitGroup
	closeOnce    sync.Once
	swuBackoff   swuBackoffGate
	swuPDNTypes  swuPDNTypeRestrictionGate
	reconnectSeq atomic.Uint64
}

type Client struct {
	cfg    Config
	card   Card
	reader usimcard.Reader
	logger *slog.Logger

	state clientState

	events       eventHub
	sms          SMSService
	ussd         USSDService
	voice        VoiceService
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

func (c *Client) SMS() *SMSService {
	return &c.sms
}

func (c *Client) USSD() *USSDService {
	return &c.ussd
}

func (c *Client) Voice() *VoiceService {
	return &c.voice
}
