package vowifi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	imssession "github.com/damonto/vowifi-go/ims/session"
	imssms "github.com/damonto/vowifi-go/ims/sms"
	imsussd "github.com/damonto/vowifi-go/ims/ussd"
	imsvoice "github.com/damonto/vowifi-go/ims/voice"
	swutunnel "github.com/damonto/vowifi-go/swu/tunnel"
	"github.com/damonto/vowifi-go/usim"
	usimreader "github.com/damonto/vowifi-go/usim/reader"
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
	SMSSubmitReportTimeout   time.Duration
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
	CallID        string
	From          string
	To            string
	ServiceCenter string
	Text          string
	ReceivedAt    time.Time
}

type SMSReportStatus = imssms.ReportStatus
type SMSReportStatusClass = imssms.ReportStatusClass

const (
	SMSReportStatusClassCompleted              SMSReportStatusClass = imssms.ReportStatusClassCompleted
	SMSReportStatusClassTemporaryErrorRetrying SMSReportStatusClass = imssms.ReportStatusClassTemporaryErrorRetrying
	SMSReportStatusClassPermanentError         SMSReportStatusClass = imssms.ReportStatusClassPermanentError
	SMSReportStatusClassTemporaryErrorNoRetry  SMSReportStatusClass = imssms.ReportStatusClassTemporaryErrorNoRetry

	SMSReportStatusReceivedBySME             SMSReportStatus = imssms.ReportStatusReceivedBySME
	SMSReportStatusForwardedUnconfirmed      SMSReportStatus = imssms.ReportStatusForwardedUnconfirmed
	SMSReportStatusReplacedByServiceCenter   SMSReportStatus = imssms.ReportStatusReplacedByServiceCenter
	SMSReportStatusRetryingCongestion        SMSReportStatus = imssms.ReportStatusRetryingCongestion
	SMSReportStatusRetryingSMEBusy           SMSReportStatus = imssms.ReportStatusRetryingSMEBusy
	SMSReportStatusRetryingNoResponseFromSME SMSReportStatus = imssms.ReportStatusRetryingNoResponseFromSME
	SMSReportStatusRetryingServiceRejected   SMSReportStatus = imssms.ReportStatusRetryingServiceRejected
	SMSReportStatusRetryingQoSUnavailable    SMSReportStatus = imssms.ReportStatusRetryingQoSUnavailable
	SMSReportStatusRetryingErrorInSME        SMSReportStatus = imssms.ReportStatusRetryingErrorInSME

	SMSReportStatusPermanentRemoteProcedureError    SMSReportStatus = imssms.ReportStatusPermanentRemoteProcedureError
	SMSReportStatusPermanentIncompatibleDestination SMSReportStatus = imssms.ReportStatusPermanentIncompatibleDestination
	SMSReportStatusPermanentConnectionRejectedBySME SMSReportStatus = imssms.ReportStatusPermanentConnectionRejectedBySME
	SMSReportStatusPermanentNotObtainable           SMSReportStatus = imssms.ReportStatusPermanentNotObtainable
	SMSReportStatusPermanentQoSUnavailable          SMSReportStatus = imssms.ReportStatusPermanentQoSUnavailable
	SMSReportStatusPermanentNoInterworking          SMSReportStatus = imssms.ReportStatusPermanentNoInterworking
	SMSReportStatusPermanentValidityExpired         SMSReportStatus = imssms.ReportStatusPermanentValidityExpired
	SMSReportStatusPermanentDeletedByOriginatingSME SMSReportStatus = imssms.ReportStatusPermanentDeletedByOriginatingSME
	SMSReportStatusPermanentDeletedByServiceCenter  SMSReportStatus = imssms.ReportStatusPermanentDeletedByServiceCenter
	SMSReportStatusPermanentSMDoesNotExist          SMSReportStatus = imssms.ReportStatusPermanentSMDoesNotExist

	SMSReportStatusNoRetryCongestion        SMSReportStatus = imssms.ReportStatusNoRetryCongestion
	SMSReportStatusNoRetrySMEBusy           SMSReportStatus = imssms.ReportStatusNoRetrySMEBusy
	SMSReportStatusNoRetryNoResponseFromSME SMSReportStatus = imssms.ReportStatusNoRetryNoResponseFromSME
	SMSReportStatusNoRetryServiceRejected   SMSReportStatus = imssms.ReportStatusNoRetryServiceRejected
	SMSReportStatusNoRetryQoSUnavailable    SMSReportStatus = imssms.ReportStatusNoRetryQoSUnavailable
	SMSReportStatusNoRetryErrorInSME        SMSReportStatus = imssms.ReportStatusNoRetryErrorInSME
)

type SMSReport struct {
	SubmissionID          string
	SegmentIndex          int
	SegmentCount          int
	ServiceCenter         string
	Recipient             string
	MessageReference      byte
	Status                SMSReportStatus
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
	Index         int
	SubmittedAt   time.Time
	Recipient     string
	ServiceCenter string
	CallID        string
	RPReference   byte
	TPReference   byte
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

type VoiceEvents struct {
	Incoming <-chan IncomingCall
	Events   <-chan CallEvent

	closeOnce sync.Once
	closeFn   func()
}

func (e *VoiceEvents) Close() {
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
	reader usimreader.Reader
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
	reconnectFn  func(error) (*activeConn, error)

	events       eventHub
	swuBackoff   swuBackoffGate
	sms          SMSService
	ussd         USSDService
	voice        VoiceService
	smsSeq       atomic.Uint64
	smsReportsMu sync.Mutex
	smsReports   map[byte][]smsReportLink
	ussdSessions map[*imsussd.Session]*Session
}

type SMSService struct {
	client *Client
}

type smsReportLink struct {
	submissionID  string
	segmentIndex  int
	segmentCount  int
	recipient     string
	serviceCenter string
}

type USSDService struct {
	client *Client
}

type VoiceService struct {
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

// New takes ownership of reader. The SIM state is loaded by Connect(ctx), so
// callers can cancel the first connect attempt with ctx.
// On construction failure it closes reader before returning the error.
// The returned Client closes the underlying reader when Close is called.
func New(reader usimreader.Reader, cfg *Config) (*Client, error) {
	if reader == nil {
		return nil, errors.New("creating client: reader is nil")
	}
	raw := cloneConfig(cfg)
	if raw.Logger == nil {
		raw.Logger = slog.Default()
	}
	raw = raw.trimmed()
	if err := raw.validate(); err != nil {
		return nil, errors.Join(fmt.Errorf("creating client: %w", err), wrapCloseError("closing reader", reader.Close()))
	}
	raw.Terminal = raw.Terminal.trimmed()
	if raw.Terminal.ID == "" {
		return nil, errors.Join(errors.New("creating client: terminal id is empty"), wrapCloseError("closing reader", reader.Close()))
	}
	client := newClient(raw)
	client.reader = reader
	return client, nil
}

func newClient(cfg Config) *Client {
	lifecycleCtx, lifecycleCancel := context.WithCancel(context.Background())
	client := &Client{
		cfg:             cfg,
		logger:          cfg.Logger.With("component", "vowifi-go"),
		lifecycleCtx:    lifecycleCtx,
		lifecycleCancel: lifecycleCancel,
		events:          newEventHub(),
		smsReports:      make(map[byte][]smsReportLink),
		ussdSessions:    make(map[*imsussd.Session]*Session),
	}
	client.reconnectFn = client.reconnect
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
