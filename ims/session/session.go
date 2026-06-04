package session

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/sip"
)

type Transport interface {
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	WritePacket(ctx context.Context, data []byte) error
	ReadPacket(ctx context.Context) ([]byte, net.Addr, error)
	Close() error
}

type SecureTCPConfig struct {
	LocalPort       int
	RemotePort      int
	DataACKTimeouts []time.Duration
	OutboundSPI     uint32
	InboundSPI      uint32
	Encryption      string
	EncryptionKey   []byte
	Integrity       string
	IntegrityKey    []byte
}

type SecureUDPConfig struct {
	LocalPort     int
	RemotePort    int
	OutboundSPI   uint32
	InboundSPI    uint32
	Encryption    string
	EncryptionKey []byte
	Integrity     string
	IntegrityKey  []byte
}

type Config struct {
	Transport         string
	Logger            *slog.Logger
	TransactionTimers TransactionTimers
	ResponseDecorator func(*sip.Message)
}

type Request struct {
	Message   sip.Message
	Transport Transport
	PeerAddr  net.Addr
}

const (
	sipStatusOK                          = 200
	sipStatusTrying                      = 100
	sipStatusMethodNotAllowed            = 405
	sipStatusCallTransactionDoesNotExist = 481
	sipStatusRequestTerminated           = 487
	sipStatusServiceUnavailable          = 503
)

type Handler interface {
	HandleRequest(ctx context.Context, req Request) (bool, error)
	HandleError(err error)
}

type ResponseHandler interface {
	HandleResponse(ctx context.Context, msg sip.Message) (bool, error)
}

type ExchangeOptions struct {
	OnProvisional           func(sip.Message)
	AcceptResponseTransport func(Transport) bool
	ResponseTransports      []Transport
}

type Attachment interface {
	Close() error
}

type TransportAttachment interface {
	Attachment
	Transport() Transport
}

type Session struct {
	cfg    Config
	logger *slog.Logger

	mu             sync.Mutex
	sendMu         sync.Mutex
	readWG         sync.WaitGroup
	primary        Transport
	aux            []Transport
	active         map[Transport]struct{}
	responseRoutes map[Transport]Transport
	runtime        *runtimeState
	dialogs        map[string][]*dialogEntry
	transactions   map[string]*clientTransaction
	serverTxs      map[string]*serverTransaction
	txChanged      chan struct{}
	handlers       []*handlerEntry
	startedCh      chan struct{}
	closedCh       chan struct{}
	closed         bool
	started        bool
	ready          bool
	running        bool

	responseDecorator func(*sip.Message)
	notifyOnce        sync.Once
}

type handlerEntry struct {
	session *Session
	handler Handler
	closed  bool
}

type transportAttachment struct {
	session   *Session
	transport Transport
	closed    bool
}

type responseRouteAttachment struct {
	session *Session
	from    Transport
	to      Transport
	closed  bool
}

type runtimeState struct {
	ctx     context.Context
	inbound chan<- inboundMessage
}

type inboundMessage struct {
	msg       sip.Message
	transport Transport
	peer      net.Addr
	err       error
}

type targetedPacketWriter interface {
	WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error
}

func Open(cfg Config, primary Transport) (*Session, error) {
	if primary == nil {
		return nil, errors.New("opening session: primary transport is nil")
	}
	cfg, err := cfg.Normalized()
	if err != nil {
		return nil, fmt.Errorf("opening session: %w", err)
	}
	return &Session{
		cfg:            cfg,
		logger:         cfg.Logger.With("component", "ims-session"),
		primary:        primary,
		active:         map[Transport]struct{}{primary: {}},
		responseRoutes: make(map[Transport]Transport),
		dialogs:        make(map[string][]*dialogEntry),
		transactions:   make(map[string]*clientTransaction),
		serverTxs:      make(map[string]*serverTransaction),
		txChanged:      make(chan struct{}),
		startedCh:      make(chan struct{}),
		closedCh:       make(chan struct{}),
	}, nil
}

func (cfg Config) Normalized() (Config, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	timers, err := cfg.TransactionTimers.Normalized()
	if err != nil {
		return Config{}, err
	}
	cfg.TransactionTimers = timers
	return cfg, nil
}

func (s *Session) TransactionTimers() TransactionTimers {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg.TransactionTimers
}
