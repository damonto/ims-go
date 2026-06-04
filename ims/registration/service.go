package registration

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"github.com/damonto/vowifi-go/usim"
)

const (
	sipStatusOK                          = 200
	sipStatusBadRequest                  = 400
	sipStatusUnauthorized                = 401
	sipStatusForbidden                   = 403
	sipStatusRequestTimeout              = 408
	sipStatusIntervalTooBrief            = 423
	sipStatusCallTransactionDoesNotExist = 481
	sipStatusBadEvent                    = 489
	sipStatusServerInternalError         = 500
	sipStatusServiceUnavailable          = 503
	sipStatusServerTimeout               = 504
)

type Config struct {
	PrivateIdentity         string
	PublicIdentity          string
	HomeDomain              string
	UserAgent               string
	AccessNetworkInfo       string
	WLANNodeID              string
	RegisterExpires         time.Duration
	IMEI                    string
	AuthAlgorithm           string
	GeolocationPIDFRegister []int
	GeolocationCountry      string
	UseTelURIForPIDFXML     bool
	Logger                  *slog.Logger

	DialSecureTCP   func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error)
	DialSecureUDP   func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error)
	ListenSecureTCP func(ctx context.Context, cfg session.SecureTCPConfig) (session.Transport, error)
	ListenSecureUDP func(ctx context.Context, cfg session.SecureUDPConfig) (session.Transport, error)
}

type Card interface {
	IMSI() string
	MCC() string
	MNC() string
	AKA(ctx context.Context, rand, autn []byte) (usim.AKAResult, error)
}

type IdentityProvider interface {
	PrivateIdentity() string
	PublicIdentity() string
	HomeDomain() string
}

type State struct {
	Registered          bool
	PublicIdentity      string
	DefaultPublicID     string
	PrivateIdentity     string
	HomeDomain          string
	RegisterURI         string
	SIPPublicID         string
	TelPublicID         string
	Flow                Flow
	ServiceRoutes       []string
	SecurityClient      security.Param
	SecurityClients     security.Params
	SecurityVerify      *security.Param
	RegisterExpires     time.Duration
	ContactHost         string
	RegisterPort        int
	MessagePort         int
	UserAgent           string
	AccessNetworkInfo   string
	IMEI                string
	GeolocationCountry  string
	UseTelURIForPIDFXML bool
}

type Service struct {
	cfg        Config
	sess       *session.Session
	card       Card
	logger     *slog.Logger
	attachment session.Attachment

	mu                  sync.Mutex
	state               State
	flow                Flow
	authCK              []byte
	authIK              []byte
	authNonce           string
	authRealm           string
	authAlgorithm       string
	authQOP             string
	authNonceCount      uint32
	authDigestNonce     string
	authDigestAlgorithm string
	authDigestPassword  string
	callID              string
	sessionID           string
	tag                 string
	cseq                int64

	subscribeExpires     time.Duration
	subscribeUnsupported bool
	subscription         subscriptionDialog
	regInfoVersion       int
	regInfoVersionSet    bool

	registrationEvents        chan error
	subscribeRefreshRequests  chan struct{}
	registrationGate          chan struct{}
	done                      chan struct{}
	secureServerAttachments   []session.Attachment
	secureResponseAttachments []session.Attachment
	drainTimers               []*attachmentDrain
	activeSecureSAExpiresAt   time.Time
	activeSecureSAExpiry      *secureAssociationExpiry
	bgWG                      sync.WaitGroup
	closed                    bool
}

const defaultIMSExpires = 600000 * time.Second
const secureAssociationLifetimeGrace = 30 * time.Second
const maxSIPCSeq = 1<<31 - 1

func New(cfg Config, sess *session.Session, card Card) (*Service, error) {
	cfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}

	identity, err := resolveIdentity(cfg, card)
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}
	host, port, err := resolveLocalAddr(sess.LocalAddr())
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}
	callID, sessionID, tag, _ := sip.NewTransaction()
	svc := &Service{
		cfg:    cfg,
		sess:   sess,
		card:   card,
		logger: cfg.Logger.With("component", "ims-registration"),
		state: State{
			PublicIdentity:      identity.publicIdentity,
			DefaultPublicID:     identity.publicIdentity,
			PrivateIdentity:     identity.privateIdentity,
			HomeDomain:          identity.realm,
			RegisterURI:         "sip:" + identity.realm,
			RegisterExpires:     cfg.RegisterExpires,
			UserAgent:           cfg.UserAgent,
			AccessNetworkInfo:   accessNetworkInfo(cfg),
			IMEI:                cfg.IMEI,
			GeolocationCountry:  cfg.GeolocationCountry,
			UseTelURIForPIDFXML: cfg.UseTelURIForPIDFXML,
		},
		flow:                     newFlow(host, port),
		callID:                   callID,
		sessionID:                sessionID,
		tag:                      tag,
		registrationEvents:       make(chan error, 1),
		subscribeRefreshRequests: make(chan struct{}, 1),
		registrationGate:         make(chan struct{}, 1),
		done:                     make(chan struct{}),
	}
	attachment, err := sess.Attach(svc)
	if err != nil {
		return nil, fmt.Errorf("creating registration service: %w", err)
	}
	svc.attachment = attachment
	return svc, nil
}
