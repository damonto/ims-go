package ussd

import (
	"encoding/xml"
	"log/slog"
	"net/textproto"
	"sync"
	"time"

	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

const (
	infoPackage                 = "g.3gpp.ussd"
	xmlContentType              = "application/vnd.3gpp.ussd+xml"
	sdpContentType              = "application/sdp"
	mixedMultipartType          = "multipart/mixed"
	acceptHeader                = xmlContentType + ", " + sdpContentType + ", " + mixedMultipartType
	infoPackageDisposition      = "info-package"
	renderOptionalDisposition   = "render;handling=optional"
	handlingDispositionParam    = "handling"
	optionalHandlingDisposition = "optional"
	mmtelICSIEncoded            = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
	icsiRefFeatureTag           = `+g.3gpp.icsi-ref="` + mmtelICSIEncoded + `"`
	midCallFeatureTag           = "+g.3gpp.mid-call"
	nwInitUSSI                  = "+g.3gpp.nw-init-ussi"
	ps2csSRVCCOrigPreAlerting   = "+g.3gpp.ps2cs-srvcc-orig-pre-alerting"
	smsIPFeatureTag             = "+g.3gpp.smsip"
	srvccAlertingFeatureTag     = "+g.3gpp.srvcc-alerting"
	defaultLang                 = "en"
	undefinedLang               = "undefined"
	defaultQueuedRequestTimeout = 30 * time.Second
	inviteOKWriteTimeout        = 5 * time.Second
	inviteOKTimeoutMultiplier   = 64
)

const (
	ErrorCodeUnspecified         = 1
	ErrorCodeLanguageUnsupported = 2
	ErrorCodeUnexpectedDataValue = 3
)

type Domain string

const (
	DomainIMS      Domain = "ims"
	DomainCS       Domain = "cs"
	DomainDisabled Domain = "disabled"
)

const (
	sipStatusTrying                      = 100
	sipStatusOK                          = 200
	sipStatusBadRequest                  = 400
	sipStatusNotFound                    = 404
	sipStatusUnsupportedMediaType        = 415
	sipStatusBadInfoPackage              = 469
	sipStatusCallTransactionDoesNotExist = 481
	sipStatusBusyHere                    = 486
	sipStatusNotAcceptableHere           = 488
	sipStatusServerInternalError         = 500
)

type Config struct {
	Language                  string
	PhoneContextDomain        string
	Domain                    Domain
	NetworkInitiatedSupported bool
	OnIncoming                func(*Session, Message)
	Logger                    *slog.Logger
}

type Message struct {
	Text      string
	Language  string
	ErrorCode int
	Final     bool
	Notify    bool
	Request   bool
}

type Service struct {
	cfg        Config
	sess       *session.Session
	reg        *registration.Service
	logger     *slog.Logger
	attachment session.Attachment
	done       chan struct{}

	mu            sync.Mutex
	sessions      map[string]*Session
	incomingIndex map[string]string
	closed        bool
	cseq          int64
	bgWG          sync.WaitGroup
}

type Session struct {
	service          *Service
	dialogAttachment session.Attachment
	incomingInviteID string
	callID           string
	sessionID        string
	localURI         string
	localTag         string
	remoteTag        string
	remoteTo         string
	targetURI        string
	routeSet         []string
	inviteSeq        int64
	localCSeq        int64
	language         string
	networkInitiated bool
	responseKind     dialogKind
	inviteOK         sip.Message
	inviteOKStop     chan struct{}
	ackCh            chan struct{}
	acked            bool
	state            sessionState
	events           chan Message
	remoteCSeq       int64
	remoteCSeqs      map[string]struct{}
	pendingInitial   *queuedRequest
	deliveringInvite bool

	mu sync.Mutex
}

type dialogKind uint8

const (
	dialogKindNone dialogKind = iota
	dialogKindRequest
	dialogKindNotify
)

type sessionState uint8

const (
	sessionStateActive sessionState = iota
	sessionStateWaitingACK
	sessionStateInfoInFlight
	sessionStateWaitingACKInfoInFlight
	sessionStateClosed
)

type xmlPayload struct {
	XMLName   xml.Name `xml:"ussd-data"`
	Language  string   `xml:"language,omitempty"`
	String    string   `xml:"ussd-string,omitempty"`
	ErrorCode *int     `xml:"error-code,omitempty"`
	AnyExt    *anyExt  `xml:"anyExt,omitempty"`
}

type anyExt struct {
	Request *struct{} `xml:"UnstructuredSS-Request,omitempty"`
	Notify  *struct{} `xml:"UnstructuredSS-Notify,omitempty"`
}

type multipartBodyPart struct {
	Header textproto.MIMEHeader
	Body   []byte
}

type queuedRequest struct {
	msg     sip.Message
	action  sessionAction
	final   bool
	timeout time.Duration
}

type sessionAction uint8

const (
	sessionActionReplyUSSD sessionAction = iota
	sessionActionEndUSSD
)

func (a sessionAction) String() string {
	switch a {
	case sessionActionReplyUSSD:
		return "replying USSD"
	case sessionActionEndUSSD:
		return "ending USSD"
	default:
		return "exchanging USSD"
	}
}

type startRequest struct {
	code      string
	target    string
	callID    string
	sessionID string
	localTag  string
	branch    string
	inviteSeq int64
	language  string
}
