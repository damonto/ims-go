package ussd

import (
	"context"
	"encoding/xml"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"log/slog"
	"net/textproto"
	"sync"
	"time"
)

const (
	infoPackage                 = "g.3gpp.ussd"
	xmlContentType              = "application/vnd.3gpp.ussd+xml"
	mixedMultipartType          = "multipart/mixed"
	defaultLang                 = "en"
	defaultQueuedRequestTimeout = 30 * time.Second
)

type Config struct {
	Language           string
	PhoneContextDomain string
	OnIncoming         func(*Session, Message)
	Logger             *slog.Logger
}

type Message struct {
	Text      string
	Language  string
	ErrorCode int
	Final     bool
	Notify    bool
	Request   bool
}

type USSDMessage = Message

type Service struct {
	cfg           Config
	sess          *session.Session
	reg           *registration.Service
	logger        *slog.Logger
	attachment    session.Attachment
	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc

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
	language         string
	networkInitiated bool
	responseKind     dialogKind
	inviteOK         sip.Message
	ackCh            chan struct{}
	acked            bool
	awaitingInfo     bool
	events           chan Message
	remoteCSeqs      map[string]struct{}
	pendingInitial   *queuedRequest
	deliveringInvite bool

	mu     sync.Mutex
	closed bool
}

type USSDSession = Session

type dialogKind uint8

const (
	dialogKindNone dialogKind = iota
	dialogKindRequest
	dialogKindNotify
)

type xmlPayload struct {
	XMLName   xml.Name `xml:"ussd-data"`
	Language  string   `xml:"language,omitempty"`
	String    string   `xml:"ussd-string,omitempty"`
	ErrorCode int      `xml:"error-code,omitempty"`
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
	action  string
	final   bool
	timeout time.Duration
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
