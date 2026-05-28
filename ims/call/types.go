package call

import (
	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"log/slog"
	"sync"
	"time"
)

type Direction string

const (
	DirectionOutgoing Direction = "outgoing"
	DirectionIncoming Direction = "incoming"
)

const (
	mmtelICSI        = "urn:urn-7:3gpp-service.ims.icsi.mmtel"
	mmtelICSIEncoded = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"
)

type State string

const (
	StateDialing    State = "dialing"
	StateRinging    State = "ringing"
	StateEarlyMedia State = "early_media"
	StateAnswering  State = "answering"
	StateConfirmed  State = "confirmed"
	StateActive     State = "active"
	StateEnding     State = "ending"
	StateEnded      State = "ended"
	StateFailed     State = "failed"
)

type Request struct {
	To    string
	Media MediaOffer
}

type Incoming struct {
	Call       *Call
	From       string
	FromURI    string
	FromNumber string
	Offer      MediaOffer
	Received   time.Time
}

type Event struct {
	CallID string
	State  State
	Cause  string
	At     time.Time
}

type Service struct {
	cfg        Config
	sess       *session.Session
	reg        *registration.Service
	logger     *slog.Logger
	attachment session.Attachment
	timers     session.TransactionTimers

	mu        sync.Mutex
	cseq      int64
	nextPort  int
	calls     map[string]*Call
	incomings map[string]*Call
	closed    bool
}

type Call struct {
	service *Service

	mu                 sync.Mutex
	id                 string
	sessionID          string
	direction          Direction
	state              State
	localURI           string
	localTag           string
	remoteURI          string
	remoteTag          string
	remoteTo           string
	targetURI          string
	routeSet           []string
	inviteSeq          int64
	inviteRequest      sip.Message
	inviteResponse     bool
	cancelOnResponse   bool
	cancelSent         bool
	localPort          int
	incomingRequest    *session.Request
	remoteOffer        sdpOffer
	earlyDialogs       map[string]earlyDialog
	inviteOK           sip.Message
	inviteOKStop       chan struct{}
	ringbackStop       chan struct{}
	ringingStop        chan struct{}
	inviteACK          sip.Message
	prackedRSeq        map[string]struct{}
	nextRSeq           int64
	pendingReliable    reliableProvisional
	provisionalReady   chan struct{}
	delayedOffer       bool
	prackAnsweredOffer bool
	provisionalAnswer  bool
	mediaActivity      chan MediaPacket
	mediaWatchStop     chan struct{}
	dialogAttachment   session.Attachment
	media              NegotiatedMedia
	transport          MediaTransport
	rtcpSSRC           uint32
	closed             bool
}

type earlyDialog struct {
	answer               sdpOffer
	hasAnswer            bool
	earlyMediaAuthorized bool
}

type reliableProvisional struct {
	rseq   int64
	cseq   int64
	method string
	status int
}

const (
	inviteOKWriteTimeout = 5 * time.Second
	callReleaseTimeout   = 5 * time.Second
)

const (
	reasonUserTriggered       = `RELEASE_CAUSE;cause=1;text="User ends call"`
	reasonMediaBearerReleased = `RELEASE_CAUSE;cause=3;text="Media bearer loss"`
)

func (c *Call) Direction() Direction {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.direction
}

func (c *Call) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

type rackHeader struct {
	rseq   int64
	cseq   int64
	method string
}
