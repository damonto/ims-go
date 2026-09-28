package voice

import (
	"log/slog"
	"sync"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

type CallDirection string

const (
	CallDirectionOutgoing CallDirection = "outgoing"
	CallDirectionIncoming CallDirection = "incoming"
)

const (
	mmtelICSI        = "urn:urn-7:3gpp-service.ims.icsi.mmtel"
	mmtelICSIEncoded = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"

	emergencyServiceURNSOS = "urn:endpoint:sos"

	currentLocationDiscoveryInfoPackage = "g.3gpp.current-location-discovery"
	currentLocationDiscoveryContentType = "application/vnd.3gpp.current-location-discovery+xml"
	currentLocationDiscoveryDisposition = "info-package"
	presenceEventPackage                = "presence"

	reliableProvisionalOption = "100rel"
)

const (
	sipStatusTrying                      = 100
	sipStatusRinging                     = 180
	sipStatusSessionProgress             = 183
	sipStatusEarlyDialogTerminated       = 199
	sipStatusOK                          = 200
	sipStatusMultipleChoices             = 300
	sipStatusBadRequest                  = 400
	sipStatusRequestTimeout              = 408
	sipStatusUnsupportedMediaType        = 415
	sipStatusBadExtension                = 420
	sipStatusSessionIntervalTooSmall     = 422
	sipStatusBadInfoPackage              = 469
	sipStatusCallTransactionDoesNotExist = 481
	sipStatusBusyHere                    = 486
	sipStatusRequestTerminated           = 487
	sipStatusNotAcceptableHere           = 488
	sipStatusPreconditionFailure         = 580
	sipStatusRequestPending              = 491
	sipStatusServerInternalError         = 500
)

type CallState string

const (
	CallStateDialing    CallState = "dialing"
	CallStateRinging    CallState = "ringing"
	CallStateEarlyMedia CallState = "early_media"
	CallStateAnswering  CallState = "answering"
	CallStateConfirmed  CallState = "confirmed"
	CallStateActive     CallState = "active"
	CallStateEnding     CallState = "ending"
	CallStateEnded      CallState = "ended"
	CallStateFailed     CallState = "failed"
)

type CallHoldState string

const (
	CallHoldNone        CallHoldState = "none"
	CallHoldLocal       CallHoldState = "local"
	CallHoldRemote      CallHoldState = "remote"
	CallHoldLocalRemote CallHoldState = "local_remote"
)

type DialRequest struct {
	To           string
	Media        MediaOffer
	Emergency    bool
	EmergencyURN string
}

type IncomingCall struct {
	Call       *Call
	From       string
	FromURI    string
	FromNumber string
	Offer      MediaDescription
	Received   time.Time
}

type CallEvent struct {
	Call   *Call
	CallID string
	State  CallState
	Hold   CallHoldState
	Cause  string
	At     time.Time
}

// MediaEvent reports an initial or updated negotiated media description.
type MediaEvent struct {
	Call   *Call
	CallID string
	Media  NegotiatedMedia
	At     time.Time
}

type Endpoint struct {
	cfg                    Config
	sess                   *session.Stack
	reg                    *registration.Registrar
	logger                 *slog.Logger
	attachment             session.Attachment
	timers                 session.TransactionTimers
	rtcpInterval           func(NegotiatedMedia) time.Duration
	preconditionRetryDelay func(CallDirection) time.Duration

	mu        sync.Mutex
	cseq      int64
	nextPort  int
	calls     map[string]*Call
	incomings map[string]*Call
	bgDone    chan struct{}
	bgWG      sync.WaitGroup
	closed    bool
}

type Call struct {
	endpoint *Endpoint

	mu                    sync.Mutex
	mediaSendMu           sync.Mutex
	preconditionUpdateMu  sync.Mutex
	id                    string
	sessionID             string
	direction             CallDirection
	state                 CallState
	localURI              string
	localTag              string
	remoteURI             string
	remoteTag             string
	remoteTo              string
	remoteAllow           string
	targetURI             string
	routeSet              []string
	inviteSeq             int64
	localCSeq             int64
	inviteRequest         sip.Message
	localSDP              []byte
	inviteResponse        bool
	cancelOnResponse      bool
	cancelSent            bool
	inviteCancel          func()
	cancelledInviteStop   chan struct{}
	localINVITEPending    bool
	refreshGlareRetried   bool
	remoteINVITEPending   bool
	remoteINVITECSeq      int64
	remoteCSeq            int64
	localPort             int
	localQoSStatus        string
	incomingRequest       *session.Request
	preconditions         bool
	incomingMediaReady    bool
	incomingConfirmations int
	incomingAlerting      bool
	incomingAlerted       bool
	incomingQoS           incomingQoSState
	incomingUnknown       []incomingUnknownPrecondition
	incomingOffer         MediaDescription
	incomingReceived      time.Time
	remoteSDP             []byte
	remoteOffer           sdpOffer
	remotePayloads        map[int]rtpPayloadMapping
	earlyDialogs          map[string]earlyDialog
	inviteOK              sip.Message
	inviteOKStop          chan struct{}
	inviteOKCSeq          int64
	ringbackStop          chan struct{}
	ringingStop           chan struct{}
	preconditionStop      chan struct{}
	inviteACK             sip.Message
	reliableRSeq          map[string]int64
	reliableStop          chan struct{}
	nextRSeq              int64
	pendingReliable       reliableProvisional
	reliableResponse      sip.Message
	provisionalReady      chan struct{}
	delayedOffer          bool
	prackAnsweredOffer    bool
	provisionalAnswer     bool
	provisionalCompleting bool
	mediaActivity         chan MediaPacket
	mediaWatchStop        chan struct{}
	sessionTimer          sessionTimerState
	sessionTimerStop      chan struct{}
	dialogAttachment      session.Attachment
	media                 NegotiatedMedia
	dtmfRecv              dtmfReceiveState
	rtpSend               rtpSendState
	rtcpSend              rtcpSendState
	rtcpRecv              rtcpReceiveState
	hold                  CallHoldState
	localHoldRTCPOff      bool
	transport             MediaTransport
	mediaGeneration       uint64
	mediaResource         mediaResourceKey
	qosMediaResource      mediaResourceKey
	callDone              chan struct{}
	rtcpSSRC              uint32
	emergency             bool
	currentLocation       bool
	closed                bool
}

type incomingQoSState struct {
	desired      qosDesiredStatus
	remoteStatus string
}

type incomingUnknownPrecondition struct {
	preconditionType string
	direction        string
	remoteStatus     string
}

type rtpSendState struct {
	initialized   bool
	ssrc          uint32
	nextSequence  uint16
	nextTimestamp uint32
}

type rtcpSendState struct {
	packetCount       uint32
	octetCount        uint32
	lastRTPTimestamp  uint32
	lastRTPSentAt     time.Time
	lastRTPClockRate  int
	reportsWithoutRTP int
}

type rtcpReceiveState struct {
	initialized   bool
	ssrc          uint32
	baseSequence  uint16
	maxSequence   uint16
	cycles        uint32
	received      uint32
	expectedPrior uint32
	receivedPrior uint32
	jitter        uint32
	transit       int64
	lastArrival   time.Time
}

type earlyDialog struct {
	answer               sdpOffer
	hasAnswer            bool
	earlyMediaAuthorized bool
	remoteTarget         string
	routeSet             []string
}

type reliableProvisional struct {
	rseq   int64
	cseq   int64
	method string
	status int
}

type sessionTimerState struct {
	active         bool
	interval       time.Duration
	minSE          int
	localRefresher bool
}

const (
	inviteOKWriteTimeout = 5 * time.Second
	callReleaseTimeout   = 5 * time.Second
)

const (
	reasonUserTriggered       = `RELEASE_CAUSE;cause=1;text="User ends call"`
	reasonMediaTimeout        = `RELEASE_CAUSE;cause=2;text="RTP/RTCP time-out"`
	reasonMediaBearerReleased = `RELEASE_CAUSE;cause=3;text="Media bearer loss"`
)

type mediaReleaseReason int

const (
	mediaReleaseRTPTimeout mediaReleaseReason = iota
	mediaReleaseRTCPTimeout
	mediaReleaseRTCPBye
)

func (r mediaReleaseReason) cause() string {
	switch r {
	case mediaReleaseRTPTimeout:
		return "rtp inactivity timeout"
	case mediaReleaseRTCPTimeout:
		return "rtcp inactivity timeout"
	case mediaReleaseRTCPBye:
		return "rtcp bye"
	default:
		return "media release"
	}
}

func (r mediaReleaseReason) sipReason() string {
	switch r {
	case mediaReleaseRTPTimeout, mediaReleaseRTCPTimeout:
		return reasonMediaTimeout
	case mediaReleaseRTCPBye:
		return reasonMediaBearerReleased
	default:
		return reasonMediaBearerReleased
	}
}

func (c *Call) Direction() CallDirection {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.direction
}

func (c *Call) State() CallState {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

type rackHeader struct {
	rseq   int64
	cseq   int64
	method string
}
