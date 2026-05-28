package sms

import (
	"context"
	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"github.com/damonto/ims-client/usim"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	ServiceCenter       string
	SubmitReportTimeout time.Duration
	OnIncoming          func(Incoming)
	OnStatusReport      func(StatusReport)
	OnError             func(error)
}

type Card interface {
	SMSC() string
}

type Service struct {
	cfg        Config
	sess       *session.Session
	reg        *registration.Service
	card       Card
	logger     *slog.Logger
	attachment session.Attachment

	cleanupCtx    context.Context
	cleanupCancel context.CancelFunc
	cleanupWG     sync.WaitGroup

	mu        sync.Mutex
	cseq      int64
	rpRef     uint32
	rpRefs    map[byte]struct{}
	pending   map[string]pendingEntry
	submitted map[string]submittedEntry
	recent    map[string]time.Time
	concat    map[string]concatState
	moActive  bool
	moSending bool
	moPending int
	mtActive  bool
	closed    bool
}

type SubmissionSegment struct {
	Index       int
	Count       int
	CallID      string
	RPReference byte
	TPReference byte
	SubmittedAt time.Time
}

type outboundSegment struct {
	index            int
	count            int
	to               string
	smscAddress      string
	target           string
	part             userDataPart
	rpRef            byte
	tpRef            byte
	retryCount       int
	rejectDuplicates bool
	callID           string
	msg              sip.Message
	reportCh         <-chan rpMessage
}

type pendingEntry struct {
	rpRef     byte
	reportCh  chan rpMessage
	segment   outboundSegment
	response  submitResponse
	expiresAt time.Time
	async     bool
}

type submittedEntry struct {
	rpRef     byte
	expiresAt time.Time
	segment   outboundSegment
	response  submitResponse
	completed bool
}

type submitResponse struct {
	statusCode   int
	reasonPhrase string
}

type concatState struct {
	total     int
	parts     map[int]string
	updatedAt time.Time
}

type serviceCentre struct {
	target  string
	address string
}

type serviceCentreProvider interface {
	ServiceCentre() usim.ServiceCentre
}

type ppDownloader interface {
	SMSPPDownload(context.Context, usim.SMSPPDownloadRequest) (usim.SMSPPDownloadResponse, error)
}

const (
	concatRetention       = 10 * time.Minute
	submitRetention       = 5 * time.Minute
	deliveryReportTimeout = 30 * time.Second
)

var submitReportTimeoutNanos atomic.Int64

const defaultSubmitReportTimeout = 130 * time.Second
