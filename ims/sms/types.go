package sms

import (
	"context"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"github.com/damonto/vowifi-go/usim"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

type Config struct {
	ServiceCenter         string
	SubmitReportTimeout   time.Duration
	DeliveryReportTimeout time.Duration
	RequestStatusReport   bool
	OnIncoming            func(Incoming)
	OnStatusReport        func(StatusReport)
	OnError               func(error)
	Logger                *slog.Logger
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
	moState   moTransferState
	moPending int
	mtState   mtTransferState
	closed    bool
}

type SubmissionSegment struct {
	Index         int
	Count         int
	Recipient     string
	ServiceCenter string
	CallID        string
	RPReference   byte
	TPReference   byte
	SubmittedAt   time.Time
}

type outboundSegment struct {
	index       int
	count       int
	to          string
	recipient   string
	smscAddress string
	target      string
	part        userDataPart
	rpRef       byte
	tpRef       byte
	callID      string
	msg         sip.Message
	reportCh    <-chan rpMessage
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
	total       int
	parts       map[int]string
	rawTPDUs    map[int][]byte
	reservedMTI bool
	updatedAt   time.Time
}

type serviceCentre struct {
	target  string
	address string
}

type moTransferState uint8

const (
	moTransferIdle moTransferState = iota
	moTransferSending
	moTransferWaitingReports
)

type mtTransferState uint8

const (
	mtTransferIdle mtTransferState = iota
	mtTransferActive
)

type serviceCentreProvider interface {
	ServiceCentre() usim.ServiceCentre
}

type ppDownloader interface {
	SMSPPDownload(context.Context, usim.SMSPPDownloadRequest) (usim.SMSPPDownloadResponse, error)
}

const (
	concatRetention   = 10 * time.Minute
	submitRetention   = 5 * time.Minute
	defaultTR1Timeout = 40 * time.Second
	defaultTR2Timeout = 15 * time.Second
)

const smsAcceptContact = "*;+g.3gpp.smsip;require;explicit"

const (
	sipStatusOK                   = 200
	sipStatusAccepted             = 202
	sipStatusUnsupportedMediaType = 415
	sipStatusNotAcceptableHere    = 488
)

var submitReportTimeoutNanos atomic.Int64

const defaultSubmitReportTimeout = defaultTR1Timeout
