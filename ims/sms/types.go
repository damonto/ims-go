package sms

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
	"github.com/damonto/uicc-go/usim"
	usimcard "github.com/damonto/uicc-go/usim/card"
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

type Endpoint struct {
	cfg        Config
	sess       *session.Session
	reg        *registration.Registrar
	card       Card
	logger     *slog.Logger
	attachment session.Attachment

	done chan struct{}
	bgWG sync.WaitGroup

	mu        sync.Mutex
	cseq      int64
	rpRef     uint32
	tpRef     uint32
	rpRefs    map[byte]struct{}
	pending   map[string]pendingEntry
	submitted map[string]submittedEntry
	recent    map[string]time.Time
	concat    map[string]concatState
	moState   moTransferState
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

type Submission struct {
	Segments []SubmissionSegment
	Updates  <-chan SubmissionUpdate
}

// PartialSubmissionError reports a multipart SMS failure after at least one
// segment was accepted by the IMS transaction layer.
type PartialSubmissionError struct {
	Submission Submission
	Err        error
}

func (e *PartialSubmissionError) Error() string {
	if e == nil || e.Err == nil {
		return "partial SMS submission"
	}
	return e.Err.Error()
}

func (e *PartialSubmissionError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

type SubmissionState string

const (
	SubmissionSubmittedToIMS SubmissionState = "submitted_to_ims"
	SubmissionAcceptedBySMSC SubmissionState = "accepted_by_smsc"
	SubmissionRejectedBySMSC SubmissionState = "rejected_by_smsc"
	SubmissionSubmitUnknown  SubmissionState = "submit_unknown"
)

type SubmissionUpdate struct {
	Index         int
	Count         int
	Recipient     string
	ServiceCenter string
	CallID        string
	RPReference   byte
	TPReference   byte
	State         SubmissionState
	RPCause       byte
	HasRPCause    bool
	At            time.Time
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
	tracker     *submissionTracker
}

type submissionTracker struct {
	updates   chan SubmissionUpdate
	remaining atomic.Int32
	mu        sync.Mutex
	closed    bool
	closeOnce sync.Once
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
	rpRef             byte
	expiresAt         time.Time
	segment           outboundSegment
	response          submitResponse
	requiresInReplyTo bool
	completed         bool
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

type serviceCenter struct {
	target  string
	address string
}

type moTransferState uint8

const (
	moTransferIdle moTransferState = iota
	moTransferSending
)

type mtTransferState uint8

const (
	mtTransferIdle mtTransferState = iota
	mtTransferActive
)

type serviceCenterProvider interface {
	ServiceCenter() usim.ServiceCenter
}

type ppDownloader interface {
	SMSPPDownload(context.Context, usimcard.SMSPPDownloadRequest) (usimcard.SMSPPDownloadResponse, error)
}

const (
	concatRetention   = 10 * time.Minute
	submitRetention   = 5 * time.Minute
	defaultTR1Timeout = 40 * time.Second
	defaultTR2Timeout = 15 * time.Second
)

const acceptContact = "*;+g.3gpp.smsip;require;explicit"

const (
	sipStatusOK                   = 200
	sipStatusAccepted             = 202
	sipStatusUnsupportedMediaType = 415
	sipStatusNotAcceptableHere    = 488
)

var submitReportTimeoutNanos atomic.Int64

const defaultSubmitReportTimeout = defaultTR1Timeout
