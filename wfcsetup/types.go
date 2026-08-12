package wfcsetup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	usim "github.com/damonto/wwan-go/sim"
)

const defaultTimeout = 30 * time.Second

var (
	ErrUserActionRequired       = errors.New("wfc setup requires user action")
	ErrPending                  = errors.New("wfc setup is pending")
	ErrDenied                   = errors.New("wfc setup denied")
	ErrExternalCredentialNeeded = errors.New("wfc setup requires external carrier credential")
	ErrNotImplemented           = errors.New("wfc setup flow is not implemented")
	errAKAAuthenticatorRequired = errors.New("AKA authenticator is required")
)

type Purpose int

const (
	PurposeActivation Purpose = iota
	PurposeActivationRecheck
	PurposeEmergencyAddressUpdate
	PurposeEmergencyAddressRecheck
)

func (p Purpose) valid() bool {
	switch p {
	case PurposeActivation, PurposeActivationRecheck, PurposeEmergencyAddressUpdate, PurposeEmergencyAddressRecheck:
		return true
	default:
		return false
	}
}

type Scheme string

const (
	SchemeNone   Scheme = ""
	SchemeTS43   Scheme = "ts43"
	SchemeNSDS   Scheme = "nsds"
	SchemeCanada Scheme = "canada"
	SchemeTelus  Scheme = "telus"
	SchemeO2UK   Scheme = "o2uk"
	SchemeVZW    Scheme = "vzw"
)

type Action int

const (
	ActionNone Action = iota
	ActionAllowActivation
	ActionOpenWebsheet
	ActionWait
	ActionDenied
	ActionDisableWFC
)

type WebsheetKind string

const (
	WebsheetKindEmergencyAddress   WebsheetKind = "emergency-address"
	WebsheetKindTermsAndConditions WebsheetKind = "terms-and-conditions"
)

type Websheet struct {
	Kind       WebsheetKind
	URL        string
	Data       string
	Title      string
	ClientName string
}

type E911Info struct {
	AddressID     string
	AIDExpiration time.Time
	ServerURL     string
	ServerData    string
}

const e911AIDMinimumValidity = 48 * time.Hour

func (i E911Info) ValidAt(now time.Time) bool {
	if i.AIDExpiration.IsZero() {
		return false
	}
	return i.AIDExpiration.Sub(now) >= e911AIDMinimumValidity
}

type Result struct {
	Scheme     Scheme
	Carrier    string
	Action     Action
	Entitled   bool
	Pending    bool
	RetryAfter time.Duration
	Websheet   *Websheet
	E911       *E911Info
	Token      *CarrierToken
	MSISDN     string
}

type CarrierToken struct {
	Type  string
	Value string
}

type Error struct {
	Err    error
	Result Result
}

func (e *Error) Error() string {
	if e.Result.Websheet != nil && e.Result.Websheet.URL != "" {
		return e.Err.Error() + ": " + e.Result.Websheet.URL
	}
	return e.Err.Error()
}

func (e *Error) Unwrap() error {
	return e.Err
}

type Card interface {
	ICCID() string
	IMSI() string
	MCC() string
	MNC() string
	MNCLength() int
	GID1() string
}

// AKAAuthenticator performs one USIM EAP-AKA calculation for a setup flow.
// The caller owns any serialization or card-session policy around the call.
type AKAAuthenticator func(context.Context, []byte, []byte) (usim.AKAResult, error)

type Device struct {
	IMEI            string
	Vendor          string
	Model           string
	SoftwareVersion string
}

func (d Device) Trimmed() Device {
	return Device{
		IMEI:            strings.TrimSpace(d.IMEI),
		Vendor:          strings.TrimSpace(d.Vendor),
		Model:           strings.TrimSpace(d.Model),
		SoftwareVersion: strings.TrimSpace(d.SoftwareVersion),
	}
}

type Request struct {
	Card            Card
	AuthenticateAKA AKAAuthenticator
	Device          Device
	Purpose         Purpose
	CurrentE911     *E911Info
	Now             time.Time
	Logger          *slog.Logger
	HTTPClient      *http.Client
}

func (r Request) validate() error {
	if r.Card == nil {
		return errors.New("wfc setup card is required")
	}
	if !r.Purpose.valid() {
		return fmt.Errorf("wfc setup purpose %d is invalid", r.Purpose)
	}
	return nil
}

func (r Request) now() time.Time {
	if r.Now.IsZero() {
		return time.Now()
	}
	return r.Now
}

func (r Request) logger() *slog.Logger {
	if r.Logger != nil {
		return r.Logger
	}
	return slog.Default()
}

type E911UpdateSupport struct {
	Supported                  bool
	BuiltIn                    bool
	Scheme                     Scheme
	Carrier                    string
	RequiresExternalCredential bool
	Reason                     string
}
