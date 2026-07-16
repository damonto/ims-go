package registration

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const (
	regInfoNamespace                   = "urn:ietf:params:xml:ns:reginfo"
	regInfoContentType                 = "application/reginfo+xml"
	regEventPackage                    = "reg"
	regInfoStateFull                   = "full"
	regInfoStatePartial                = "partial"
	regInfoRegistrationStateInit       = "init"
	regInfoRegistrationStateActive     = "active"
	regInfoRegistrationStateTerminated = "terminated"
	regInfoContactStateActive          = "active"
	regInfoContactStateTerminated      = "terminated"
	regInfoContactEventRegistered      = "registered"
	regInfoContactEventCreated         = "created"
	regInfoContactEventRefreshed       = "refreshed"
	regInfoContactEventShortened       = "shortened"
	regInfoContactEventExpired         = "expired"
	regInfoContactEventDeactivated     = "deactivated"
	regInfoContactEventProbation       = "probation"
	regInfoContactEventUnregistered    = "unregistered"
	regInfoContactEventRejected        = "rejected"
)

type regInfo struct {
	XMLName      xml.Name              `xml:"urn:ietf:params:xml:ns:reginfo reginfo"`
	Version      string                `xml:"version,attr"`
	State        string                `xml:"state,attr"`
	Registration []regInfoRegistration `xml:"urn:ietf:params:xml:ns:reginfo registration"`
}

type regInfoRegistration struct {
	ID      string           `xml:"id,attr"`
	AOR     string           `xml:"aor,attr"`
	State   string           `xml:"state,attr"`
	Contact []regInfoContact `xml:"urn:ietf:params:xml:ns:reginfo contact"`
}

type regInfoContact struct {
	ID                 string                `xml:"id,attr"`
	State              string                `xml:"state,attr"`
	Event              string                `xml:"event,attr"`
	DurationRegistered string                `xml:"duration-registered,attr"`
	ExpiresAttr        string                `xml:"expires,attr"`
	RetryAfter         string                `xml:"retry-after,attr"`
	Q                  string                `xml:"q,attr"`
	CallID             string                `xml:"callid,attr"`
	CSeq               string                `xml:"cseq,attr"`
	URI                string                `xml:"urn:ietf:params:xml:ns:reginfo uri"`
	Unknown            []regInfoUnknownParam `xml:"urn:ietf:params:xml:ns:reginfo unknown-param"`
}

type regInfoUnknownParam struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

func parseRegInfo(body []byte) (regInfo, bool, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return regInfo{}, false, nil
	}
	var info regInfo
	if err := info.UnmarshalText(body); err != nil {
		return regInfo{}, false, err
	}
	return info, true, nil
}

func (i *regInfo) UnmarshalText(text []byte) error {
	if len(bytes.TrimSpace(text)) == 0 {
		*i = regInfo{}
		return nil
	}
	return xml.Unmarshal(text, i)
}

func (i regInfo) MarshalText() ([]byte, error) {
	if _, ok := i.version(); !ok {
		return nil, fmtRegInfoError("version must be a 32-bit non-negative integer")
	}
	state := strings.TrimSpace(i.State)
	if state != regInfoStateFull && state != regInfoStatePartial {
		return nil, fmtRegInfoError("state must be full or partial")
	}
	if err := i.validate(); err != nil {
		return nil, err
	}
	type regInfoXML regInfo
	out := regInfoXML(i)
	return xml.Marshal(out)
}

func (i *regInfo) ReadFrom(r io.Reader) (int64, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return 0, fmt.Errorf("reading registration event body: %w", err)
	}
	if err := i.UnmarshalText(data); err != nil {
		return int64(len(data)), err
	}
	return int64(len(data)), nil
}

func (i regInfo) WriteTo(w io.Writer) (int64, error) {
	data, err := i.MarshalText()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	if err != nil {
		return int64(n), fmt.Errorf("writing registration event body: %w", err)
	}
	if n != len(data) {
		return int64(n), io.ErrShortWrite
	}
	return int64(n), nil
}

func (i *regInfo) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	if start.Name.Local != "reginfo" || start.Name.Space != regInfoNamespace {
		return fmtRegInfoError("root element must be urn:ietf:params:xml:ns:reginfo reginfo")
	}
	type regInfoXML regInfo
	var info regInfoXML
	if err := d.DecodeElement(&info, &start); err != nil {
		return err
	}
	parsed := regInfo(info)
	if _, ok := parsed.version(); !ok {
		return fmtRegInfoError("version must be a 32-bit non-negative integer")
	}
	state := strings.TrimSpace(parsed.State)
	if state != regInfoStateFull && state != regInfoStatePartial {
		return fmtRegInfoError("state must be full or partial")
	}
	if err := parsed.validate(); err != nil {
		return err
	}
	*i = parsed
	return nil
}

func (i regInfo) validate() error {
	seenRegistrations := make(map[string]struct{}, len(i.Registration))
	seenContacts := make(map[string]string)
	for _, reg := range i.Registration {
		id := strings.TrimSpace(reg.ID)
		if id == "" {
			return fmtRegInfoError("registration id is required")
		}
		if _, ok := seenRegistrations[id]; ok {
			return fmtRegInfoError("registration id must be unique")
		}
		seenRegistrations[id] = struct{}{}
		if strings.TrimSpace(reg.AOR) == "" {
			return fmtRegInfoError("registration aor is required")
		}
		if !validRegInfoRegistrationState(reg.State) {
			return fmtRegInfoError("registration state must be init, active or terminated")
		}
		if err := validateRegInfoContacts(reg.Contact, seenContacts); err != nil {
			return err
		}
	}
	return nil
}

func validateRegInfoContacts(contacts []regInfoContact, seenContacts map[string]string) error {
	seenInRegistration := make(map[string]struct{}, len(contacts))
	for _, contact := range contacts {
		id := strings.TrimSpace(contact.ID)
		if id == "" {
			return fmtRegInfoError("contact id is required")
		}
		if _, ok := seenInRegistration[id]; ok {
			return fmtRegInfoError("contact id must be unique within registration")
		}
		seenInRegistration[id] = struct{}{}
		uri := strings.TrimSpace(contact.URI)
		if uri == "" {
			return fmtRegInfoError("contact uri is required")
		}
		if previousURI, ok := seenContacts[id]; ok && !sameRegInfoURI(previousURI, uri) {
			return fmtRegInfoError("contact id must identify the same contact URI")
		}
		seenContacts[id] = uri
		if !validRegInfoContactState(contact.State) {
			return fmtRegInfoError("contact state must be active or terminated")
		}
		if !validRegInfoContactEvent(contact.Event) {
			return fmtRegInfoError("contact event is invalid")
		}
		if !validRegInfoUnsignedAttribute(contact.DurationRegistered) {
			return fmtRegInfoError("duration-registered must be an unsigned integer")
		}
		if !validRegInfoUnsignedAttribute(contact.ExpiresAttr) {
			return fmtRegInfoError("expires must be an unsigned integer")
		}
		if !validRegInfoUnsignedAttribute(contact.RetryAfter) {
			return fmtRegInfoError("retry-after must be an unsigned integer")
		}
		if !validRegInfoUnsignedAttribute(contact.CSeq) {
			return fmtRegInfoError("cseq must be an unsigned integer")
		}
		if strings.EqualFold(strings.TrimSpace(contact.Event), regInfoContactEventShortened) && strings.TrimSpace(contact.ExpiresAttr) == "" {
			return fmtRegInfoError("shortened contact requires expires")
		}
		if strings.EqualFold(strings.TrimSpace(contact.Event), regInfoContactEventProbation) && strings.TrimSpace(contact.RetryAfter) == "" {
			return fmtRegInfoError("probation contact requires retry-after")
		}
		for _, unknown := range contact.Unknown {
			if strings.TrimSpace(unknown.Name) == "" {
				return fmtRegInfoError("unknown-param name is required")
			}
		}
	}
	return nil
}

func validRegInfoUnsignedAttribute(value string) bool {
	value = strings.TrimSpace(value)
	if value == "" {
		return true
	}
	_, err := strconv.ParseUint(value, 10, 64)
	return err == nil
}

func validRegInfoRegistrationState(value string) bool {
	switch strings.TrimSpace(value) {
	case regInfoRegistrationStateInit, regInfoRegistrationStateActive, regInfoRegistrationStateTerminated:
		return true
	default:
		return false
	}
}

func validRegInfoContactState(value string) bool {
	switch strings.TrimSpace(value) {
	case regInfoContactStateActive, regInfoContactStateTerminated:
		return true
	default:
		return false
	}
}

func validRegInfoContactEvent(value string) bool {
	switch strings.TrimSpace(value) {
	case regInfoContactEventRegistered,
		regInfoContactEventCreated,
		regInfoContactEventRefreshed,
		regInfoContactEventShortened,
		regInfoContactEventExpired,
		regInfoContactEventDeactivated,
		regInfoContactEventProbation,
		regInfoContactEventUnregistered,
		regInfoContactEventRejected:
		return true
	default:
		return false
	}
}

func (i regInfo) version() (int, bool) {
	version, err := strconv.ParseUint(strings.TrimSpace(i.Version), 10, 32)
	if err != nil {
		return 0, false
	}
	return int(version), true
}

func (c regInfoContact) expiresDuration() (time.Duration, bool) {
	value := strings.TrimSpace(c.ExpiresAttr)
	seconds, err := strconv.Atoi(value)
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return time.Duration(seconds) * time.Second, true
}

func (c regInfoContact) active() bool {
	return strings.EqualFold(strings.TrimSpace(c.State), regInfoContactStateActive)
}

func (c regInfoContact) terminated() bool {
	return strings.EqualFold(strings.TrimSpace(c.State), regInfoContactStateTerminated)
}

var errInvalidRegInfo = errors.New("registration event body is invalid")

func fmtRegInfoError(text string) error {
	return fmt.Errorf("%w: %s", errInvalidRegInfo, text)
}
