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
	ID          string `xml:"id,attr"`
	State       string `xml:"state,attr"`
	Event       string `xml:"event,attr"`
	ExpiresAttr string `xml:"expires,attr"`
	URI         string `xml:"urn:ietf:params:xml:ns:reginfo uri"`
	Expires     string `xml:"urn:ietf:params:xml:ns:reginfo expires"`
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
		if err := validateRegInfoContacts(reg.Contact); err != nil {
			return err
		}
	}
	return nil
}

func validateRegInfoContacts(contacts []regInfoContact) error {
	seenContacts := make(map[string]struct{}, len(contacts))
	for _, contact := range contacts {
		id := strings.TrimSpace(contact.ID)
		if id == "" {
			return fmtRegInfoError("contact id is required")
		}
		if _, ok := seenContacts[id]; ok {
			return fmtRegInfoError("contact id must be unique")
		}
		seenContacts[id] = struct{}{}
		if !validRegInfoContactState(contact.State) {
			return fmtRegInfoError("contact state must be active or terminated")
		}
		if !validRegInfoContactEvent(contact.Event) {
			return fmtRegInfoError("contact event is invalid")
		}
		if strings.TrimSpace(contact.URI) == "" {
			return fmtRegInfoError("contact uri is required")
		}
	}
	return nil
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
	if value == "" {
		value = strings.TrimSpace(c.Expires)
	}
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

func fmtRegInfoError(text string) error {
	return errors.New("parsing registration event body: " + text)
}
