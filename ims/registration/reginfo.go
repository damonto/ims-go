package registration

import (
	"bytes"
	"encoding/xml"
	"strconv"
	"strings"
	"time"
)

type regInfo struct {
	Version      string                `xml:"version,attr"`
	State        string                `xml:"state,attr"`
	Registration []regInfoRegistration `xml:"registration"`
}

type regInfoRegistration struct {
	AOR     string           `xml:"aor,attr"`
	State   string           `xml:"state,attr"`
	Contact []regInfoContact `xml:"contact"`
}

type regInfoContact struct {
	State       string `xml:"state,attr"`
	Event       string `xml:"event,attr"`
	ExpiresAttr string `xml:"expires,attr"`
	URI         string `xml:"uri"`
	Expires     string `xml:"expires"`
}

func parseRegInfo(body []byte) (regInfo, bool, error) {
	if len(bytes.TrimSpace(body)) == 0 {
		return regInfo{}, false, nil
	}
	var info regInfo
	if err := xml.Unmarshal(body, &info); err != nil {
		return regInfo{}, false, err
	}
	if len(info.Registration) == 0 {
		return regInfo{}, false, nil
	}
	return info, true, nil
}

func (i regInfo) version() (int, bool) {
	version, err := strconv.Atoi(strings.TrimSpace(i.Version))
	if err != nil || version < 0 {
		return 0, false
	}
	return version, true
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
	return strings.EqualFold(strings.TrimSpace(c.State), "active")
}

func (c regInfoContact) terminated() bool {
	return strings.EqualFold(strings.TrimSpace(c.State), "terminated")
}
