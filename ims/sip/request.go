package sip

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

const (
	DefaultClientAllow     = "ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,REFER,UPDATE"
	DefaultClientSupported = "100rel,path,replaces"
)

type SecurityAgreement struct {
	Verify   string
	Required bool
}

type ClientRequestPolicy struct {
	Routes            []string
	UserAgent         string
	AccessNetworkInfo string
	Security          SecurityAgreement
}

type DialogID struct {
	CallID    string
	LocalTag  string
	RemoteTag string
}

func (p ClientRequestPolicy) Apply(msg *Message) {
	msg.Headers.Add("Allow", DefaultClientAllow)
	msg.Headers.Add("Max-Forwards", "70")
	msg.Headers.Add("Supported", DefaultClientSupported)
	if userAgent := strings.TrimSpace(p.UserAgent); userAgent != "" {
		msg.Headers.Add("User-Agent", userAgent)
	}
	if value := strings.TrimSpace(p.AccessNetworkInfo); value != "" {
		msg.Headers.Add("P-Access-Network-Info", value)
	}
	AddRouteHeaders(msg, p.Routes)
	p.Security.Apply(msg)
}

func (s SecurityAgreement) Apply(msg *Message) bool {
	verify := strings.TrimSpace(s.Verify)
	if verify != "" {
		msg.Headers.Add("Security-Verify", verify)
	}
	if s.Required {
		msg.Headers.Add("Require", "sec-agree")
		msg.Headers.Add("Proxy-Require", "sec-agree")
	}
	return verify != ""
}

func (id DialogID) Matches(msg Message) bool {
	if msg.Header("Call-ID") != id.CallID {
		return false
	}
	if tag := HeaderTag(msg.Header("To")); tag != "" && id.LocalTag != "" && tag != id.LocalTag {
		return false
	}
	if tag := HeaderTag(msg.Header("From")); tag != "" && id.RemoteTag != "" && tag != id.RemoteTag {
		return false
	}
	return true
}

func AddRouteHeaders(msg *Message, routes []string) {
	for _, route := range routes {
		if route = strings.TrimSpace(route); route != "" {
			msg.Headers.Add("Route", route)
		}
	}
}

func BuildVia(transport, host string, port int, branch string) string {
	return fmt.Sprintf("SIP/2.0/%s %s;branch=z9hG4bK%s;rport", transport, net.JoinHostPort(host, strconv.Itoa(port)), branch)
}

func TransportToken(addr net.Addr) string {
	switch addr.(type) {
	case *net.TCPAddr:
		return "TCP"
	default:
		return "UDP"
	}
}

func NewTransaction() (callID, sessionID, tag, branch string) {
	return RandomAlphaNum(24), RandomHex(32), RandomAlphaNum(10), RandomAlphaNum(15)
}

func RandomAlphaNum(length int) string {
	return randomString(length, "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

func RandomHex(length int) string {
	return randomString(length, "0123456789abcdef")
}

func RandomUint32() uint32 {
	var buf [4]byte
	_, _ = rand.Read(buf[:])
	return binary.BigEndian.Uint32(buf[:])
}

func randomString(length int, alphabet string) string {
	buf := make([]byte, length)
	rnd := make([]byte, length)
	_, _ = rand.Read(rnd)
	for i, b := range rnd {
		buf[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(buf)
}
