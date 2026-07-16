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
	DefaultClientAllow     = "ACK,BYE,CANCEL,INFO,INVITE,MESSAGE,NOTIFY,OPTIONS,PRACK,UPDATE"
	DefaultClientSupported = "199,path,sec-agree"
	DefaultMaxForwards     = 70
)

type SecurityAgreement struct {
	Verify   string
	Required bool
}

type ViaOptions struct {
	Keep bool
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
	if strings.TrimSpace(msg.Header("Max-Forwards")) == "" {
		msg.Headers.Add("Max-Forwards", strconv.Itoa(DefaultMaxForwards))
	}
	msg.Headers.Add("Supported", DefaultClientSupported)
	if userAgent := strings.TrimSpace(p.UserAgent); userAgent != "" {
		msg.Headers.Add("User-Agent", userAgent)
	}
	if value := strings.TrimSpace(p.AccessNetworkInfo); value != "" {
		msg.Headers.Add("P-Access-Network-Info", value)
	}
	ApplyRouteSet(msg, p.Routes)
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
	if id.LocalTag != "" {
		if tag := HeaderTag(msg.Header("To")); tag != id.LocalTag {
			return false
		}
	}
	if id.RemoteTag != "" {
		if tag := HeaderTag(msg.Header("From")); tag != id.RemoteTag {
			return false
		}
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

func ApplyRouteSet(msg *Message, routes []string) {
	remoteTarget := strings.TrimSpace(RequestURI(*msg))
	requestURI, routeHeaders := BuildRouteSet(remoteTarget, routes)
	if requestURI != "" {
		SetRequestURI(msg, requestURI)
	}
	msg.Headers.Del("Route")
	AddRouteHeaders(msg, routeHeaders)
}

func BuildRouteSet(remoteTarget string, routes []string) (string, []string) {
	remoteTarget = strings.TrimSpace(remoteTarget)
	filtered := make([]string, 0, len(routes))
	for _, route := range routes {
		if route = strings.TrimSpace(route); route != "" {
			filtered = append(filtered, route)
		}
	}
	if len(filtered) == 0 || remoteTarget == "" {
		return remoteTarget, filtered
	}
	firstURI := strings.TrimSpace(AddressURI(filtered[0]))
	if firstURI == "" || routeHasParam(firstURI, "lr") {
		return remoteTarget, filtered
	}
	rewritten := make([]string, 0, len(filtered))
	rewritten = append(rewritten, filtered[1:]...)
	rewritten = append(rewritten, routeHeaderValue(remoteTarget))
	return firstURI, rewritten
}

func BuildVia(transport, host string, port int, branch string) string {
	return BuildViaWithOptions(transport, host, port, branch, ViaOptions{})
}

func BuildViaWithOptions(transport, host string, port int, branch string, options ViaOptions) string {
	var params []string
	params = append(params, "branch=z9hG4bK"+branch)
	if strings.EqualFold(transport, "UDP") {
		params = append(params, "rport")
	}
	if options.Keep {
		params = append(params, "keep")
	}
	return fmt.Sprintf("SIP/2.0/%s %s;%s", transport, net.JoinHostPort(host, strconv.Itoa(port)), strings.Join(params, ";"))
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
	if _, err := rand.Read(buf[:]); err != nil {
		panic(err)
	}
	return binary.BigEndian.Uint32(buf[:])
}

func randomString(length int, alphabet string) string {
	buf := make([]byte, length)
	limit := 256 - 256%len(alphabet)
	var rnd [32]byte
	for written := 0; written < len(buf); {
		if _, err := rand.Read(rnd[:]); err != nil {
			panic(err)
		}
		for _, b := range rnd {
			if int(b) >= limit {
				continue
			}
			buf[written] = alphabet[int(b)%len(alphabet)]
			written++
			if written == len(buf) {
				break
			}
		}
	}
	return string(buf)
}

func routeHasParam(uri, want string) bool {
	uri, _, _ = strings.Cut(uri, "?")
	for _, field := range strings.Split(uri, ";")[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(field), "=")
		if strings.EqualFold(name, want) {
			return true
		}
	}
	return false
}

func routeHeaderValue(uri string) string {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return ""
	}
	if strings.HasPrefix(uri, "<") && strings.Contains(uri, ">") {
		return uri
	}
	return "<" + uri + ">"
}
