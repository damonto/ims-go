package ussd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/sip"
)

func (s *Endpoint) targetURI(code string) string {
	realm := strings.TrimPrefix(s.reg.State().RegisterURI, "sip:")
	phoneContext := strings.TrimSpace(s.cfg.PhoneContextDomain)
	if phoneContext == "" {
		phoneContext = realm
	}
	dial := strings.ReplaceAll(code, "#", "%23")
	return fmt.Sprintf("sip:%s;phone-context=%s@%s;user=dialstring", dial, phoneContext, realm)
}

func (s *Endpoint) sdp() string {
	host := s.reg.State().ContactHost
	network := "IP4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "IP6"
	}
	sessionID := sip.RandomUint32()
	return fmt.Sprintf("v=0\r\no=- %d %d IN %s %s\r\ns=-\r\nc=IN %s %s\r\nt=0 0\r\nm=audio 0 RTP/AVP 97 96\r\na=rtpmap:97 AMR\r\na=fmtp:97 mode-set=0,2,5,7; maxframes=2\r\na=rtpmap:96 telephone-event\r\n", sessionID, sessionID, network, host, network, host)
}

func (s *Endpoint) sdpAnswer(offer []byte) ([]byte, error) {
	var timing string
	var media []string
	for _, raw := range strings.Split(strings.ReplaceAll(string(offer), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "t=") && timing == "":
			timing = line
		case strings.HasPrefix(line, "m="):
			fields := strings.Fields(strings.TrimPrefix(line, "m="))
			if len(fields) < 4 {
				return nil, errors.New("building SDP answer: malformed media description")
			}
			fields[1] = "0"
			media = append(media, "m="+strings.Join(fields, " "))
		}
	}
	if timing == "" || len(media) != 1 {
		return nil, errors.New("building SDP answer: incomplete SDP offer")
	}
	host := s.reg.State().ContactHost
	network := "IP4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "IP6"
	}
	sessionID := sip.RandomUint32()
	answer := fmt.Sprintf("v=0\r\no=- %d %d IN %s %s\r\ns=-\r\nc=IN %s %s\r\n%s\r\n%s\r\n", sessionID, sessionID, network, host, network, host, timing, media[0])
	return []byte(answer), nil
}

func buildCancel(invite sip.Message) sip.Message {
	cancelMsg := sip.NewRequest("CANCEL", sip.RequestURI(invite))
	cancelMsg.Headers.Add("Via", invite.Header("Via"))
	cancelMsg.Headers.Add("Max-Forwards", nonEmpty(invite.Header("Max-Forwards"), strconv.Itoa(sip.DefaultMaxForwards)))
	for _, route := range invite.HeadersByName("Route") {
		cancelMsg.Headers.Add("Route", route)
	}
	for _, supported := range invite.HeadersByName("Supported") {
		cancelMsg.Headers.Add("Supported", supported)
	}
	cancelMsg.Headers.Add("From", invite.Header("From"))
	cancelMsg.Headers.Add("To", invite.Header("To"))
	cancelMsg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	cancelMsg.Headers.Add("CSeq", fmt.Sprintf("%d CANCEL", sip.CSeqNumber(invite.Header("CSeq"))))
	if securityVerify := strings.TrimSpace(invite.Header("Security-Verify")); securityVerify != "" {
		cancelMsg.Headers.Add("Security-Verify", securityVerify)
	}
	return cancelMsg
}

func reverseValues(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for i := len(values) - 1; i >= 0; i-- {
		out = append(out, values[i])
	}
	return out
}

func dialogContactURI(msg sip.Message) (string, error) {
	contacts := msg.HeaderList("Contact")
	if len(contacts) != 1 {
		return "", fmt.Errorf("Contact field count is %d, want 1", len(contacts))
	}
	uri := strings.TrimSpace(sip.AddressURI(contacts[0]))
	lowerURI := strings.ToLower(uri)
	if !strings.HasPrefix(lowerURI, "sip:") && !strings.HasPrefix(lowerURI, "sips:") {
		return "", errors.New("Contact must contain a SIP or SIPS URI")
	}
	return uri, nil
}

func nonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func defaultValue(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return strings.TrimSpace(value)
}

func contactValue(state registration.State, networkInitiatedSupported bool) string {
	return contactValueForURI(state.ContactURI, networkInitiatedSupported)
}

func requestContactValue(state registration.State, networkInitiatedSupported bool) string {
	return contactValueForURI(state.RequestContactURI(), networkInitiatedSupported)
}

func contactValueForURI(uri string, networkInitiatedSupported bool) string {
	params := []string{
		icsiRefFeatureTag,
		midCallFeatureTag,
		ps2csSRVCCOrigPreAlerting,
		smsIPFeatureTag,
		srvccAlertingFeatureTag,
	}
	if networkInitiatedSupported {
		params = append(params, nwInitUSSI)
	}
	params = append(params, "text")
	return fmt.Sprintf("<%s>;%s", uri, strings.Join(params, ";"))
}

func preferredIdentity(state registration.State) string {
	if identity := strings.TrimSpace(state.DefaultPublicID); identity != "" {
		return identity
	}
	return state.PublicIdentity
}

func queuedRequestTimeout(ctx context.Context) (time.Duration, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return defaultQueuedRequestTimeout, nil
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return 0, context.DeadlineExceeded
	}
	return timeout, nil
}
