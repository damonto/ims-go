package ussd

import (
	"context"
	"fmt"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/sip"
	"net"
	"strconv"
	"strings"
	"time"
)

func (s *Service) ussdTargetURI(code string) string {
	realm := strings.TrimPrefix(s.reg.State().RegisterURI, "sip:")
	phoneContext := strings.TrimSpace(s.cfg.PhoneContextDomain)
	if phoneContext == "" {
		phoneContext = realm
	}
	dial := strings.ReplaceAll(code, "#", "%23")
	return fmt.Sprintf("sip:%s;phone-context=%s@%s;user=dialstring", dial, phoneContext, realm)
}

func (s *Service) ussdSDP() string {
	host := s.reg.State().ContactHost
	network := "IP4"
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		network = "IP6"
	}
	sessionID := sip.RandomUint32()
	return fmt.Sprintf("v=0\r\no=- %d %d IN %s %s\r\ns=-\r\nc=IN %s %s\r\nt=0 0\r\nm=audio 0 RTP/AVP 97 96\r\na=rtpmap:97 AMR\r\na=fmtp:97 mode-set=0,2,5,7; maxframes=2\r\na=rtpmap:96 telephone-event\r\n", sessionID, sessionID, network, host, network, host)
}

func (s *Service) startBackgroundTask(task func()) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.bgWG.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.bgWG.Done()
		task()
	}()
}

func buildCancel(invite sip.Message) sip.Message {
	cancelMsg := sip.NewRequest("CANCEL", sip.RequestURI(invite))
	cancelMsg.Headers.Add("Via", invite.Header("Via"))
	cancelMsg.Headers.Add("Max-Forwards", nonEmpty(invite.Header("Max-Forwards"), "70"))
	for _, route := range invite.HeadersByName("Route") {
		cancelMsg.Headers.Add("Route", route)
	}
	cancelMsg.Headers.Add("From", invite.Header("From"))
	cancelMsg.Headers.Add("To", invite.Header("To"))
	cancelMsg.Headers.Add("Call-ID", invite.Header("Call-ID"))
	cancelMsg.Headers.Add("CSeq", fmt.Sprintf("%d CANCEL", sip.CSeqNumber(invite.Header("CSeq"))))
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

func contactValue(state registration.State) string {
	params := []string{
		`+g.3gpp.icsi-ref="urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"`,
		`+g.3gpp.mid-call`,
		`+g.3gpp.nw-init-ussi`,
		`+g.3gpp.ps2cs-srvcc-orig-pre-alerting`,
		`+g.3gpp.smsip`,
		`+g.3gpp.srvcc-alerting`,
	}
	if state.IMEI != "" {
		params = append(params, fmt.Sprintf(`+sip.instance="<urn:gsma:imei:%s>"`, state.IMEI))
	}
	params = append(params, "text")
	return fmt.Sprintf("<%s>;%s", sipContactURI(state.ContactHost, state.MessagePort), strings.Join(params, ";"))
}

func sipContactURI(host string, port int) string {
	return "sip:" + net.JoinHostPort(host, strconv.Itoa(port))
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
