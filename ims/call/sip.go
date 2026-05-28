package call

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/sip"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

func mediaOfferFromSDP(offer sdpOffer) MediaOffer {
	seen := make(map[AudioCodec]struct{}, len(offer.Codecs))
	codecs := make([]AudioCodec, 0, len(offer.Codecs))
	for _, payload := range offer.Payloads {
		codec := offer.Codecs[payload]
		if codec.Name == "" {
			continue
		}
		if _, ok := seen[codec.Name]; ok {
			continue
		}
		seen[codec.Name] = struct{}{}
		codecs = append(codecs, codec.Name)
	}
	return MediaOffer{Codecs: codecs, PTime: offer.PTime}
}

func callAcceptHeader(cfg Config) string {
	if cfg.IncludeGeolocationPIDF {
		return "application/sdp, application/pidf+xml, multipart/mixed"
	}
	return "application/sdp"
}

func addInviteOKSessionTimer(resp *sip.Message, invite sip.Message, cfg Config) {
	if !cfg.SessionTimer || !tokenHeaderContains(invite, "Supported", "timer") {
		return
	}
	sessionExpires := strings.TrimSpace(invite.Header("Session-Expires"))
	if sessionExpires == "" {
		seconds := sessionExpiresSeconds()
		if minSE, ok := parseSessionSeconds(invite.Header("Min-SE")); ok && minSE > seconds {
			seconds = minSE
		}
		resp.Headers.Set("Session-Expires", fmt.Sprintf("%d;refresher=uac", seconds))
		return
	}
	if sessionExpiresHasRefresher(sessionExpires) {
		resp.Headers.Set("Session-Expires", sessionExpires)
		return
	}
	resp.Headers.Set("Session-Expires", strings.TrimSpace(sessionExpires)+";refresher=uac")
}

func addInviteSessionTimer(invite *sip.Message, cfg Config) {
	if !cfg.SessionTimer {
		return
	}
	addTokenHeader(invite, "Supported", "timer")
}

func addTokenHeader(msg *sip.Message, name string, token string) {
	current := strings.TrimSpace(msg.Header(name))
	if current == "" {
		msg.Headers.Set(name, token)
		return
	}
	if sip.TokenListContains(current, token) {
		return
	}
	msg.Headers.Set(name, current+","+token)
}

func sessionExpiresSeconds() int {
	return durationSeconds(defaultSessionExpires)
}

func durationSeconds(d time.Duration) int {
	return int(d / time.Second)
}

func parseSessionSeconds(value string) (int, bool) {
	value, _, _ = strings.Cut(strings.TrimSpace(value), ";")
	seconds, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || seconds <= 0 {
		return 0, false
	}
	return seconds, true
}

func sessionExpiresHasRefresher(value string) bool {
	for _, part := range strings.Split(value, ";")[1:] {
		name, _, _ := strings.Cut(strings.TrimSpace(part), "=")
		if strings.EqualFold(name, "refresher") {
			return true
		}
	}
	return false
}

func setInviteBody(msg *sip.Message, cfg Config, localURI string, sdp []byte) error {
	if !cfg.IncludeGeolocationPIDF {
		msg.Headers.Add("Content-Type", "application/sdp")
		msg.Body = sdp
		return nil
	}
	boundary := "call-" + sip.RandomAlphaNum(18)
	locationID := "pidf-" + sip.RandomAlphaNum(16)
	body, err := buildMultipartInviteBody(boundary, locationID, sdp, buildPIDF(localURI, cfg.GeolocationCountry))
	if err != nil {
		return fmt.Errorf("building call INVITE body: %w", err)
	}
	msg.Headers.Add("Geolocation", "<cid:"+locationID+">")
	msg.Headers.Add("Geolocation-Routing", "yes")
	msg.Headers.Add("Content-Type", `multipart/mixed; boundary=`+boundary)
	msg.Body = body
	return nil
}

func setInviteResponseBody(msg *sip.Message, cfg Config, localURI string, sdp []byte) error {
	if !cfg.IncludeGeolocationPIDF {
		msg.Headers.Add("Content-Type", "application/sdp")
		msg.Body = sdp
		return nil
	}
	boundary := "call-" + sip.RandomAlphaNum(18)
	locationID := "pidf-" + sip.RandomAlphaNum(16)
	body, err := buildMultipartInviteBody(boundary, locationID, sdp, buildPIDF(localURI, cfg.GeolocationCountry))
	if err != nil {
		return fmt.Errorf("building call INVITE response body: %w", err)
	}
	msg.Headers.Add("Geolocation", "<cid:"+locationID+">")
	msg.Headers.Add("Geolocation-Routing", "yes")
	msg.Headers.Add("Content-Type", `multipart/mixed; boundary=`+boundary)
	msg.Body = body
	return nil
}

func buildMultipartInviteBody(boundary string, locationID string, sdp []byte, pidf []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.SetBoundary(boundary); err != nil {
		return nil, err
	}
	sdpHeader := textproto.MIMEHeader{}
	sdpHeader.Set("Content-Type", "application/sdp")
	sdpHeader.Set("Content-Disposition", "session")
	part, err := writer.CreatePart(sdpHeader)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(sdp); err != nil {
		return nil, err
	}
	pidfHeader := textproto.MIMEHeader{}
	pidfHeader.Set("Content-Type", "application/pidf+xml")
	pidfHeader.Set("Content-ID", "<"+locationID+">")
	pidfHeader.Set("Content-Disposition", "render;handling=optional")
	part, err = writer.CreatePart(pidfHeader)
	if err != nil {
		return nil, err
	}
	if _, err := part.Write(pidf); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func sdpBody(msg sip.Message) ([]byte, bool) {
	if len(msg.Body) == 0 {
		return nil, false
	}
	mediaType, params, err := mime.ParseMediaType(msg.Header("Content-Type"))
	if err != nil {
		return nil, false
	}
	switch strings.ToLower(mediaType) {
	case "application/sdp":
		return msg.Body, true
	case "multipart/mixed":
		boundary := strings.TrimSpace(params["boundary"])
		if boundary == "" {
			return nil, false
		}
		reader := multipart.NewReader(bytes.NewReader(msg.Body), boundary)
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				return nil, false
			}
			if err != nil {
				return nil, false
			}
			partType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if err != nil || !strings.EqualFold(partType, "application/sdp") {
				continue
			}
			body, err := io.ReadAll(part)
			return body, err == nil && len(body) > 0
		}
	default:
		return nil, false
	}
}

func incomingInviteKey(msg sip.Message) string {
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	if callID == "" || cseq == "" {
		return ""
	}
	return callID + "|" + cseq
}

func contactValue(state registration.State) string {
	params := []string{
		`audio`,
		fmt.Sprintf(`+g.3gpp.icsi-ref="%s"`, mmtelICSIEncoded),
		`+g.3gpp.mid-call`,
		`+g.3gpp.ps2cs-srvcc-orig-pre-alerting`,
		`+g.3gpp.srvcc-alerting`,
	}
	if state.IMEI != "" {
		params = append(params, fmt.Sprintf(`+sip.instance="<urn:gsma:imei:%s>"`, state.IMEI))
	}
	return fmt.Sprintf("<%s>;%s", sipContactURI(state.ContactHost, state.MessagePort), strings.Join(params, ";"))
}

func sipContactURI(host string, port int) string {
	return "sip:" + net.JoinHostPort(host, strconv.Itoa(port))
}

func preferredIdentity(state registration.State) string {
	if identity := strings.TrimSpace(state.SIPPublicID); identity != "" {
		return identity
	}
	if identity := strings.TrimSpace(state.DefaultPublicID); identity != "" {
		return identity
	}
	return state.PublicIdentity
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
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func nonZeroDuration(values ...time.Duration) time.Duration {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
