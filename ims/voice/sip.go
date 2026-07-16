package voice

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/damonto/ims-go/ims/pidf"
	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/sip"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/textproto"
	"slices"
	"strconv"
	"strings"
	"time"
)

func mediaDescriptionFromSDP(offer sdpOffer) MediaDescription {
	formats := make([]AudioFormat, 0, len(offer.Codecs))
	for _, payload := range offer.Payloads {
		codec, ok := offer.Codecs[payload]
		if !ok || codec.Name == "" {
			continue
		}
		formats = append(formats, audioFormat(codec, payload, offer.FMTP[payload]))
	}
	return MediaDescription{
		Formats:               formats,
		Profile:               offer.Profile,
		PTime:                 offer.PTime,
		MaxPTime:              offer.MaxPTime,
		Direction:             offer.Direction,
		IP:                    append(net.IP(nil), offer.RemoteIP...),
		Port:                  offer.RemotePort,
		RTCPIP:                append(net.IP(nil), offer.RemoteRTCPIP...),
		RTCPPort:              offer.RemoteRTCPPort,
		RTCPMux:               offer.RTCPMux,
		RTCPDisabled:          rtcpDisabled(offer),
		RTCPSenderBandwidth:   effectiveRTCPBandwidth(offer.RTCPSenderBandwidth, rtcpSenderBandwidth),
		RTCPReceiverBandwidth: effectiveRTCPBandwidth(offer.RTCPReceiverBandwidth, rtcpReceiverBandwidth),
		RawSDP:                append([]byte(nil), offer.RawSDP...),
	}
}

func callAcceptHeader(includePIDF bool, includeCurrentLocation bool) string {
	types := []string{"application/sdp"}
	if includePIDF {
		types = append(types, "application/pidf+xml", "multipart/mixed")
	}
	if includeCurrentLocation {
		types = append(types, currentLocationDiscoveryContentType)
	}
	return strings.Join(types, ", ")
}

func addInviteOKSessionTimer(resp *sip.Message, invite sip.Message, cfg Config) {
	if !cfg.SessionTimer {
		return
	}
	uacSupportsTimer := tokenHeaderContains(invite, "Supported", sessionTimerOption)
	value := strings.TrimSpace(invite.Header("Session-Expires"))
	if value == "" {
		if !uacSupportsTimer {
			return
		}
		seconds := inviteOKMissingSessionExpiresSeconds(invite)
		resp.Headers.Set("Session-Expires", sessionExpiresHeader{seconds: seconds, refresher: sessionRefresherUAC}.String())
		addTokenHeader(resp, "Require", sessionTimerOption)
		return
	}

	sessionExpires, ok := parseSessionExpiresHeader(value)
	if !ok {
		return
	}
	switch {
	case sessionExpires.refresher == "":
		if uacSupportsTimer {
			sessionExpires.refresher = sessionRefresherUAC
		} else {
			sessionExpires.refresher = sessionRefresherUAS
		}
	case !uacSupportsTimer && sessionExpires.refresher == sessionRefresherUAC:
		sessionExpires.refresher = sessionRefresherUAS
	}
	resp.Headers.Set("Session-Expires", sessionExpires.String())
	if sessionExpires.refresher == sessionRefresherUAC || (uacSupportsTimer && sessionExpires.refresher == sessionRefresherUAS) {
		addTokenHeader(resp, "Require", sessionTimerOption)
	}
}

func incomingSessionTimerTooSmall(invite sip.Message, cfg Config) (int, bool) {
	if !cfg.SessionTimer {
		return 0, false
	}
	sessionExpires := strings.TrimSpace(invite.Header("Session-Expires"))
	if sessionExpires == "" {
		return 0, false
	}
	parsed, ok := parseSessionExpiresHeader(sessionExpires)
	if !ok {
		return minSessionExpiresSeconds(cfg, invite), true
	}
	minSE := minSessionExpiresSeconds(cfg, invite)
	return minSE, parsed.seconds < minSE
}

func invalidSessionTimerRefresher(msg sip.Message) bool {
	value := strings.TrimSpace(msg.Header("Session-Expires"))
	if value == "" || tokenHeaderContains(msg, "Supported", sessionTimerOption) {
		return false
	}
	sessionExpires, ok := parseSessionExpiresHeader(value)
	return ok && sessionExpires.refresher != ""
}

func (s *Endpoint) unsupportedRequiredTimer(msg sip.Message) bool {
	return !s.cfg.SessionTimer && tokenHeaderContains(msg, "Require", sessionTimerOption)
}

func (s *Endpoint) unsupportedRequiredPrecondition(msg sip.Message) bool {
	return !s.cfg.Preconditions && tokenHeaderContains(msg, "Require", preconditionOption)
}

func minSessionExpiresSeconds(cfg Config, msg sip.Message) int {
	minSE := durationSeconds(defaultMinSessionExpires)
	if configured := durationSeconds(cfg.MinSessionExpires); configured > minSE {
		minSE = configured
	}
	if requested, ok := parseMinSessionSeconds(msg.Header("Min-SE")); ok && requested > minSE {
		minSE = requested
	}
	return minSE
}

func receivedMinSessionExpiresSeconds(msg sip.Message) int {
	if requested, ok := parseMinSessionSeconds(msg.Header("Min-SE")); ok {
		return requested
	}
	return durationSeconds(defaultMinSessionExpires)
}

func addInviteSessionTimer(invite *sip.Message, cfg Config) {
	if !cfg.SessionTimer {
		return
	}
	addTokenHeader(invite, "Supported", sessionTimerOption)
	if minSE := minSessionExpiresSeconds(cfg, *invite); minSE > durationSeconds(defaultMinSessionExpires) {
		invite.Headers.Set("Min-SE", strconv.Itoa(minSE))
	}
	if cfg.SessionExpires > 0 {
		if h, ok := initialInviteSessionExpiresHeader(cfg, *invite); ok {
			invite.Headers.Set("Session-Expires", h.String())
		}
	}
}

func addInviteFeatureTags(invite *sip.Message, cfg Config) {
	if cfg.ReliableProvisional || cfg.Preconditions {
		addTokenHeader(invite, "Supported", reliableProvisionalOption)
	}
	if cfg.Preconditions {
		addTokenHeader(invite, "Supported", preconditionOption)
	}
}

func addTokenHeader(msg *sip.Message, name string, token string) {
	current := strings.TrimSpace(strings.Join(msg.HeadersByName(name), ","))
	if current == "" {
		msg.Headers.Set(name, token)
		return
	}
	if msg.HeaderHasToken(name, token) {
		return
	}
	msg.Headers.Set(name, current+","+token)
}

func sessionExpiresSeconds(cfg Config, msg sip.Message) int {
	if h, ok := parseSessionExpiresHeader(msg.Header("Session-Expires")); ok {
		return max(h.seconds, minSessionExpiresSeconds(cfg, msg))
	}
	seconds := durationSeconds(defaultSessionExpires)
	if cfg.SessionExpires > 0 {
		seconds = durationSeconds(cfg.SessionExpires)
	}
	return max(seconds, minSessionExpiresSeconds(cfg, msg))
}

func sessionExpiresRequestHeader(cfg Config, msg sip.Message) sessionExpiresHeader {
	return sessionExpiresHeader{
		seconds:   requestSessionExpiresSeconds(cfg, msg),
		refresher: configuredRequestSessionRefresher(cfg),
	}
}

func initialInviteSessionExpiresHeader(cfg Config, msg sip.Message) (sessionExpiresHeader, bool) {
	if minSE := minSessionExpiresSeconds(cfg, msg); minSE > durationSeconds(defaultSessionExpires) {
		return sessionExpiresHeader{}, false
	}
	return sessionExpiresHeader{
		seconds:   durationSeconds(defaultSessionExpires),
		refresher: configuredRequestSessionRefresher(cfg),
	}, true
}

func requestSessionExpiresSeconds(cfg Config, msg sip.Message) int {
	return max(durationSeconds(defaultSessionExpires), minSessionExpiresSeconds(cfg, msg))
}

func inviteOKMissingSessionExpiresSeconds(msg sip.Message) int {
	return max(durationSeconds(defaultSessionExpires), receivedMinSessionExpiresSeconds(msg))
}

func configuredRequestSessionRefresher(cfg Config) string {
	refresher := strings.ToLower(strings.TrimSpace(cfg.SessionRefresher))
	if refresher == sessionRefresherUAC {
		return sessionRefresherUAC
	}
	return ""
}

func durationSeconds(d time.Duration) int {
	return int(d / time.Second)
}

func parseMinSessionSeconds(value string) (int, bool) {
	var h minSEHeader
	if err := h.UnmarshalText([]byte(value)); err != nil {
		return 0, false
	}
	return h.seconds, true
}

const (
	sessionTimerOption   = "timer"
	preconditionOption   = "precondition"
	sessionRefresherNone = "none"
	sessionRefresherUAC  = "uac"
	sessionRefresherUAS  = "uas"
)

type minSEHeader struct {
	seconds int
	params  []string
}

func (h minSEHeader) MarshalText() ([]byte, error) {
	if h.seconds < durationSeconds(defaultMinSessionExpires) {
		return nil, fmt.Errorf("building Min-SE: invalid delta %d", h.seconds)
	}
	parts := make([]string, 0, len(h.params)+1)
	parts = append(parts, strconv.Itoa(h.seconds))
	parts = append(parts, h.params...)
	return []byte(strings.Join(parts, ";")), nil
}

func (h *minSEHeader) UnmarshalText(text []byte) error {
	value := strings.TrimSpace(string(text))
	if value == "" {
		return errors.New("parsing Min-SE: empty value")
	}
	parts := strings.Split(value, ";")
	seconds, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || seconds < durationSeconds(defaultMinSessionExpires) {
		return fmt.Errorf("parsing Min-SE: invalid delta %q", parts[0])
	}
	params := make([]string, 0, len(parts)-1)
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part != "" {
			params = append(params, part)
		}
	}
	*h = minSEHeader{seconds: seconds, params: params}
	return nil
}

type sessionExpiresHeader struct {
	seconds   int
	refresher string
	params    []string
}

func parseSessionExpiresHeader(value string) (sessionExpiresHeader, bool) {
	var h sessionExpiresHeader
	if err := h.UnmarshalText([]byte(value)); err != nil {
		return sessionExpiresHeader{}, false
	}
	return h, true
}

func (h sessionExpiresHeader) String() string {
	text, err := h.MarshalText()
	if err != nil {
		return ""
	}
	return string(text)
}

func (h sessionExpiresHeader) MarshalText() ([]byte, error) {
	if h.seconds <= 0 {
		return nil, fmt.Errorf("building Session-Expires: invalid delta %d", h.seconds)
	}
	if h.refresher != "" && h.refresher != sessionRefresherUAC && h.refresher != sessionRefresherUAS {
		return nil, fmt.Errorf("building Session-Expires: invalid refresher %q", h.refresher)
	}
	parts := make([]string, 0, len(h.params)+2)
	parts = append(parts, strconv.Itoa(h.seconds))
	parts = append(parts, h.params...)
	if h.refresher != "" {
		parts = append(parts, "refresher="+h.refresher)
	}
	return []byte(strings.Join(parts, ";")), nil
}

func (h *sessionExpiresHeader) UnmarshalText(text []byte) error {
	value := strings.TrimSpace(string(text))
	if value == "" {
		return errors.New("parsing Session-Expires: empty value")
	}
	parts := strings.Split(value, ";")
	seconds, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || seconds <= 0 {
		return fmt.Errorf("parsing Session-Expires: invalid delta %q", parts[0])
	}
	refresher := ""
	params := make([]string, 0, len(parts)-1)
	for _, part := range parts[1:] {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, paramValue, ok := strings.Cut(part, "=")
		if !strings.EqualFold(strings.TrimSpace(name), "refresher") {
			params = append(params, part)
			continue
		}
		if !ok {
			return fmt.Errorf("parsing Session-Expires: invalid refresher %q", part)
		}
		refresher = strings.ToLower(strings.Trim(strings.TrimSpace(paramValue), `"`))
		if refresher != sessionRefresherUAC && refresher != sessionRefresherUAS {
			return fmt.Errorf("parsing Session-Expires: invalid refresher %q", paramValue)
		}
	}
	*h = sessionExpiresHeader{seconds: seconds, refresher: refresher, params: params}
	return nil
}

func setInviteBody(msg *sip.Message, cfg Config, localURI string, includePIDF bool, sdp []byte) error {
	if !includePIDF {
		msg.Headers.Add("Content-Type", "application/sdp")
		msg.Body = sdp
		return nil
	}
	boundary := "call-" + sip.RandomAlphaNum(18)
	locationID := "pidf-" + sip.RandomAlphaNum(16)
	body, err := buildMultipartInviteBody(boundary, locationID, sdp, pidf.Build(localURI, cfg.GeolocationCountry))
	if err != nil {
		return fmt.Errorf("building call INVITE body: %w", err)
	}
	msg.Headers.Add("Geolocation", "<cid:"+locationID+">")
	msg.Headers.Add("Geolocation-Routing", "yes")
	msg.Headers.Add("Content-Type", `multipart/mixed; boundary=`+boundary)
	msg.Body = body
	return nil
}

func setInviteResponseBody(msg *sip.Message, cfg Config, localURI string, includePIDF bool, sdp []byte) error {
	if !includePIDF {
		msg.Headers.Add("Content-Type", "application/sdp")
		msg.Body = sdp
		return nil
	}
	boundary := "call-" + sip.RandomAlphaNum(18)
	locationID := "pidf-" + sip.RandomAlphaNum(16)
	body, err := buildMultipartInviteBody(boundary, locationID, sdp, pidf.Build(localURI, cfg.GeolocationCountry))
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

func includePIDFForInvite(cfg Config, req DialRequest) bool {
	if req.Emergency {
		return slices.Contains(cfg.GeolocationPIDFInvite, GeolocationPIDFEmergencyWiFi)
	}
	if slices.Contains(cfg.GeolocationPIDFInvite, GeolocationPIDFNonEmergencyWiFi) {
		return true
	}
	return slices.Contains(cfg.PIDFShortCodes, normalizeDialString(req.To))
}

func includeCurrentLocationDiscoveryForInvite(cfg Config, req DialRequest) bool {
	return req.Emergency && slices.Contains(cfg.GeolocationPIDFInvite, GeolocationPIDFEmergencyWiFi)
}

func isEmergencyServiceURN(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == emergencyServiceURNSOS || strings.HasPrefix(value, emergencyServiceURNSOS+".")
}

func pidfEntityURI(cfg Config, state registration.State) string {
	if cfg.UseTelURIForPIDFXML {
		if uri := strings.TrimSpace(state.TelPublicID); uri != "" {
			return uri
		}
	}
	return preferredIdentity(state)
}

func normalizeDialString(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "tel:") {
		value = value[4:]
	}
	value = strings.TrimPrefix(value, "+")
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
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
		var sdp []byte
		for {
			part, err := reader.NextPart()
			if errors.Is(err, io.EOF) {
				return sdp, len(sdp) > 0
			}
			if err != nil {
				return nil, false
			}
			partType, _, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
			if err != nil || !strings.EqualFold(partType, "application/sdp") {
				continue
			}
			body, err := io.ReadAll(part)
			if err != nil || len(body) == 0 {
				return nil, false
			}
			if len(sdp) > 0 {
				return nil, false
			}
			sdp = body
		}
	default:
		return nil, false
	}
}

func incomingInviteKey(msg sip.Message, method string) string {
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := sip.CSeqNumber(msg.Header("CSeq"))
	method = strings.ToUpper(strings.TrimSpace(method))
	if callID == "" || cseq <= 0 || method == "" {
		return ""
	}
	return fmt.Sprintf("%s|%d %s", callID, cseq, method)
}

func contactValue(state registration.State) string {
	params := []string{
		`audio`,
		fmt.Sprintf(`+g.3gpp.icsi-ref="%s"`, mmtelICSIEncoded),
		`+g.3gpp.mid-call`,
		`+g.3gpp.ps2cs-srvcc-orig-pre-alerting`,
		`+g.3gpp.srvcc-alerting`,
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
