package call

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type MediaOffer struct {
	Codecs []AudioCodec
	PTime  time.Duration
}

type NegotiatedMedia struct {
	Codec           AudioCodec
	PayloadType     int
	ClockRate       int
	Channels        int
	OctetAlign      bool
	DTMFPayloadType int
	DTMFClockRate   int
	PTime           time.Duration
	RemoteIP        net.IP
	RemotePort      int
}

type sdpOffer struct {
	RemoteIP         net.IP
	RemotePort       int
	Profile          string
	Payloads         []int
	Codecs           map[int]AudioCodecConfig
	PTime            time.Duration
	UnsupportedMedia []sdpMediaLine
}

type sdpMediaLine struct {
	Media    string
	Protocol string
	Formats  []string
}

const (
	rtcpSenderBandwidth   = 0
	rtcpReceiverBandwidth = 2500
)

func buildSDPOffer(cfg Config, localIP net.IP, localPort int, offer MediaOffer) ([]byte, NegotiatedMedia, error) {
	codecs := selectOfferCodecs(cfg.Codecs, offer.Codecs)
	if len(codecs) == 0 {
		return nil, NegotiatedMedia{}, errors.New("building call SDP offer: no matching codecs")
	}
	if localIP == nil || localIP.IsUnspecified() {
		localIP = net.IPv4(0, 0, 0, 0)
	}
	ptime := offer.PTime
	if ptime == 0 {
		ptime = cfg.PTime
	}
	if ptime < 0 {
		return nil, NegotiatedMedia{}, errors.New("building call SDP offer: ptime must be >= 0")
	}
	var b strings.Builder
	ipType := "IP4"
	if localIP.To4() == nil {
		ipType = "IP6"
	}
	payloads := codecPayloadList(codecs)
	fmt.Fprintf(&b, "v=0\r\n")
	fmt.Fprintf(&b, "o=- %d 1 IN %s %s\r\n", time.Now().UnixNano(), ipType, localIP.String())
	fmt.Fprintf(&b, "s=-\r\n")
	fmt.Fprintf(&b, "c=IN %s %s\r\n", ipType, localIP.String())
	fmt.Fprintf(&b, "t=0 0\r\n")
	fmt.Fprintf(&b, "m=audio %d %s %s\r\n", localPort, cfg.RTPProfile, strings.Join(payloads, " "))
	if bandwidth := audioBandwidthAS(cfg, firstSpeechCodec(codecs)); bandwidth > 0 {
		fmt.Fprintf(&b, "b=AS:%d\r\n", bandwidth)
	}
	appendRTCPBandwidth(&b, rtcpSenderBandwidth, rtcpReceiverBandwidth)
	for _, codec := range codecs {
		appendOfferCodecAttributes(&b, codec)
	}
	if ptime > 0 {
		fmt.Fprintf(&b, "a=ptime:%d\r\n", durationMillis(ptime))
	}
	if cfg.MaxPTime > 0 {
		fmt.Fprintf(&b, "a=maxptime:%d\r\n", durationMillis(cfg.MaxPTime))
	}
	fmt.Fprintf(&b, "a=sendrecv\r\n")
	media := NegotiatedMedia{
		Codec:       firstSpeechCodec(codecs).Name,
		PayloadType: firstSpeechCodec(codecs).PayloadTypes[0],
		ClockRate:   firstSpeechCodec(codecs).ClockRate,
		Channels:    firstSpeechCodec(codecs).Channels,
		OctetAlign:  firstSpeechCodec(codecs).OctetAlign,
		PTime:       ptime,
	}
	return []byte(b.String()), media, nil
}

func buildSDPAnswer(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer) ([]byte, NegotiatedMedia, error) {
	if len(remote.Payloads) == 0 {
		return nil, NegotiatedMedia{}, errors.New("building call SDP answer: remote offer has no audio payloads")
	}
	selected, ok := chooseCodec(remote, selectOfferCodecs(cfg.Codecs, offer.Codecs))
	if !ok {
		return nil, NegotiatedMedia{}, errors.New("building call SDP answer: no compatible codec")
	}
	dtmf, hasDTMF := chooseTelephoneEvent(remote, cfg.Codecs)
	if localIP == nil || localIP.IsUnspecified() {
		localIP = net.IPv4(0, 0, 0, 0)
	}
	ptime := offer.PTime
	if ptime == 0 {
		ptime = remote.PTime
	}
	if ptime == 0 {
		ptime = cfg.PTime
	}
	if ptime < 0 {
		return nil, NegotiatedMedia{}, errors.New("building call SDP answer: ptime must be >= 0")
	}
	ipType := "IP4"
	if localIP.To4() == nil {
		ipType = "IP6"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "v=0\r\n")
	fmt.Fprintf(&b, "o=- %d 1 IN %s %s\r\n", time.Now().UnixNano(), ipType, localIP.String())
	fmt.Fprintf(&b, "s=-\r\n")
	fmt.Fprintf(&b, "c=IN %s %s\r\n", ipType, localIP.String())
	fmt.Fprintf(&b, "t=0 0\r\n")
	answerPayloads := []string{strconv.Itoa(selected.PayloadTypes[0])}
	if hasDTMF {
		answerPayloads = append(answerPayloads, strconv.Itoa(dtmf.PayloadTypes[0]))
	}
	fmt.Fprintf(&b, "m=audio %d %s %s\r\n", localPort, cfg.RTPProfile, strings.Join(answerPayloads, " "))
	if bandwidth := audioBandwidthAS(cfg, selected); bandwidth > 0 {
		fmt.Fprintf(&b, "b=AS:%d\r\n", bandwidth)
	}
	appendRTCPBandwidth(&b, rtcpSenderBandwidth, rtcpReceiverBandwidth)
	appendAnswerCodecAttributes(&b, selected)
	if hasDTMF {
		appendAnswerCodecAttributes(&b, dtmf)
	}
	if ptime > 0 {
		fmt.Fprintf(&b, "a=ptime:%d\r\n", durationMillis(ptime))
	}
	if cfg.MaxPTime > 0 {
		fmt.Fprintf(&b, "a=maxptime:%d\r\n", durationMillis(cfg.MaxPTime))
	}
	fmt.Fprintf(&b, "a=sendrecv\r\n")
	appendRejectedMedia(&b, remote.UnsupportedMedia)
	return []byte(b.String()), negotiatedMedia(remote, selected, ptime, dtmf, hasDTMF), nil
}

func appendRejectedMedia(b *strings.Builder, media []sdpMediaLine) {
	for _, m := range media {
		if m.Media == "" || m.Protocol == "" {
			continue
		}
		line := "m=" + m.Media + " 0 " + m.Protocol
		if len(m.Formats) > 0 {
			line += " " + strings.Join(m.Formats, " ")
		}
		fmt.Fprintf(b, "%s\r\n", line)
	}
}

func appendRTCPBandwidth(b *strings.Builder, rs int, rr int) {
	fmt.Fprintf(b, "b=RS:%d\r\n", rs)
	fmt.Fprintf(b, "b=RR:%d\r\n", rr)
}

func negotiatedMedia(remote sdpOffer, selected AudioCodecConfig, ptime time.Duration, dtmf AudioCodecConfig, hasDTMF bool) NegotiatedMedia {
	media := NegotiatedMedia{
		Codec:       selected.Name,
		PayloadType: selected.PayloadTypes[0],
		ClockRate:   selected.ClockRate,
		Channels:    selected.Channels,
		OctetAlign:  selected.OctetAlign,
		PTime:       ptime,
		RemoteIP:    append(net.IP(nil), remote.RemoteIP...),
		RemotePort:  remote.RemotePort,
	}
	if hasDTMF {
		media.DTMFPayloadType = dtmf.PayloadTypes[0]
		media.DTMFClockRate = dtmf.ClockRate
	}
	return media
}

func parseSDP(text []byte) (sdpOffer, error) {
	offer := sdpOffer{Codecs: make(map[int]AudioCodecConfig)}
	var mediaPayloads map[int]struct{}
	inAudio := false
	lines := strings.FieldsFunc(string(text), func(r rune) bool { return r == '\n' || r == '\r' })
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "c="):
			ip, err := parseConnectionLine(line)
			if err != nil {
				return sdpOffer{}, err
			}
			if inAudio || offer.RemoteIP == nil {
				offer.RemoteIP = ip
			}
		case strings.HasPrefix(line, "m=audio "):
			port, profile, payloads, err := parseAudioLine(line)
			if err != nil {
				return sdpOffer{}, err
			}
			inAudio = true
			offer.RemotePort = port
			offer.Profile = profile
			offer.Payloads = payloads
			mediaPayloads = make(map[int]struct{}, len(payloads))
			for _, payload := range payloads {
				mediaPayloads[payload] = struct{}{}
			}
		case strings.HasPrefix(line, "m="):
			inAudio = false
			media, err := parseMediaLine(line)
			if err != nil {
				return sdpOffer{}, err
			}
			offer.UnsupportedMedia = append(offer.UnsupportedMedia, media)
		case strings.HasPrefix(line, "a=rtpmap:"):
			if !inAudio {
				continue
			}
			payloadType, codec, err := parseRTPMap(line)
			if err != nil {
				return sdpOffer{}, err
			}
			if mediaPayloads == nil {
				continue
			}
			if _, ok := mediaPayloads[payloadType]; ok {
				offer.Codecs[payloadType] = codec
			}
		case strings.HasPrefix(line, "a=fmtp:"):
			if !inAudio {
				continue
			}
			payloadType, fmtp := parseFMTP(line)
			codec := offer.Codecs[payloadType]
			codec.OctetAlign = fmtpFlag(fmtp, "octet-align")
			codec.ModeSet = fmtpParam(fmtp, "mode-set")
			codec.Bitrate = fmtpParam(fmtp, "br")
			codec.Bandwidth = fmtpParam(fmtp, "bw")
			if value, ok := fmtpSignedParam(fmtp, "ch-aw-recv"); ok {
				codec.ChAwRecv = &value
			}
			if codec.Name != "" {
				offer.Codecs[payloadType] = codec
			}
		case strings.HasPrefix(line, "a=ptime:"):
			if inAudio {
				offer.PTime = parseSDPDuration(strings.TrimPrefix(line, "a=ptime:"))
			}
		}
	}
	if offer.RemotePort == 0 {
		return sdpOffer{}, errors.New("parsing call SDP: audio media line is missing")
	}
	if offer.RemoteIP == nil {
		return sdpOffer{}, errors.New("parsing call SDP: connection line is missing")
	}
	applyStaticRTPPayloads(&offer)
	return offer, nil
}

func applyStaticRTPPayloads(offer *sdpOffer) {
	if !strings.EqualFold(offer.Profile, "RTP/AVP") {
		return
	}
	for _, payload := range offer.Payloads {
		if _, ok := offer.Codecs[payload]; ok {
			continue
		}
		if payload == 0 {
			offer.Codecs[payload] = AudioCodecConfig{
				Name:         CodecPCMU,
				PayloadTypes: []int{payload},
				ClockRate:    8000,
			}
		}
	}
}

func selectOfferCodecs(configured []AudioCodecConfig, requested []AudioCodec) []AudioCodecConfig {
	if len(requested) == 0 {
		return cloneCodecConfigs(configured)
	}
	wanted := make(map[AudioCodec]struct{}, len(requested))
	for _, name := range requested {
		switch strings.ToUpper(strings.TrimSpace(string(name))) {
		case "AMR":
			wanted[CodecAMR] = struct{}{}
		case "AMR-WB", "AMRWB":
			wanted[CodecAMRWB] = struct{}{}
		case "EVS":
			wanted[CodecEVS] = struct{}{}
		case "PCMU":
			wanted[CodecPCMU] = struct{}{}
		case "TELEPHONE-EVENT":
			wanted[CodecTelephoneEvent] = struct{}{}
		}
	}
	codecs := make([]AudioCodecConfig, 0, len(configured))
	for _, codec := range configured {
		if _, ok := wanted[codec.Name]; ok {
			codecs = append(codecs, cloneCodecConfig(codec))
		}
	}
	for _, codec := range codecs {
		if codec.Name == CodecTelephoneEvent {
			return codecs
		}
	}
	for _, codec := range configured {
		if codec.Name == CodecTelephoneEvent {
			codecs = append(codecs, cloneCodecConfig(codec))
			break
		}
	}
	return codecs
}

func chooseCodec(remote sdpOffer, local []AudioCodecConfig) (AudioCodecConfig, bool) {
	localByName := make(map[AudioCodec]AudioCodecConfig, len(local))
	for _, codec := range local {
		if codec.Name == CodecTelephoneEvent {
			continue
		}
		localByName[codec.Name] = codec
	}
	for _, payload := range remote.Payloads {
		remoteCodec, ok := remote.Codecs[payload]
		if !ok || remoteCodec.Name == CodecTelephoneEvent {
			continue
		}
		localCodec, ok := localByName[remoteCodec.Name]
		if !ok {
			continue
		}
		selected := localCodec
		selected.PayloadTypes = []int{payload}
		if remoteCodec.ClockRate != 0 {
			selected.ClockRate = remoteCodec.ClockRate
		}
		if remoteCodec.Channels != 0 {
			selected.Channels = remoteCodec.Channels
		}
		if selected.Name == CodecEVS {
			selected.ModeSet = remoteCodec.ModeSet
			selected.Bitrate = remoteCodec.Bitrate
			selected.Bandwidth = remoteCodec.Bandwidth
		}
		if selected.ModeSet == "" {
			selected.ModeSet = remoteCodec.ModeSet
		}
		if remoteCodec.OctetAlign {
			selected.OctetAlign = true
		}
		if selected.Bitrate == "" {
			selected.Bitrate = remoteCodec.Bitrate
		}
		if selected.Bandwidth == "" {
			selected.Bandwidth = remoteCodec.Bandwidth
		}
		if remoteCodec.ChAwRecv != nil {
			value := *remoteCodec.ChAwRecv
			selected.ChAwRecv = &value
		}
		return selected, true
	}
	return AudioCodecConfig{}, false
}

func chooseTelephoneEvent(remote sdpOffer, local []AudioCodecConfig) (AudioCodecConfig, bool) {
	var localCodec AudioCodecConfig
	for _, codec := range local {
		if codec.Name == CodecTelephoneEvent {
			localCodec = codec
			break
		}
	}
	if localCodec.Name == "" {
		return AudioCodecConfig{}, false
	}
	for _, payload := range remote.Payloads {
		remoteCodec, ok := remote.Codecs[payload]
		if !ok || remoteCodec.Name != CodecTelephoneEvent {
			continue
		}
		selected := localCodec
		selected.PayloadTypes = []int{payload}
		if remoteCodec.ClockRate != 0 {
			selected.ClockRate = remoteCodec.ClockRate
		}
		if remoteCodec.Channels != 0 {
			selected.Channels = remoteCodec.Channels
		}
		return selected, true
	}
	return AudioCodecConfig{}, false
}

func appendOfferCodecAttributes(b *strings.Builder, codec AudioCodecConfig) {
	for _, payloadType := range codec.PayloadTypes {
		if codec.Channels > 1 {
			fmt.Fprintf(b, "a=rtpmap:%d %s/%d/%d\r\n", payloadType, codec.Name, codec.ClockRate, codec.Channels)
		} else {
			fmt.Fprintf(b, "a=rtpmap:%d %s/%d\r\n", payloadType, codec.Name, codec.ClockRate)
		}
		fmtp := offerCodecFMTP(codec)
		if fmtp != "" {
			fmt.Fprintf(b, "a=fmtp:%d %s\r\n", payloadType, fmtp)
		}
	}
}

func appendAnswerCodecAttributes(b *strings.Builder, codec AudioCodecConfig) {
	for _, payloadType := range codec.PayloadTypes {
		if codec.Channels > 1 {
			fmt.Fprintf(b, "a=rtpmap:%d %s/%d/%d\r\n", payloadType, codec.Name, codec.ClockRate, codec.Channels)
		} else {
			fmt.Fprintf(b, "a=rtpmap:%d %s/%d\r\n", payloadType, codec.Name, codec.ClockRate)
		}
		fmtp := answerCodecFMTP(codec)
		if fmtp != "" {
			fmt.Fprintf(b, "a=fmtp:%d %s\r\n", payloadType, fmtp)
		}
	}
}

func offerCodecFMTP(codec AudioCodecConfig) string {
	switch codec.Name {
	case CodecAMR, CodecAMRWB:
		if codec.OctetAlign {
			return "octet-align=1"
		}
		return ""
	case CodecEVS:
		var params []string
		if codec.Bitrate != "" {
			params = append(params, "br="+codec.Bitrate)
		}
		if codec.Bandwidth != "" {
			params = append(params, "bw="+codec.Bandwidth)
		}
		if codec.ChAwRecv != nil {
			params = append(params, "ch-aw-recv="+strconv.Itoa(*codec.ChAwRecv))
		}
		return strings.Join(params, ";")
	default:
		return answerCodecFMTP(codec)
	}
}

func answerCodecFMTP(codec AudioCodecConfig) string {
	var params []string
	switch codec.Name {
	case CodecAMR, CodecAMRWB:
		if codec.OctetAlign {
			params = append(params, "octet-align=1")
		}
		if codec.ModeSet != "" {
			params = append(params, "mode-set="+codec.ModeSet)
		}
	case CodecEVS:
		if codec.Bitrate != "" {
			params = append(params, "br="+codec.Bitrate)
		}
		if codec.Bandwidth != "" {
			params = append(params, "bw="+codec.Bandwidth)
		}
		if codec.ChAwRecv != nil {
			params = append(params, "ch-aw-recv="+strconv.Itoa(*codec.ChAwRecv))
		}
		if codec.ModeSet != "" {
			params = append(params, "mode-set="+codec.ModeSet)
		}
	}
	return strings.Join(params, ";")
}

func audioBandwidthAS(cfg Config, codec AudioCodecConfig) int {
	if cfg.AudioASBandwidthKbps > 0 {
		return cfg.AudioASBandwidthKbps
	}
	return codecBandwidthAS(codec)
}

func codecBandwidthAS(codec AudioCodecConfig) int {
	switch codec.Name {
	case CodecAMR:
		return 13
	case CodecAMRWB:
		return 14
	case CodecEVS:
		return evsBandwidthAS(codec.Bitrate)
	default:
		return 0
	}
}

func evsBandwidthAS(bitrate string) int {
	bitrate = strings.TrimSpace(bitrate)
	if bitrate == "" {
		return 25
	}
	if _, right, ok := strings.Cut(bitrate, "-"); ok {
		bitrate = right
	}
	value, err := strconv.ParseFloat(bitrate, 64)
	if err != nil || value <= 0 {
		return 25
	}
	return int(value + 0.999)
}

func parseConnectionLine(line string) (net.IP, error) {
	fields := strings.Fields(strings.TrimPrefix(line, "c="))
	if len(fields) != 3 || !strings.EqualFold(fields[0], "IN") {
		return nil, fmt.Errorf("parsing call SDP: invalid connection line %q", line)
	}
	ip := net.ParseIP(fields[2])
	if ip == nil {
		return nil, fmt.Errorf("parsing call SDP: invalid connection address %q", fields[2])
	}
	return ip, nil
}

func parseAudioLine(line string) (int, string, []int, error) {
	fields := strings.Fields(strings.TrimPrefix(line, "m=audio "))
	if len(fields) < 3 {
		return 0, "", nil, fmt.Errorf("parsing call SDP: invalid audio line %q", line)
	}
	port, ok := parseBoundedDecimal(fields[0], 1, 65535)
	if !ok {
		return 0, "", nil, fmt.Errorf("parsing call SDP: invalid audio port %q", fields[0])
	}
	payloads := make([]int, 0, len(fields)-2)
	for _, field := range fields[2:] {
		payload, ok := parseRTPPayloadType(field)
		if !ok {
			return 0, "", nil, fmt.Errorf("parsing call SDP: invalid payload type %q", field)
		}
		payloads = append(payloads, payload)
	}
	return port, fields[1], payloads, nil
}

func parseMediaLine(line string) (sdpMediaLine, error) {
	fields := strings.Fields(strings.TrimPrefix(line, "m="))
	if len(fields) < 3 {
		return sdpMediaLine{}, fmt.Errorf("parsing call SDP: invalid media line %q", line)
	}
	if _, ok := parseBoundedDecimal(fields[1], 0, 65535); !ok {
		return sdpMediaLine{}, fmt.Errorf("parsing call SDP: invalid media port %q", fields[1])
	}
	return sdpMediaLine{
		Media:    fields[0],
		Protocol: fields[2],
		Formats:  append([]string(nil), fields[3:]...),
	}, nil
}

func parseRTPPayloadType(value string) (int, bool) {
	return parseBoundedDecimal(value, 0, 127)
}

func parsePositiveDecimal(value string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

func parseBoundedDecimal(value string, minValue, maxValue int) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < minValue || n > maxValue {
		return 0, false
	}
	return n, true
}

func parseRTPMap(line string) (int, AudioCodecConfig, error) {
	value := strings.TrimPrefix(line, "a=rtpmap:")
	left, right, ok := strings.Cut(value, " ")
	if !ok {
		return 0, AudioCodecConfig{}, fmt.Errorf("parsing call SDP: invalid rtpmap %q", line)
	}
	payloadType, ok := parseRTPPayloadType(left)
	if !ok {
		return 0, AudioCodecConfig{}, fmt.Errorf("parsing call SDP: invalid rtpmap payload %q", left)
	}
	parts := strings.Split(right, "/")
	if len(parts) < 2 {
		return 0, AudioCodecConfig{}, fmt.Errorf("parsing call SDP: invalid rtpmap encoding %q", right)
	}
	clock, ok := parsePositiveDecimal(parts[1])
	if !ok {
		return 0, AudioCodecConfig{}, fmt.Errorf("parsing call SDP: invalid rtpmap clock %q", parts[1])
	}
	channels := 0
	if len(parts) > 2 {
		channels, ok = parsePositiveDecimal(parts[2])
		if !ok {
			return 0, AudioCodecConfig{}, fmt.Errorf("parsing call SDP: invalid rtpmap channels %q", parts[2])
		}
	}
	codec := AudioCodec(strings.TrimSpace(parts[0]))
	switch strings.ToUpper(string(codec)) {
	case "AMR":
		codec = CodecAMR
	case "AMR-WB", "AMRWB":
		codec = CodecAMRWB
	case "EVS":
		codec = CodecEVS
	case "PCMU":
		codec = CodecPCMU
	case "TELEPHONE-EVENT":
		codec = CodecTelephoneEvent
	default:
		return payloadType, AudioCodecConfig{}, nil
	}
	return payloadType, AudioCodecConfig{Name: codec, PayloadTypes: []int{payloadType}, ClockRate: clock, Channels: channels}, nil
}

func parseFMTP(line string) (int, string) {
	value := strings.TrimPrefix(line, "a=fmtp:")
	left, right, ok := strings.Cut(value, " ")
	if !ok {
		return 0, ""
	}
	payloadType, ok := parseRTPPayloadType(left)
	if !ok {
		return 0, ""
	}
	return payloadType, right
}

func fmtpParam(fmtp, want string) string {
	for _, part := range strings.Split(fmtp, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(name, want) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func fmtpSignedParam(fmtp, want string) (int, bool) {
	value := fmtpParam(fmtp, want)
	if value == "" {
		return 0, false
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, false
	}
	return n, true
}

func fmtpFlag(fmtp, want string) bool {
	for _, part := range strings.Split(fmtp, ";") {
		name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || !strings.EqualFold(name, want) {
			continue
		}
		return strings.TrimSpace(value) == "1"
	}
	return false
}

func parseSDPDuration(value string) time.Duration {
	ms, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || ms < 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func codecPayloadList(codecs []AudioCodecConfig) []string {
	var payloads []int
	for _, codec := range codecs {
		payloads = append(payloads, codec.PayloadTypes...)
	}
	values := make([]string, 0, len(payloads))
	for _, payload := range payloads {
		values = append(values, strconv.Itoa(payload))
	}
	return values
}

func firstSpeechCodec(codecs []AudioCodecConfig) AudioCodecConfig {
	for _, codec := range codecs {
		if codec.Name != CodecTelephoneEvent {
			return codec
		}
	}
	return codecs[0]
}

func cloneCodecConfigs(codecs []AudioCodecConfig) []AudioCodecConfig {
	cloned := make([]AudioCodecConfig, 0, len(codecs))
	for _, codec := range codecs {
		cloned = append(cloned, cloneCodecConfig(codec))
	}
	return cloned
}

func cloneCodecConfig(codec AudioCodecConfig) AudioCodecConfig {
	codec.PayloadTypes = append([]int(nil), codec.PayloadTypes...)
	if codec.ChAwRecv != nil {
		value := *codec.ChAwRecv
		codec.ChAwRecv = &value
	}
	return codec
}

func durationMillis(d time.Duration) int {
	return int(d / time.Millisecond)
}
