package voice

import (
	"encoding"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

var _ encoding.TextUnmarshaler = (*sdpOffer)(nil)
var _ encoding.TextMarshaler = sdpConnectionLine{}
var _ encoding.TextUnmarshaler = (*sdpConnectionLine)(nil)

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
	Direction       mediaDirection
	RemoteIP        net.IP
	RemotePort      int
	RemoteRTCPIP    net.IP
	RemoteRTCPPort  int
	RTCPMux         bool
	RTCPDisabled    bool
}

type mediaDirection string

const (
	mediaDirectionSendRecv mediaDirection = "sendrecv"
	mediaDirectionSendOnly mediaDirection = "sendonly"
	mediaDirectionRecvOnly mediaDirection = "recvonly"
	mediaDirectionInactive mediaDirection = "inactive"
)

type sdpOffer struct {
	RemoteIP              net.IP
	RemotePort            int
	RemoteRTCPIP          net.IP
	RemoteRTCPPort        int
	RTCPMux               bool
	Preconditions         bool
	LocalQoSStatus        string
	RemoteQoSConfirmation bool
	Profile               string
	Payloads              []int
	Codecs                map[int]AudioCodecConfig
	PTime                 time.Duration
	RTCPSenderBandwidth   *int
	RTCPReceiverBandwidth *int
	Direction             mediaDirection
	UnsupportedMedia      []sdpMediaLine
}

type sdpMediaLine struct {
	Media    string
	Protocol string
	Formats  []string
}

type sdpAudioLine struct {
	Port     int
	Protocol string
	Payloads []int
}

type sdpConnectionLine struct {
	Network     string
	AddressType string
	IP          net.IP
}

const (
	rtcpSenderBandwidth   = 0
	rtcpReceiverBandwidth = 2500

	amrModeChangeCapability = 2
	amrMaxRedMillis         = 220

	sdpNetworkIN      = "IN"
	sdpAddressTypeIP4 = "IP4"
	sdpAddressTypeIP6 = "IP6"
)

func buildSDPOffer(cfg Config, localIP net.IP, localPort int, offer MediaOffer) ([]byte, NegotiatedMedia, error) {
	return buildSDPOfferWithDirection(cfg, localIP, localPort, offer, mediaDirectionSendRecv)
}

func buildSDPOfferWithDirection(cfg Config, localIP net.IP, localPort int, offer MediaOffer, direction mediaDirection) ([]byte, NegotiatedMedia, error) {
	if !direction.valid() {
		return nil, NegotiatedMedia{}, fmt.Errorf("building voice SDP offer: invalid media direction %q", direction)
	}
	codecs := selectOfferCodecs(cfg.Codecs, offer.Codecs)
	if len(codecs) == 0 {
		return nil, NegotiatedMedia{}, errors.New("building voice SDP offer: no matching codecs")
	}
	if localIP == nil || localIP.IsUnspecified() {
		localIP = net.IPv4(0, 0, 0, 0)
	}
	ptime := offer.PTime
	if ptime == 0 {
		ptime = cfg.PTime
	}
	if ptime < 0 {
		return nil, NegotiatedMedia{}, errors.New("building voice SDP offer: ptime must be >= 0")
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
	fmt.Fprintf(&b, "a=%s\r\n", direction)
	if cfg.Preconditions {
		appendQoSPreconditions(&b, qosStatusNone, qosStatusNone, false)
	}
	media := NegotiatedMedia{
		Codec:       firstSpeechCodec(codecs).Name,
		PayloadType: firstSpeechCodec(codecs).PayloadTypes[0],
		ClockRate:   firstSpeechCodec(codecs).ClockRate,
		Channels:    firstSpeechCodec(codecs).Channels,
		OctetAlign:  firstSpeechCodec(codecs).OctetAlign,
		PTime:       ptime,
		Direction:   direction,
	}
	return []byte(b.String()), media, nil
}

func buildSDPAnswer(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer) ([]byte, NegotiatedMedia, error) {
	return buildSDPAnswerWithDirection(cfg, localIP, localPort, remote, offer, answerDirection(remote.Direction, false))
}

func buildSDPAnswerWithLocalHold(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer, localHold bool) ([]byte, NegotiatedMedia, error) {
	return buildSDPAnswerWithDirection(cfg, localIP, localPort, remote, offer, answerDirection(remote.Direction, localHold))
}

func buildSDPAnswerWithDirection(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer, direction mediaDirection) ([]byte, NegotiatedMedia, error) {
	if !direction.valid() {
		return nil, NegotiatedMedia{}, fmt.Errorf("building voice SDP answer: invalid media direction %q", direction)
	}
	if len(remote.Payloads) == 0 {
		return nil, NegotiatedMedia{}, errors.New("building voice SDP answer: remote offer has no audio payloads")
	}
	selected, ok := chooseCodec(remote, selectOfferCodecs(cfg.Codecs, offer.Codecs))
	if !ok {
		return nil, NegotiatedMedia{}, errors.New("building voice SDP answer: no compatible codec")
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
		return nil, NegotiatedMedia{}, errors.New("building voice SDP answer: ptime must be >= 0")
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
	rs, rr := rtcpAnswerBandwidth(remote)
	appendRTCPBandwidth(&b, rs, rr)
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
	if remote.RTCPMux {
		fmt.Fprintf(&b, "a=rtcp-mux\r\n")
	}
	fmt.Fprintf(&b, "a=%s\r\n", direction)
	if cfg.Preconditions && remote.Preconditions {
		appendQoSPreconditions(&b, qosStatusNone, qosStatusNone, remote.LocalQoSStatus != qosStatusSendRecv)
	}
	appendRejectedMedia(&b, remote.UnsupportedMedia)
	media := negotiatedMedia(remote, selected, ptime, dtmf, hasDTMF)
	media.Direction = direction
	media.RTCPDisabled = rtcpBandwidthDisabled(rs, rr)
	return []byte(b.String()), media, nil
}

func buildSDPPreconditionUpdate(cfg Config, localIP net.IP, localPort int, answer sdpOffer, current NegotiatedMedia) ([]byte, error) {
	selected, ok := chooseCodec(answer, cfg.Codecs)
	if !ok {
		return nil, errors.New("building voice precondition SDP update: no compatible codec")
	}
	dtmf, hasDTMF := chooseTelephoneEvent(answer, cfg.Codecs)
	if localIP == nil || localIP.IsUnspecified() {
		localIP = net.IPv4(0, 0, 0, 0)
	}
	ptime := nonZeroDuration(answer.PTime, current.PTime, cfg.PTime)
	ipType := "IP4"
	if localIP.To4() == nil {
		ipType = "IP6"
	}
	payloads := []string{strconv.Itoa(selected.PayloadTypes[0])}
	if hasDTMF {
		payloads = append(payloads, strconv.Itoa(dtmf.PayloadTypes[0]))
	}
	var b strings.Builder
	fmt.Fprintf(&b, "v=0\r\n")
	fmt.Fprintf(&b, "o=- %d 1 IN %s %s\r\n", time.Now().UnixNano(), ipType, localIP.String())
	fmt.Fprintf(&b, "s=-\r\n")
	fmt.Fprintf(&b, "c=IN %s %s\r\n", ipType, localIP.String())
	fmt.Fprintf(&b, "t=0 0\r\n")
	fmt.Fprintf(&b, "m=audio %d %s %s\r\n", localPort, cfg.RTPProfile, strings.Join(payloads, " "))
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
	appendQoSPreconditions(&b, qosStatusSendRecv, qosStatusNone, false)
	return []byte(b.String()), nil
}

func answerDirection(remote mediaDirection, localHold bool) mediaDirection {
	if remote == "" {
		remote = mediaDirectionSendRecv
	}
	if localHold {
		return mediaDirectionInactive
	}
	switch remote {
	case mediaDirectionSendOnly:
		return mediaDirectionRecvOnly
	case mediaDirectionRecvOnly:
		return mediaDirectionSendOnly
	case mediaDirectionInactive:
		return mediaDirectionInactive
	default:
		return mediaDirectionSendRecv
	}
}

func (d mediaDirection) valid() bool {
	switch d {
	case mediaDirectionSendRecv, mediaDirectionSendOnly, mediaDirectionRecvOnly, mediaDirectionInactive:
		return true
	default:
		return false
	}
}

const (
	qosStatusNone     = "none"
	qosStatusSendRecv = "sendrecv"
)

func appendQoSPreconditions(b *strings.Builder, localStatus string, remoteStatus string, requestRemoteConfirmation bool) {
	fmt.Fprintf(b, "a=curr:qos local %s\r\n", localStatus)
	fmt.Fprintf(b, "a=curr:qos remote %s\r\n", remoteStatus)
	fmt.Fprintf(b, "a=des:qos mandatory local sendrecv\r\n")
	fmt.Fprintf(b, "a=des:qos optional remote sendrecv\r\n")
	if requestRemoteConfirmation {
		fmt.Fprintf(b, "a=conf:qos remote sendrecv\r\n")
	}
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
	remoteRTCPIP := append(net.IP(nil), remote.RemoteRTCPIP...)
	if len(remoteRTCPIP) == 0 {
		remoteRTCPIP = append(net.IP(nil), remote.RemoteIP...)
	}
	remoteRTCPPort := remote.RemoteRTCPPort
	if remote.RTCPMux {
		remoteRTCPIP = append(net.IP(nil), remote.RemoteIP...)
		remoteRTCPPort = remote.RemotePort
	}
	media := NegotiatedMedia{
		Codec:          selected.Name,
		PayloadType:    selected.PayloadTypes[0],
		ClockRate:      selected.ClockRate,
		Channels:       selected.Channels,
		OctetAlign:     selected.OctetAlign,
		PTime:          ptime,
		Direction:      answerDirection(remote.Direction, false),
		RemoteIP:       append(net.IP(nil), remote.RemoteIP...),
		RemotePort:     remote.RemotePort,
		RemoteRTCPIP:   remoteRTCPIP,
		RemoteRTCPPort: remoteRTCPPort,
		RTCPMux:        remote.RTCPMux,
		RTCPDisabled:   rtcpDisabled(remote),
	}
	if hasDTMF {
		media.DTMFPayloadType = dtmf.PayloadTypes[0]
		media.DTMFClockRate = dtmf.ClockRate
	}
	return media
}

func parseSDP(text []byte) (sdpOffer, error) {
	var offer sdpOffer
	if err := offer.UnmarshalText(text); err != nil {
		return sdpOffer{}, err
	}
	return offer, nil
}

func (offer *sdpOffer) UnmarshalText(text []byte) error {
	*offer = sdpOffer{Codecs: make(map[int]AudioCodecConfig), Direction: mediaDirectionSendRecv}
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
				return err
			}
			if inAudio || offer.RemoteIP == nil {
				offer.RemoteIP = ip
			}
		case strings.HasPrefix(line, "m=audio "):
			var audio sdpAudioLine
			if err := audio.UnmarshalText([]byte(line)); err != nil {
				return err
			}
			inAudio = true
			offer.RemotePort = audio.Port
			offer.Profile = audio.Protocol
			offer.Payloads = audio.Payloads
			mediaPayloads = make(map[int]struct{}, len(audio.Payloads))
			for _, payload := range audio.Payloads {
				mediaPayloads[payload] = struct{}{}
			}
		case strings.HasPrefix(line, "m="):
			inAudio = false
			media, err := parseMediaLine(line)
			if err != nil {
				return err
			}
			offer.UnsupportedMedia = append(offer.UnsupportedMedia, media)
		case strings.HasPrefix(line, "a=rtpmap:"):
			if !inAudio {
				continue
			}
			payloadType, codec, err := parseRTPMap(line)
			if err != nil {
				return err
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
		case strings.HasPrefix(line, "a=rtcp:"):
			if !inAudio {
				continue
			}
			port, ip, err := parseRTCPAttribute(line)
			if err != nil {
				return err
			}
			offer.RemoteRTCPPort = port
			offer.RemoteRTCPIP = ip
		case strings.EqualFold(line, "a=rtcp-mux"):
			if inAudio {
				offer.RTCPMux = true
			}
		case isSDPDirectionLine(line):
			if inAudio {
				offer.Direction = mediaDirection(strings.TrimPrefix(strings.ToLower(line), "a="))
			}
		case strings.HasPrefix(line, "a=curr:qos") || strings.HasPrefix(line, "a=des:qos") || strings.HasPrefix(line, "a=conf:qos"):
			if inAudio {
				offer.Preconditions = true
				if status, ok := parseCurrentQoSLocal(line); ok {
					offer.LocalQoSStatus = status
				}
				if parseQoSConfirmationRemote(line) {
					offer.RemoteQoSConfirmation = true
				}
			}
		case strings.HasPrefix(line, "b="):
			if !inAudio {
				continue
			}
			modifier, value, ok, err := parseRTCPBandwidth(line)
			if err != nil {
				return err
			}
			if !ok {
				continue
			}
			switch modifier {
			case "RS":
				offer.RTCPSenderBandwidth = new(value)
			case "RR":
				offer.RTCPReceiverBandwidth = new(value)
			}
		}
	}
	if offer.RemotePort == 0 {
		return errors.New("parsing voice SDP: audio media line is missing")
	}
	if offer.RemoteIP == nil {
		return errors.New("parsing voice SDP: connection line is missing")
	}
	applyStaticRTPPayloads(offer)
	return nil
}

func isSDPDirectionLine(line string) bool {
	switch strings.ToLower(line) {
	case "a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive":
		return true
	default:
		return false
	}
}

func parseCurrentQoSLocal(line string) (string, bool) {
	fields := strings.Fields(strings.TrimPrefix(line, "a=curr:qos"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "local") {
		return "", false
	}
	return strings.ToLower(fields[1]), true
}

func parseQoSConfirmationRemote(line string) bool {
	fields := strings.Fields(strings.TrimPrefix(line, "a=conf:qos"))
	return len(fields) == 2 && strings.EqualFold(fields[0], "remote")
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
		params := []string{
			"mode-change-capability=" + strconv.Itoa(amrModeChangeCapability),
			"max-red=" + strconv.Itoa(amrMaxRedMillis),
		}
		if codec.OctetAlign {
			params = append([]string{"octet-align=1"}, params...)
		}
		return strings.Join(params, ";")
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
		params = append(params,
			"mode-change-capability="+strconv.Itoa(amrModeChangeCapability),
			"max-red="+strconv.Itoa(amrMaxRedMillis),
		)
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
	var conn sdpConnectionLine
	if err := conn.UnmarshalText([]byte(line)); err != nil {
		return nil, err
	}
	return conn.IP, nil
}

func (l sdpConnectionLine) MarshalText() ([]byte, error) {
	network := strings.TrimSpace(l.Network)
	if network == "" {
		network = sdpNetworkIN
	}
	if !strings.EqualFold(network, sdpNetworkIN) {
		return nil, fmt.Errorf("building voice SDP: invalid connection network %q", l.Network)
	}
	addressType := strings.TrimSpace(l.AddressType)
	if addressType == "" {
		if l.IP.To4() == nil {
			addressType = sdpAddressTypeIP6
		} else {
			addressType = sdpAddressTypeIP4
		}
	}
	if err := validateSDPConnectionAddress(addressType, l.IP); err != nil {
		return nil, err
	}
	return []byte(fmt.Sprintf("c=%s %s %s", sdpNetworkIN, strings.ToUpper(addressType), l.IP.String())), nil
}

func (l *sdpConnectionLine) UnmarshalText(text []byte) error {
	line := string(text)
	fields := strings.Fields(strings.TrimPrefix(line, "c="))
	if len(fields) != 3 || !strings.EqualFold(fields[0], sdpNetworkIN) {
		return fmt.Errorf("parsing voice SDP: invalid connection line %q", line)
	}
	ip := net.ParseIP(fields[2])
	if ip == nil {
		return fmt.Errorf("parsing voice SDP: invalid connection address %q", fields[2])
	}
	if err := validateSDPConnectionAddress(fields[1], ip); err != nil {
		return err
	}
	*l = sdpConnectionLine{
		Network:     sdpNetworkIN,
		AddressType: strings.ToUpper(fields[1]),
		IP:          ip,
	}
	return nil
}

func validateSDPConnectionAddress(addressType string, ip net.IP) error {
	switch {
	case ip == nil:
		return errors.New("building voice SDP: connection address is empty")
	case strings.EqualFold(addressType, sdpAddressTypeIP4) && ip.To4() == nil:
		return fmt.Errorf("parsing voice SDP: invalid connection IP4 address %q", ip.String())
	case strings.EqualFold(addressType, sdpAddressTypeIP6) && ip.To4() != nil:
		return fmt.Errorf("parsing voice SDP: invalid connection IP6 address %q", ip.String())
	case !strings.EqualFold(addressType, sdpAddressTypeIP4) && !strings.EqualFold(addressType, sdpAddressTypeIP6):
		return fmt.Errorf("parsing voice SDP: invalid connection address type %q", addressType)
	}
	return nil
}

func (l sdpAudioLine) MarshalText() ([]byte, error) {
	if l.Port <= 0 || l.Port > 65535 {
		return nil, fmt.Errorf("building voice SDP: invalid audio port %d", l.Port)
	}
	if strings.TrimSpace(l.Protocol) == "" {
		return nil, errors.New("building voice SDP: audio protocol is empty")
	}
	if len(l.Payloads) == 0 {
		return nil, errors.New("building voice SDP: audio payloads are empty")
	}
	payloads := make([]string, 0, len(l.Payloads))
	for _, payload := range l.Payloads {
		if payload < 0 || payload > 127 {
			return nil, fmt.Errorf("building voice SDP: invalid payload type %d", payload)
		}
		payloads = append(payloads, strconv.Itoa(payload))
	}
	return []byte(fmt.Sprintf("m=audio %d %s %s", l.Port, l.Protocol, strings.Join(payloads, " "))), nil
}

func (l *sdpAudioLine) UnmarshalText(text []byte) error {
	line := string(text)
	fields := strings.Fields(strings.TrimPrefix(line, "m=audio "))
	if len(fields) < 3 {
		return fmt.Errorf("parsing voice SDP: invalid audio line %q", line)
	}
	port, ok := parseBoundedDecimal(fields[0], 1, 65535)
	if !ok {
		return fmt.Errorf("parsing voice SDP: invalid audio port %q", fields[0])
	}
	payloads := make([]int, 0, len(fields)-2)
	for _, field := range fields[2:] {
		payload, ok := parseRTPPayloadType(field)
		if !ok {
			return fmt.Errorf("parsing voice SDP: invalid payload type %q", field)
		}
		payloads = append(payloads, payload)
	}
	*l = sdpAudioLine{Port: port, Protocol: fields[1], Payloads: payloads}
	return nil
}

func parseMediaLine(line string) (sdpMediaLine, error) {
	fields := strings.Fields(strings.TrimPrefix(line, "m="))
	if len(fields) < 3 {
		return sdpMediaLine{}, fmt.Errorf("parsing voice SDP: invalid media line %q", line)
	}
	if _, ok := parseBoundedDecimal(fields[1], 0, 65535); !ok {
		return sdpMediaLine{}, fmt.Errorf("parsing voice SDP: invalid media port %q", fields[1])
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

func parseNonNegativeDecimal(value string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func parseRTCPBandwidth(line string) (string, int, bool, error) {
	value := strings.TrimPrefix(line, "b=")
	left, right, ok := strings.Cut(value, ":")
	if !ok {
		return "", 0, false, nil
	}
	modifier := strings.ToUpper(strings.TrimSpace(left))
	if modifier != "RS" && modifier != "RR" {
		return "", 0, false, nil
	}
	bandwidth, ok := parseNonNegativeDecimal(right)
	if !ok {
		return "", 0, false, fmt.Errorf("parsing voice SDP: invalid %s bandwidth %q", modifier, right)
	}
	return modifier, bandwidth, true, nil
}

func parseRTCPAttribute(line string) (int, net.IP, error) {
	fields := strings.Fields(strings.TrimPrefix(line, "a=rtcp:"))
	if len(fields) != 1 && len(fields) != 4 {
		return 0, nil, fmt.Errorf("parsing voice SDP: invalid rtcp attribute %q", line)
	}
	port, ok := parseBoundedDecimal(fields[0], 1, 65535)
	if !ok {
		return 0, nil, fmt.Errorf("parsing voice SDP: invalid rtcp port %q", fields[0])
	}
	if len(fields) == 1 {
		return port, nil, nil
	}
	if !strings.EqualFold(fields[1], "IN") {
		return 0, nil, fmt.Errorf("parsing voice SDP: invalid rtcp network type %q", fields[1])
	}
	ip := net.ParseIP(fields[3])
	if ip == nil {
		return 0, nil, fmt.Errorf("parsing voice SDP: invalid rtcp address %q", fields[3])
	}
	switch {
	case strings.EqualFold(fields[2], sdpAddressTypeIP4) && ip.To4() == nil:
		return 0, nil, fmt.Errorf("parsing voice SDP: invalid rtcp IP4 address %q", fields[3])
	case strings.EqualFold(fields[2], sdpAddressTypeIP6) && ip.To4() != nil:
		return 0, nil, fmt.Errorf("parsing voice SDP: invalid rtcp IP6 address %q", fields[3])
	case !strings.EqualFold(fields[2], sdpAddressTypeIP4) && !strings.EqualFold(fields[2], sdpAddressTypeIP6):
		return 0, nil, fmt.Errorf("parsing voice SDP: invalid rtcp address type %q", fields[2])
	}
	return port, ip, nil
}

func rtcpAnswerBandwidth(remote sdpOffer) (int, int) {
	rs := rtcpSenderBandwidth
	rr := rtcpReceiverBandwidth
	if remote.RTCPSenderBandwidth != nil && *remote.RTCPSenderBandwidth == 0 {
		rs = 0
	}
	if remote.RTCPReceiverBandwidth != nil && *remote.RTCPReceiverBandwidth == 0 {
		rr = 0
	}
	return rs, rr
}

func rtcpDisabled(remote sdpOffer) bool {
	return remote.RTCPSenderBandwidth != nil && *remote.RTCPSenderBandwidth == 0 &&
		remote.RTCPReceiverBandwidth != nil && *remote.RTCPReceiverBandwidth == 0
}

func rtcpBandwidthDisabled(rs int, rr int) bool {
	return rs == 0 && rr == 0
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
		return 0, AudioCodecConfig{}, fmt.Errorf("parsing voice SDP: invalid rtpmap %q", line)
	}
	payloadType, ok := parseRTPPayloadType(left)
	if !ok {
		return 0, AudioCodecConfig{}, fmt.Errorf("parsing voice SDP: invalid rtpmap payload %q", left)
	}
	parts := strings.Split(right, "/")
	if len(parts) < 2 {
		return 0, AudioCodecConfig{}, fmt.Errorf("parsing voice SDP: invalid rtpmap encoding %q", right)
	}
	clock, ok := parsePositiveDecimal(parts[1])
	if !ok {
		return 0, AudioCodecConfig{}, fmt.Errorf("parsing voice SDP: invalid rtpmap clock %q", parts[1])
	}
	channels := 0
	if len(parts) > 2 {
		channels, ok = parsePositiveDecimal(parts[2])
		if !ok {
			return 0, AudioCodecConfig{}, fmt.Errorf("parsing voice SDP: invalid rtpmap channels %q", parts[2])
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
