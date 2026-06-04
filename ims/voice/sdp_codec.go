package voice

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

func selectOfferCodecs(configured []AudioCodecConfig, requested []AudioCodec) []AudioCodecConfig {
	if len(requested) == 0 {
		return filterTelephoneEventsForSpeech(cloneCodecConfigs(configured))
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
			return filterTelephoneEventsForSpeech(codecs)
		}
	}
	clockRates := make(map[int]struct{})
	for _, codec := range codecs {
		if codec.Name == CodecTelephoneEvent {
			continue
		}
		clockRates[codec.ClockRate] = struct{}{}
	}
	for _, codec := range configured {
		if codec.Name == CodecTelephoneEvent {
			if _, ok := clockRates[codec.ClockRate]; !ok {
				continue
			}
			codecs = append(codecs, cloneCodecConfig(codec))
		}
	}
	return filterTelephoneEventsForSpeech(codecs)
}

func filterTelephoneEventsForSpeech(codecs []AudioCodecConfig) []AudioCodecConfig {
	clockRates := make(map[int]struct{})
	for _, codec := range codecs {
		if codec.Name != CodecTelephoneEvent {
			clockRates[codec.ClockRate] = struct{}{}
		}
	}
	out := codecs[:0]
	for _, codec := range codecs {
		if codec.Name == CodecTelephoneEvent {
			if _, ok := clockRates[codec.ClockRate]; !ok {
				continue
			}
		}
		out = append(out, codec)
	}
	return out
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

func chooseTelephoneEventForClock(remote sdpOffer, local []AudioCodecConfig, clockRate int) (AudioCodecConfig, bool) {
	localCodec, ok := chooseLocalTelephoneEventForClock(local, clockRate)
	if !ok {
		return AudioCodecConfig{}, false
	}
	for _, payload := range remote.Payloads {
		remoteCodec, ok := remote.Codecs[payload]
		if !ok || remoteCodec.Name != CodecTelephoneEvent {
			continue
		}
		if remoteCodec.ClockRate != 0 && remoteCodec.ClockRate != clockRate {
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
		selected.DTMFEventMask = dtmfEventMaskOrDefault(localCodec.DTMFEventMask) & remoteCodec.DTMFEventMask
		if selected.DTMFEventMask == 0 {
			continue
		}
		return selected, true
	}
	return AudioCodecConfig{}, false
}

func chooseLocalTelephoneEventForClock(codecs []AudioCodecConfig, clockRate int) (AudioCodecConfig, bool) {
	for _, codec := range codecs {
		if codec.Name != CodecTelephoneEvent || codec.ClockRate != clockRate || len(codec.PayloadTypes) == 0 {
			continue
		}
		codec.DTMFEventMask = dtmfEventMaskOrDefault(codec.DTMFEventMask)
		return codec, true
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
	case CodecTelephoneEvent:
		params = append(params, formatTelephoneEventMask(dtmfEventMaskOrDefault(codec.DTMFEventMask)))
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
	config := AudioCodecConfig{Name: codec, PayloadTypes: []int{payloadType}, ClockRate: clock, Channels: channels}
	if codec == CodecTelephoneEvent {
		config.DTMFEventMask = dtmfAllEventsMask
	}
	return payloadType, config, nil
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

func parseTelephoneEventMask(fmtp string) uint16 {
	var mask uint16
	for _, part := range strings.Split(fmtp, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		startText, endText, hasRange := strings.Cut(part, "-")
		start, ok := parseBoundedDecimal(startText, 0, 15)
		if !ok {
			continue
		}
		end := start
		if hasRange {
			end, ok = parseBoundedDecimal(endText, start, 15)
			if !ok {
				continue
			}
		}
		for event := start; event <= end; event++ {
			mask |= 1 << event
		}
	}
	return mask
}

func dtmfEventMaskOrDefault(mask uint16) uint16 {
	if mask == 0 {
		return dtmfAllEventsMask
	}
	return mask
}

func formatTelephoneEventMask(mask uint16) string {
	mask = dtmfEventMaskOrDefault(mask)
	parts := make([]string, 0, 4)
	for event := 0; event <= 15; event++ {
		if mask&(1<<event) == 0 {
			continue
		}
		start := event
		for event+1 <= 15 && mask&(1<<(event+1)) != 0 {
			event++
		}
		if start == event {
			parts = append(parts, strconv.Itoa(start))
			continue
		}
		parts = append(parts, strconv.Itoa(start)+"-"+strconv.Itoa(event))
	}
	return strings.Join(parts, ",")
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

func parseSDPDuration(value string) time.Duration {
	ms, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || ms < 0 {
		return 0
	}
	return time.Duration(ms) * time.Millisecond
}

func durationMillis(d time.Duration) int {
	return int(d / time.Millisecond)
}
