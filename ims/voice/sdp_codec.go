package voice

import (
	"cmp"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

func selectOfferCodecs(configured []AudioCodecConfig, offer MediaOffer) []AudioCodecConfig {
	if len(offer.Codecs) == 0 && len(offer.PayloadTypes) == 0 {
		return filterTelephoneEventsForSpeech(cloneCodecConfigs(configured))
	}
	wantedCodecs := make(map[AudioCodec]struct{}, len(offer.Codecs))
	for _, name := range offer.Codecs {
		switch strings.ToUpper(strings.TrimSpace(string(name))) {
		case "AMR":
			wantedCodecs[CodecAMR] = struct{}{}
		case "AMR-WB", "AMRWB":
			wantedCodecs[CodecAMRWB] = struct{}{}
		case "EVS":
			wantedCodecs[CodecEVS] = struct{}{}
		case "PCMU":
			wantedCodecs[CodecPCMU] = struct{}{}
		case "TELEPHONE-EVENT":
			wantedCodecs[CodecTelephoneEvent] = struct{}{}
		}
	}
	wantedPayloads := make(map[int]struct{}, len(offer.PayloadTypes))
	for _, payloadType := range offer.PayloadTypes {
		wantedPayloads[payloadType] = struct{}{}
	}
	codecs := make([]AudioCodecConfig, 0, len(configured))
	for _, codec := range configured {
		if len(wantedCodecs) > 0 {
			if _, ok := wantedCodecs[codec.Name]; !ok {
				continue
			}
		}
		codec = cloneCodecConfig(codec)
		if len(wantedPayloads) > 0 && codec.Name != CodecTelephoneEvent {
			payloads := codec.PayloadTypes[:0]
			for _, payloadType := range codec.PayloadTypes {
				if _, ok := wantedPayloads[payloadType]; ok {
					payloads = append(payloads, payloadType)
				}
			}
			codec.PayloadTypes = payloads
			if len(codec.PayloadTypes) == 0 {
				continue
			}
		}
		codecs = append(codecs, codec)
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
	return chooseCodecPayloads(remote, local, nil)
}

func chooseCodecPayloads(remote sdpOffer, local []AudioCodecConfig, payloadTypes []int) (AudioCodecConfig, bool) {
	if !strings.EqualFold(remote.Profile, defaultRTPProfile) {
		return AudioCodecConfig{}, false
	}
	wantedPayloads := make(map[int]struct{}, len(payloadTypes))
	for _, payloadType := range payloadTypes {
		wantedPayloads[payloadType] = struct{}{}
	}
	for _, payload := range remote.Payloads {
		if len(wantedPayloads) > 0 {
			if _, ok := wantedPayloads[payload]; !ok {
				continue
			}
		}
		remoteCodec, ok := remote.Codecs[payload]
		if !ok || remoteCodec.Name == CodecTelephoneEvent {
			continue
		}
		for _, localCodec := range local {
			selected, ok := negotiateAudioCodec(localCodec, remoteCodec)
			if !ok {
				continue
			}
			selected.PayloadTypes = []int{payload}
			return selected, true
		}
	}
	return AudioCodecConfig{}, false
}

// AudioFormatCompatible reports whether local can send and receive the remote RTP format.
func AudioFormatCompatible(local AudioCodecConfig, remote AudioFormat) bool {
	_, ok := negotiateAudioCodec(local, audioCodecConfig(remote))
	return ok
}

func audioCodecConfig(format AudioFormat) AudioCodecConfig {
	return AudioCodecConfig{
		Name:          format.Codec,
		PayloadTypes:  []int{format.PayloadType},
		ClockRate:     format.ClockRate,
		Channels:      format.Channels,
		DTMFEventMask: format.DTMFEventMask,
		OctetAlign:    format.OctetAlign,
		ModeSet:       format.ModeSet,
		Bitrate:       format.Bitrate,
		Bandwidth:     format.Bandwidth,
		ChAwRecv:      format.ChAwRecv,
		HFOnly:        format.HFOnly,
	}
}

func negotiateAudioCodec(local, remote AudioCodecConfig) (AudioCodecConfig, bool) {
	if local.Name != remote.Name ||
		local.ClockRate != remote.ClockRate ||
		max(local.Channels, 1) != max(remote.Channels, 1) {
		return AudioCodecConfig{}, false
	}

	selected := cloneCodecConfig(local)
	selected.Channels = max(remote.Channels, 1)
	selected.OctetAlign = local.OctetAlign || remote.OctetAlign
	if remote.ChAwRecv != nil {
		selected.ChAwRecv = new(*remote.ChAwRecv)
	}

	var ok bool
	switch selected.Name {
	case CodecAMR, CodecAMRWB:
		selected.ModeSet, ok = intersectModeSets(local.ModeSet, remote.ModeSet)
	case CodecEVS:
		selected.ModeSet, ok = intersectModeSets(local.ModeSet, remote.ModeSet)
		if !ok {
			break
		}
		selected.Bitrate, ok = intersectNumericRanges(local.Bitrate, remote.Bitrate)
		if !ok {
			break
		}
		selected.Bandwidth, ok = intersectEVSBandwidths(local.Bandwidth, remote.Bandwidth)
		selected.HFOnly = local.HFOnly || remote.HFOnly
	default:
		ok = true
	}
	if !ok {
		return AudioCodecConfig{}, false
	}
	return selected, true
}

func intersectModeSets(local, remote string) (string, bool) {
	local = strings.TrimSpace(local)
	remote = strings.TrimSpace(remote)
	if local == "" && remote == "" {
		return "", true
	}
	if local == "" || remote == "" {
		modes, ok := parseIntegerSet(local + remote)
		if !ok {
			return "", false
		}
		return formatIntegerSet(modes), true
	}
	localModes, ok := parseIntegerSet(local)
	if !ok {
		return "", false
	}
	remoteModes, ok := parseIntegerSet(remote)
	if !ok {
		return "", false
	}
	modes := make(map[int]bool, min(len(localModes), len(remoteModes)))
	for mode := range localModes {
		if remoteModes[mode] {
			modes[mode] = true
		}
	}
	if len(modes) == 0 {
		return "", false
	}
	return formatIntegerSet(modes), true
}

func formatIntegerSet(set map[int]bool) string {
	modes := make([]int, 0, len(set))
	for mode := range set {
		modes = append(modes, mode)
	}
	slices.Sort(modes)
	values := make([]string, len(modes))
	for i, mode := range modes {
		values[i] = strconv.Itoa(mode)
	}
	return strings.Join(values, ",")
}

func parseIntegerSet(value string) (map[int]bool, bool) {
	set := make(map[int]bool)
	for part := range strings.SplitSeq(value, ",") {
		left, right, hasRange := strings.Cut(strings.TrimSpace(part), "-")
		start, ok := parseNonNegativeDecimal(left)
		if !ok {
			return nil, false
		}
		end := start
		if hasRange {
			end, ok = parseNonNegativeDecimal(right)
			if !ok || end < start {
				return nil, false
			}
		}
		for mode := start; mode <= end; mode++ {
			set[mode] = true
		}
	}
	return set, len(set) > 0
}

type numericRange struct {
	minimum float64
	maximum float64
}

func intersectNumericRanges(local, remote string) (string, bool) {
	local = strings.TrimSpace(local)
	remote = strings.TrimSpace(remote)
	if local == "" && remote == "" {
		return "", true
	}
	if local == "" || remote == "" {
		ranges, ok := parseNumericRanges(local + remote)
		if !ok {
			return "", false
		}
		return formatNumericRanges(ranges), true
	}
	localRanges, ok := parseNumericRanges(local)
	if !ok {
		return "", false
	}
	remoteRanges, ok := parseNumericRanges(remote)
	if !ok {
		return "", false
	}
	var intersections []numericRange
	for _, localRange := range localRanges {
		for _, remoteRange := range remoteRanges {
			intersection := numericRange{
				minimum: max(localRange.minimum, remoteRange.minimum),
				maximum: min(localRange.maximum, remoteRange.maximum),
			}
			if intersection.minimum <= intersection.maximum {
				intersections = append(intersections, intersection)
			}
		}
	}
	intersections = normalizeNumericRanges(intersections)
	if len(intersections) == 0 {
		return "", false
	}
	return formatNumericRanges(intersections), true
}

func formatNumericRanges(ranges []numericRange) string {
	parts := make([]string, len(ranges))
	for i, value := range ranges {
		parts[i] = formatNumericRange(value)
	}
	return strings.Join(parts, ",")
}

func parseNumericRanges(value string) ([]numericRange, bool) {
	var ranges []numericRange
	for part := range strings.SplitSeq(value, ",") {
		left, right, hasRange := strings.Cut(strings.TrimSpace(part), "-")
		minimum, err := strconv.ParseFloat(strings.TrimSpace(left), 64)
		if err != nil || math.IsNaN(minimum) || math.IsInf(minimum, 0) || minimum <= 0 {
			return nil, false
		}
		maximum := minimum
		if hasRange {
			maximum, err = strconv.ParseFloat(strings.TrimSpace(right), 64)
			if err != nil || math.IsNaN(maximum) || math.IsInf(maximum, 0) || maximum < minimum {
				return nil, false
			}
		}
		ranges = append(ranges, numericRange{minimum: minimum, maximum: maximum})
	}
	return normalizeNumericRanges(ranges), len(ranges) > 0
}

func normalizeNumericRanges(ranges []numericRange) []numericRange {
	if len(ranges) == 0 {
		return nil
	}
	slices.SortFunc(ranges, func(a, b numericRange) int {
		if order := cmp.Compare(a.minimum, b.minimum); order != 0 {
			return order
		}
		return cmp.Compare(a.maximum, b.maximum)
	})
	merged := ranges[:1]
	for _, current := range ranges[1:] {
		last := &merged[len(merged)-1]
		if current.minimum <= last.maximum {
			last.maximum = max(last.maximum, current.maximum)
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func formatNumericRange(value numericRange) string {
	minimum := strconv.FormatFloat(value.minimum, 'f', -1, 64)
	if value.minimum == value.maximum {
		return minimum
	}
	return minimum + "-" + strconv.FormatFloat(value.maximum, 'f', -1, 64)
}

func intersectEVSBandwidths(local, remote string) (string, bool) {
	local = strings.TrimSpace(local)
	remote = strings.TrimSpace(remote)
	if local == "" && remote == "" {
		return "", true
	}
	if local == "" || remote == "" {
		bandwidths, ok := parseEVSBandwidths(local + remote)
		if !ok {
			return "", false
		}
		return formatEVSBandwidthSet(bandwidths), true
	}
	localBandwidths, ok := parseEVSBandwidths(local)
	if !ok {
		return "", false
	}
	remoteBandwidths, ok := parseEVSBandwidths(remote)
	if !ok {
		return "", false
	}
	var bandwidths []int
	for bandwidth := range localBandwidths {
		if remoteBandwidths[bandwidth] {
			bandwidths = append(bandwidths, bandwidth)
		}
	}
	if len(bandwidths) == 0 {
		return "", false
	}
	slices.Sort(bandwidths)
	return formatEVSBandwidths(bandwidths), true
}

func formatEVSBandwidthSet(set map[int]bool) string {
	bandwidths := make([]int, 0, len(set))
	for bandwidth := range set {
		bandwidths = append(bandwidths, bandwidth)
	}
	slices.Sort(bandwidths)
	return formatEVSBandwidths(bandwidths)
}

var evsBandwidthNames = []string{"nb", "wb", "swb", "fb"}

func parseEVSBandwidths(value string) (map[int]bool, bool) {
	bandwidths := make(map[int]bool)
	for part := range strings.SplitSeq(strings.ToLower(value), ",") {
		left, right, hasRange := strings.Cut(strings.TrimSpace(part), "-")
		start := slices.Index(evsBandwidthNames, left)
		if start < 0 {
			return nil, false
		}
		end := start
		if hasRange {
			end = slices.Index(evsBandwidthNames, strings.TrimSpace(right))
			if end < start {
				return nil, false
			}
		}
		for bandwidth := start; bandwidth <= end; bandwidth++ {
			bandwidths[bandwidth] = true
		}
	}
	return bandwidths, len(bandwidths) > 0
}

func formatEVSBandwidths(bandwidths []int) string {
	parts := make([]string, 0, len(bandwidths))
	for i := 0; i < len(bandwidths); {
		start := bandwidths[i]
		end := start
		for i+1 < len(bandwidths) && bandwidths[i+1] == end+1 {
			i++
			end = bandwidths[i]
		}
		if start == end {
			parts = append(parts, evsBandwidthNames[start])
		} else {
			parts = append(parts, evsBandwidthNames[start]+"-"+evsBandwidthNames[end])
		}
		i++
	}
	return strings.Join(parts, ",")
}

func audioFormat(codec AudioCodecConfig, payloadType int, fmtp string) AudioFormat {
	format := AudioFormat{
		Codec:         codec.Name,
		PayloadType:   payloadType,
		ClockRate:     codec.ClockRate,
		Channels:      max(codec.Channels, 1),
		FMTP:          strings.TrimSpace(fmtp),
		DTMFEventMask: codec.DTMFEventMask,
		OctetAlign:    codec.OctetAlign,
		ModeSet:       codec.ModeSet,
		Bitrate:       codec.Bitrate,
		Bandwidth:     codec.Bandwidth,
		HFOnly:        codec.HFOnly,
	}
	if codec.ChAwRecv != nil {
		format.ChAwRecv = new(*codec.ChAwRecv)
	}
	return format
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
		if codec.HFOnly {
			params = append(params, "hf-only=1")
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
		if codec.HFOnly {
			params = append(params, "hf-only=1")
		}
		if codec.ModeSet != "" {
			params = append(params, "mode-set="+codec.ModeSet)
		}
	case CodecTelephoneEvent:
		params = append(params, formatTelephoneEventMask(dtmfEventMaskOrDefault(codec.DTMFEventMask)))
	}
	return strings.Join(params, ";")
}

func audioOfferBandwidthAS(cfg Config, codecs []AudioCodecConfig, localIP net.IP, ptime time.Duration) int {
	if cfg.AudioASBandwidthKbps > 0 {
		return cfg.AudioASBandwidthKbps
	}
	bandwidth := 0
	for _, codec := range codecs {
		bandwidth = max(bandwidth, codecBandwidthAS(codec, localIP, ptime))
	}
	return bandwidth
}

func audioBandwidthAS(cfg Config, codec AudioCodecConfig, localIP net.IP, ptime time.Duration) int {
	if cfg.AudioASBandwidthKbps > 0 {
		return cfg.AudioASBandwidthKbps
	}
	return codecBandwidthAS(codec, localIP, ptime)
}

func codecBandwidthAS(codec AudioCodecConfig, localIP net.IP, ptime time.Duration) int {
	bitrate, payloadHeaderBytes := codecBandwidthParameters(codec)
	if bitrate == 0 {
		return 0
	}
	if ptime <= 0 {
		ptime = 20 * time.Millisecond
	}
	ipHeaderBytes := 20
	if localIP.To4() == nil {
		ipHeaderBytes = 40
	}
	const udpRTPHeaderBytes = 8 + 12
	overheadKbps := float64((ipHeaderBytes+udpRTPHeaderBytes+payloadHeaderBytes)*8) / ptime.Seconds() / 1000
	return int(math.Ceil(bitrate + overheadKbps))
}

func codecBandwidthParameters(codec AudioCodecConfig) (float64, int) {
	channels := max(codec.Channels, 1)
	switch codec.Name {
	case CodecAMR:
		if codec.OctetAlign {
			return 12.2, 4
		}
		return 12.2, 2
	case CodecAMRWB:
		if codec.OctetAlign {
			return 23.85, 4
		}
		return 23.85, 2
	case CodecEVS:
		return evsMaximumBitrate(codec.Bitrate) * float64(channels), 2
	case CodecPCMU:
		return 64 * float64(channels), 0
	default:
		return 0, 0
	}
}

func evsMaximumBitrate(bitrate string) float64 {
	bitrate = strings.TrimSpace(bitrate)
	if bitrate == "" {
		return 128
	}
	if _, right, ok := strings.Cut(bitrate, "-"); ok {
		bitrate = right
	}
	value, err := strconv.ParseFloat(bitrate, 64)
	if err != nil || value <= 0 {
		return 128
	}
	return value
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

func applyCodecFMTP(codec AudioCodecConfig, fmtp string) AudioCodecConfig {
	codec.OctetAlign = fmtpFlag(fmtp, "octet-align")
	codec.ModeSet = fmtpParam(fmtp, "mode-set")
	codec.Bitrate = fmtpParam(fmtp, "br")
	codec.Bandwidth = fmtpParam(fmtp, "bw")
	codec.HFOnly = fmtpFlag(fmtp, "hf-only")
	if codec.Name == CodecTelephoneEvent {
		codec.DTMFEventMask = parseTelephoneEventMask(fmtp)
	}
	if value, ok := fmtpSignedParam(fmtp, "ch-aw-recv"); ok {
		codec.ChAwRecv = &value
	}
	return codec
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

func parseSDPDuration(value string) (time.Duration, error) {
	ms, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil || math.IsNaN(ms) || math.IsInf(ms, 0) || ms <= 0 {
		return 0, fmt.Errorf("duration %q must be a positive number", value)
	}
	duration := time.Duration(ms * float64(time.Millisecond))
	if duration <= 0 {
		return 0, fmt.Errorf("duration %q is too small", value)
	}
	return duration, nil
}

func formatSDPDuration(d time.Duration) string {
	return strconv.FormatFloat(float64(d)/float64(time.Millisecond), 'f', -1, 64)
}
