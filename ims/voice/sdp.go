package voice

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func buildSDPOffer(cfg Config, localIP net.IP, localPort int, offer MediaOffer) ([]byte, NegotiatedMedia, error) {
	return buildSDPOfferWithDirection(cfg, localIP, localPort, offer, MediaDirectionSendRecv)
}

func buildSDPOfferWithDirection(cfg Config, localIP net.IP, localPort int, offer MediaOffer, direction MediaDirection) ([]byte, NegotiatedMedia, error) {
	if !direction.valid() {
		return nil, NegotiatedMedia{}, fmt.Errorf("building voice SDP offer: invalid media direction %q", direction)
	}
	codecs := selectOfferCodecs(cfg.Codecs, offer)
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
	if bandwidth := audioOfferBandwidthAS(cfg, codecs, localIP, ptime); bandwidth > 0 {
		fmt.Fprintf(&b, "b=AS:%d\r\n", bandwidth)
	}
	appendRTCPBandwidth(&b, rtcpSenderBandwidth, rtcpReceiverBandwidth)
	for _, codec := range codecs {
		appendOfferCodecAttributes(&b, codec)
	}
	if ptime > 0 {
		fmt.Fprintf(&b, "a=ptime:%s\r\n", formatSDPDuration(ptime))
	}
	if cfg.MaxPTime > 0 {
		fmt.Fprintf(&b, "a=maxptime:%s\r\n", formatSDPDuration(cfg.MaxPTime))
	}
	fmt.Fprintf(&b, "a=%s\r\n", direction)
	if cfg.Preconditions {
		appendQoSPreconditions(&b, qosStatusNone, qosStatusNone, defaultQoSDesiredStatus(), false)
	}
	speech := firstSpeechCodec(codecs)
	dtmf, hasDTMF := chooseLocalTelephoneEventForClock(codecs, speech.ClockRate)
	media := NegotiatedMedia{
		AudioFormat: audioFormat(speech, speech.PayloadTypes[0], offerCodecFMTP(speech)),
		Profile:     cfg.RTPProfile,
		PTime:       ptime,
		MaxPTime:    cfg.MaxPTime,
		Direction:   direction,
	}
	if hasDTMF {
		format := audioFormat(dtmf, dtmf.PayloadTypes[0], offerCodecFMTP(dtmf))
		media.DTMF = &format
	}
	return []byte(b.String()), media, nil
}

func buildSDPAnswer(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer) ([]byte, NegotiatedMedia, error) {
	return buildSDPAnswerWithState(cfg, localIP, localPort, remote, offer, sdpAnswerState{
		direction:      answerDirection(remote.Direction, false),
		localQoSStatus: qosStatusNone,
	})
}

func buildSDPAnswerWithLocalHold(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer, localHold bool) ([]byte, NegotiatedMedia, error) {
	return buildSDPAnswerWithState(cfg, localIP, localPort, remote, offer, sdpAnswerState{
		direction:      answerDirection(remote.Direction, localHold),
		localQoSStatus: qosStatusNone,
	})
}

type sdpAnswerState struct {
	direction      MediaDirection
	localQoSStatus string
}

func buildSDPAnswerWithState(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer, state sdpAnswerState) ([]byte, NegotiatedMedia, error) {
	direction := state.direction
	if !direction.valid() {
		return nil, NegotiatedMedia{}, fmt.Errorf("building voice SDP answer: invalid media direction %q", direction)
	}
	if len(remote.Payloads) == 0 {
		return nil, NegotiatedMedia{}, errors.New("building voice SDP answer: remote offer has no audio payloads")
	}
	selected, ok := chooseCodecPayloads(remote, selectOfferCodecs(cfg.Codecs, offer), offer.PayloadTypes)
	if !ok {
		return nil, NegotiatedMedia{}, errors.New("building voice SDP answer: no compatible codec")
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(remote, cfg.Codecs, selected.ClockRate)
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
	if len(remote.TimeDescriptions) == 0 {
		fmt.Fprintf(&b, "t=0 0\r\n")
	} else {
		for _, line := range remote.TimeDescriptions {
			fmt.Fprintf(&b, "%s\r\n", line)
		}
	}
	answerPayloads := []string{strconv.Itoa(selected.PayloadTypes[0])}
	if hasDTMF {
		answerPayloads = append(answerPayloads, strconv.Itoa(dtmf.PayloadTypes[0]))
	}
	rs, rr := rtcpAnswerBandwidth(remote)
	for i, offered := range remote.Media {
		if i != remote.AudioIndex {
			appendRejectedMediaLine(&b, offered)
			continue
		}
		fmt.Fprintf(&b, "m=audio %d %s %s\r\n", localPort, cfg.RTPProfile, strings.Join(answerPayloads, " "))
		if bandwidth := audioBandwidthAS(cfg, selected, localIP, ptime); bandwidth > 0 {
			fmt.Fprintf(&b, "b=AS:%d\r\n", bandwidth)
		}
		appendRTCPBandwidth(&b, rs, rr)
		appendAnswerCodecAttributes(&b, selected)
		if hasDTMF {
			appendAnswerCodecAttributes(&b, dtmf)
		}
		if ptime > 0 {
			fmt.Fprintf(&b, "a=ptime:%s\r\n", formatSDPDuration(ptime))
		}
		if cfg.MaxPTime > 0 {
			fmt.Fprintf(&b, "a=maxptime:%s\r\n", formatSDPDuration(cfg.MaxPTime))
		}
		if remote.RTCPMux {
			fmt.Fprintf(&b, "a=rtcp-mux\r\n")
		}
		fmt.Fprintf(&b, "a=%s\r\n", direction)
		if cfg.Preconditions && remote.Preconditions {
			appendQoSPreconditions(
				&b,
				normalizedQoSStatus(state.localQoSStatus),
				invertQoSStatus(remote.LocalQoSStatus),
				answerQoSDesiredStatus(remote.DesiredQoS),
				remote.LocalQoSStatus != qosStatusSendRecv,
			)
		}
		if cfg.Preconditions {
			appendUnknownPreconditionAnswer(&b, remote)
		}
	}
	media := negotiatedMedia(remote, selected, ptime, nonZeroDuration(remote.MaxPTime, cfg.MaxPTime), dtmf, hasDTMF)
	media.Direction = direction
	media.RTCPDisabled = rtcpBandwidthDisabled(rs, rr)
	return []byte(b.String()), media, nil
}

type sdpPreconditionUpdateState struct {
	localIP        net.IP
	localPort      int
	answer         sdpOffer
	media          NegotiatedMedia
	localQoSStatus string
	desiredQoS     *qosDesiredStatus
}

func buildSDPPreconditionUpdate(cfg Config, state sdpPreconditionUpdateState) ([]byte, error) {
	selected, ok := chooseCodec(state.answer, cfg.Codecs)
	if !ok {
		return nil, errors.New("building voice precondition SDP update: no compatible codec")
	}
	dtmf, hasDTMF := chooseTelephoneEventForClock(state.answer, cfg.Codecs, selected.ClockRate)
	localIP := state.localIP
	if localIP == nil || localIP.IsUnspecified() {
		localIP = net.IPv4(0, 0, 0, 0)
	}
	ptime := nonZeroDuration(state.answer.PTime, state.media.PTime, cfg.PTime)
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
	fmt.Fprintf(&b, "m=audio %d %s %s\r\n", state.localPort, cfg.RTPProfile, strings.Join(payloads, " "))
	if bandwidth := audioBandwidthAS(cfg, selected, localIP, ptime); bandwidth > 0 {
		fmt.Fprintf(&b, "b=AS:%d\r\n", bandwidth)
	}
	appendRTCPBandwidth(&b, rtcpSenderBandwidth, rtcpReceiverBandwidth)
	appendAnswerCodecAttributes(&b, selected)
	if hasDTMF {
		appendAnswerCodecAttributes(&b, dtmf)
	}
	if ptime > 0 {
		fmt.Fprintf(&b, "a=ptime:%s\r\n", formatSDPDuration(ptime))
	}
	if cfg.MaxPTime > 0 {
		fmt.Fprintf(&b, "a=maxptime:%s\r\n", formatSDPDuration(cfg.MaxPTime))
	}
	direction := state.media.Direction
	if !direction.valid() {
		direction = MediaDirectionSendRecv
	}
	fmt.Fprintf(&b, "a=%s\r\n", direction)
	desired := answerQoSDesiredStatus(state.answer.DesiredQoS)
	if state.desiredQoS != nil {
		desired = *state.desiredQoS
	}
	appendQoSPreconditions(
		&b,
		normalizedQoSStatus(state.localQoSStatus),
		invertQoSStatus(state.answer.LocalQoSStatus),
		desired,
		false,
	)
	return []byte(b.String()), nil
}

func answerDirection(remote MediaDirection, localHold bool) MediaDirection {
	if remote == "" {
		remote = MediaDirectionSendRecv
	}
	if localHold {
		return MediaDirectionInactive
	}
	switch remote {
	case MediaDirectionSendOnly:
		return MediaDirectionRecvOnly
	case MediaDirectionRecvOnly:
		return MediaDirectionSendOnly
	case MediaDirectionInactive:
		return MediaDirectionInactive
	default:
		return MediaDirectionSendRecv
	}
}

func (d MediaDirection) valid() bool {
	switch d {
	case MediaDirectionSendRecv, MediaDirectionSendOnly, MediaDirectionRecvOnly, MediaDirectionInactive:
		return true
	default:
		return false
	}
}

const (
	qosStatusNone     = "none"
	qosStatusSend     = "send"
	qosStatusRecv     = "recv"
	qosStatusSendRecv = "sendrecv"
)

const (
	qosStrengthNone      = "none"
	qosStrengthOptional  = "optional"
	qosStrengthMandatory = "mandatory"
	qosStrengthFailure   = "failure"
	qosStrengthUnknown   = "unknown"
)

func normalizedQoSStatus(status string) string {
	switch strings.ToLower(status) {
	case qosStatusNone:
		return qosStatusNone
	case qosStatusSend:
		return qosStatusSend
	case qosStatusRecv:
		return qosStatusRecv
	case qosStatusSendRecv:
		return qosStatusSendRecv
	default:
		return qosStatusNone
	}
}

func invertQoSStatus(status string) string {
	switch normalizedQoSStatus(status) {
	case qosStatusSend:
		return qosStatusRecv
	case qosStatusRecv:
		return qosStatusSend
	default:
		return normalizedQoSStatus(status)
	}
}

func validQoSStrength(strength string) bool {
	switch strength {
	case qosStrengthNone, qosStrengthOptional, qosStrengthMandatory:
		return true
	default:
		return false
	}
}

func strongerQoSStrength(a, b string) string {
	rank := func(strength string) int {
		switch strength {
		case qosStrengthMandatory:
			return 2
		case qosStrengthOptional:
			return 1
		default:
			return 0
		}
	}
	if rank(a) >= rank(b) {
		if validQoSStrength(a) {
			return a
		}
		return qosStrengthNone
	}
	return b
}

func defaultQoSDesiredStatus() qosDesiredStatus {
	return qosDesiredStatus{
		localSend:  qosStrengthMandatory,
		localRecv:  qosStrengthMandatory,
		remoteSend: qosStrengthOptional,
		remoteRecv: qosStrengthOptional,
	}
}

func answerQoSDesiredStatus(offered qosDesiredStatus) qosDesiredStatus {
	// RFC 3312 section 5.2 requires both scope and direction to be inverted
	// in an answer. Local policy may upgrade the offered strength, but never
	// downgrade it.
	inverted := qosDesiredStatus{
		localSend:  offered.remoteRecv,
		localRecv:  offered.remoteSend,
		remoteSend: offered.localRecv,
		remoteRecv: offered.localSend,
	}
	policy := defaultQoSDesiredStatus()
	return qosDesiredStatus{
		localSend:  strongerQoSStrength(inverted.localSend, policy.localSend),
		localRecv:  strongerQoSStrength(inverted.localRecv, policy.localRecv),
		remoteSend: strongerQoSStrength(inverted.remoteSend, policy.remoteSend),
		remoteRecv: strongerQoSStrength(inverted.remoteRecv, policy.remoteRecv),
	}
}

func invertQoSDesiredStatus(status qosDesiredStatus) qosDesiredStatus {
	return qosDesiredStatus{
		localSend:  status.remoteRecv,
		localRecv:  status.remoteSend,
		remoteSend: status.localRecv,
		remoteRecv: status.localSend,
	}
}

func strongerQoSDesiredStatus(a, b qosDesiredStatus) qosDesiredStatus {
	return qosDesiredStatus{
		localSend:  strongerQoSStrength(a.localSend, b.localSend),
		localRecv:  strongerQoSStrength(a.localRecv, b.localRecv),
		remoteSend: strongerQoSStrength(a.remoteSend, b.remoteSend),
		remoteRecv: strongerQoSStrength(a.remoteRecv, b.remoteRecv),
	}
}

func qosStatusMeetsMandatory(status, sendStrength, recvStrength string) bool {
	status = normalizedQoSStatus(status)
	if sendStrength == qosStrengthMandatory && status != qosStatusSend && status != qosStatusSendRecv {
		return false
	}
	if recvStrength == qosStrengthMandatory && status != qosStatusRecv && status != qosStatusSendRecv {
		return false
	}
	return true
}

func qosStatusMeetsDirection(status, direction string) bool {
	sendStrength := qosStrengthNone
	recvStrength := qosStrengthNone
	if direction == qosStatusSend || direction == qosStatusSendRecv {
		sendStrength = qosStrengthMandatory
	}
	if direction == qosStatusRecv || direction == qosStatusSendRecv {
		recvStrength = qosStrengthMandatory
	}
	return qosStatusMeetsMandatory(status, sendStrength, recvStrength)
}

func (s *qosDesiredStatus) set(scope, direction, strength string) {
	set := func(current *string) {
		*current = strongerQoSStrength(*current, strength)
	}
	switch scope {
	case "local":
		if direction == qosStatusSend || direction == qosStatusSendRecv {
			set(&s.localSend)
		}
		if direction == qosStatusRecv || direction == qosStatusSendRecv {
			set(&s.localRecv)
		}
	case "remote":
		if direction == qosStatusSend || direction == qosStatusSendRecv {
			set(&s.remoteSend)
		}
		if direction == qosStatusRecv || direction == qosStatusSendRecv {
			set(&s.remoteRecv)
		}
	}
}

func appendQoSDesiredStatus(b *strings.Builder, scope, send, recv string) {
	send = strongerQoSStrength(send, qosStrengthNone)
	recv = strongerQoSStrength(recv, qosStrengthNone)
	if send == recv {
		fmt.Fprintf(b, "a=des:qos %s %s sendrecv\r\n", send, scope)
		return
	}
	fmt.Fprintf(b, "a=des:qos %s %s send\r\n", send, scope)
	fmt.Fprintf(b, "a=des:qos %s %s recv\r\n", recv, scope)
}

func appendQoSPreconditions(b *strings.Builder, localStatus string, remoteStatus string, desired qosDesiredStatus, requestRemoteConfirmation bool) {
	fmt.Fprintf(b, "a=curr:qos local %s\r\n", localStatus)
	fmt.Fprintf(b, "a=curr:qos remote %s\r\n", remoteStatus)
	appendQoSDesiredStatus(b, "local", desired.localSend, desired.localRecv)
	appendQoSDesiredStatus(b, "remote", desired.remoteSend, desired.remoteRecv)
	if requestRemoteConfirmation {
		fmt.Fprintf(b, "a=conf:qos remote sendrecv\r\n")
	}
}

func appendUnknownPreconditionAnswer(b *strings.Builder, remote sdpOffer) {
	for _, desired := range remote.UnknownLocalMandatory {
		direction := invertQoSStatus(desired.direction)
		current := invertQoSStatus(remote.UnknownLocalStatus[desired.preconditionType])
		fmt.Fprintf(b, "a=curr:%s remote %s\r\n", desired.preconditionType, current)
		fmt.Fprintf(b, "a=des:%s mandatory remote %s\r\n", desired.preconditionType, direction)
		if !qosStatusMeetsDirection(current, direction) {
			fmt.Fprintf(b, "a=conf:%s remote %s\r\n", desired.preconditionType, direction)
		}
	}
}

func buildPreconditionFailureSDP(remote []byte, failure sdpPreconditionFailureError) []byte {
	lines := strings.FieldsFunc(string(remote), func(r rune) bool { return r == '\n' || r == '\r' })
	matched := false
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 4 || !strings.EqualFold(fields[0], "a=des:"+failure.preconditionType) {
			continue
		}
		if failure.statusType != "" && !strings.EqualFold(fields[2], failure.statusType) {
			continue
		}
		if failure.direction != "" && !strings.EqualFold(fields[3], failure.direction) && failure.direction != qosStatusSendRecv {
			continue
		}
		fields[1] = failure.strength
		lines[i] = strings.Join(fields, " ")
		matched = true
	}

	var b strings.Builder
	inserted := false
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && strings.HasPrefix(strings.ToLower(fields[0]), "m=") {
			fields[1] = "0"
			line = strings.Join(fields, " ")
		}
		fmt.Fprintf(&b, "%s\r\n", line)
		if !matched && !inserted && len(fields) >= 3 && strings.EqualFold(fields[0], "m=audio") {
			statusType := nonEmpty(failure.statusType, "remote")
			direction := nonEmpty(failure.direction, qosStatusSendRecv)
			fmt.Fprintf(&b, "a=des:%s %s %s %s\r\n", failure.preconditionType, failure.strength, statusType, direction)
			inserted = true
		}
	}
	return []byte(b.String())
}

func appendRejectedMediaLine(b *strings.Builder, media sdpMediaLine) {
	media.Port = 0
	media.PortCount = 0
	line, err := media.MarshalText()
	if err != nil {
		return
	}
	b.Write(line)
	b.WriteString("\r\n")
}

func appendRTCPBandwidth(b *strings.Builder, rs int, rr int) {
	fmt.Fprintf(b, "b=RS:%d\r\n", rs)
	fmt.Fprintf(b, "b=RR:%d\r\n", rr)
}

func negotiatedMedia(remote sdpOffer, selected AudioCodecConfig, ptime, maxptime time.Duration, dtmf AudioCodecConfig, hasDTMF bool) NegotiatedMedia {
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
		AudioFormat:           audioFormat(selected, selected.PayloadTypes[0], answerCodecFMTP(selected)),
		Negotiated:            true,
		Profile:               remote.Profile,
		PTime:                 ptime,
		MaxPTime:              maxptime,
		Direction:             answerDirection(remote.Direction, false),
		RemoteIP:              append(net.IP(nil), remote.RemoteIP...),
		RemotePort:            remote.RemotePort,
		RemoteRTCPIP:          remoteRTCPIP,
		RemoteRTCPPort:        remoteRTCPPort,
		RTCPMux:               remote.RTCPMux,
		RTCPDisabled:          rtcpDisabled(remote),
		RTCPSenderBandwidth:   effectiveRTCPBandwidth(remote.RTCPSenderBandwidth, rtcpSenderBandwidth),
		RTCPReceiverBandwidth: effectiveRTCPBandwidth(remote.RTCPReceiverBandwidth, rtcpReceiverBandwidth),
	}
	if remoteCodec, ok := remote.Codecs[selected.PayloadTypes[0]]; ok {
		media.RemoteFormat = audioFormat(remoteCodec, selected.PayloadTypes[0], remote.FMTP[selected.PayloadTypes[0]])
	}
	if hasDTMF {
		format := audioFormat(dtmf, dtmf.PayloadTypes[0], answerCodecFMTP(dtmf))
		media.DTMF = &format
	}
	return media
}

func effectiveRTCPBandwidth(value *int, fallback int) int {
	if value == nil {
		return fallback
	}
	return *value
}
