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
	speech := firstSpeechCodec(codecs)
	dtmf, hasDTMF := chooseLocalTelephoneEventForClock(codecs, speech.ClockRate)
	media := NegotiatedMedia{
		Codec:       speech.Name,
		PayloadType: speech.PayloadTypes[0],
		ClockRate:   speech.ClockRate,
		Channels:    speech.Channels,
		OctetAlign:  speech.OctetAlign,
		HFOnly:      speech.HFOnly,
		PTime:       ptime,
		Direction:   direction,
	}
	if hasDTMF {
		media.HasDTMF = true
		media.DTMFPayloadType = dtmf.PayloadTypes[0]
		media.DTMFClockRate = dtmf.ClockRate
		media.DTMFEventMask = dtmf.DTMFEventMask
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
	dtmf, hasDTMF := chooseTelephoneEventForClock(answer, cfg.Codecs, selected.ClockRate)
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
		HFOnly:         selected.HFOnly,
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
		media.HasDTMF = true
		media.DTMFPayloadType = dtmf.PayloadTypes[0]
		media.DTMFClockRate = dtmf.ClockRate
		media.DTMFEventMask = dtmf.DTMFEventMask
	}
	return media
}
