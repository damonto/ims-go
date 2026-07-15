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
		appendQoSPreconditions(&b, qosStatusNone, qosStatusNone, false)
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
	return buildSDPAnswerWithDirection(cfg, localIP, localPort, remote, offer, answerDirection(remote.Direction, false))
}

func buildSDPAnswerWithLocalHold(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer, localHold bool) ([]byte, NegotiatedMedia, error) {
	return buildSDPAnswerWithDirection(cfg, localIP, localPort, remote, offer, answerDirection(remote.Direction, localHold))
}

func buildSDPAnswerWithDirection(cfg Config, localIP net.IP, localPort int, remote sdpOffer, offer MediaOffer, direction MediaDirection) ([]byte, NegotiatedMedia, error) {
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
			appendQoSPreconditions(&b, qosStatusNone, qosStatusNone, remote.LocalQoSStatus != qosStatusSendRecv)
		}
	}
	media := negotiatedMedia(remote, selected, ptime, nonZeroDuration(remote.MaxPTime, cfg.MaxPTime), dtmf, hasDTMF)
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
	fmt.Fprintf(&b, "a=sendrecv\r\n")
	appendQoSPreconditions(&b, qosStatusSendRecv, qosStatusNone, false)
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

func appendRejectedMediaLine(b *strings.Builder, media sdpMediaLine) {
	if media.Media == "" || media.Protocol == "" {
		return
	}
	line := "m=" + media.Media + " 0 " + media.Protocol
	if len(media.Formats) > 0 {
		line += " " + strings.Join(media.Formats, " ")
	}
	fmt.Fprintf(b, "%s\r\n", line)
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
		AudioFormat:    audioFormat(selected, selected.PayloadTypes[0], answerCodecFMTP(selected)),
		Negotiated:     true,
		Profile:        remote.Profile,
		PTime:          ptime,
		MaxPTime:       maxptime,
		Direction:      answerDirection(remote.Direction, false),
		RemoteIP:       append(net.IP(nil), remote.RemoteIP...),
		RemotePort:     remote.RemotePort,
		RemoteRTCPIP:   remoteRTCPIP,
		RemoteRTCPPort: remoteRTCPPort,
		RTCPMux:        remote.RTCPMux,
		RTCPDisabled:   rtcpDisabled(remote),
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
