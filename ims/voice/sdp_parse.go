package voice

import (
	"encoding"
	"errors"
	"strings"
)

var _ encoding.TextUnmarshaler = (*sdpOffer)(nil)

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
			codec.HFOnly = fmtpFlag(fmtp, "hf-only")
			if codec.Name == CodecTelephoneEvent {
				codec.DTMFEventMask = parseTelephoneEventMask(fmtp)
			}
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
