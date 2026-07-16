package voice

import (
	"encoding"
	"errors"
	"fmt"
	"net"
	"strings"
)

var (
	_ encoding.BinaryUnmarshaler = (*sdpOffer)(nil)
	_ encoding.BinaryUnmarshaler = (*MediaDescription)(nil)
)

// UnmarshalBinary decodes an SDP body into its audio media description.
func (description *MediaDescription) UnmarshalBinary(data []byte) error {
	*description = MediaDescription{}
	var offer sdpOffer
	if err := offer.UnmarshalBinary(data); err != nil {
		return err
	}
	*description = mediaDescriptionFromSDP(offer)
	return nil
}

func (offer *sdpOffer) UnmarshalBinary(data []byte) error {
	*offer = sdpOffer{
		RawSDP:     append([]byte(nil), data...),
		Codecs:     make(map[int]AudioCodecConfig),
		FMTP:       make(map[int]string),
		Direction:  MediaDirectionSendRecv,
		AudioIndex: -1,
	}
	var mediaPayloads map[int]struct{}
	inAudio := false
	seenMedia := false
	sessionDirection := MediaDirectionSendRecv
	var sessionIP net.IP
	lines := strings.FieldsFunc(string(data), func(r rune) bool { return r == '\n' || r == '\r' })
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
			if !seenMedia {
				sessionIP = append(net.IP(nil), ip...)
				offer.RemoteIP = append(net.IP(nil), ip...)
			} else if inAudio {
				offer.RemoteIP = ip
			}
		case !seenMedia && (strings.HasPrefix(line, "t=") || strings.HasPrefix(line, "r=") || strings.HasPrefix(line, "z=")):
			offer.TimeDescriptions = append(offer.TimeDescriptions, line)
		case strings.HasPrefix(line, "m=audio ") && offer.AudioIndex < 0:
			var audio sdpAudioLine
			if err := audio.UnmarshalText([]byte(line)); err != nil {
				return err
			}
			media, err := parseMediaLine(line)
			if err != nil {
				return err
			}
			offer.Media = append(offer.Media, media)
			offer.AudioIndex = len(offer.Media) - 1
			seenMedia = true
			inAudio = true
			offer.Direction = sessionDirection
			if len(sessionIP) > 0 {
				offer.RemoteIP = append(net.IP(nil), sessionIP...)
			}
			offer.RemotePort = audio.Port
			offer.Profile = audio.Protocol
			offer.Payloads = audio.Payloads
			mediaPayloads = make(map[int]struct{}, len(audio.Payloads))
			for _, payload := range audio.Payloads {
				mediaPayloads[payload] = struct{}{}
			}
		case strings.HasPrefix(line, "m="):
			inAudio = false
			seenMedia = true
			media, err := parseMediaLine(line)
			if err != nil {
				return err
			}
			offer.Media = append(offer.Media, media)
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
			if _, ok := mediaPayloads[payloadType]; ok {
				offer.FMTP[payloadType] = strings.TrimSpace(fmtp)
			}
		case strings.HasPrefix(line, "a=ptime:"):
			if inAudio {
				ptime, err := parseSDPDuration(strings.TrimPrefix(line, "a=ptime:"))
				if err != nil {
					return fmt.Errorf("parsing voice SDP: invalid ptime: %w", err)
				}
				offer.PTime = ptime
			}
		case strings.HasPrefix(line, "a=maxptime:"):
			if inAudio {
				maxptime, err := parseSDPDuration(strings.TrimPrefix(line, "a=maxptime:"))
				if err != nil {
					return fmt.Errorf("parsing voice SDP: invalid maxptime: %w", err)
				}
				offer.MaxPTime = maxptime
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
			direction := MediaDirection(strings.TrimPrefix(strings.ToLower(line), "a="))
			if inAudio {
				offer.Direction = direction
			} else if !seenMedia {
				sessionDirection = direction
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
	if offer.AudioIndex < 0 || offer.RemotePort == 0 {
		return errors.New("parsing voice SDP: audio media line is missing")
	}
	if offer.RemoteIP == nil {
		return errors.New("parsing voice SDP: connection line is missing")
	}
	if offer.PTime > 0 && offer.MaxPTime > 0 && offer.PTime > offer.MaxPTime {
		return errors.New("parsing voice SDP: ptime exceeds maxptime")
	}
	applyStaticRTPPayloads(offer)
	for payloadType, fmtp := range offer.FMTP {
		codec, ok := offer.Codecs[payloadType]
		if !ok {
			continue
		}
		if codec.Name == CodecTelephoneEvent && !validTelephoneEventFMTP(fmtp) {
			// A malformed optional telephone-event format must not reject the
			// audio offer; discard only that payload instead of treating it as
			// the RFC 4733 default event set.
			delete(offer.Codecs, payloadType)
			delete(offer.FMTP, payloadType)
			continue
		}
		offer.Codecs[payloadType] = applyCodecFMTP(codec, fmtp)
	}
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
	return len(fields) == 2 && strings.EqualFold(fields[0], "remote") && strings.EqualFold(fields[1], qosStatusSendRecv)
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
