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

type sdpPreconditionFailureError struct {
	preconditionType string
	statusType       string
	direction        string
	strength         string
}

func (e *sdpPreconditionFailureError) Error() string {
	return fmt.Sprintf("parsing voice SDP: unsupported mandatory %s precondition", e.preconditionType)
}

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
		RawSDP:             append([]byte(nil), data...),
		Codecs:             make(map[int]AudioCodecConfig),
		FMTP:               make(map[int]string),
		UnknownLocalStatus: make(map[string]string),
		Direction:          MediaDirectionSendRecv,
		AudioIndex:         -1,
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
		case isPreconditionAttribute(line):
			if inAudio {
				if err := offer.applyPrecondition(line); err != nil {
					return err
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

func isPreconditionAttribute(line string) bool {
	fields := strings.Fields(strings.ToLower(line))
	if len(fields) == 0 {
		return false
	}
	return strings.HasPrefix(fields[0], "a=curr:") ||
		strings.HasPrefix(fields[0], "a=des:") ||
		strings.HasPrefix(fields[0], "a=conf:")
}

func (offer *sdpOffer) applyPrecondition(line string) error {
	fields := strings.Fields(strings.ToLower(line))
	if len(fields) == 0 {
		return errors.New("parsing voice SDP: empty precondition attribute")
	}
	attribute := strings.TrimPrefix(fields[0], "a=")
	parts := strings.SplitN(attribute, ":", 2)
	if len(parts) != 2 || parts[1] == "" {
		return errors.New("parsing voice SDP: invalid precondition attribute")
	}
	kind, preconditionType := parts[0], parts[1]
	if preconditionType != "qos" {
		return offer.applyUnknownPrecondition(kind, preconditionType, fields)
	}

	offer.Preconditions = true
	switch kind {
	case "curr":
		scope, status, ok := parseCurrentQoS(line)
		if !ok {
			return qosPreconditionParseError(fields)
		}
		switch scope {
		case "local":
			offer.LocalQoSStatus = status
		case "remote":
			offer.RemoteQoSStatus = status
		}
	case "des":
		strength, scope, direction, ok := parseDesiredQoS(line)
		if !ok {
			return qosPreconditionParseError(fields)
		}
		offer.DesiredQoS.set(scope, direction, strength)
	case "conf":
		scope, direction, ok := parseQoSConfirmation(line)
		if !ok {
			return qosPreconditionParseError(fields)
		}
		if scope == "remote" {
			offer.RemoteQoSConfirmation = true
			offer.QoSConfirmation = direction
		}
	default:
		return errors.New("parsing voice SDP: invalid QoS precondition attribute")
	}
	return nil
}

func (offer *sdpOffer) applyUnknownPrecondition(kind, preconditionType string, fields []string) error {
	switch kind {
	case "curr":
		if len(fields) != 3 || (fields[1] != "local" && fields[1] != "remote") || normalizedQoSStatus(fields[2]) != fields[2] {
			return errors.New("parsing voice SDP: invalid unknown current-status precondition")
		}
		if fields[1] == "local" {
			offer.UnknownLocalStatus[preconditionType] = fields[2]
		}
	case "des":
		if len(fields) != 4 || !validQoSStrength(fields[1]) ||
			(fields[3] != qosStatusSend && fields[3] != qosStatusRecv && fields[3] != qosStatusSendRecv) {
			return errors.New("parsing voice SDP: invalid unknown desired-status precondition")
		}
		if fields[1] != qosStrengthMandatory {
			return nil
		}
		if fields[2] != "local" {
			return &sdpPreconditionFailureError{
				preconditionType: preconditionType,
				statusType:       fields[2],
				direction:        fields[3],
				strength:         qosStrengthUnknown,
			}
		}
		offer.UnknownLocalMandatory = append(offer.UnknownLocalMandatory, sdpUnknownPrecondition{
			preconditionType: preconditionType,
			direction:        fields[3],
		})
	case "conf":
		if len(fields) != 3 {
			return errors.New("parsing voice SDP: invalid unknown confirm-status precondition")
		}
	default:
		return errors.New("parsing voice SDP: invalid unknown precondition attribute")
	}
	return nil
}

func qosPreconditionParseError(fields []string) error {
	statusType := ""
	direction := qosStatusSendRecv
	if len(fields) >= 3 {
		statusType = fields[len(fields)-2]
		direction = fields[len(fields)-1]
	}
	if statusType == "e2e" {
		return &sdpPreconditionFailureError{
			preconditionType: "qos",
			statusType:       statusType,
			direction:        direction,
			strength:         qosStrengthFailure,
		}
	}
	return errors.New("parsing voice SDP: invalid QoS precondition attribute")
}

func isSDPDirectionLine(line string) bool {
	switch strings.ToLower(line) {
	case "a=sendrecv", "a=sendonly", "a=recvonly", "a=inactive":
		return true
	default:
		return false
	}
}

func parseCurrentQoS(line string) (string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.EqualFold(fields[0], "a=curr:qos") {
		return "", "", false
	}
	scope := strings.ToLower(fields[1])
	if scope != "local" && scope != "remote" {
		return "", "", false
	}
	status := strings.ToLower(fields[2])
	if normalizedQoSStatus(status) != status {
		return "", "", false
	}
	return scope, status, true
}

func parseDesiredQoS(line string) (string, string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) != 4 || !strings.EqualFold(fields[0], "a=des:qos") {
		return "", "", "", false
	}
	strength := strings.ToLower(fields[1])
	if !validQoSStrength(strength) {
		return "", "", "", false
	}
	scope := strings.ToLower(fields[2])
	if scope != "local" && scope != "remote" {
		return "", "", "", false
	}
	direction := strings.ToLower(fields[3])
	if direction != qosStatusSend && direction != qosStatusRecv && direction != qosStatusSendRecv {
		return "", "", "", false
	}
	return strength, scope, direction, true
}

func parseQoSConfirmation(line string) (string, string, bool) {
	fields := strings.Fields(line)
	if len(fields) != 3 || !strings.EqualFold(fields[0], "a=conf:qos") {
		return "", "", false
	}
	scope := strings.ToLower(fields[1])
	if scope != "local" && scope != "remote" {
		return "", "", false
	}
	direction := strings.ToLower(fields[2])
	if direction != qosStatusSend && direction != qosStatusRecv && direction != qosStatusSendRecv {
		return "", "", false
	}
	return scope, direction, true
}

func parseQoSConfirmationRemote(line string) bool {
	scope, _, ok := parseQoSConfirmation(line)
	return ok && scope == "remote"
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
