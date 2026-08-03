package voice

import (
	"encoding"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

var (
	_ encoding.TextAppender    = sdpConnectionLine{}
	_ encoding.TextMarshaler   = sdpConnectionLine{}
	_ encoding.TextUnmarshaler = (*sdpConnectionLine)(nil)
	_ encoding.TextAppender    = sdpAudioLine{}
	_ encoding.TextMarshaler   = sdpAudioLine{}
	_ encoding.TextUnmarshaler = (*sdpAudioLine)(nil)
	_ encoding.TextAppender    = sdpMediaLine{}
	_ encoding.TextMarshaler   = sdpMediaLine{}
	_ encoding.TextUnmarshaler = (*sdpMediaLine)(nil)
)

func parseConnectionLine(line string) (net.IP, error) {
	var conn sdpConnectionLine
	if err := conn.UnmarshalText([]byte(line)); err != nil {
		return nil, err
	}
	return conn.IP, nil
}

func (l sdpConnectionLine) MarshalText() ([]byte, error) {
	return l.AppendText(nil)
}

func (l sdpConnectionLine) AppendText(dst []byte) ([]byte, error) {
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
	return fmt.Appendf(dst, "c=%s %s %s", sdpNetworkIN, strings.ToUpper(addressType), l.IP.String()), nil
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
	return l.AppendText(nil)
}

func (l sdpAudioLine) AppendText(dst []byte) ([]byte, error) {
	if l.Port <= 0 || l.Port > 65535 {
		return nil, fmt.Errorf("building voice SDP: invalid audio port %d", l.Port)
	}
	if strings.TrimSpace(l.Protocol) == "" {
		return nil, errors.New("building voice SDP: audio protocol is empty")
	}
	if len(l.Payloads) == 0 {
		return nil, errors.New("building voice SDP: audio payloads are empty")
	}
	port := strconv.Itoa(l.Port)
	if l.PortCount < 0 || l.PortCount > 65535 {
		return nil, fmt.Errorf("building voice SDP: invalid audio port count %d", l.PortCount)
	}
	if l.PortCount > 0 {
		port += "/" + strconv.Itoa(l.PortCount)
	}
	payloads := make([]string, 0, len(l.Payloads))
	for _, payload := range l.Payloads {
		if payload < 0 || payload > 127 {
			return nil, fmt.Errorf("building voice SDP: invalid payload type %d", payload)
		}
		payloads = append(payloads, strconv.Itoa(payload))
	}
	return fmt.Appendf(dst, "m=audio %s %s %s", port, l.Protocol, strings.Join(payloads, " ")), nil
}

func (l *sdpAudioLine) UnmarshalText(text []byte) error {
	line := string(text)
	fields := strings.Fields(strings.TrimPrefix(line, "m=audio "))
	if len(fields) < 3 {
		return fmt.Errorf("parsing voice SDP: invalid audio line %q", line)
	}
	port, portCount, ok := parseMediaPort(fields[0], 1)
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
	*l = sdpAudioLine{Port: port, PortCount: portCount, Protocol: fields[1], Payloads: payloads}
	return nil
}

func parseMediaLine(line string) (sdpMediaLine, error) {
	var media sdpMediaLine
	if err := media.UnmarshalText([]byte(line)); err != nil {
		return sdpMediaLine{}, err
	}
	return media, nil
}

func (l sdpMediaLine) MarshalText() ([]byte, error) {
	return l.AppendText(nil)
}

func (l sdpMediaLine) AppendText(dst []byte) ([]byte, error) {
	if strings.TrimSpace(l.Media) == "" {
		return nil, errors.New("building voice SDP: media is empty")
	}
	if l.Port < 0 || l.Port > 65535 {
		return nil, fmt.Errorf("building voice SDP: invalid media port %d", l.Port)
	}
	if l.PortCount < 0 || l.PortCount > 65535 {
		return nil, fmt.Errorf("building voice SDP: invalid media port count %d", l.PortCount)
	}
	if strings.TrimSpace(l.Protocol) == "" {
		return nil, errors.New("building voice SDP: media protocol is empty")
	}
	port := strconv.Itoa(l.Port)
	if l.PortCount > 0 {
		port += "/" + strconv.Itoa(l.PortCount)
	}
	dst = fmt.Appendf(dst, "m=%s %s %s", l.Media, port, l.Protocol)
	for _, format := range l.Formats {
		if strings.TrimSpace(format) == "" || strings.ContainsAny(format, " \t\r\n") {
			return nil, fmt.Errorf("building voice SDP: invalid media format %q", format)
		}
		dst = append(dst, ' ')
		dst = append(dst, format...)
	}
	return dst, nil
}

func (l *sdpMediaLine) UnmarshalText(text []byte) error {
	line := string(text)
	fields := strings.Fields(strings.TrimPrefix(line, "m="))
	if len(fields) < 3 {
		return fmt.Errorf("parsing voice SDP: invalid media line %q", line)
	}
	port, portCount, ok := parseMediaPort(fields[1], 0)
	if !ok {
		return fmt.Errorf("parsing voice SDP: invalid media port %q", fields[1])
	}
	*l = sdpMediaLine{
		Media:     fields[0],
		Port:      port,
		PortCount: portCount,
		Protocol:  fields[2],
		Formats:   append([]string(nil), fields[3:]...),
	}
	return nil
}

func parseMediaPort(value string, minimum int) (port, count int, ok bool) {
	portText, countText, hasCount := strings.Cut(strings.TrimSpace(value), "/")
	port, ok = parseBoundedDecimal(portText, minimum, 65535)
	if !ok {
		return 0, 0, false
	}
	if !hasCount {
		return port, 0, true
	}
	if strings.Contains(countText, "/") {
		return 0, 0, false
	}
	count, ok = parseBoundedDecimal(countText, 1, 65535)
	if !ok {
		return 0, 0, false
	}
	return port, count, true
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
