package voice

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	rtcpBYEPacketType = 203
	rtcpPacketTypeMin = 192
	rtcpPacketTypeMax = 223
)

// HasRTCPBye reports whether payload contains an RTCP BYE packet.
func HasRTCPBye(payload []byte) bool {
	for len(payload) >= rtcpWordSize {
		if payload[0]>>rtpVersionShift != rtpVersion {
			return false
		}
		packetLen := int(binary.BigEndian.Uint16(payload[2:4])+1) * rtcpWordSize
		if packetLen < rtcpWordSize || packetLen > len(payload) {
			return false
		}
		if payload[1] == rtcpBYEPacketType {
			return true
		}
		payload = payload[packetLen:]
	}
	return false
}

// IsRTCPPacket reports whether payload looks like an RTCP packet.
func IsRTCPPacket(payload []byte) bool {
	if len(payload) < rtcpWordSize || payload[0]>>rtpVersionShift != rtpVersion {
		return false
	}
	if payload[1] < rtcpPacketTypeMin || payload[1] > rtcpPacketTypeMax {
		return false
	}
	packetLen := int(binary.BigEndian.Uint16(payload[2:4])+1) * rtcpWordSize
	return packetLen >= rtcpWordSize && packetLen <= len(payload)
}

// CloneUDPAddr returns an independent copy of addr.
func CloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

// RTCPAddr returns the conventional RTCP address for an RTP address.
func RTCPAddr(addr *net.UDPAddr) *net.UDPAddr {
	cloned := CloneUDPAddr(addr)
	if cloned == nil {
		return nil
	}
	cloned.Port++
	return cloned
}

// UDPAddrMatches reports whether two UDP addresses have the same IP and port.
func UDPAddrMatches(got, want *net.UDPAddr) bool {
	if got == nil || want == nil {
		return got == nil && want == nil
	}
	return got.Port == want.Port && got.IP.Equal(want.IP)
}

// MediaRemote contains the RTP/RTCP peer addresses negotiated for one media stream.
type MediaRemote struct {
	RTP     *net.UDPAddr
	RTCP    *net.UDPAddr
	RTCPMux bool
}

// MediaRemoteFromConfig resolves RTP and RTCP remote addresses from media config.
func MediaRemoteFromConfig(cfg MediaConfig) (MediaRemote, error) {
	if len(cfg.RemoteIP) == 0 || cfg.RemotePort == 0 {
		return MediaRemote{}, errors.New("remote address is required")
	}
	if cfg.RemoteRTCPPort < 0 || cfg.RemoteRTCPPort > 65535 {
		return MediaRemote{}, errors.New("remote rtcp port must be 0 or between 1 and 65535")
	}
	remote := &net.UDPAddr{IP: append(net.IP(nil), cfg.RemoteIP...), Port: cfg.RemotePort}
	if cfg.RTCPMux {
		return MediaRemote{RTP: remote, RTCP: CloneUDPAddr(remote), RTCPMux: true}, nil
	}
	if cfg.RemoteRTCPPort == 0 {
		return MediaRemote{RTP: remote}, nil
	}
	remoteRTCPIP := cfg.RemoteRTCPIP
	if len(remoteRTCPIP) == 0 {
		remoteRTCPIP = cfg.RemoteIP
	}
	remoteRTCP := &net.UDPAddr{IP: append(net.IP(nil), remoteRTCPIP...), Port: cfg.RemoteRTCPPort}
	return MediaRemote{RTP: remote, RTCP: remoteRTCP}, nil
}

// Addr returns the RTP or RTCP address to use on the wire.
func (r MediaRemote) Addr(rtcp bool) *net.UDPAddr {
	if !rtcp {
		return CloneUDPAddr(r.RTP)
	}
	if r.RTCPMux {
		return CloneUDPAddr(r.RTP)
	}
	if r.RTCP != nil {
		return CloneUDPAddr(r.RTCP)
	}
	return RTCPAddr(r.RTP)
}

// MediaLocalUDPAddr returns the local RTP or RTCP address for a media socket.
func MediaLocalUDPAddr(local *net.UDPAddr, rtcp bool, rtcpMux bool) *net.UDPAddr {
	if rtcp && !rtcpMux {
		return RTCPAddr(local)
	}
	return CloneUDPAddr(local)
}

// MediaPacketFromPayload builds packet metadata for media activity tracking.
func MediaPacketFromPayload(rtcp bool, payload []byte) MediaPacket {
	return MediaPacket{RTCP: rtcp, RTCPBye: rtcp && HasRTCPBye(payload)}
}
