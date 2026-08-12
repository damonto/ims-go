package tunnel

import (
	"errors"
	"log/slog"
	"net"

	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
)

type Info struct {
	APN                       string
	InnerIPv4                 net.IP
	InnerIPv6                 handshake.IPAddress
	InnerIPv6Prefix           handshake.IPPrefix
	PDNTypeRestriction        handshake.PDNType
	PCSCFIPs                  []net.IP
	ESPInitiatorSPI           uint32
	ESPResponderSPI           uint32
	Encryption                uint16
	EncryptionKeyLen          uint16
	Integrity                 uint16
	InitiatorTrafficSelectors []ike.TrafficSelector
	ResponderTrafficSelectors []ike.TrafficSelector
	PDUSessionID              byte
	SNSSAI                    []byte
	SNSSAIPLMNID              []byte
}

func (s *Session) Tunnel() Info {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneInfo(s.tunnel)
}

func (s *Session) Info() Info {
	return s.Tunnel()
}

func (s *Session) ReadyInfo() (Info, error) {
	if s.isClosed() {
		return Info{}, errSessionClosed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.connected {
		if err := s.disconnectedTunnelErr(); err != nil {
			return Info{}, err
		}
		return Info{}, errChildSAUnavailable
	}
	info := cloneInfo(s.tunnel)
	if !info.HasInnerAddress() {
		return Info{}, errors.New("tunnel inner ip is empty")
	}
	return info, nil
}

func (s *Session) InnerIPsForRemote(remoteIP net.IP) (net.IP, net.IP, error) {
	if s.isClosed() {
		return nil, nil, errSessionClosed
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.connected {
		if err := s.disconnectedTunnelErr(); err != nil {
			return nil, nil, err
		}
		return nil, nil, errChildSAUnavailable
	}
	local, remote := innerIPsForInfo(s.tunnel, remoteIP)
	if len(local) == 0 {
		return nil, nil, errors.New("tunnel inner local address is unavailable")
	}
	if len(remote) == 0 {
		return nil, nil, errors.New("tunnel inner remote address is unavailable")
	}
	return local, remote, nil
}

func (i Info) HasInnerAddress() bool {
	return len(i.InnerIPv4) != 0 || !i.InnerIPv6.IsZero()
}

func (i Info) DefaultInnerIP() net.IP {
	if pcscf := i.DefaultPCSCFIP(); len(pcscf) != 0 {
		return i.InnerIPForRemote(pcscf)
	}
	if !i.InnerIPv6.IsZero() {
		return append(net.IP(nil), i.InnerIPv6.IP...)
	}
	return append(net.IP(nil), i.InnerIPv4...)
}

func (i Info) InnerIPForRemote(remoteIP net.IP) net.IP {
	if len(remoteIP) == 0 {
		return i.DefaultInnerIP()
	}
	if remoteIP.To4() != nil {
		return append(net.IP(nil), i.InnerIPv4...)
	}
	if remoteIP.To16() != nil && !i.InnerIPv6.IsZero() {
		return append(net.IP(nil), i.InnerIPv6.IP...)
	}
	return nil
}

func (i Info) DefaultPCSCFIP() net.IP {
	ips := i.PCSCFAddresses()
	if len(ips) == 0 {
		return nil
	}
	return append(net.IP(nil), ips[0]...)
}

func (i Info) PCSCFAddresses() []net.IP {
	return cloneIPList(i.PCSCFIPs)
}

func innerIPsForInfo(info Info, remoteIP net.IP) (net.IP, net.IP) {
	remote := append(net.IP(nil), remoteIP...)
	if len(remote) == 0 {
		remote = info.DefaultPCSCFIP()
	}
	local := info.InnerIPForRemote(remote)
	if len(local) == 0 && len(remote) == 0 {
		local = info.DefaultInnerIP()
	}
	return local, remote
}

func handshakeInfo(info Info) handshake.Info {
	return handshake.Info{
		APN:                       info.APN,
		InnerIPv4:                 append(net.IP(nil), info.InnerIPv4...),
		InnerIPv6:                 cloneIPAddress(info.InnerIPv6),
		InnerIPv6Prefix:           cloneIPPrefix(info.InnerIPv6Prefix),
		PDNTypeRestriction:        info.PDNTypeRestriction,
		PCSCFIPs:                  cloneIPList(info.PCSCFIPs),
		ESPInitiatorSPI:           info.ESPInitiatorSPI,
		ESPResponderSPI:           info.ESPResponderSPI,
		Encryption:                info.Encryption,
		EncryptionKeyLen:          info.EncryptionKeyLen,
		Integrity:                 info.Integrity,
		InitiatorTrafficSelectors: cloneTrafficSelectors(info.InitiatorTrafficSelectors),
		ResponderTrafficSelectors: cloneTrafficSelectors(info.ResponderTrafficSelectors),
		PDUSessionID:              info.PDUSessionID,
		SNSSAI:                    append([]byte(nil), info.SNSSAI...),
		SNSSAIPLMNID:              append([]byte(nil), info.SNSSAIPLMNID...),
	}
}

func infoFromHandshake(info handshake.Info) Info {
	return Info{
		APN:                       info.APN,
		InnerIPv4:                 append(net.IP(nil), info.InnerIPv4...),
		InnerIPv6:                 cloneIPAddress(info.InnerIPv6),
		InnerIPv6Prefix:           cloneIPPrefix(info.InnerIPv6Prefix),
		PDNTypeRestriction:        info.PDNTypeRestriction,
		PCSCFIPs:                  cloneIPList(info.PCSCFIPs),
		ESPInitiatorSPI:           info.ESPInitiatorSPI,
		ESPResponderSPI:           info.ESPResponderSPI,
		Encryption:                info.Encryption,
		EncryptionKeyLen:          info.EncryptionKeyLen,
		Integrity:                 info.Integrity,
		InitiatorTrafficSelectors: cloneTrafficSelectors(info.InitiatorTrafficSelectors),
		ResponderTrafficSelectors: cloneTrafficSelectors(info.ResponderTrafficSelectors),
		PDUSessionID:              info.PDUSessionID,
		SNSSAI:                    append([]byte(nil), info.SNSSAI...),
		SNSSAIPLMNID:              append([]byte(nil), info.SNSSAIPLMNID...),
	}
}

func cloneIPAddress(address handshake.IPAddress) handshake.IPAddress {
	return handshake.IPAddress{
		IP:        append(net.IP(nil), address.IP...),
		PrefixLen: address.PrefixLen,
	}
}

func cloneIPPrefix(prefix handshake.IPPrefix) handshake.IPPrefix {
	return handshake.IPPrefix{
		IP:        append(net.IP(nil), prefix.IP...),
		PrefixLen: prefix.PrefixLen,
	}
}

func cloneIPList(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	cloned := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		cloned = append(cloned, append(net.IP(nil), ip...))
	}
	return cloned
}

func (s *Session) Logger() *slog.Logger {
	return s.logger
}
