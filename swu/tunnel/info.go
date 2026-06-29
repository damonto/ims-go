package tunnel

import (
	"errors"
	"log/slog"
	"net"

	"github.com/damonto/vowifi-go/swu/handshake"
	"github.com/damonto/vowifi-go/swu/ike"
)

type Info struct {
	InnerIPv4                 net.IP
	InnerIPv6                 IPAddress
	InnerIPv6Prefix           IPPrefix
	PDNTypeRestriction        PDNType
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
	SNSSAIPlmnID              []byte
}

func (s *Session) LocalAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connected && s.innerLocal != nil {
		return cloneUDPAddr(s.innerLocal)
	}
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.connected && s.innerRemote != nil {
		return cloneUDPAddr(s.innerRemote)
	}
	return cloneUDPAddr(s.outerRemote)
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

func (info Info) HasInnerAddress() bool {
	return len(info.InnerIPv4) != 0 || !info.InnerIPv6.IsZero()
}

func (info Info) DefaultInnerIP() net.IP {
	if pcscf := info.DefaultPCSCFIP(); len(pcscf) != 0 {
		return info.InnerIPForRemote(pcscf)
	}
	if !info.InnerIPv6.IsZero() {
		return append(net.IP(nil), info.InnerIPv6.IP...)
	}
	return append(net.IP(nil), info.InnerIPv4...)
}

func (info Info) InnerIPForRemote(remoteIP net.IP) net.IP {
	if len(remoteIP) == 0 {
		return info.DefaultInnerIP()
	}
	if remoteIP.To4() != nil {
		return append(net.IP(nil), info.InnerIPv4...)
	}
	if remoteIP.To16() != nil && !info.InnerIPv6.IsZero() {
		return append(net.IP(nil), info.InnerIPv6.IP...)
	}
	return nil
}

func (info Info) DefaultPCSCFIP() net.IP {
	ips := info.PCSCFAddresses()
	if len(ips) == 0 {
		return nil
	}
	return append(net.IP(nil), ips[0]...)
}

func (info Info) PCSCFAddresses() []net.IP {
	return cloneIPList(info.PCSCFIPs)
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

func innerAddrsForInfo(info Info, remoteIP net.IP, localPort, remotePort int) (*net.UDPAddr, *net.UDPAddr) {
	local, remote := innerIPsForInfo(info, remoteIP)
	var localAddr *net.UDPAddr
	if len(local) != 0 {
		localAddr = &net.UDPAddr{IP: local, Port: localPort}
	}
	var remoteAddr *net.UDPAddr
	if len(remote) != 0 {
		remoteAddr = &net.UDPAddr{IP: remote, Port: remotePort}
	}
	return localAddr, remoteAddr
}

func handshakeInfo(info Info) handshake.Info {
	return handshake.Info{
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
		SNSSAIPlmnID:              append([]byte(nil), info.SNSSAIPlmnID...),
	}
}

func infoFromHandshake(info handshake.Info) Info {
	return Info{
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
		SNSSAIPlmnID:              append([]byte(nil), info.SNSSAIPlmnID...),
	}
}

func cloneIPAddress(address IPAddress) IPAddress {
	return IPAddress{
		IP:        append(net.IP(nil), address.IP...),
		PrefixLen: address.PrefixLen,
	}
}

func cloneIPPrefix(prefix IPPrefix) IPPrefix {
	return IPPrefix{
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
