package tunnel

import (
	"errors"
	"log/slog"
	"net"
)

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
	return Info{
		InnerIP:                   append(net.IP(nil), s.tunnel.InnerIP...),
		PCSCFIP:                   append(net.IP(nil), s.tunnel.PCSCFIP...),
		PCSCFIPs:                  cloneIPList(s.tunnel.PCSCFIPs),
		ESPInitiatorSPI:           s.tunnel.ESPInitiatorSPI,
		ESPResponderSPI:           s.tunnel.ESPResponderSPI,
		Encryption:                s.tunnel.Encryption,
		EncryptionKeyLen:          s.tunnel.EncryptionKeyLen,
		Integrity:                 s.tunnel.Integrity,
		InitiatorTrafficSelectors: cloneTrafficSelectors(s.tunnel.InitiatorTrafficSelectors),
		ResponderTrafficSelectors: cloneTrafficSelectors(s.tunnel.ResponderTrafficSelectors),
		PDUSessionID:              s.tunnel.PDUSessionID,
		SNSSAI:                    append([]byte(nil), s.tunnel.SNSSAI...),
		SNSSAIPlmnID:              append([]byte(nil), s.tunnel.SNSSAIPlmnID...),
	}
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
	if len(info.InnerIP) == 0 {
		return Info{}, errors.New("tunnel inner ip is empty")
	}
	return info, nil
}

func (s *Session) Logger() *slog.Logger {
	return s.logger
}
