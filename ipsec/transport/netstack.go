package transport

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/ipsec/packet"
	"github.com/damonto/ims-go/ipsec/transport/netstack/buffer"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/channel"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/network/ipv4"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/network/ipv6"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/transport/tcp"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/transport/udp"
)

const (
	netstackNIC          tcpip.NICID = 1
	netstackWriteTimeout             = 2 * time.Second
	// The channel ends at the IPsec boundary, not at a physical link. ESP
	// transport mode must receive a complete IP datagram; using a path MTU here
	// would make IPv6 fragment the plaintext packet before ESP processing.
	netstackMTU uint32 = header.IPv6MinimumSize + header.IPv6MaximumPayloadSize
)

var errNetstackClosed = errors.New("IMS netstack is closed")

// Netstack owns the userspace IP, TCP, and UDP stack for one IMS packet
// session. ESP remains at the link boundary because its policies are negotiated
// by IMS, not by the IP stack.
type Netstack struct {
	session PacketSession
	stack   *stack.Stack
	link    *netstackLink

	mu               sync.Mutex
	addresses        map[string]struct{}
	policies         []*netstackSecurityPolicy
	writeContexts    map[netstackFlowKey]netstackWriteContext
	writeErrors      map[netstackFlowKey]error
	tcpListeners     map[netstackTCPListenerKey]*netstackTCPListener
	udpKeepalives    map[netstackPeerKey]*netstackUDPEncKeepalive
	nextWriteContext uint64
	closed           bool
	err              error

	attachment Attachment
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	closeOnce  sync.Once
}

type netstackLink struct {
	*channel.Endpoint
	writePacket func(*stack.PacketBuffer) tcpip.Error
}

func (l *netstackLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	for i, pkt := range pkts.AsSlice() {
		if err := l.writePacket(pkt); err != nil {
			return i, err
		}
	}
	return pkts.Len(), nil
}

type netstackFlowKey struct {
	protocol              byte
	localIP, remoteIP     string
	localPort, remotePort int
}

type netstackWriteContext struct {
	id  uint64
	ctx context.Context
}

type netstackTCPListenerKey struct {
	localIP string
	port    int
}

type netstackPeerKey struct {
	localIP  string
	remoteIP string
}

type netstackUDPEncKeepalive struct {
	localIP  net.IP
	remoteIP net.IP
	stop     chan struct{}
	refs     int

	writeMu   sync.Mutex
	lastWrite time.Time
}

type netstackSecurityPolicy struct {
	protocol      byte
	localIP       net.IP
	remoteIP      net.IP
	outerLocalIP  net.IP
	outerRemoteIP net.IP
	localPort     int
	remotePort    int
	mode          string
	associationID string

	outboundESP  esp.Codec
	inboundESP   esp.Codec
	associations *SecurityAssociations
	keepalive    *netstackUDPEncKeepalive
}

type netstackSecurityConfig struct {
	protocol      byte
	localIP       net.IP
	remoteIP      net.IP
	outerLocalIP  net.IP
	outerRemoteIP net.IP
	localPort     int
	remotePort    int
	mode          string

	outboundSPI  uint32
	inboundSPI   uint32
	encryption   string
	integrity    string
	associations *SecurityAssociations

	encryptionKey []byte
	integrityKey  []byte
	outboundSalt  [4]byte
	inboundSalt   [4]byte
}

func NewNetstack(session PacketSession) (*Netstack, error) {
	if session == nil {
		return nil, errors.New("creating IMS netstack: packet session is nil")
	}
	link := &netstackLink{Endpoint: channel.New(1, netstackMTU, "")}
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	if err := s.CreateNIC(netstackNIC, link); err != nil {
		s.Destroy()
		return nil, fmt.Errorf("creating IMS netstack NIC: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: netstackNIC},
		{Destination: header.IPv6EmptySubnet, NIC: netstackNIC},
	})
	ctx, cancel := context.WithCancel(context.Background())
	n := &Netstack{
		session:       session,
		stack:         s,
		link:          link,
		addresses:     make(map[string]struct{}),
		writeContexts: make(map[netstackFlowKey]netstackWriteContext),
		writeErrors:   make(map[netstackFlowKey]error),
		tcpListeners:  make(map[netstackTCPListenerKey]*netstackTCPListener),
		udpKeepalives: make(map[netstackPeerKey]*netstackUDPEncKeepalive),
		ctx:           ctx,
		cancel:        cancel,
	}
	link.writePacket = n.writeLinkPacket
	attachment, err := session.Attach(n)
	if err != nil {
		cancel()
		link.Close()
		s.Destroy()
		return nil, fmt.Errorf("creating IMS netstack: attaching packet session: %w", err)
	}
	n.attachment = attachment
	return n, nil
}

func (n *Netstack) ensureAddress(ip net.IP) (tcpip.NetworkProtocolNumber, error) {
	normalized, protocol, prefix, err := netstackIP(ip)
	if err != nil {
		return 0, err
	}
	key := normalized.String()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return 0, fmt.Errorf("adding IMS netstack address: %w", n.closedErr())
	}
	if _, ok := n.addresses[key]; ok {
		return protocol, nil
	}
	address := tcpip.ProtocolAddress{
		Protocol: protocol,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(normalized),
			PrefixLen: prefix,
		},
	}
	if err := n.stack.AddProtocolAddress(netstackNIC, address, stack.AddressProperties{}); err != nil {
		return 0, fmt.Errorf("adding IMS netstack address %s: %s", normalized, err)
	}
	n.addresses[key] = struct{}{}
	return protocol, nil
}

func netstackIP(ip net.IP) (net.IP, tcpip.NetworkProtocolNumber, int, error) {
	if v4 := ip.To4(); v4 != nil {
		return append(net.IP(nil), v4...), ipv4.ProtocolNumber, net.IPv4len * 8, nil
	}
	if v6 := ip.To16(); v6 != nil {
		return append(net.IP(nil), v6...), ipv6.ProtocolNumber, net.IPv6len * 8, nil
	}
	return nil, 0, 0, fmt.Errorf("resolving IMS netstack address: invalid IP %v", ip)
}

func netstackFullAddress(ip net.IP, port int) tcpip.FullAddress {
	return tcpip.FullAddress{
		NIC:  netstackNIC,
		Addr: tcpip.AddrFromSlice(ip),
		Port: uint16(port),
	}
}

func (n *Netstack) writeLinkPacket(pkt *stack.PacketBuffer) tcpip.Error {
	view := pkt.ToView()
	wire := append([]byte(nil), view.AsSlice()...)
	view.Release()

	var inner packet.InnerPacket
	if err := inner.UnmarshalBinary(wire); err != nil {
		n.fail(fmt.Errorf("writing IMS netstack packet: %w", err))
		return &tcpip.ErrAborted{}
	}
	key := netstackPacketFlowKey(inner)
	ctx, cancel := n.writeContext(key)
	defer cancel()
	if err := n.writePacket(ctx, inner, wire); err != nil {
		n.recordWriteError(key, fmt.Errorf("writing IMS netstack packet: %w", err))
		return &tcpip.ErrAborted{}
	}
	return nil
}

func (n *Netstack) writePacket(ctx context.Context, inner packet.InnerPacket, wire []byte) error {
	policy, protectedPort := n.outboundPolicy(inner)
	if policy == nil {
		if protectedPort {
			return errors.New("sending plaintext from an IMS protected port")
		}
		return n.session.WriteInnerPacket(ctx, inner)
	}
	payload := inner.IP.Payload
	nextHeader := inner.IP.Protocol
	if policy.mode == SecureModeUDPEncTunnel {
		payload = wire
		var err error
		nextHeader, err = secureTunnelNextHeader(policy.localIP, policy.remoteIP)
		if err != nil {
			return err
		}
	}
	sealed, err := policy.associations.sealESP(policy.outboundESP, nextHeader, payload)
	if err != nil {
		return err
	}
	protected, err := secureInnerPacket(policy.outerLocalIP, policy.outerRemoteIP, policy.mode, sealed)
	if err != nil {
		return err
	}
	if policy.keepalive == nil {
		return n.session.WriteInnerPacket(ctx, protected)
	}
	policy.keepalive.writeMu.Lock()
	defer policy.keepalive.writeMu.Unlock()
	if err := n.session.WriteInnerPacket(ctx, protected); err != nil {
		return err
	}
	policy.keepalive.lastWrite = time.Now()
	return nil
}

func netstackPacketFlowKey(pkt packet.InnerPacket) netstackFlowKey {
	protocol, srcIP, dstIP, srcPort, dstPort := netstackPacketFlow(pkt)
	return netstackFlowKey{
		protocol: protocol,
		localIP:  srcIP.String(), remoteIP: dstIP.String(),
		localPort: srcPort, remotePort: dstPort,
	}
}

func netstackFlowKeyForAddresses(protocol byte, localIP, remoteIP net.IP, localPort, remotePort int) netstackFlowKey {
	return netstackFlowKey{
		protocol: protocol,
		localIP:  localIP.String(), remoteIP: remoteIP.String(),
		localPort: localPort, remotePort: remotePort,
	}
}

func (n *Netstack) withWriteContext(key netstackFlowKey, ctx context.Context, write func() error) error {
	n.mu.Lock()
	n.nextWriteContext++
	current := netstackWriteContext{id: n.nextWriteContext, ctx: ctx}
	previous, hadPrevious := n.writeContexts[key]
	n.writeContexts[key] = current
	delete(n.writeErrors, key)
	n.mu.Unlock()

	err := write()

	n.mu.Lock()
	if active, ok := n.writeContexts[key]; ok && active.id == current.id {
		if hadPrevious {
			n.writeContexts[key] = previous
		} else {
			delete(n.writeContexts, key)
		}
	}
	n.mu.Unlock()
	return err
}

func (n *Netstack) writeContext(key netstackFlowKey) (context.Context, context.CancelFunc) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if current, ok := n.writeContexts[key]; ok {
		return current.ctx, func() {}
	}
	return context.WithTimeout(n.ctx, netstackWriteTimeout)
}

func (n *Netstack) recordWriteError(key netstackFlowKey, err error) {
	n.mu.Lock()
	n.writeErrors[key] = err
	n.mu.Unlock()
}

func (n *Netstack) transportError(key netstackFlowKey, fallback error) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	if err := n.writeErrors[key]; err != nil {
		delete(n.writeErrors, key)
		return err
	}
	if n.closed {
		return errNetstackClosed
	}
	return fallback
}

func (n *Netstack) clearFlow(key netstackFlowKey) {
	n.mu.Lock()
	delete(n.writeContexts, key)
	delete(n.writeErrors, key)
	n.mu.Unlock()
}

func (n *Netstack) outboundPolicy(pkt packet.InnerPacket) (*netstackSecurityPolicy, bool) {
	protocol, srcIP, dstIP, srcPort, dstPort := netstackPacketFlow(pkt)
	n.mu.Lock()
	defer n.mu.Unlock()
	protectedPort := false
	for i := len(n.policies) - 1; i >= 0; i-- {
		policy := n.policies[i]
		if srcIP.Equal(policy.localIP) && srcPort == policy.localPort {
			protectedPort = true
		}
		if policy.matches(protocol, srcIP, dstIP, srcPort, dstPort) {
			return policy, true
		}
	}
	return nil, protectedPort
}

func (n *Netstack) registerSecurity(cfg netstackSecurityConfig) (*netstackSecurityPolicy, error) {
	if err := validateSecureTransportPorts(cfg.localPort, cfg.remotePort); err != nil {
		return nil, err
	}
	if err := validateSecureSPIs(cfg.outboundSPI, cfg.inboundSPI); err != nil {
		return nil, err
	}
	encryption, err := secureEncryption(cfg.encryption)
	if err != nil {
		return nil, err
	}
	mode, err := secureMode(cfg.mode)
	if err != nil {
		return nil, err
	}
	if err := validateSecureESPConfig(encryption, cfg.integrity, cfg.encryptionKey, cfg.integrityKey); err != nil {
		return nil, err
	}
	if len(cfg.outerLocalIP) == 0 {
		cfg.outerLocalIP = cfg.localIP
	}
	if len(cfg.outerRemoteIP) == 0 {
		cfg.outerRemoteIP = cfg.remoteIP
	}
	policy := &netstackSecurityPolicy{
		protocol:      cfg.protocol,
		localIP:       append(net.IP(nil), cfg.localIP...),
		remoteIP:      append(net.IP(nil), cfg.remoteIP...),
		outerLocalIP:  append(net.IP(nil), cfg.outerLocalIP...),
		outerRemoteIP: append(net.IP(nil), cfg.outerRemoteIP...),
		localPort:     cfg.localPort,
		remotePort:    cfg.remotePort,
		mode:          mode,
		associationID: securityAssociationFingerprint(cfg, encryption, mode),
		associations:  secureAssociations(cfg.associations),
		outboundESP:   secureESPCodec(cfg.outboundSPI, encryption, cfg.encryptionKey, cfg.integrity, cfg.integrityKey, cfg.outboundSalt),
		inboundESP:    secureESPCodec(cfg.inboundSPI, encryption, cfg.encryptionKey, cfg.integrity, cfg.integrityKey, cfg.inboundSalt),
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil, fmt.Errorf("registering IMS netstack security policy: %w", n.closedErr())
	}
	startKeepalive := false
	if mode == SecureModeUDPEncTunnel {
		policy.keepalive, startKeepalive = n.retainUDPEncKeepaliveLocked(policy.outerLocalIP, policy.outerRemoteIP)
	}
	n.policies = append(n.policies, policy)
	if startKeepalive {
		n.wg.Add(1)
	}
	n.mu.Unlock()
	if startKeepalive {
		go n.runUDPEncKeepalive(policy.keepalive)
	}
	return policy, nil
}

func securityAssociationFingerprint(cfg netstackSecurityConfig, encryption, mode string) string {
	data := make([]byte, 0, 128)
	var spis [8]byte
	binary.BigEndian.PutUint32(spis[:4], cfg.outboundSPI)
	binary.BigEndian.PutUint32(spis[4:], cfg.inboundSPI)
	data = append(data, spis[:]...)
	for _, value := range [][]byte{
		[]byte(encryption),
		[]byte(strings.ToLower(strings.TrimSpace(cfg.integrity))),
		[]byte(mode),
		cfg.encryptionKey,
		cfg.integrityKey,
		cfg.outboundSalt[:],
		cfg.inboundSalt[:],
	} {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(value)))
		data = append(data, size[:]...)
		data = append(data, value...)
	}
	sum := sha256.Sum256(data)
	return string(sum[:])
}

func (n *Netstack) retainUDPEncKeepaliveLocked(localIP, remoteIP net.IP) (*netstackUDPEncKeepalive, bool) {
	key := netstackPeerKey{localIP: localIP.String(), remoteIP: remoteIP.String()}
	keepalive := n.udpKeepalives[key]
	if keepalive != nil {
		keepalive.refs++
		return keepalive, false
	}
	keepalive = &netstackUDPEncKeepalive{
		localIP:   append(net.IP(nil), localIP...),
		remoteIP:  append(net.IP(nil), remoteIP...),
		stop:      make(chan struct{}),
		refs:      1,
		lastWrite: time.Now(),
	}
	n.udpKeepalives[key] = keepalive
	return keepalive, true
}

func (n *Netstack) runUDPEncKeepalive(keepalive *netstackUDPEncKeepalive) {
	defer n.wg.Done()
	timer := time.NewTimer(udpEncapsulatedESPKeepaliveTick)
	defer timer.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-keepalive.stop:
			return
		case <-timer.C:
		}

		keepalive.writeMu.Lock()
		idle := time.Since(keepalive.lastWrite)
		if idle < udpEncapsulatedESPKeepaliveTick {
			keepalive.writeMu.Unlock()
			timer.Reset(udpEncapsulatedESPKeepaliveTick - idle)
			continue
		}
		ctx, cancel := context.WithTimeout(n.ctx, udpEncapsulatedESPKeepaliveTimeout)
		err := writeUDPEncTunnelKeepalive(ctx, n.session, keepalive.localIP, keepalive.remoteIP)
		cancel()
		if err == nil {
			keepalive.lastWrite = time.Now()
		}
		keepalive.writeMu.Unlock()
		if err != nil {
			select {
			case <-n.ctx.Done():
				return
			case <-keepalive.stop:
				return
			default:
			}
			n.session.Logger().Debug("writing IMS UDP-enc-tun keepalive failed", "err", err)
		}
		timer.Reset(udpEncapsulatedESPKeepaliveTick)
	}
}

func (n *Netstack) removeSecurity(target *netstackSecurityPolicy) {
	if target == nil {
		return
	}
	n.mu.Lock()
	for i, policy := range n.policies {
		if policy == target {
			n.policies = append(n.policies[:i], n.policies[i+1:]...)
			n.releaseUDPEncKeepaliveLocked(policy)
			n.mu.Unlock()
			return
		}
	}
	n.mu.Unlock()
}

func (n *Netstack) releaseUDPEncKeepaliveLocked(policy *netstackSecurityPolicy) {
	keepalive := policy.keepalive
	if keepalive == nil {
		return
	}
	keepalive.refs--
	if keepalive.refs != 0 {
		return
	}
	key := netstackPeerKey{localIP: keepalive.localIP.String(), remoteIP: keepalive.remoteIP.String()}
	delete(n.udpKeepalives, key)
	close(keepalive.stop)
}

func (p *netstackSecurityPolicy) matches(protocol byte, srcIP, dstIP net.IP, srcPort, dstPort int) bool {
	return protocol == p.protocol && srcIP.Equal(p.localIP) && dstIP.Equal(p.remoteIP) &&
		srcPort == p.localPort && dstPort == p.remotePort
}

func (p *netstackSecurityPolicy) matchesInbound(protocol byte, srcIP, dstIP net.IP, srcPort, dstPort int) bool {
	return protocol == p.protocol && srcIP.Equal(p.remoteIP) && dstIP.Equal(p.localIP) &&
		srcPort == p.remotePort && dstPort == p.localPort
}

func (p *netstackSecurityPolicy) matchesInboundPacket(pkt packet.InnerPacket) bool {
	protocol, srcIP, dstIP, srcPort, dstPort := netstackPacketFlow(pkt)
	if p.matchesInbound(protocol, srcIP, dstIP, srcPort, dstPort) {
		return true
	}
	if protocol != packet.ProtocolICMP && protocol != packet.ProtocolICMPv6 {
		return false
	}
	protocol, srcIP, dstIP, srcPort, dstPort, ok := quotedTransportFlow(pkt.IP.Payload)
	return ok && p.matches(protocol, srcIP, dstIP, srcPort, dstPort)
}

func netstackPacketFlow(pkt packet.InnerPacket) (byte, net.IP, net.IP, int, int) {
	switch {
	case pkt.TCP != nil && pkt.TCP.Src != nil && pkt.TCP.Dst != nil:
		return packet.ProtocolTCP, pkt.TCP.Src.IP, pkt.TCP.Dst.IP, pkt.TCP.Src.Port, pkt.TCP.Dst.Port
	case pkt.UDP != nil && pkt.UDP.Src != nil && pkt.UDP.Dst != nil:
		return packet.ProtocolUDP, pkt.UDP.Src.IP, pkt.UDP.Dst.IP, pkt.UDP.Src.Port, pkt.UDP.Dst.Port
	default:
		return pkt.IP.Protocol, pkt.IP.SrcIP, pkt.IP.DstIP, 0, 0
	}
}

func (n *Netstack) HandleInnerPacket(pkt packet.InnerPacket) bool {
	if udpEncapsulatedESPKeepalivePacket(pkt) && n.isLocalUDPEncKeepalive(pkt) {
		return true
	}
	if inner, recognized, valid := n.unprotect(pkt); recognized {
		if valid {
			n.inject(inner)
		}
		return true
	}
	protocol, _, dstIP, _, dstPort := netstackPacketFlow(pkt)
	if protocol != packet.ProtocolTCP && protocol != packet.ProtocolUDP &&
		protocol != packet.ProtocolICMP && protocol != packet.ProtocolICMPv6 {
		return false
	}
	n.mu.Lock()
	protected := false
	local := false
	for _, policy := range n.policies {
		if dstIP.Equal(policy.localIP) && dstPort == policy.localPort {
			protected = true
			break
		}
	}
	_, local = n.addresses[dstIP.String()]
	n.mu.Unlock()
	if protected && protocol != packet.ProtocolICMP && protocol != packet.ProtocolICMPv6 {
		return true
	}
	if !local {
		return false
	}
	n.inject(pkt)
	return true
}

func (n *Netstack) isLocalUDPEncKeepalive(pkt packet.InnerPacket) bool {
	udp := pkt.UDP
	if udp == nil || udp.Src == nil || udp.Dst == nil {
		return false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	_, ok := n.udpKeepalives[netstackPeerKey{localIP: udp.Dst.IP.String(), remoteIP: udp.Src.IP.String()}]
	return ok
}

func (n *Netstack) unprotect(pkt packet.InnerPacket) (packet.InnerPacket, bool, bool) {
	n.mu.Lock()
	policies := append([]*netstackSecurityPolicy(nil), n.policies...)
	n.mu.Unlock()
	recognized := false
	for i := len(policies) - 1; i >= 0; i-- {
		policy := policies[i]
		espPayload, ok := secureESPPayload(pkt, policy.mode)
		if !ok || !secureOuterDestinationMatches(pkt, policy.outerLocalIP, policy.mode) || packetSPI(espPayload) != policy.inboundESP.SPI {
			continue
		}
		recognized = true
		if sequence, ok := packetESPSequence(espPayload); ok && !policy.associations.mayAcceptInboundESP(policy.inboundESP, sequence) {
			return packet.InnerPacket{}, true, false
		}
		decoded, err := policy.inboundESP.Decode(espPayload)
		if err != nil {
			return packet.InnerPacket{}, true, false
		}
		if policy.mode == SecureModeTransport && decoded.NextHeader != policy.protocol {
			continue
		}
		if policy.mode == SecureModeUDPEncTunnel && decoded.NextHeader != packet.OuterIPv4 && decoded.NextHeader != packet.OuterIPv6 {
			continue
		}
		inner, err := netstackDecodedPacket(policy, pkt, decoded)
		if err != nil {
			return packet.InnerPacket{}, true, false
		}
		if !policy.matchesInboundPacket(inner) {
			continue
		}
		if !policy.associations.acceptInboundESP(policy.inboundESP, decoded.Sequence) {
			return packet.InnerPacket{}, true, false
		}
		return inner, true, true
	}
	return packet.InnerPacket{}, recognized, false
}

func quotedTransportFlow(icmp []byte) (byte, net.IP, net.IP, int, int, bool) {
	if len(icmp) < 8 {
		return 0, nil, nil, 0, 0, false
	}
	quoted := icmp[8:]
	if len(quoted) == 0 {
		return 0, nil, nil, 0, 0, false
	}
	switch int(quoted[0] >> 4) {
	case packet.IPVersion4:
		if len(quoted) < 20 {
			return 0, nil, nil, 0, 0, false
		}
		offset := int(quoted[0]&0x0f) * 4
		if offset < 20 || len(quoted) < offset+4 || binary.BigEndian.Uint16(quoted[6:8])&0x1fff != 0 {
			return 0, nil, nil, 0, 0, false
		}
		return quoted[9],
			append(net.IP(nil), quoted[12:16]...),
			append(net.IP(nil), quoted[16:20]...),
			int(binary.BigEndian.Uint16(quoted[offset : offset+2])),
			int(binary.BigEndian.Uint16(quoted[offset+2 : offset+4])), true
	case packet.IPVersion6:
		if len(quoted) < 40 {
			return 0, nil, nil, 0, 0, false
		}
		protocol := quoted[6]
		offset := 40
		for {
			switch protocol {
			case 0, 43, 60:
				if offset+2 > len(quoted) {
					return 0, nil, nil, 0, 0, false
				}
				next := quoted[offset]
				length := (int(quoted[offset+1]) + 1) * 8
				if length < 8 || offset+length > len(quoted) {
					return 0, nil, nil, 0, 0, false
				}
				protocol = next
				offset += length
			case 44:
				if offset+8 > len(quoted) || binary.BigEndian.Uint16(quoted[offset+2:offset+4])>>3 != 0 {
					return 0, nil, nil, 0, 0, false
				}
				protocol = quoted[offset]
				offset += 8
			case 51:
				if offset+2 > len(quoted) {
					return 0, nil, nil, 0, 0, false
				}
				next := quoted[offset]
				length := (int(quoted[offset+1]) + 2) * 4
				if length < 8 || offset+length > len(quoted) {
					return 0, nil, nil, 0, 0, false
				}
				protocol = next
				offset += length
			default:
				if len(quoted) < offset+4 {
					return 0, nil, nil, 0, 0, false
				}
				return protocol,
					append(net.IP(nil), quoted[8:24]...),
					append(net.IP(nil), quoted[24:40]...),
					int(binary.BigEndian.Uint16(quoted[offset : offset+2])),
					int(binary.BigEndian.Uint16(quoted[offset+2 : offset+4])), true
			}
		}
	default:
		return 0, nil, nil, 0, 0, false
	}
}

func netstackDecodedPacket(policy *netstackSecurityPolicy, outer packet.InnerPacket, decoded esp.ESPPacket) (packet.InnerPacket, error) {
	if policy.mode == SecureModeUDPEncTunnel {
		if decoded.NextHeader != packet.OuterIPv4 && decoded.NextHeader != packet.OuterIPv6 {
			return packet.InnerPacket{}, errors.New("decoding IMS netstack ESP tunnel packet: unsupported next header")
		}
		var inner packet.InnerPacket
		if err := inner.UnmarshalBinary(decoded.Payload); err != nil {
			return packet.InnerPacket{}, err
		}
		return inner, nil
	}
	if decoded.NextHeader != policy.protocol {
		return packet.InnerPacket{}, errors.New("decoding IMS netstack ESP transport packet: protocol mismatch")
	}
	return packet.DecodePayload(decoded.NextHeader, outer.IP.SrcIP, outer.IP.DstIP, decoded.Payload)
}

func (n *Netstack) inject(pkt packet.InnerPacket) {
	wire := pkt.OriginalWire()
	if len(wire) == 0 {
		var err error
		wire, err = pkt.MarshalBinary()
		if err != nil {
			n.session.Logger().Debug("injecting IMS netstack packet failed", "err", err)
			return
		}
	}
	_, protocol, _, err := netstackIP(pkt.IP.DstIP)
	if err != nil {
		n.session.Logger().Debug("injecting IMS netstack packet failed", "err", err)
		return
	}
	packetBuffer := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(wire)})
	defer packetBuffer.DecRef()
	n.link.InjectInbound(protocol, packetBuffer)
}

func (n *Netstack) HandleError(err error) {
	n.fail(fmt.Errorf("running IMS packet session: %w", err))
}

func (n *Netstack) fail(err error) {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	n.err = err
	n.mu.Unlock()
	n.cancel()
	n.stack.Close()
}

func (n *Netstack) Err() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.err
}

func (n *Netstack) terminalErr() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return n.err
	}
	if n.closed {
		return errNetstackClosed
	}
	return nil
}

func (n *Netstack) closedErr() error {
	if n.err != nil {
		return n.err
	}
	return errNetstackClosed
}

func (n *Netstack) Close() error {
	n.closeOnce.Do(func() {
		n.mu.Lock()
		n.closed = true
		attachment := n.attachment
		n.attachment = nil
		listeners := make([]*netstackTCPListener, 0, len(n.tcpListeners))
		for _, listener := range n.tcpListeners {
			listeners = append(listeners, listener)
		}
		n.tcpListeners = make(map[netstackTCPListenerKey]*netstackTCPListener)
		n.mu.Unlock()
		if attachment != nil {
			_ = attachment.Close()
		}
		for _, listener := range listeners {
			listener.stop()
		}
		n.cancel()
		n.link.Close()
		n.stack.Destroy()
		n.wg.Wait()
	})
	return nil
}
