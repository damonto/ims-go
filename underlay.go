package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

// Underlay supplies the outer network used by Wi-Fi Calling.
//
// IMS traffic itself is carried inside the SWu/IPsec tunnel. These operations
// therefore cover only ePDG discovery, WFC provisioning HTTP, and the outer
// IKE/NAT-T packet socket.
type Underlay interface {
	// LocalIP identifies the selected outer-network address. Returning the zero
	// value allows both address families.
	LocalIP() netip.Addr
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
	DialContext(context.Context, string, string) (net.Conn, error)
	ListenPacket(context.Context, string, string) (net.PacketConn, error)
}

type systemUnderlay struct{}

func (systemUnderlay) LocalIP() netip.Addr {
	return netip.Addr{}
}

func (systemUnderlay) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, network, host)
}

func (systemUnderlay) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address)
}

func (systemUnderlay) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, network, address)
}

func effectiveUnderlay(underlay Underlay) Underlay {
	if underlay != nil {
		return underlay
	}
	return systemUnderlay{}
}

func underlayHTTPClient(underlay Underlay) *http.Client {
	return &http.Client{
		Transport: underlayHTTPTransport(underlay),
		Timeout:   30 * time.Second,
	}
}

func underlayHTTPTransport(underlay Underlay) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// A selected underlay must not accidentally send traffic through a proxy
	// that is reachable only through the host's default route.
	transport.Proxy = nil
	transport.DialContext = underlay.DialContext
	// Leaving this nil makes HTTPS use DialContext before Transport performs TLS.
	transport.DialTLSContext = nil
	return transport
}

func epdgRemoteCandidates(ctx context.Context, underlay Underlay, remote string, initialPort int) ([]string, error) {
	host, port, err := splitEPDGRemote(remote, initialPort)
	if err != nil {
		return nil, err
	}

	underlay = effectiveUnderlay(underlay)
	localIP := underlay.LocalIP().Unmap()
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		if localIP.IsValid() && addr.Is4() != localIP.Is4() {
			return nil, fmt.Errorf("resolving ePDG %q: address does not match local IP %s", host, localIP)
		}
		return []string{net.JoinHostPort(addr.String(), strconv.Itoa(port))}, nil
	}

	network := "ip"
	if localIP.Is4() {
		network = "ip4"
	} else if localIP.Is6() {
		network = "ip6"
	}
	addresses, err := underlay.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, fmt.Errorf("resolving ePDG %q: %w", host, err)
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("resolving ePDG %q: no addresses returned", host)
	}

	candidates := make([]string, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, addr := range addresses {
		if !addr.IsValid() {
			continue
		}
		addr = addr.Unmap()
		if localIP.IsValid() && addr.Is4() != localIP.Is4() {
			continue
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		candidates = append(candidates, net.JoinHostPort(addr.String(), strconv.Itoa(port)))
	}
	if len(candidates) == 0 {
		if localIP.IsValid() {
			return nil, fmt.Errorf("resolving ePDG %q: no addresses matching local IP %s", host, localIP)
		}
		return nil, fmt.Errorf("resolving ePDG %q: no valid addresses returned", host)
	}
	return candidates, nil
}

func splitEPDGRemote(remote string, initialPort int) (string, int, error) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", 0, errors.New("resolving ePDG: remote address is empty")
	}
	if initialPort == 0 {
		initialPort = swutunnel.DefaultIKEPort
	}
	if initialPort < 1 || initialPort > 65535 {
		return "", 0, fmt.Errorf("resolving ePDG: invalid initial port %d", initialPort)
	}

	if addr, err := netip.ParseAddr(remote); err == nil {
		return addr.String(), initialPort, nil
	}
	if strings.HasPrefix(remote, "[") && strings.HasSuffix(remote, "]") {
		host := strings.TrimSuffix(strings.TrimPrefix(remote, "["), "]")
		if addr, err := netip.ParseAddr(host); err == nil {
			return addr.String(), initialPort, nil
		}
	}
	if host, service, err := net.SplitHostPort(remote); err == nil {
		port, err := strconv.Atoi(service)
		if err != nil || port < 1 || port > 65535 {
			return "", 0, fmt.Errorf("resolving ePDG: invalid port %q", service)
		}
		if strings.TrimSpace(host) == "" {
			return "", 0, errors.New("resolving ePDG: host is empty")
		}
		return strings.TrimSpace(host), port, nil
	}
	if strings.Contains(remote, ":") {
		return "", 0, fmt.Errorf("resolving ePDG: invalid remote address %q", remote)
	}
	return remote, initialPort, nil
}

func shouldTryNextEPDG(ctx context.Context, err error) bool {
	return ctx.Err() == nil && errors.Is(err, swutunnel.ErrIKESAInitNoResponse)
}
