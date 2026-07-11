package lte

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

const (
	// DefaultAPN is the IMS APN normally requested for VoLTE.
	DefaultAPN = "ims"
	// DefaultPDNType requests dual-stack IMS PDN when the modem and network support it.
	DefaultPDNType = "ipv4v6"
	// DefaultAccessNetworkInfo is retained for callers that explicitly know the
	// access is E-UTRAN FDD. It is not applied automatically because the modem
	// can be attached to TDD or another radio access type.
	//
	// Deprecated: populate Config.AccessNetworkInfo from lower-layer access data.
	DefaultAccessNetworkInfo = "3GPP-E-UTRAN-FDD"
)

// Config describes LTE IMS PDN overrides and transport hints used by VoLTE.
type Config struct {
	InterfaceName     string
	LocalIPv4         net.IP
	LocalIPv6         net.IP
	PCSCFIPs          []net.IP
	AccessNetworkInfo string
	APN               string
	PDNType           string
	ProfileIndex      uint8
	RequireVoPS       bool
}

// Info is the LTE access state consumed by IMS SIP and media transports.
type Info struct {
	InterfaceName     string
	LocalIPv4         net.IP
	LocalIPv6         net.IP
	PCSCFIPs          []net.IP
	AccessNetworkInfo string
	VoPSSupported     bool
	IMSPDNConnected   bool
	VoiceBearerReady  bool
}

// Route describes the local and remote IP pair usable on the IMS PDN.
type Route struct {
	LocalIP  net.IP
	RemoteIP net.IP
}

// Normalized trims text fields, fills LTE IMS defaults, and validates configured IP families.
func (cfg Config) Normalized() (Config, error) {
	cfg.InterfaceName = strings.TrimSpace(cfg.InterfaceName)
	cfg.AccessNetworkInfo = strings.TrimSpace(cfg.AccessNetworkInfo)
	cfg.APN = strings.TrimSpace(cfg.APN)
	if cfg.APN == "" {
		cfg.APN = DefaultAPN
	}
	cfg.PDNType = strings.ToLower(strings.TrimSpace(cfg.PDNType))
	if cfg.PDNType == "" {
		cfg.PDNType = DefaultPDNType
	}
	switch cfg.PDNType {
	case "ipv4", "ipv6", "ipv4v6":
	default:
		return Config{}, fmt.Errorf("normalizing LTE config: unsupported pdn type %q", cfg.PDNType)
	}
	cfg.LocalIPv4 = normalizeConfigIP(cfg.LocalIPv4)
	if len(cfg.LocalIPv4) != 0 && cfg.LocalIPv4.To4() == nil {
		return Config{}, errors.New("normalizing LTE config: local ipv4 must be an IPv4 address")
	}
	cfg.LocalIPv6 = normalizeConfigIP(cfg.LocalIPv6)
	if len(cfg.LocalIPv6) != 0 && cfg.LocalIPv6.To4() != nil {
		return Config{}, errors.New("normalizing LTE config: local ipv6 must be an IPv6 address")
	}
	cfg.PCSCFIPs = normalizeIPList(cfg.PCSCFIPs)
	return cfg, nil
}

// Clone returns an independent copy of Info, including all net.IP byte slices.
func (info Info) Clone() Info {
	info.LocalIPv4 = append(net.IP(nil), info.LocalIPv4...)
	info.LocalIPv6 = append(net.IP(nil), info.LocalIPv6...)
	info.PCSCFIPs = cloneIPs(info.PCSCFIPs)
	return info
}

// LocalIPForRemote chooses the local IMS PDN address matching the remote IP family.
func (info Info) LocalIPForRemote(remote net.IP) net.IP {
	if len(remote) != 0 {
		if remote.To4() != nil && len(info.LocalIPv4) != 0 {
			return append(net.IP(nil), info.LocalIPv4...)
		}
		if remote.To4() == nil && len(info.LocalIPv6) != 0 {
			return append(net.IP(nil), info.LocalIPv6...)
		}
		return nil
	}
	if pcscf := info.DefaultPCSCFIP(); len(pcscf) != 0 {
		return info.LocalIPForRemote(pcscf)
	}
	if len(info.LocalIPv6) != 0 {
		return append(net.IP(nil), info.LocalIPv6...)
	}
	return append(net.IP(nil), info.LocalIPv4...)
}

// RouteTo chooses a local IMS PDN address matching remote.
func (info Info) RouteTo(remote net.IP) (Route, bool) {
	local := info.LocalIPForRemote(remote)
	if len(local) == 0 {
		return Route{}, false
	}
	return Route{
		LocalIP:  local,
		RemoteIP: append(net.IP(nil), remote...),
	}, true
}

// RouteToPCSCF chooses the first P-CSCF with a matching local IMS PDN address.
func (info Info) RouteToPCSCF() (Route, bool) {
	for _, pcscf := range info.pcscfCandidateIPs() {
		route, ok := info.RouteTo(pcscf)
		if ok {
			return route, true
		}
	}
	return Route{}, false
}

// PCSCFCandidateCount reports how many P-CSCF addresses have a matching local
// IMS PDN address.
func (info Info) PCSCFCandidateCount() int {
	count := 0
	for _, pcscf := range info.pcscfCandidateIPs() {
		if _, ok := info.RouteTo(pcscf); ok {
			count++
		}
	}
	return count
}

// WithNextPCSCF rotates the P-CSCF list to the next address usable on this IMS
// PDN. The receiver is not modified.
func (info Info) WithNextPCSCF() (Info, bool) {
	candidates := info.pcscfCandidateIPs()
	current, ok := info.RouteToPCSCF()
	if !ok || info.PCSCFCandidateCount() < 2 {
		return info, false
	}
	currentIndex := slices.IndexFunc(candidates, current.RemoteIP.Equal)
	for offset := 1; offset < len(candidates); offset++ {
		next := (currentIndex + offset) % len(candidates)
		if _, ok := info.RouteTo(candidates[next]); !ok {
			continue
		}
		rotated := append(append(make([]net.IP, 0, len(candidates)), candidates[next:]...), candidates[:next]...)
		info.PCSCFIPs = cloneIPs(rotated)
		return info, true
	}
	return info, false
}

// PCSCFAddresses returns the configured or modem-provided P-CSCF addresses.
func (info Info) PCSCFAddresses() []net.IP {
	return cloneIPs(info.PCSCFIPs)
}

// DefaultPCSCFIP returns the first usable P-CSCF address.
func (info Info) DefaultPCSCFIP() net.IP {
	return firstPCSCFIP(info.pcscfCandidateIPs())
}

func (info Info) pcscfCandidateIPs() []net.IP {
	return uniqueIPs(info.PCSCFIPs)
}

func normalizeConfigIP(ip net.IP) net.IP {
	if len(ip) == 0 {
		return nil
	}
	parsed := net.ParseIP(strings.TrimSpace(ip.String()))
	if parsed == nil {
		return nil
	}
	return append(net.IP(nil), parsed...)
}

func normalizeIPList(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		ip = normalizeConfigIP(ip)
		if len(ip) == 0 || slices.ContainsFunc(out, ip.Equal) {
			continue
		}
		out = append(out, ip)
	}
	return out
}

func firstPCSCFIP(ips []net.IP) net.IP {
	if len(ips) == 0 {
		return nil
	}
	return append(net.IP(nil), ips[0]...)
}

func uniqueIPs(ips []net.IP) []net.IP {
	unique := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if len(ip) == 0 {
			continue
		}
		seen := false
		for _, existing := range unique {
			if existing.Equal(ip) {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, append(net.IP(nil), ip...))
		}
	}
	return unique
}

func cloneIPs(ips []net.IP) []net.IP {
	if len(ips) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		out = append(out, append(net.IP(nil), ip...))
	}
	return out
}
