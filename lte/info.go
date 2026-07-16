package lte

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
)

const (
	// DefaultAPN is the IMS APN normally requested for VoLTE.
	DefaultAPN = "ims"
	// DefaultPDNType requests dual-stack IMS PDN when the modem and network support it.
	DefaultPDNType = "ipv4v6"

	accessTypeEUTRANFDD = "3GPP-E-UTRAN-FDD"
	accessTypeEUTRANTDD = "3GPP-E-UTRAN-TDD"
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
	VoPSKnown         bool
	VoPSSupported     bool
	IMSPDNConnected   bool
	// VoiceBearerReady is reserved for a lower layer that can explicitly
	// report the dedicated voice bearer. IMS PDN readiness alone must not set it.
	VoiceBearerReady bool
}

// Route describes the local and remote IP pair usable on the IMS PDN.
type Route struct {
	LocalIP  net.IP
	RemoteIP net.IP
}

// Normalized trims text fields, fills LTE IMS defaults, and validates configured IP families.
func (cfg Config) Normalized() (Config, error) {
	cfg.InterfaceName = strings.TrimSpace(cfg.InterfaceName)
	var err error
	cfg.AccessNetworkInfo, err = NormalizeAccessNetworkInfo(cfg.AccessNetworkInfo)
	if err != nil {
		return Config{}, fmt.Errorf("normalizing LTE config: %w", err)
	}
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
	cfg.LocalIPv4, err = normalizeConfigIP(cfg.LocalIPv4)
	if err != nil {
		return Config{}, fmt.Errorf("normalizing LTE config: local ipv4: %w", err)
	}
	if len(cfg.LocalIPv4) != 0 && cfg.LocalIPv4.To4() == nil {
		return Config{}, errors.New("normalizing LTE config: local ipv4 must be an IPv4 address")
	}
	cfg.LocalIPv6, err = normalizeConfigIP(cfg.LocalIPv6)
	if err != nil {
		return Config{}, fmt.Errorf("normalizing LTE config: local ipv6: %w", err)
	}
	if len(cfg.LocalIPv6) != 0 && cfg.LocalIPv6.To4() != nil {
		return Config{}, errors.New("normalizing LTE config: local ipv6 must be an IPv6 address")
	}
	if cfg.PDNType == "ipv4" && len(cfg.LocalIPv6) != 0 {
		return Config{}, errors.New("normalizing LTE config: local ipv6 requires ipv6 or ipv4v6 pdn type")
	}
	if cfg.PDNType == "ipv6" && len(cfg.LocalIPv4) != 0 {
		return Config{}, errors.New("normalizing LTE config: local ipv4 requires ipv4 or ipv4v6 pdn type")
	}
	cfg.PCSCFIPs, err = normalizeIPList(cfg.PCSCFIPs)
	if err != nil {
		return Config{}, fmt.Errorf("normalizing LTE config: p-cscf addresses: %w", err)
	}
	return cfg, nil
}

// NormalizeAccessNetworkInfo validates and canonicalizes an E-UTRAN
// P-Access-Network-Info value supplied by the UE.
func NormalizeAccessNetworkInfo(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	parts := strings.Split(value, ";")
	accessType := strings.TrimSpace(parts[0])
	switch {
	case strings.EqualFold(accessType, accessTypeEUTRANFDD):
		accessType = accessTypeEUTRANFDD
	case strings.EqualFold(accessType, accessTypeEUTRANTDD):
		accessType = accessTypeEUTRANTDD
	default:
		return "", fmt.Errorf("access network info: unsupported VoLTE access type %q", accessType)
	}

	cellID := ""
	normalized := []string{accessType}
	for _, raw := range parts[1:] {
		param := strings.TrimSpace(raw)
		if param == "" {
			return "", errors.New("access network info: empty parameter")
		}
		name, paramValue, hasValue := strings.Cut(param, "=")
		name = strings.TrimSpace(name)
		if strings.EqualFold(name, "network-provided") {
			return "", errors.New("access network info: network-provided is reserved for the network")
		}
		if !strings.EqualFold(name, "utran-cell-id-3gpp") {
			normalized = append(normalized, param)
			continue
		}
		if !hasValue || cellID != "" {
			return "", errors.New("access network info: utran-cell-id-3gpp must occur once with a value")
		}
		parsedCellID, err := parseAccessInfoValue(paramValue)
		if err != nil {
			return "", fmt.Errorf("access network info: utran-cell-id-3gpp: %w", err)
		}
		cellID = parsedCellID
		if err := validateEUTRANCellID(cellID); err != nil {
			return "", err
		}
		normalized = append(normalized, "utran-cell-id-3gpp="+strings.ToUpper(cellID))
	}
	if cellID == "" {
		return "", errors.New("access network info: utran-cell-id-3gpp is required for E-UTRAN")
	}
	return strings.Join(normalized, ";"), nil
}

func parseAccessInfoValue(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("value is empty")
	}
	if value[0] != '"' {
		if strings.ContainsAny(value, "\"\r\n") {
			return "", errors.New("value is not a valid token")
		}
		return value, nil
	}
	if len(value) < 2 || value[len(value)-1] != '"' {
		return "", errors.New("quoted string is unterminated")
	}

	payload := value[1 : len(value)-1]
	var parsed strings.Builder
	parsed.Grow(len(payload))
	for i := 0; i < len(payload); i++ {
		switch payload[i] {
		case '\\':
			if i+1 == len(payload) {
				return "", errors.New("quoted pair is unterminated")
			}
			i++
			if payload[i] == '\r' || payload[i] == '\n' {
				return "", errors.New("quoted pair contains CR or LF")
			}
			parsed.WriteByte(payload[i])
		case '"':
			return "", errors.New("quoted string contains an unescaped quote")
		case '\r', '\n':
			return "", errors.New("quoted string contains CR or LF")
		default:
			parsed.WriteByte(payload[i])
		}
	}
	return parsed.String(), nil
}

func validateEUTRANCellID(value string) error {
	if len(value) != 16 && len(value) != 17 {
		return errors.New("access network info: utran-cell-id-3gpp must contain 5 or 6 PLMN digits followed by 11 hexadecimal digits")
	}
	plmnLength := len(value) - 11
	for _, c := range value[:plmnLength] {
		if c < '0' || c > '9' {
			return errors.New("access network info: utran-cell-id-3gpp PLMN must be decimal")
		}
	}
	for _, c := range value[plmnLength:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return errors.New("access network info: utran-cell-id-3gpp TAC and cell identity must be hexadecimal")
		}
	}
	return nil
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
		addr, ok := netip.AddrFromSlice(remote)
		if !ok {
			return nil
		}
		if addr.Unmap().Is4() && ipMatchesFamily(info.LocalIPv4, true) {
			return append(net.IP(nil), info.LocalIPv4...)
		}
		if !addr.Unmap().Is4() && ipMatchesFamily(info.LocalIPv6, false) {
			return append(net.IP(nil), info.LocalIPv6...)
		}
		return nil
	}
	if pcscf := info.DefaultPCSCFIP(); len(pcscf) != 0 {
		return info.LocalIPForRemote(pcscf)
	}
	if ipMatchesFamily(info.LocalIPv6, false) {
		return append(net.IP(nil), info.LocalIPv6...)
	}
	if ipMatchesFamily(info.LocalIPv4, true) {
		return append(net.IP(nil), info.LocalIPv4...)
	}
	return nil
}

// RouteTo chooses a local IMS PDN address matching remote.
func (info Info) RouteTo(remote net.IP) (Route, bool) {
	if _, ok := netip.AddrFromSlice(remote); !ok {
		return Route{}, false
	}
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

// WithNextPCSCF returns a copy with the current P-CSCF removed, making the next
// usable address the preferred candidate. The receiver is not modified.
func (info Info) WithNextPCSCF() (Info, bool) {
	candidates := info.pcscfCandidateIPs()
	current, ok := info.RouteToPCSCF()
	if !ok || info.PCSCFCandidateCount() < 2 {
		return info, false
	}
	currentIndex := slices.IndexFunc(candidates, current.RemoteIP.Equal)
	remaining := make([]net.IP, 0, len(candidates)-1)
	for offset := 1; offset < len(candidates); offset++ {
		next := (currentIndex + offset) % len(candidates)
		remaining = append(remaining, candidates[next])
	}
	info.PCSCFIPs = cloneIPs(remaining)
	_, ok = info.RouteToPCSCF()
	return info, ok
}

// PCSCFAddresses returns the configured or modem-provided P-CSCF addresses.
func (info Info) PCSCFAddresses() []net.IP {
	return cloneIPs(info.PCSCFIPs)
}

// DefaultPCSCFIP returns the first usable P-CSCF address.
func (info Info) DefaultPCSCFIP() net.IP {
	route, ok := info.RouteToPCSCF()
	if !ok {
		return nil
	}
	return append(net.IP(nil), route.RemoteIP...)
}

func (info Info) pcscfCandidateIPs() []net.IP {
	candidates := uniqueIPs(info.PCSCFIPs)
	if !ipMatchesFamily(info.LocalIPv4, true) || !ipMatchesFamily(info.LocalIPv6, false) {
		return candidates
	}
	// IR.92 requires IPv6 P-CSCF preference when the IMS PDN assigned both
	// address families. Stable sorting preserves network priority within each
	// address family.
	slices.SortStableFunc(candidates, func(a, b net.IP) int {
		aIPv4 := a.To4() != nil
		bIPv4 := b.To4() != nil
		switch {
		case !aIPv4 && bIPv4:
			return -1
		case aIPv4 && !bIPv4:
			return 1
		default:
			return 0
		}
	})
	return candidates
}

func normalizeConfigIP(ip net.IP) (net.IP, error) {
	if len(ip) == 0 {
		return nil, nil
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, errors.New("invalid IP address")
	}
	return net.IP(addr.Unmap().AsSlice()), nil
}

func normalizeIPList(ips []net.IP) ([]net.IP, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	out := make([]net.IP, 0, len(ips))
	for i, ip := range ips {
		var err error
		ip, err = normalizeConfigIP(ip)
		if err != nil {
			return nil, fmt.Errorf("address %d: %w", i, err)
		}
		if len(ip) == 0 {
			return nil, fmt.Errorf("address %d is empty", i)
		}
		if slices.ContainsFunc(out, ip.Equal) {
			continue
		}
		out = append(out, ip)
	}
	return out, nil
}

func uniqueIPs(ips []net.IP) []net.IP {
	unique := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		ip = net.IP(addr.Unmap().AsSlice())
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

func ipMatchesFamily(ip net.IP, ipv4 bool) bool {
	addr, ok := netip.AddrFromSlice(ip)
	return ok && addr.Unmap().Is4() == ipv4
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
