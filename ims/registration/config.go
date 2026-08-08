package registration

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/damonto/ims-go/ims/pidf"
	"github.com/damonto/ims-go/ims/security"
)

type clientIdentity struct {
	realm           string
	privateIdentity string
	publicIdentity  string
}

const (
	imeiDigitCount = 15
	imeiTACEnd     = 8
	imeiSNREnd     = 14
)

func validIMEI(imei string) bool {
	return len(imei) == imeiDigitCount && strings.IndexFunc(imei, func(r rune) bool {
		return r < '0' || r > '9'
	}) == -1
}

// 3GPP TS 23.003 section 13.8 excludes the IMEI check digit and appends a zero spare digit.
func imeiURN(imei string) string {
	return "urn:gsma:imei:" + imei[:imeiTACEnd] + "-" + imei[imeiTACEnd:imeiSNREnd] + "-0"
}

func normalizedPLMNDigits(card Card) (string, string, error) {
	mcc := strings.TrimSpace(card.MCC())
	if len(mcc) != 3 {
		return "", "", fmt.Errorf("mcc %q must be 3 digits", mcc)
	}

	mnc := strings.TrimSpace(card.MNC())
	switch len(mnc) {
	case 2:
		mnc = "0" + mnc
	case 3:
	default:
		return "", "", fmt.Errorf("mnc %q must be 2 or 3 digits", mnc)
	}
	return mcc, mnc, nil
}

func resolveIdentity(cfg Config, card Card) (clientIdentity, error) {
	identity := clientIdentity{
		realm:           strings.TrimSpace(cfg.HomeDomain),
		privateIdentity: strings.TrimSpace(cfg.PrivateIdentity),
		publicIdentity:  strings.TrimSpace(cfg.PublicIdentity),
	}
	if idp, ok := card.(IdentityProvider); ok {
		if identity.realm == "" {
			identity.realm = strings.TrimSpace(idp.HomeDomain())
		}
		if identity.privateIdentity == "" {
			identity.privateIdentity = strings.TrimSpace(idp.PrivateIdentity())
		}
		if identity.publicIdentity == "" {
			identity.publicIdentity = strings.TrimSpace(idp.PublicIdentity())
		}
	}
	if identity.realm == "" {
		mcc, mnc, err := normalizedPLMNDigits(card)
		if err != nil {
			return clientIdentity{}, err
		}
		identity.realm = fmt.Sprintf("ims.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
	}
	if identity.privateIdentity == "" {
		identity.privateIdentity = fmt.Sprintf("%s@%s", card.IMSI(), identity.realm)
	}
	if identity.publicIdentity == "" {
		identity.publicIdentity = "sip:" + identity.privateIdentity
	}
	return identity, nil
}

func resolveLocalAddr(addr net.Addr) (string, int, error) {
	if addr == nil {
		return "", 0, errors.New("session has no local address")
	}
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return "", 0, fmt.Errorf("parsing local address %q: %w", addr.String(), err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("parsing local port %q: %w", portStr, err)
	}
	return sanitizeHost(host), port, nil
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.PrivateIdentity = strings.TrimSpace(cfg.PrivateIdentity)
	cfg.PublicIdentity = strings.TrimSpace(cfg.PublicIdentity)
	cfg.HomeDomain = strings.TrimSpace(cfg.HomeDomain)
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	cfg.AccessNetworkInfo = strings.TrimSpace(cfg.AccessNetworkInfo)
	cfg.WLANNodeID = strings.TrimSpace(cfg.WLANNodeID)
	cfg.IMEI = strings.TrimSpace(cfg.IMEI)
	cfg.AuthAlgorithm = strings.TrimSpace(cfg.AuthAlgorithm)
	if cfg.IMEI != "" && !validIMEI(cfg.IMEI) {
		return Config{}, errors.New("normalizing registration config: imei must contain exactly 15 decimal digits")
	}
	if cfg.RegistrationGroup == nil {
		if cfg.RegistrationID != 0 || cfg.RegistrationPreference != 0 {
			return Config{}, errors.New("normalizing registration config: registration group is required for multiple registration settings")
		}
	} else {
		if cfg.RegistrationID == 0 {
			return Config{}, errors.New("normalizing registration config: registration id must be greater than zero")
		}
		if cfg.RegistrationPreference < 1 || cfg.RegistrationPreference > 1000 {
			return Config{}, errors.New("normalizing registration config: registration preference must be between 1 and 1000")
		}
		if cfg.IMEI == "" {
			return Config{}, errors.New("normalizing registration config: imei is required for multiple registration")
		}
	}
	var err error
	cfg.IPSecIntegrityAlgorithms, err = security.NormalizeIPSecIntegrityAlgorithms(cfg.IPSecIntegrityAlgorithms)
	if err != nil {
		return Config{}, fmt.Errorf("normalizing registration config: %w", err)
	}
	cfg.IPSecEncryptionAlgorithms, err = security.NormalizeIPSecEncryptionAlgorithms(cfg.IPSecEncryptionAlgorithms)
	if err != nil {
		return Config{}, fmt.Errorf("normalizing registration config: %w", err)
	}
	cfg.IPSecModes, err = security.NormalizeIPSecModes(cfg.IPSecModes)
	if err != nil {
		return Config{}, fmt.Errorf("normalizing registration config: %w", err)
	}
	if !hasCompatibleIPSecAlgorithms(cfg.IPSecIntegrityAlgorithms, cfg.IPSecEncryptionAlgorithms) {
		return Config{}, errors.New("normalizing registration config: IPsec algorithm sets have no compatible pair")
	}
	if cfg.AuthAlgorithm == "" {
		cfg.AuthAlgorithm = security.AlgorithmAKAv1MD5
	} else {
		algorithm, ok := security.NormalizeAKAAlgorithm(cfg.AuthAlgorithm)
		if !ok {
			return Config{}, fmt.Errorf("normalizing registration config: unsupported AKA algorithm %q", cfg.AuthAlgorithm)
		}
		if algorithm == security.AlgorithmAKAv2SHA256 {
			return Config{}, errors.New("normalizing registration config: AKAv2-SHA-256 requires TLS SIP transport")
		}
		cfg.AuthAlgorithm = algorithm
	}
	cfg.GeolocationPIDFRegister = pidf.NormalizeTypes(cfg.GeolocationPIDFRegister)
	cfg.GeolocationCountry = strings.ToUpper(strings.TrimSpace(cfg.GeolocationCountry))
	if len(cfg.GeolocationPIDFRegister) > 0 && cfg.GeolocationCountry == "" {
		cfg.GeolocationCountry = "US"
	}
	if cfg.GeolocationCountry != "" && len(cfg.GeolocationCountry) != 2 {
		return Config{}, errors.New("normalizing registration config: geolocation country must be two letters")
	}
	if cfg.RegisterExpires == 0 {
		cfg.RegisterExpires = defaultIMSExpires
	}
	return cfg, nil
}

func accessNetworkInfo(cfg Config) string {
	value := strings.TrimSpace(cfg.AccessNetworkInfo)
	nodeID := normalizeWLANNodeID(cfg.WLANNodeID)
	if value == "" {
		if nodeID == "" {
			return ""
		}
		return "IEEE-802.11;i-wlan-node-id=" + nodeID
	}
	if !isWLANAccessNetwork(value) || wlanNodeIDParameterPresent(value) || nodeID == "" {
		return value
	}
	return value + ";i-wlan-node-id=" + nodeID
}

func isWLANAccessNetwork(value string) bool {
	accessType, _, _ := strings.Cut(value, ";")
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(accessType)), "ieee-802.11")
}

func wlanNodeIDParameterPresent(value string) bool {
	for _, parameter := range strings.Split(value, ";")[1:] {
		name, _, _ := strings.Cut(parameter, "=")
		if strings.EqualFold(strings.TrimSpace(name), "i-wlan-node-id") {
			return true
		}
	}
	return false
}

func normalizeWLANNodeID(nodeID string) string {
	nodeID = strings.ToLower(strings.TrimSpace(nodeID))
	nodeID = strings.ReplaceAll(nodeID, ":", "")
	nodeID = strings.ReplaceAll(nodeID, "-", "")
	nodeID = strings.ReplaceAll(nodeID, ".", "")
	return nodeID
}

func sanitizeHost(host string) string {
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	if host == "" || host == "::" || host == "0.0.0.0" {
		return "127.0.0.1"
	}
	return host
}
