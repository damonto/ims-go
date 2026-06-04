package registration

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/damonto/vowifi-go/ims/pidf"
	"github.com/damonto/vowifi-go/ims/security"
)

type clientIdentity struct {
	realm           string
	privateIdentity string
	publicIdentity  string
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
	if value := strings.TrimSpace(cfg.AccessNetworkInfo); value != "" {
		return value
	}
	if nodeID := strings.TrimSpace(cfg.WLANNodeID); nodeID != "" {
		return "IEEE-802.11;i-wlan-node-id=" + normalizeWLANNodeID(nodeID)
	}
	return ""
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
