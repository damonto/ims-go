package vowifi

import "strings"

const (
	defaultUserAgentManufacturer   = "Google"
	defaultUserAgentModel          = "Pixel 3XL"
	defaultUserAgentAndroidVersion = "12"
	defaultUserAgentBuild          = "SQ3A.220705.004"
	defaultUserAgentDeviceType     = "Smartphone"
)

func defaultUserAgent() string {
	return defaultUserAgentManufacturer + "_" + defaultUserAgentModel + "Android" + defaultUserAgentAndroidVersion + defaultUserAgentBuild
}

func renderWFCUserAgent(template string, cfg Config, profile wfcProfile) string {
	replacer := strings.NewReplacer(
		"#MANUFACTURE#", defaultUserAgentManufacturer,
		"#MANUFACTURER#", defaultUserAgentManufacturer,
		"#MODEL#", defaultUserAgentModel,
		"#AV#", defaultUserAgentAndroidVersion,
		"#BUILD#", defaultUserAgentBuild,
		"#TYPE#", defaultUserAgentDeviceType,
		"#MCCMNC#", strings.TrimSpace(profile.MCC)+strings.TrimSpace(profile.MNC),
		"#IMEISV#", imeisvFromIMEI(cfg.IMEI),
		"#OPERATOR#", strings.TrimSpace(profile.WFCSPN),
		"#HWSKU#", defaultUserAgentModel,
	)
	return replacer.Replace(template)
}

func imeisvFromIMEI(imei string) string {
	imei = strings.TrimSpace(imei)
	if len(imei) >= 16 {
		return imei[:16]
	}
	if len(imei) >= 14 {
		return imei[:14] + "00"
	}
	return imei
}
