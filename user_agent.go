package vowifi

import "strings"

func renderWFCUserAgent(template string, cfg Config, profile wfcProfile) string {
	terminal := cfg.Terminal.trimmed()
	replacer := strings.NewReplacer(
		"#MANUFACTURE#", terminal.Vendor,
		"#MANUFACTURER#", terminal.Vendor,
		"#MODEL#", terminal.Model,
		"#AV#", terminal.SoftwareVersion,
		"#BUILD#", terminal.Build,
		"#TYPE#", terminal.Type,
		"#MCCMNC#", strings.TrimSpace(profile.MCC)+strings.TrimSpace(profile.MNC),
		"#IMEISV#", imeisvFromIMEI(terminal.ID),
		"#OPERATOR#", strings.TrimSpace(profile.WFCSPN),
		"#HWSKU#", terminal.HardwareSKU,
	)
	return replacer.Replace(template)
}

func (terminal TerminalInfo) trimmed() TerminalInfo {
	terminal.ID = strings.TrimSpace(terminal.ID)
	terminal.Vendor = strings.TrimSpace(terminal.Vendor)
	terminal.Model = strings.TrimSpace(terminal.Model)
	terminal.SoftwareVersion = strings.TrimSpace(terminal.SoftwareVersion)
	terminal.Build = strings.TrimSpace(terminal.Build)
	terminal.Type = strings.TrimSpace(terminal.Type)
	terminal.HardwareSKU = strings.TrimSpace(terminal.HardwareSKU)
	return terminal
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
