package ims

func withTestIPSecAlgorithms(cfg Config) Config {
	cfg.IMS = withTestIMSIPSecAlgorithms(cfg.IMS)
	return cfg
}

func withTestIMSIPSecAlgorithms(cfg ServiceConfig) ServiceConfig {
	if len(cfg.IPSecIntegrityAlgorithms) == 0 {
		cfg.IPSecIntegrityAlgorithms = []string{"hmac-sha-1-96"}
	}
	if len(cfg.IPSecEncryptionAlgorithms) == 0 {
		cfg.IPSecEncryptionAlgorithms = []string{"null", "aes-cbc"}
	}
	if len(cfg.IPSecModes) == 0 {
		cfg.IPSecModes = []string{"trans", "UDP-enc-tun"}
	}
	return cfg
}
