package imsclient

func defaultUserAgent() string {
	const (
		manufacturer   = "Google"
		model          = "Pixel 3XL"
		androidVersion = "12"
		build          = "SQ3A.220705.004"
	)

	return manufacturer + "_" + model + "Android" + androidVersion + build
}
