package transport

type transportAction uint8

const (
	transportActionDialTCP transportAction = iota
	transportActionListenSecureTCP
	transportActionDialSecureUDP
	transportActionListenSecureUDP
)

func (a transportAction) String() string {
	switch a {
	case transportActionDialTCP:
		return "dialing tcp transport"
	case transportActionListenSecureTCP:
		return "listening secure tcp transport"
	case transportActionDialSecureUDP:
		return "dialing secure udp transport"
	case transportActionListenSecureUDP:
		return "listening secure udp transport"
	default:
		return "using transport"
	}
}
