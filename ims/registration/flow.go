package registration

import (
	"strings"

	"github.com/damonto/vowifi-go/ims/security"
	"github.com/damonto/vowifi-go/ims/sip"
)

type Flow struct {
	ContactHost       string
	RegisterPort      int
	MessagePort       int
	ServiceRoutes     []string
	SecurityClient    security.Param
	SecurityVerify    *security.Param
	SecurityServerRaw []string
}

func (f Flow) clone() Flow {
	f.ServiceRoutes = append([]string(nil), f.ServiceRoutes...)
	f.SecurityServerRaw = append([]string(nil), f.SecurityServerRaw...)
	if f.SecurityVerify != nil {
		verify := *f.SecurityVerify
		f.SecurityVerify = &verify
	}
	return f
}

func (f Flow) SecurityVerifyValue() string {
	if f.SecurityVerify == nil {
		return ""
	}
	if len(f.SecurityServerRaw) != 0 {
		return strings.Join(f.SecurityServerRaw, ",")
	}
	return f.SecurityVerify.String()
}

func (f Flow) RequestPolicy(userAgent, accessNetworkInfo string) sip.ClientRequestPolicy {
	return f.requestPolicy(f.ServiceRoutes, userAgent, accessNetworkInfo)
}

func (f Flow) DialogRequestPolicy(routes []string, userAgent, accessNetworkInfo string) sip.ClientRequestPolicy {
	if len(routes) == 0 {
		routes = f.ServiceRoutes
	}
	return f.requestPolicy(routes, userAgent, accessNetworkInfo)
}

func (f Flow) StrictDialogRequestPolicy(routes []string, userAgent, accessNetworkInfo string) sip.ClientRequestPolicy {
	return f.requestPolicy(routes, userAgent, accessNetworkInfo)
}

func (f Flow) requestPolicy(routes []string, userAgent, accessNetworkInfo string) sip.ClientRequestPolicy {
	verify := f.SecurityVerifyValue()
	return sip.ClientRequestPolicy{
		Routes:            append([]string(nil), routes...),
		UserAgent:         userAgent,
		AccessNetworkInfo: accessNetworkInfo,
		Security: sip.SecurityAgreement{
			Verify:   verify,
			Required: verify != "",
		},
	}
}
