package wfcsetup

import (
	"context"
	"strings"
)

const canadaWebViewClientName = "WiFiCallingWebViewController"
const videotronCanadaURL = "https://fe.videotron.com/a/few/frg/angular-app-v-vowifi-911/latest/index.html#/login"

type canadaPortal struct {
	Carrier    string
	SIM        simMatch
	URL        string
	ClientName string
}

var canadaPortals = []canadaPortal{
	{Carrier: "Virgin Plus", SIM: simMatch{MCC: "302", MNC: "610", GID1: "3E"}, URL: "http://mobilebrowser.bwanet.ca/GlobalRedirector/Redirector?application=AndroidWifiCalling&brand=virgin", ClientName: canadaWebViewClientName},
	{Carrier: "Shaw Mobile", SIM: simMatch{MCC: "302", MNC: "490", GID1: "53"}, URL: "https://vowifi.authenticateme.ca", ClientName: canadaWebViewClientName},
	{Carrier: "Videotron", SIM: simMatch{MCC: "302", MNC: "500", GID1: "53"}, URL: videotronCanadaURL},
	{Carrier: "Fizz", SIM: simMatch{MCC: "302", MNC: "500", GID1: "55"}, URL: "https://vowifi.authenticateme.ca", ClientName: canadaWebViewClientName},
	{Carrier: "Rogers", SIM: simMatch{MCC: "302", MNC: "720", GID1: "A4"}, URL: "https://www.rogers.com/AndroidWiFi/", ClientName: canadaWebViewClientName},
	{Carrier: "Chatr", SIM: simMatch{MCC: "302", MNC: "720", GID1: "D2"}, URL: "https://www.rogers.com/AndroidWiFi/", ClientName: canadaWebViewClientName},
	{Carrier: "Fido", SIM: simMatch{MCC: "302", MNC: "370", GID1: "DD"}, URL: "https://www.fido.ca/AndroidWiFi/", ClientName: canadaWebViewClientName},
	{Carrier: "Bell", SIM: simMatch{MCC: "302", MNC: "610"}, URL: "http://mobilebrowser.bwanet.ca/GlobalRedirector/Redirector?application=AndroidWifiCalling&brand=bell", ClientName: canadaWebViewClientName},
	{Carrier: "Bell", SIM: simMatch{MCC: "302", MNC: "630"}, URL: "http://mobilebrowser.bwanet.ca/GlobalRedirector/Redirector?application=AndroidWifiCalling&brand=bell", ClientName: canadaWebViewClientName},
	{Carrier: "Bell", SIM: simMatch{MCC: "302", MNC: "640"}, URL: "http://mobilebrowser.bwanet.ca/GlobalRedirector/Redirector?application=AndroidWifiCalling&brand=bell", ClientName: canadaWebViewClientName},
	{Carrier: "Freedom Mobile", SIM: simMatch{MCC: "302", MNC: "490"}, URL: "https://vowifi.authenticateme.ca", ClientName: canadaWebViewClientName},
	{Carrier: "Rogers", SIM: simMatch{MCC: "302", MNC: "720"}, URL: "https://www.rogers.com/AndroidWiFi/", ClientName: canadaWebViewClientName},
	{Carrier: "Fido", SIM: simMatch{MCC: "302", MNC: "370"}, URL: "https://www.fido.ca/AndroidWiFi/", ClientName: canadaWebViewClientName},
	{Carrier: "Chatr", SIM: simMatch{MCC: "302", MNC: "320"}, URL: "https://www.rogers.com/AndroidWiFi/", ClientName: canadaWebViewClientName},
}

type canadaFlow struct {
	req    Request
	portal canadaPortal
}

func newCanadaFlow(req Request) (flow, bool, error) {
	portal, ok := canadaPortalForCard(req.Card)
	if !ok {
		return nil, false, nil
	}
	return canadaFlow{req: req, portal: portal}, true, nil
}

func (f canadaFlow) Check(context.Context) (Result, error) {
	result := Result{
		Scheme:   SchemeCanada,
		Carrier:  f.portal.Carrier,
		Action:   ActionOpenWebsheet,
		Entitled: true,
		Websheet: &Websheet{
			Kind:       WebsheetKindEmergencyAddress,
			URL:        f.portal.URL,
			Title:      "Wi-Fi Calling",
			ClientName: f.portal.ClientName,
		},
	}
	return result, nil
}

func (f canadaFlow) E911UpdateSupport(context.Context) (E911UpdateSupport, error) {
	return E911UpdateSupport{
		Supported: true,
		BuiltIn:   true,
		Scheme:    SchemeCanada,
		Carrier:   f.portal.Carrier,
		Reason:    "canada android flow exposes an emergency address web portal",
	}, nil
}

func canadaPortalForCard(card Card) (canadaPortal, bool) {
	for _, portal := range canadaPortals {
		if matchCanadaPortal(card, portal) {
			return portal, true
		}
	}
	return canadaPortal{}, false
}

func matchCanadaPortal(card Card, portal canadaPortal) bool {
	if strings.TrimSpace(portal.SIM.GID1) == "" && strings.TrimSpace(card.GID1()) != "" {
		return false
	}
	return matchSIM(card, portal.SIM)
}
