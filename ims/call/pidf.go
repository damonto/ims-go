package call

import (
	"bytes"
	"encoding/xml"
	"strings"
)

func buildPIDF(entity string, country string) []byte {
	entity = strings.TrimSpace(entity)
	country = strings.ToUpper(strings.TrimSpace(country))
	if country == "" {
		country = "US"
	}

	var b bytes.Buffer
	b.WriteString(xml.Header)
	b.WriteString(`<presence xmlns="urn:ietf:params:xml:ns:pidf" entity="`)
	escapeXML(&b, entity)
	b.WriteString(`">`)
	b.WriteString(`<tuple id="location">`)
	b.WriteString(`<status>`)
	b.WriteString(`<geopriv xmlns="urn:ietf:params:xml:ns:pidf:geopriv10">`)
	b.WriteString(`<location-info>`)
	b.WriteString(`<civicAddress xmlns="urn:ietf:params:xml:ns:pidf:geopriv10:civicAddr">`)
	b.WriteString(`<country>`)
	escapeXML(&b, country)
	b.WriteString(`</country>`)
	b.WriteString(`</civicAddress>`)
	b.WriteString(`</location-info>`)
	b.WriteString(`<usage-rules>`)
	b.WriteString(`<retransmission-allowed>false</retransmission-allowed>`)
	b.WriteString(`</usage-rules>`)
	b.WriteString(`</geopriv>`)
	b.WriteString(`</status>`)
	b.WriteString(`</tuple>`)
	b.WriteString(`</presence>`)
	return b.Bytes()
}

func escapeXML(b *bytes.Buffer, text string) {
	_ = xml.EscapeText(b, []byte(text))
}
