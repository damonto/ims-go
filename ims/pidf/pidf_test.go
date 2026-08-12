package pidf

import (
	"bytes"
	"encoding/xml"
	"strings"
	"testing"
)

func TestBuildProducesValidXML(t *testing.T) {
	tests := []struct {
		name        string
		entity      string
		country     string
		wantEntity  string
		wantCountry string
	}{
		{
			name:        "escapes markup",
			entity:      `sip:a&"b@example.com`,
			country:     "u<s",
			wantEntity:  `sip:a&"b@example.com`,
			wantCountry: "U<S",
		},
		{
			name:        "replaces invalid control characters",
			entity:      "sip:a\x01b@example.com",
			country:     "u\x01s",
			wantEntity:  "sip:a\ufffdb@example.com",
			wantCountry: "U\ufffdS",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := Build(tt.entity, tt.country)
			if bytes.ContainsRune(data, '\x01') {
				t.Fatalf("Build() contains an invalid XML control character: %q", data)
			}
			var got struct {
				Entity  string `xml:"entity,attr"`
				Country string `xml:"tuple>status>geopriv>location-info>civicAddress>country"`
			}
			if err := xml.Unmarshal(data, &got); err != nil {
				t.Fatalf("xml.Unmarshal(Build()) error = %v", err)
			}
			if got.Entity != tt.wantEntity {
				t.Errorf("entity = %q, want %q", got.Entity, tt.wantEntity)
			}
			if got.Country != tt.wantCountry {
				t.Errorf("country = %q, want %q", got.Country, tt.wantCountry)
			}
			if !strings.HasPrefix(string(data), xml.Header) {
				t.Errorf("Build() does not start with the XML header: %q", data)
			}
		})
	}
}
