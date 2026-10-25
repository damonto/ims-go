package ims

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestCarrierProfilesCodecs(t *testing.T) {
	var profiles CarrierProfiles
	zero, err := json.Marshal(profiles)
	if err != nil || string(zero) != "[]" {
		t.Fatalf("zero = %s, %v", zero, err)
	}
	data := []byte(`[{"mcc":"001","mnc":"01","epdg":"one.example"}]`)
	if err := json.Unmarshal(data, &profiles); err != nil {
		t.Fatal(err)
	}
	clear(data)
	original, err := profiles.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := profiles.MarshalJSON()
	if err != nil || !bytes.Equal(original, encoded) {
		t.Fatalf("JSON = %s, %v", encoded, err)
	}
	clear(encoded)
	var roundtrip CarrierProfiles
	if err := roundtrip.UnmarshalBinary(original); err != nil {
		t.Fatal(err)
	}
	found, ok, err := parseIMSProfile(roundtrip.json(), plmnWFCCard{mcc: "001", mnc: "01", mncLength: 2})
	if err != nil || !ok || found.EPDG != "one.example" {
		t.Fatalf("profile = %+v, %v, %v", found, ok, err)
	}
	for _, invalid := range []string{"", "null", "{}", "[] []", `[{"unknown":1}]`, "[[["} {
		if err := profiles.UnmarshalBinary([]byte(invalid)); err == nil {
			t.Errorf("accepted %q", invalid)
		}
		got, err := profiles.MarshalBinary()
		if err != nil || !bytes.Equal(got, original) {
			t.Fatalf("invalid decode changed config: %s, %v", got, err)
		}
	}
	clear(original)
	found, ok, err = parseIMSProfile(roundtrip.json(), plmnWFCCard{mcc: "001", mnc: "01", mncLength: 2})
	if err != nil || !ok || found.EPDG != "one.example" {
		t.Fatalf("aliased input: %+v, %v, %v", found, ok, err)
	}
}
