package ims

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var loadPrivateIMSConfig = sync.OnceValues(func() ([]byte, error) {
	return os.ReadFile(filepath.Join(os.Getenv("IMS_CARRIER_CONFIG_DIR"), "ims.json"))
})
var loadPrivateIMSProfiles = sync.OnceValues(func() (*CarrierProfiles, error) {
	data, err := loadPrivateIMSConfig()
	if err != nil {
		return nil, err
	}
	var profiles CarrierProfiles
	if err := profiles.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return &profiles, nil
})

func privateIMSConfig(t *testing.T) []byte {
	t.Helper()
	dir := os.Getenv("IMS_CARRIER_CONFIG_DIR")
	if dir == "" {
		t.Skip("private carrier catalog regression requires IMS_CARRIER_CONFIG_DIR")
	}
	data, err := loadPrivateIMSConfig()
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func privateIMSProfiles(t *testing.T) *CarrierProfiles {
	t.Helper()
	_ = privateIMSConfig(t)
	profiles, err := loadPrivateIMSProfiles()
	if err != nil {
		t.Fatal(err)
	}
	return profiles
}
