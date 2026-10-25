package ims

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// CarrierProfiles contains application-supplied IMS profile JSON. Decode before
// sharing a value with clients. JSON and binary encodings use the same JSON array.
type CarrierProfiles struct{ data []byte }

var (
	_ json.Marshaler             = CarrierProfiles{}
	_ json.Unmarshaler           = (*CarrierProfiles)(nil)
	_ encoding.BinaryMarshaler   = CarrierProfiles{}
	_ encoding.BinaryUnmarshaler = (*CarrierProfiles)(nil)
)

// MarshalJSON returns an independent copy of the profile array.
func (c CarrierProfiles) MarshalJSON() ([]byte, error) {
	if len(c.data) == 0 {
		return []byte("[]"), nil
	}
	return bytes.Clone(c.data), nil
}

// UnmarshalJSON validates an array and replaces profiles only on success.
func (c *CarrierProfiles) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || data[0] != '[' {
		return errors.New("decode IMS profiles: expected profile array")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var profiles []imsProfile
	if err := decoder.Decode(&profiles); err != nil {
		return fmt.Errorf("decode IMS profiles: %w", err)
	}
	if err := decoder.Decode(new(json.RawMessage)); err != io.EOF {
		return errors.New("decode IMS profiles: unexpected trailing data")
	}
	c.data = bytes.Clone(data)
	return nil
}

// MarshalBinary returns profile JSON, without introducing a second wire format.
func (c CarrierProfiles) MarshalBinary() ([]byte, error) { return c.MarshalJSON() }

// UnmarshalBinary decodes profile JSON.
func (c *CarrierProfiles) UnmarshalBinary(data []byte) error { return c.UnmarshalJSON(data) }

func (c *CarrierProfiles) json() []byte {
	if c == nil || len(c.data) == 0 {
		return []byte("[]")
	}
	return c.data
}
