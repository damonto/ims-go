package voice

import (
	"fmt"
	"strings"
)

const firstDynamicPayloadType = 96

type rtpPayloadMapping struct {
	encoding  string
	clockRate int
	channels  int
}

func remotePayloadMappings(description sdpOffer) map[int]rtpPayloadMapping {
	mappings := make(map[int]rtpPayloadMapping)
	for _, payloadType := range description.Payloads {
		if payloadType < firstDynamicPayloadType {
			continue
		}
		codec, ok := description.Codecs[payloadType]
		if !ok || codec.Name == "" {
			continue
		}
		mappings[payloadType] = rtpPayloadMapping{
			encoding:  strings.ToLower(string(codec.Name)),
			clockRate: codec.ClockRate,
			channels:  max(codec.Channels, 1),
		}
	}
	return mappings
}

func validateRemotePayloadMappings(previous map[int]rtpPayloadMapping, description sdpOffer) error {
	for payloadType, current := range remotePayloadMappings(description) {
		if existing, ok := previous[payloadType]; ok && existing != current {
			return fmt.Errorf(
				"payload type %d changed from %s/%d/%d to %s/%d/%d",
				payloadType,
				existing.encoding,
				existing.clockRate,
				existing.channels,
				current.encoding,
				current.clockRate,
				current.channels,
			)
		}
	}
	return nil
}

func mergeRemotePayloadMappings(previous map[int]rtpPayloadMapping, description sdpOffer) map[int]rtpPayloadMapping {
	if previous == nil {
		previous = make(map[int]rtpPayloadMapping)
	}
	for payloadType, mapping := range remotePayloadMappings(description) {
		previous[payloadType] = mapping
	}
	return previous
}

func (c *Call) acceptRemotePayloadMappings(description sdpOffer) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := validateRemotePayloadMappings(c.remotePayloads, description); err != nil {
		return err
	}
	c.remotePayloads = mergeRemotePayloadMappings(c.remotePayloads, description)
	return nil
}
