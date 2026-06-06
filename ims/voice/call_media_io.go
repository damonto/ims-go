package voice

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
)

func (c *Call) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	transport, err := c.mediaTransport(callActionReadMedia)
	if err != nil {
		return nil, nil, err
	}
	return transport.ReadPacket(ctx)
}

func (c *Call) WritePacket(ctx context.Context, data []byte) error {
	c.mediaSendMu.Lock()
	defer c.mediaSendMu.Unlock()

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return errors.New("writing call media: call is closed")
	}
	if c.transport == nil {
		c.mu.Unlock()
		return errors.New("writing call media: media transport is not configured")
	}
	if holdHasLocal(c.hold) || localMediaSendBlocked(c.media.Direction) {
		c.mu.Unlock()
		return errors.New("writing call media: call is on hold")
	}
	transport := c.transport
	media := c.media
	c.mu.Unlock()
	wire, sent, ok, err := c.prepareOutgoingRTPPacket(data)
	if err != nil {
		return err
	}
	if err := transport.WritePacket(ctx, wire); err != nil {
		return err
	}
	if ok {
		c.saveRTPSendState(sent, media)
	}
	return nil
}

func (c *Call) ReadRTP(ctx context.Context) ([]byte, net.Addr, error) {
	return c.ReadPacket(ctx)
}

func (c *Call) WriteRTP(ctx context.Context, data []byte) error {
	return c.WritePacket(ctx, data)
}

func (c *Call) prepareOutgoingRTPPacket(data []byte) ([]byte, RTPPacket, bool, error) {
	packet, err := ParseRTPPacket(data)
	if err != nil {
		return data, RTPPacket{}, false, nil
	}
	c.mu.Lock()
	rtp := c.rtpSend
	if rtp.initialized {
		packet.SSRC = rtp.ssrc
		packet.SequenceNumber = rtp.nextSequence
		packet.Timestamp = rtp.nextTimestamp
	}
	c.mu.Unlock()
	if !rtp.initialized {
		return data, packet, true, nil
	}
	wire := rewriteRTPHeader(data, packet)
	return wire, packet, true, nil
}

func rewriteRTPHeader(data []byte, packet RTPPacket) []byte {
	wire := append([]byte(nil), data...)
	binary.BigEndian.PutUint16(wire[2:4], packet.SequenceNumber)
	binary.BigEndian.PutUint32(wire[4:8], packet.Timestamp)
	binary.BigEndian.PutUint32(wire[8:12], packet.SSRC)
	return wire
}

func (c *Call) saveRTPSendState(packet RTPPacket, media NegotiatedMedia) {
	c.mu.Lock()
	c.rtpSend = rtpSendState{
		initialized:   true,
		ssrc:          packet.SSRC,
		nextSequence:  packet.SequenceNumber + 1,
		nextTimestamp: packet.Timestamp + mediaFrameTicks(media),
	}
	c.mu.Unlock()
}

func (c *Call) ReadRTCP(ctx context.Context) ([]byte, net.Addr, error) {
	transport, err := c.mediaTransport(callActionReadRTCP)
	if err != nil {
		return nil, nil, err
	}
	if rtcp, ok := transport.(rtcpReader); ok {
		return rtcp.ReadRTCP(ctx)
	}
	return nil, nil, errors.New("reading call rtcp: media transport does not support rtcp")
}

func (c *Call) WriteRTCP(ctx context.Context, data []byte) error {
	transport, err := c.mediaTransport(callActionWriteRTCP)
	if err != nil {
		return err
	}
	if rtcp, ok := transport.(rtcpWriter); ok {
		return rtcp.WriteRTCP(ctx, data)
	}
	return errors.New("writing call rtcp: media transport does not support rtcp")
}
