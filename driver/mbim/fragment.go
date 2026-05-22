package mbim

import (
	"encoding/binary"
	"errors"
	"fmt"
)

func isFragmentMessage(messageType MessageType) bool {
	return messageType == MessageTypeCommand ||
		messageType == MessageTypeCommandDone ||
		messageType == MessageTypeIndicateStatus
}

type fragmentedMessage struct {
	data         []byte
	maxFrameSize int
}

func (m fragmentedMessage) Frames() ([][]byte, error) {
	if len(m.data) <= m.maxFrameSize {
		return [][]byte{m.data}, nil
	}
	if len(m.data) < 20 {
		return nil, fmt.Errorf("fragmenting MBIM message: message length %d is too short", len(m.data))
	}
	messageType := MessageType(binary.LittleEndian.Uint32(m.data[:4]))
	if !isFragmentMessage(messageType) {
		return nil, fmt.Errorf("fragmenting MBIM message: message type %#x does not support fragments", messageType)
	}
	if binary.LittleEndian.Uint32(m.data[4:8]) != uint32(len(m.data)) {
		return nil, fmt.Errorf("fragmenting MBIM message: header length %d does not match actual length %d", binary.LittleEndian.Uint32(m.data[4:8]), len(m.data))
	}
	if m.maxFrameSize <= 20 {
		return nil, fmt.Errorf("fragmenting MBIM message: max frame size %d is too small", m.maxFrameSize)
	}

	transactionID := binary.LittleEndian.Uint32(m.data[8:12])
	payload := m.data[20:]
	maxPayloadSize := m.maxFrameSize - 20
	total := max(1, (len(payload)+maxPayloadSize-1)/maxPayloadSize)

	frames := make([][]byte, 0, total)
	for current, offset := 0, 0; offset < len(payload); current++ {
		end := min(offset+maxPayloadSize, len(payload))
		fragmentLength := 20 + end - offset
		fragment := make([]byte, fragmentLength)
		binary.LittleEndian.PutUint32(fragment[:4], uint32(messageType))
		binary.LittleEndian.PutUint32(fragment[4:8], uint32(fragmentLength))
		binary.LittleEndian.PutUint32(fragment[8:12], transactionID)
		binary.LittleEndian.PutUint32(fragment[12:16], uint32(total))
		binary.LittleEndian.PutUint32(fragment[16:20], uint32(current))
		copy(fragment[20:], payload[offset:end])
		frames = append(frames, fragment)
		offset = end
	}
	return frames, nil
}

type fragmentCollector struct {
	messageType   MessageType
	transactionID uint32
	total         uint32
	current       uint32
	payload       []byte
}

func newFragmentCollector(frame []byte) (*fragmentCollector, error) {
	var f fragment
	if err := f.UnmarshalBinary(frame); err != nil {
		return nil, err
	}
	if f.current != 0 {
		return nil, fmt.Errorf("collecting MBIM fragments: got fragment %d/%d before fragment 0", f.current, f.total)
	}
	return &fragmentCollector{
		messageType:   f.messageType,
		transactionID: f.transactionID,
		total:         f.total,
		current:       f.current,
		payload:       append([]byte(nil), f.payload...),
	}, nil
}

func (c *fragmentCollector) add(frame []byte) error {
	var f fragment
	if err := f.UnmarshalBinary(frame); err != nil {
		return err
	}
	if f.messageType != c.messageType {
		return fmt.Errorf("collecting MBIM fragments: message type %#x does not match %#x", f.messageType, c.messageType)
	}
	if f.transactionID != c.transactionID {
		return fmt.Errorf("collecting MBIM fragments: transaction ID %d does not match %d", f.transactionID, c.transactionID)
	}
	if f.total != c.total {
		return fmt.Errorf("collecting MBIM fragments: total %d does not match %d", f.total, c.total)
	}
	if f.current != c.current+1 {
		return fmt.Errorf("collecting MBIM fragments: got fragment %d/%d, want %d/%d", f.current, f.total, c.current+1, c.total)
	}
	c.current = f.current
	c.payload = append(c.payload, f.payload...)
	return nil
}

func (c *fragmentCollector) complete() bool {
	return c.current == c.total-1
}

func (c *fragmentCollector) MarshalBinary() ([]byte, error) {
	if !c.complete() {
		return nil, fmt.Errorf("collecting MBIM fragments: got %d/%d fragments", c.current+1, c.total)
	}
	length := uint32(20 + len(c.payload))
	buf := make([]byte, length)
	binary.LittleEndian.PutUint32(buf[:4], uint32(c.messageType))
	binary.LittleEndian.PutUint32(buf[4:8], length)
	binary.LittleEndian.PutUint32(buf[8:12], c.transactionID)
	binary.LittleEndian.PutUint32(buf[12:16], 1)
	binary.LittleEndian.PutUint32(buf[16:20], 0)
	copy(buf[20:], c.payload)
	return buf, nil
}

type fragment struct {
	messageType   MessageType
	transactionID uint32
	total         uint32
	current       uint32
	payload       []byte
}

func (f *fragment) UnmarshalBinary(frame []byte) error {
	if len(frame) < 20 {
		return fmt.Errorf("parsing MBIM fragment: length %d is too short", len(frame))
	}
	messageType := MessageType(binary.LittleEndian.Uint32(frame[:4]))
	if !isFragmentMessage(messageType) {
		return fmt.Errorf("parsing MBIM fragment: message type %#x does not support fragments", messageType)
	}
	messageLength := binary.LittleEndian.Uint32(frame[4:8])
	if messageLength != uint32(len(frame)) {
		return fmt.Errorf("parsing MBIM fragment: header length %d does not match actual length %d", messageLength, len(frame))
	}
	total := binary.LittleEndian.Uint32(frame[12:16])
	current := binary.LittleEndian.Uint32(frame[16:20])
	if total == 0 {
		return errors.New("parsing MBIM fragment: total is zero")
	}
	if current >= total {
		return fmt.Errorf("parsing MBIM fragment: fragment %d is outside total %d", current, total)
	}
	*f = fragment{
		messageType:   messageType,
		transactionID: binary.LittleEndian.Uint32(frame[8:12]),
		total:         total,
		current:       current,
		payload:       frame[20:],
	}
	return nil
}
