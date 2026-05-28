package voice

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	rtpHeaderSize      = 12
	rtpVersion         = 2
	rtcpRRPacketType   = 201
	rtcpSDESPacketType = 202
	rtcpSDESCNAMEItem  = 1
	AMRNoModeRequest   = 15
)

var (
	amrFrameBits   = []int{95, 103, 118, 134, 148, 159, 204, 244, 39}
	amrWBFrameBits = []int{132, 177, 253, 285, 317, 365, 397, 461, 477, 40}
)

type RTPPacket struct {
	PayloadType    int
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
	Marker         bool
	Payload        []byte
}

type AMRPayload struct {
	CMR    int
	Frames []AMRFrame
}

type AMRFrame struct {
	FrameType int
	Quality   bool
	Data      []byte
}

func ParseRTPPacket(packet []byte) (RTPPacket, error) {
	if len(packet) < rtpHeaderSize {
		return RTPPacket{}, errors.New("parsing RTP packet: packet is too short")
	}
	if version := packet[0] >> 6; version != rtpVersion {
		return RTPPacket{}, fmt.Errorf("parsing RTP packet: unsupported version %d", version)
	}
	hasPadding := packet[0]&0x20 != 0
	hasExtension := packet[0]&0x10 != 0
	csrcCount := int(packet[0] & 0x0f)
	offset := rtpHeaderSize + csrcCount*4
	if offset > len(packet) {
		return RTPPacket{}, errors.New("parsing RTP packet: csrc list is truncated")
	}
	if hasExtension {
		if offset+4 > len(packet) {
			return RTPPacket{}, errors.New("parsing RTP packet: extension header is truncated")
		}
		extensionWords := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		offset += 4 + extensionWords*4
		if offset > len(packet) {
			return RTPPacket{}, errors.New("parsing RTP packet: extension payload is truncated")
		}
	}
	end := len(packet)
	if hasPadding {
		padding := int(packet[len(packet)-1])
		if padding == 0 || padding > len(packet)-offset {
			return RTPPacket{}, errors.New("parsing RTP packet: padding is invalid")
		}
		end -= padding
	}
	return RTPPacket{
		PayloadType:    int(packet[1] & 0x7f),
		SequenceNumber: binary.BigEndian.Uint16(packet[2:4]),
		Timestamp:      binary.BigEndian.Uint32(packet[4:8]),
		SSRC:           binary.BigEndian.Uint32(packet[8:12]),
		Marker:         packet[1]&0x80 != 0,
		Payload:        append([]byte(nil), packet[offset:end]...),
	}, nil
}

func BuildRTPPacket(packet RTPPacket) ([]byte, error) {
	if packet.PayloadType < 0 || packet.PayloadType > 127 {
		return nil, fmt.Errorf("building RTP packet: payload type %d is outside 0..127", packet.PayloadType)
	}
	out := make([]byte, rtpHeaderSize+len(packet.Payload))
	out[0] = rtpVersion << 6
	out[1] = byte(packet.PayloadType)
	if packet.Marker {
		out[1] |= 0x80
	}
	binary.BigEndian.PutUint16(out[2:4], packet.SequenceNumber)
	binary.BigEndian.PutUint32(out[4:8], packet.Timestamp)
	binary.BigEndian.PutUint32(out[8:12], packet.SSRC)
	copy(out[rtpHeaderSize:], packet.Payload)
	return out, nil
}

func randomRTCPSSRC() uint32 {
	var data [4]byte
	if _, err := rand.Read(data[:]); err == nil {
		if ssrc := binary.BigEndian.Uint32(data[:]); ssrc != 0 {
			return ssrc
		}
	}
	return uint32(time.Now().UnixNano()) | 1
}

func buildRTCPReceiverReport(ssrc uint32, cname string) []byte {
	if ssrc == 0 {
		ssrc = 1
	}
	cname = strings.TrimSpace(cname)
	if len(cname) > 255 {
		cname = cname[:255]
	}
	if cname == "" {
		cname = "vowifi-go"
	}

	rr := make([]byte, 8)
	rr[0] = rtpVersion << 6
	rr[1] = rtcpRRPacketType
	binary.BigEndian.PutUint16(rr[2:4], 1)
	binary.BigEndian.PutUint32(rr[4:8], ssrc)

	sdesLen := 4 + 2 + len(cname) + 1
	for sdesLen%4 != 0 {
		sdesLen++
	}
	sdes := make([]byte, 4+sdesLen)
	sdes[0] = (rtpVersion << 6) | 1
	sdes[1] = rtcpSDESPacketType
	binary.BigEndian.PutUint16(sdes[2:4], uint16(len(sdes)/4-1))
	binary.BigEndian.PutUint32(sdes[4:8], ssrc)
	sdes[8] = rtcpSDESCNAMEItem
	sdes[9] = byte(len(cname))
	copy(sdes[10:], cname)

	out := make([]byte, 0, len(rr)+len(sdes))
	out = append(out, rr...)
	out = append(out, sdes...)
	return out
}

func ParseAMRPayload(media NegotiatedMedia, payload []byte) (AMRPayload, error) {
	if !isAMRCodec(media.Codec) {
		return AMRPayload{}, fmt.Errorf("parsing AMR payload: media codec is %s", media.Codec)
	}
	if media.OctetAlign {
		return ParseAMROctetAlignedPayload(media.Codec, payload)
	}
	return ParseAMRBandwidthEfficientPayload(media.Codec, payload)
}

func BuildAMRPayload(media NegotiatedMedia, frames []AMRFrame, cmr int) ([]byte, error) {
	if !isAMRCodec(media.Codec) {
		return nil, fmt.Errorf("building AMR payload: media codec is %s", media.Codec)
	}
	if media.OctetAlign {
		return BuildAMROctetAlignedPayload(media.Codec, frames, cmr)
	}
	return BuildAMRBandwidthEfficientPayload(media.Codec, frames, cmr)
}

func ParseAMROctetAlignedPayload(codec AudioCodec, payload []byte) (AMRPayload, error) {
	if len(payload) < 2 {
		return AMRPayload{}, errors.New("parsing AMR octet-aligned payload: payload is too short")
	}
	result := AMRPayload{CMR: int(payload[0] >> 4)}
	offset := 1
	for more := true; more; {
		if offset >= len(payload) {
			return AMRPayload{}, errors.New("parsing AMR octet-aligned payload: table of contents is truncated")
		}
		toc := payload[offset]
		offset++
		more = toc&0x80 != 0
		frameType := int((toc >> 3) & 0x0f)
		frameBytes, err := amrFrameBytes(codec, frameType)
		if err != nil {
			return AMRPayload{}, fmt.Errorf("parsing AMR octet-aligned payload: %w", err)
		}
		result.Frames = append(result.Frames, AMRFrame{
			FrameType: frameType,
			Quality:   toc&0x04 != 0,
			Data:      make([]byte, frameBytes),
		})
	}
	for i := range result.Frames {
		end := offset + len(result.Frames[i].Data)
		if end > len(payload) {
			return AMRPayload{}, errors.New("parsing AMR octet-aligned payload: speech data is truncated")
		}
		copy(result.Frames[i].Data, payload[offset:end])
		offset = end
	}
	return result, nil
}

func BuildAMROctetAlignedPayload(codec AudioCodec, frames []AMRFrame, cmr int) ([]byte, error) {
	if len(frames) == 0 {
		return nil, errors.New("building AMR octet-aligned payload: at least one frame is required")
	}
	if cmr < 0 {
		cmr = AMRNoModeRequest
	}
	if cmr > 15 {
		return nil, fmt.Errorf("building AMR octet-aligned payload: cmr %d is outside 0..15", cmr)
	}
	speechBytes := 0
	for _, frame := range frames {
		frameBytes, err := amrFrameBytes(codec, frame.FrameType)
		if err != nil {
			return nil, fmt.Errorf("building AMR octet-aligned payload: %w", err)
		}
		if len(frame.Data) != frameBytes {
			return nil, fmt.Errorf("building AMR octet-aligned payload: frame type %d has %d bytes, want %d", frame.FrameType, len(frame.Data), frameBytes)
		}
		speechBytes += frameBytes
	}
	out := make([]byte, 1+len(frames)+speechBytes)
	out[0] = byte(cmr << 4)
	offset := 1
	for i, frame := range frames {
		toc := byte((frame.FrameType & 0x0f) << 3)
		if i < len(frames)-1 {
			toc |= 0x80
		}
		if frame.Quality {
			toc |= 0x04
		}
		out[offset] = toc
		offset++
	}
	for _, frame := range frames {
		copy(out[offset:], frame.Data)
		offset += len(frame.Data)
	}
	return out, nil
}

func ParseAMRBandwidthEfficientPayload(codec AudioCodec, payload []byte) (AMRPayload, error) {
	reader := bitReader{data: payload}
	cmr, ok := reader.readBits(4)
	if !ok {
		return AMRPayload{}, errors.New("parsing AMR bandwidth-efficient payload: cmr is truncated")
	}
	result := AMRPayload{CMR: int(cmr)}
	for more := true; more; {
		f, ok := reader.readBits(1)
		if !ok {
			return AMRPayload{}, errors.New("parsing AMR bandwidth-efficient payload: table of contents is truncated")
		}
		ft, ok := reader.readBits(4)
		if !ok {
			return AMRPayload{}, errors.New("parsing AMR bandwidth-efficient payload: frame type is truncated")
		}
		q, ok := reader.readBits(1)
		if !ok {
			return AMRPayload{}, errors.New("parsing AMR bandwidth-efficient payload: frame quality is truncated")
		}
		frameType := int(ft)
		frameBits, err := amrFrameBitLen(codec, frameType)
		if err != nil {
			return AMRPayload{}, fmt.Errorf("parsing AMR bandwidth-efficient payload: %w", err)
		}
		result.Frames = append(result.Frames, AMRFrame{
			FrameType: frameType,
			Quality:   q != 0,
			Data:      make([]byte, bytesForBits(frameBits)),
		})
		more = f != 0
	}
	for i := range result.Frames {
		frameBits, _ := amrFrameBitLen(codec, result.Frames[i].FrameType)
		if !reader.readBytes(result.Frames[i].Data, frameBits) {
			return AMRPayload{}, errors.New("parsing AMR bandwidth-efficient payload: speech data is truncated")
		}
	}
	return result, nil
}

func BuildAMRBandwidthEfficientPayload(codec AudioCodec, frames []AMRFrame, cmr int) ([]byte, error) {
	if len(frames) == 0 {
		return nil, errors.New("building AMR bandwidth-efficient payload: at least one frame is required")
	}
	if cmr < 0 {
		cmr = AMRNoModeRequest
	}
	if cmr > 15 {
		return nil, fmt.Errorf("building AMR bandwidth-efficient payload: cmr %d is outside 0..15", cmr)
	}
	writer := bitWriter{}
	writer.writeBits(uint64(cmr), 4)
	for i, frame := range frames {
		frameBits, err := amrFrameBitLen(codec, frame.FrameType)
		if err != nil {
			return nil, fmt.Errorf("building AMR bandwidth-efficient payload: %w", err)
		}
		if len(frame.Data) != bytesForBits(frameBits) {
			return nil, fmt.Errorf("building AMR bandwidth-efficient payload: frame type %d has %d bytes, want %d", frame.FrameType, len(frame.Data), bytesForBits(frameBits))
		}
		if i < len(frames)-1 {
			writer.writeBits(1, 1)
		} else {
			writer.writeBits(0, 1)
		}
		writer.writeBits(uint64(frame.FrameType), 4)
		if frame.Quality {
			writer.writeBits(1, 1)
		} else {
			writer.writeBits(0, 1)
		}
	}
	for _, frame := range frames {
		frameBits, _ := amrFrameBitLen(codec, frame.FrameType)
		writer.writeBytes(frame.Data, frameBits)
	}
	return writer.bytes(), nil
}

func amrFrameBytes(codec AudioCodec, frameType int) (int, error) {
	bits, err := amrFrameBitLen(codec, frameType)
	if err != nil {
		return 0, err
	}
	return bytesForBits(bits), nil
}

func amrFrameBitLen(codec AudioCodec, frameType int) (int, error) {
	switch normalizedAMRCodec(codec) {
	case CodecAMR:
		if frameType == 15 {
			return 0, nil
		}
		if frameType >= 0 && frameType < len(amrFrameBits) {
			return amrFrameBits[frameType], nil
		}
	case CodecAMRWB:
		if frameType == 14 || frameType == 15 {
			return 0, nil
		}
		if frameType >= 0 && frameType < len(amrWBFrameBits) {
			return amrWBFrameBits[frameType], nil
		}
	default:
		return 0, fmt.Errorf("unsupported codec %q", codec)
	}
	return 0, fmt.Errorf("frame type %d is not supported for %s", frameType, codec)
}

func normalizedAMRCodec(codec AudioCodec) AudioCodec {
	switch strings.ToUpper(strings.TrimSpace(string(codec))) {
	case "AMR":
		return CodecAMR
	case "AMR-WB", "AMRWB":
		return CodecAMRWB
	default:
		return codec
	}
}

func isAMRCodec(codec AudioCodec) bool {
	codec = normalizedAMRCodec(codec)
	return codec == CodecAMR || codec == CodecAMRWB
}

func bytesForBits(bits int) int {
	return (bits + 7) / 8
}

type bitReader struct {
	data []byte
	pos  int
}

func (r *bitReader) readBits(n int) (uint64, bool) {
	if n < 0 || r.pos+n > len(r.data)*8 {
		return 0, false
	}
	var value uint64
	for range n {
		byteIndex := r.pos / 8
		bitIndex := 7 - r.pos%8
		value = value<<1 | uint64((r.data[byteIndex]>>bitIndex)&1)
		r.pos++
	}
	return value, true
}

func (r *bitReader) readBytes(dst []byte, bits int) bool {
	for i := range dst {
		dst[i] = 0
	}
	for i := 0; i < bits; i++ {
		bit, ok := r.readBits(1)
		if !ok {
			return false
		}
		if bit != 0 {
			dst[i/8] |= 1 << (7 - i%8)
		}
	}
	return true
}

type bitWriter struct {
	data []byte
	pos  int
}

func (w *bitWriter) writeBits(value uint64, n int) {
	for i := n - 1; i >= 0; i-- {
		w.writeBit((value>>i)&1 != 0)
	}
}

func (w *bitWriter) writeBytes(src []byte, bits int) {
	for i := 0; i < bits; i++ {
		bit := src[i/8]&(1<<(7-i%8)) != 0
		w.writeBit(bit)
	}
}

func (w *bitWriter) writeBit(value bool) {
	if w.pos/8 == len(w.data) {
		w.data = append(w.data, 0)
	}
	if value {
		w.data[w.pos/8] |= 1 << (7 - w.pos%8)
	}
	w.pos++
}

func (w *bitWriter) bytes() []byte {
	return append([]byte(nil), w.data...)
}
