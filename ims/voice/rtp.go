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
	rtpHeaderSize          = 12
	rtpVersion             = 2
	rtpVersionShift        = 6
	rtpPaddingFlag         = 0x20
	rtpExtensionFlag       = 0x10
	rtpCSRCCountMask       = 0x0f
	rtpCSRCSize            = 4
	rtpExtensionHeaderSize = 4
	rtpExtensionWordSize   = 4
	rtpPayloadTypeMask     = 0x7f
	rtpPayloadTypeMax      = 127
	rtpMarkerFlag          = 0x80

	rtcpRRPacketType             = 201
	rtcpSRPacketType             = 200
	rtcpSDESPacketType           = 202
	rtcpSDESCNAMEItem            = 1
	rtcpReceiverReportWordLength = 1
	rtcpSDESReportCount          = 1
	rtcpSSRCFallback             = 1
	rtcpCNAMEMaxLen              = 255
	rtcpSDESChunkHeaderSize      = 4
	rtcpSDESItemHeaderSize       = 2
	rtcpSDESEndSize              = 1
	rtcpWordSize                 = 4
	rtcpNTPUnixOffset            = 2208988800

	AMRNoModeRequest = 15

	amrCMRShift          = 4
	amrCMRMax            = 15
	amrToCFollowFlag     = 0x80
	amrToCFrameTypeShift = 3
	amrToCFrameTypeMask  = 0x0f
	amrToCQualityFlag    = 0x04
	amrToCReservedBits   = 0x03
	amrNoDataFrameType   = 15
	amrWBNoDataFrameType = 15
	amrWBSpeechLostType  = 14
	amrCMRBits           = 4
	amrToCFollowBits     = 1
	amrToCFrameTypeBits  = 4
	amrToCQualityBits    = 1

	evsHeaderHFlag     = 0x80
	evsHeaderFFlag     = 0x40
	evsHeaderAMRWBIO   = 0x20
	evsHeaderQuality   = 0x10
	evsHeaderFrameMask = 0x0f
	evsSpeechLostType  = 14
	evsNoDataType      = 15

	bitsPerByte = 8
)

var (
	amrFrameBits   = []int{95, 103, 118, 134, 148, 159, 204, 244, 39}
	amrWBFrameBits = []int{132, 177, 253, 285, 317, 365, 397, 461, 477, 40}
	evsFrameBits   = []int{56, 144, 160, 192, 264, 328, 488, 640, 960, 1280, 1920, 2560, 48, 0, 0, 0}
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

// AMRPayloadCodec marshals AMR RTP payloads with negotiated media context.
type AMRPayloadCodec struct {
	Media NegotiatedMedia
}

type AMRFrame struct {
	FrameType int
	Quality   bool
	Data      []byte
}

// AMRToCEntry is one AMR RTP table-of-contents entry.
type AMRToCEntry struct {
	Follow    bool
	FrameType int
	Quality   bool
}

// EVSPayloadCodec marshals EVS payloads using the negotiated hf-only setting.
type EVSPayloadCodec struct {
	HeaderFullOnly bool
}

// EVSCMR is one Header-Full codec mode request.
type EVSCMR struct {
	Type int
	Mode int
}

// EVSPayload contains the EVS frames carried by one RTP payload.
type EVSPayload struct {
	CMR        *EVSCMR
	HeaderFull bool
	Frames     []EVSFrame
}

// EVSFrame contains one EVS Native or AMR-WB IO access unit without RTP headers.
type EVSFrame struct {
	FrameType int
	Quality   bool
	AMRWBIO   bool
	Data      []byte
}

// MarshalBinary returns one RTP packet.
func (p RTPPacket) MarshalBinary() ([]byte, error) {
	return p.AppendBinary(nil)
}

// AppendBinary appends one RTP packet to dst.
func (p RTPPacket) AppendBinary(dst []byte) ([]byte, error) {
	if p.PayloadType < 0 || p.PayloadType > rtpPayloadTypeMax {
		return nil, fmt.Errorf("marshaling RTP packet: payload type %d is outside 0..%d", p.PayloadType, rtpPayloadTypeMax)
	}
	offset := len(dst)
	dst = append(dst, make([]byte, rtpHeaderSize+len(p.Payload))...)
	out := dst[offset:]
	out[0] = rtpVersion << rtpVersionShift
	out[1] = byte(p.PayloadType)
	if p.Marker {
		out[1] |= rtpMarkerFlag
	}
	binary.BigEndian.PutUint16(out[2:4], p.SequenceNumber)
	binary.BigEndian.PutUint32(out[4:8], p.Timestamp)
	binary.BigEndian.PutUint32(out[8:12], p.SSRC)
	copy(out[rtpHeaderSize:], p.Payload)
	return dst, nil
}

// UnmarshalBinary fills p from one RTP packet.
func (p *RTPPacket) UnmarshalBinary(data []byte) error {
	if len(data) < rtpHeaderSize {
		return errors.New("unmarshaling RTP packet: packet is too short")
	}
	if version := data[0] >> rtpVersionShift; version != rtpVersion {
		return fmt.Errorf("unmarshaling RTP packet: unsupported version %d", version)
	}
	hasPadding := data[0]&rtpPaddingFlag != 0
	hasExtension := data[0]&rtpExtensionFlag != 0
	csrcCount := int(data[0] & rtpCSRCCountMask)
	offset := rtpHeaderSize + csrcCount*rtpCSRCSize
	if offset > len(data) {
		return errors.New("unmarshaling RTP packet: csrc list is truncated")
	}
	if hasExtension {
		if offset+rtpExtensionHeaderSize > len(data) {
			return errors.New("unmarshaling RTP packet: extension header is truncated")
		}
		extensionWords := int(binary.BigEndian.Uint16(data[offset+2 : offset+rtpExtensionHeaderSize]))
		offset += rtpExtensionHeaderSize + extensionWords*rtpExtensionWordSize
		if offset > len(data) {
			return errors.New("unmarshaling RTP packet: extension payload is truncated")
		}
	}
	end := len(data)
	if hasPadding {
		padding := int(data[len(data)-1])
		if padding == 0 || padding > len(data)-offset {
			return errors.New("unmarshaling RTP packet: padding is invalid")
		}
		end -= padding
	}
	*p = RTPPacket{
		PayloadType:    int(data[1] & rtpPayloadTypeMask),
		SequenceNumber: binary.BigEndian.Uint16(data[2:4]),
		Timestamp:      binary.BigEndian.Uint32(data[4:8]),
		SSRC:           binary.BigEndian.Uint32(data[8:12]),
		Marker:         data[1]&rtpMarkerFlag != 0,
		Payload:        append(p.Payload[:0], data[offset:end]...),
	}
	return nil
}

func randomRTCPSSRC() uint32 {
	var data [4]byte
	_, _ = rand.Read(data[:])
	if ssrc := binary.BigEndian.Uint32(data[:]); ssrc != 0 {
		return ssrc
	}
	return rtcpSSRCFallback
}

func buildRTCPReceiverReport(ssrc uint32, cname string) []byte {
	return buildRTCPReceiverReportWithBlock(ssrc, cname, nil)
}

func buildRTCPReceiverReportWithBlock(ssrc uint32, cname string, block []byte) []byte {
	if ssrc == 0 {
		ssrc = rtcpSSRCFallback
	}
	cname = strings.TrimSpace(cname)
	if len(cname) > rtcpCNAMEMaxLen {
		cname = cname[:rtcpCNAMEMaxLen]
	}
	if cname == "" {
		cname = "ims-go"
	}

	reportCount := 0
	if len(block) == 24 {
		reportCount = 1
	}
	rr := make([]byte, 8+24*reportCount)
	rr[0] = rtpVersion << rtpVersionShift
	rr[0] |= byte(reportCount)
	rr[1] = rtcpRRPacketType
	binary.BigEndian.PutUint16(rr[2:4], uint16(len(rr)/rtcpWordSize-1))
	binary.BigEndian.PutUint32(rr[4:8], ssrc)
	copy(rr[8:], block)

	return appendRTCPSourceDescription(rr, ssrc, cname)
}

func buildRTCPSenderReport(ssrc uint32, cname string, now time.Time, timestamp, packets, octets uint32, block []byte) []byte {
	if ssrc == 0 {
		ssrc = rtcpSSRCFallback
	}
	ntp := now.Sub(time.Unix(0, 0))
	seconds := uint64(ntp/time.Second) + rtcpNTPUnixOffset
	frac := uint64((ntp % time.Second) * (1 << 32) / time.Second)
	reportCount := 0
	if len(block) == 24 {
		reportCount = 1
	}
	sr := make([]byte, 28+24*reportCount)
	sr[0] = rtpVersion << rtpVersionShift
	sr[0] |= byte(reportCount)
	sr[1] = rtcpSRPacketType
	binary.BigEndian.PutUint16(sr[2:4], uint16(len(sr)/rtcpWordSize-1))
	binary.BigEndian.PutUint32(sr[4:8], ssrc)
	binary.BigEndian.PutUint32(sr[8:12], uint32(seconds))
	binary.BigEndian.PutUint32(sr[12:16], uint32(frac))
	binary.BigEndian.PutUint32(sr[16:20], timestamp)
	binary.BigEndian.PutUint32(sr[20:24], packets)
	binary.BigEndian.PutUint32(sr[24:28], octets)
	copy(sr[28:], block)
	return appendRTCPSourceDescription(sr, ssrc, cname)
}

func appendRTCPSourceDescription(report []byte, ssrc uint32, cname string) []byte {
	cname = strings.TrimSpace(cname)
	if len(cname) > rtcpCNAMEMaxLen {
		cname = cname[:rtcpCNAMEMaxLen]
	}
	if cname == "" {
		cname = "ims-go"
	}
	sdesLen := rtcpSDESChunkHeaderSize + rtcpSDESItemHeaderSize + len(cname) + rtcpSDESEndSize
	for sdesLen%rtcpWordSize != 0 {
		sdesLen++
	}
	sdes := make([]byte, rtcpWordSize+sdesLen)
	sdes[0] = (rtpVersion << rtpVersionShift) | rtcpSDESReportCount
	sdes[1] = rtcpSDESPacketType
	binary.BigEndian.PutUint16(sdes[2:4], uint16(len(sdes)/rtcpWordSize-1))
	binary.BigEndian.PutUint32(sdes[4:8], ssrc)
	sdes[8] = rtcpSDESCNAMEItem
	sdes[9] = byte(len(cname))
	copy(sdes[10:], cname)

	out := make([]byte, 0, len(report)+len(sdes))
	out = append(out, report...)
	out = append(out, sdes...)
	return out
}

// Marshal builds one AMR RTP payload.
func (c AMRPayloadCodec) Marshal(p AMRPayload) ([]byte, error) {
	return c.Append(nil, p)
}

// Append appends one AMR RTP payload to dst.
func (c AMRPayloadCodec) Append(dst []byte, p AMRPayload) ([]byte, error) {
	mediaCodec := normalizedAMRCodec(c.Media.Codec)
	if !isAMRCodec(mediaCodec) {
		return nil, fmt.Errorf("marshaling AMR payload: media codec is %s", c.Media.Codec)
	}
	if c.Media.OctetAlign {
		return c.appendOctetAligned(dst, mediaCodec, p)
	}
	return c.appendBandwidthEfficient(dst, mediaCodec, p)
}

// Unmarshal parses one AMR RTP payload.
func (c AMRPayloadCodec) Unmarshal(data []byte) (AMRPayload, error) {
	mediaCodec := normalizedAMRCodec(c.Media.Codec)
	if !isAMRCodec(mediaCodec) {
		return AMRPayload{}, fmt.Errorf("unmarshaling AMR payload: media codec is %s", c.Media.Codec)
	}
	if c.Media.OctetAlign {
		return c.unmarshalOctetAligned(mediaCodec, data)
	}
	return c.unmarshalBandwidthEfficient(mediaCodec, data)
}

func (c AMRPayloadCodec) unmarshalOctetAligned(codec AudioCodec, payload []byte) (AMRPayload, error) {
	if len(payload) < 2 {
		return AMRPayload{}, errors.New("unmarshaling AMR octet-aligned payload: payload is too short")
	}
	result := AMRPayload{CMR: int(payload[0] >> amrCMRShift)}
	offset := 1
	for more := true; more; {
		if offset >= len(payload) {
			return AMRPayload{}, errors.New("unmarshaling AMR octet-aligned payload: table of contents is truncated")
		}
		var toc AMRToCEntry
		if err := toc.UnmarshalBinary(payload[offset : offset+1]); err != nil {
			return AMRPayload{}, err
		}
		offset++
		frameBytes, err := amrFrameBytes(codec, toc.FrameType)
		if err != nil {
			return AMRPayload{}, fmt.Errorf("unmarshaling AMR octet-aligned payload: %w", err)
		}
		result.Frames = append(result.Frames, AMRFrame{
			FrameType: toc.FrameType,
			Quality:   toc.Quality,
			Data:      make([]byte, frameBytes),
		})
		more = toc.Follow
	}
	for i := range result.Frames {
		end := offset + len(result.Frames[i].Data)
		if end > len(payload) {
			return AMRPayload{}, errors.New("unmarshaling AMR octet-aligned payload: speech data is truncated")
		}
		copy(result.Frames[i].Data, payload[offset:end])
		offset = end
	}
	return result, nil
}

func (c AMRPayloadCodec) appendOctetAligned(dst []byte, codec AudioCodec, payload AMRPayload) ([]byte, error) {
	cmr, err := validateAMRPayloadFrames(codec, payload, "marshaling AMR octet-aligned payload")
	if err != nil {
		return nil, err
	}
	dst = append(dst, byte(cmr<<amrCMRShift))
	for i, frame := range payload.Frames {
		toc := AMRToCEntry{
			Follow:    i < len(payload.Frames)-1,
			FrameType: frame.FrameType,
			Quality:   frame.Quality,
		}
		dst, err = toc.AppendBinary(dst)
		if err != nil {
			return nil, err
		}
	}
	for _, frame := range payload.Frames {
		dst = append(dst, frame.Data...)
	}
	return dst, nil
}

func (c AMRPayloadCodec) unmarshalBandwidthEfficient(codec AudioCodec, payload []byte) (AMRPayload, error) {
	reader := bitReader{data: payload}
	cmr, ok := reader.readBits(amrCMRBits)
	if !ok {
		return AMRPayload{}, errors.New("unmarshaling AMR bandwidth-efficient payload: cmr is truncated")
	}
	result := AMRPayload{CMR: int(cmr)}
	for more := true; more; {
		toc, ok := readAMRToCEntryBits(&reader)
		if !ok {
			return AMRPayload{}, errors.New("unmarshaling AMR bandwidth-efficient payload: table of contents is truncated")
		}
		frameBits, err := amrFrameBitLen(codec, toc.FrameType)
		if err != nil {
			return AMRPayload{}, fmt.Errorf("unmarshaling AMR bandwidth-efficient payload: %w", err)
		}
		result.Frames = append(result.Frames, AMRFrame{
			FrameType: toc.FrameType,
			Quality:   toc.Quality,
			Data:      make([]byte, bytesForBits(frameBits)),
		})
		more = toc.Follow
	}
	for i := range result.Frames {
		frameBits, err := amrFrameBitLen(codec, result.Frames[i].FrameType)
		if err != nil {
			return AMRPayload{}, fmt.Errorf("unmarshaling AMR bandwidth-efficient payload: frame %d: %w", i, err)
		}
		if !reader.readBytes(result.Frames[i].Data, frameBits) {
			return AMRPayload{}, errors.New("unmarshaling AMR bandwidth-efficient payload: speech data is truncated")
		}
	}
	return result, nil
}

func (c AMRPayloadCodec) appendBandwidthEfficient(dst []byte, codec AudioCodec, payload AMRPayload) ([]byte, error) {
	cmr, err := validateAMRPayloadFrames(codec, payload, "marshaling AMR bandwidth-efficient payload")
	if err != nil {
		return nil, err
	}
	writer := bitWriter{data: dst, pos: len(dst) * bitsPerByte}
	writer.writeBits(uint64(cmr), amrCMRBits)
	for i, frame := range payload.Frames {
		toc := AMRToCEntry{
			Follow:    i < len(payload.Frames)-1,
			FrameType: frame.FrameType,
			Quality:   frame.Quality,
		}
		toc.writeBits(&writer)
	}
	for i, frame := range payload.Frames {
		frameBits, err := amrFrameBitLen(codec, frame.FrameType)
		if err != nil {
			return nil, fmt.Errorf("marshaling AMR bandwidth-efficient payload: frame %d: %w", i, err)
		}
		writer.writeBytes(frame.Data, frameBits)
	}
	return writer.bytes(), nil
}

func validateAMRPayloadFrames(codec AudioCodec, payload AMRPayload, context string) (int, error) {
	if len(payload.Frames) == 0 {
		return 0, fmt.Errorf("%s: at least one frame is required", context)
	}
	cmr := payload.CMR
	if cmr < 0 {
		cmr = AMRNoModeRequest
	}
	if cmr > amrCMRMax {
		return 0, fmt.Errorf("%s: cmr %d is outside 0..%d", context, cmr, amrCMRMax)
	}
	for _, frame := range payload.Frames {
		frameBytes, err := amrFrameBytes(codec, frame.FrameType)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", context, err)
		}
		if len(frame.Data) != frameBytes {
			return 0, fmt.Errorf("%s: frame type %d has %d bytes, want %d", context, frame.FrameType, len(frame.Data), frameBytes)
		}
	}
	return cmr, nil
}

// AppendBinary appends one AMR RTP ToC byte to dst.
func (e AMRToCEntry) AppendBinary(dst []byte) ([]byte, error) {
	if e.FrameType < 0 || e.FrameType > amrToCFrameTypeMask {
		return nil, fmt.Errorf("marshaling AMR ToC entry: frame type %d is outside 0..%d", e.FrameType, amrToCFrameTypeMask)
	}
	toc := byte((e.FrameType & amrToCFrameTypeMask) << amrToCFrameTypeShift)
	if e.Follow {
		toc |= amrToCFollowFlag
	}
	if e.Quality {
		toc |= amrToCQualityFlag
	}
	return append(dst, toc), nil
}

// MarshalBinary returns one AMR RTP ToC byte.
func (e AMRToCEntry) MarshalBinary() ([]byte, error) {
	return e.AppendBinary(nil)
}

// UnmarshalBinary decodes one AMR RTP ToC byte.
func (e *AMRToCEntry) UnmarshalBinary(data []byte) error {
	if len(data) != 1 {
		return fmt.Errorf("unmarshaling AMR ToC entry: byte count %d, want 1", len(data))
	}
	toc := data[0]
	if toc&amrToCReservedBits != 0 {
		return errors.New("unmarshaling AMR ToC entry: reserved bits are set")
	}
	e.Follow = toc&amrToCFollowFlag != 0
	e.FrameType = int((toc >> amrToCFrameTypeShift) & amrToCFrameTypeMask)
	e.Quality = toc&amrToCQualityFlag != 0
	return nil
}

func (e AMRToCEntry) writeBits(w *bitWriter) {
	if e.Follow {
		w.writeBits(1, amrToCFollowBits)
	} else {
		w.writeBits(0, amrToCFollowBits)
	}
	w.writeBits(uint64(e.FrameType), amrToCFrameTypeBits)
	if e.Quality {
		w.writeBits(1, amrToCQualityBits)
	} else {
		w.writeBits(0, amrToCQualityBits)
	}
}

func readAMRToCEntryBits(r *bitReader) (AMRToCEntry, bool) {
	f, ok := r.readBits(amrToCFollowBits)
	if !ok {
		return AMRToCEntry{}, false
	}
	ft, ok := r.readBits(amrToCFrameTypeBits)
	if !ok {
		return AMRToCEntry{}, false
	}
	q, ok := r.readBits(amrToCQualityBits)
	if !ok {
		return AMRToCEntry{}, false
	}
	return AMRToCEntry{
		Follow:    f != 0,
		FrameType: int(ft),
		Quality:   q != 0,
	}, true
}

// MarshalBinary returns one EVS RTP payload using the default compact/header-full rules.
func (p EVSPayload) MarshalBinary() ([]byte, error) {
	return (EVSPayloadCodec{}).Marshal(p)
}

// AppendBinary appends one EVS RTP payload using the default compact/header-full rules.
func (p EVSPayload) AppendBinary(dst []byte) ([]byte, error) {
	return (EVSPayloadCodec{}).Append(dst, p)
}

// UnmarshalBinary decodes one EVS RTP payload using the default compact/header-full rules.
func (p *EVSPayload) UnmarshalBinary(payload []byte) error {
	decoded, err := (EVSPayloadCodec{}).Unmarshal(payload)
	if err != nil {
		return err
	}
	*p = decoded
	return nil
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
		if frameType == amrNoDataFrameType {
			return 0, nil
		}
		if frameType >= 0 && frameType < len(amrFrameBits) {
			return amrFrameBits[frameType], nil
		}
	case CodecAMRWB:
		if frameType == amrWBSpeechLostType || frameType == amrWBNoDataFrameType {
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

func evsFrameBytes(frameType int) (int, error) {
	bits, err := evsFrameBitLen(frameType)
	if err != nil {
		return 0, err
	}
	return bytesForBits(bits), nil
}

func evsFrameBitLen(frameType int) (int, error) {
	if frameType < 0 || frameType >= len(evsFrameBits) {
		return 0, fmt.Errorf("frame type %d is not defined for EVS", frameType)
	}
	if frameType == 13 {
		return 0, fmt.Errorf("frame type %d is reserved for EVS", frameType)
	}
	return evsFrameBits[frameType], nil
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
	return (bits + bitsPerByte - 1) / bitsPerByte
}

type bitReader struct {
	data []byte
	pos  int
}

func (r *bitReader) readBits(n int) (uint64, bool) {
	if n < 0 || r.pos+n > len(r.data)*bitsPerByte {
		return 0, false
	}
	var value uint64
	for range n {
		byteIndex := r.pos / bitsPerByte
		bitIndex := bitsPerByte - 1 - r.pos%bitsPerByte
		value = value<<1 | uint64((r.data[byteIndex]>>bitIndex)&1)
		r.pos++
	}
	return value, true
}

func (r *bitReader) readBytes(dst []byte, bits int) bool {
	for i := range dst {
		dst[i] = 0
	}
	for i := range bits {
		bit, ok := r.readBits(1)
		if !ok {
			return false
		}
		if bit != 0 {
			dst[i/bitsPerByte] |= 1 << (bitsPerByte - 1 - i%bitsPerByte)
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
	for i := range bits {
		bit := src[i/bitsPerByte]&(1<<(bitsPerByte-1-i%bitsPerByte)) != 0
		w.writeBit(bit)
	}
}

func (w *bitWriter) writeBit(value bool) {
	if w.pos/bitsPerByte == len(w.data) {
		w.data = append(w.data, 0)
	}
	if value {
		w.data[w.pos/bitsPerByte] |= 1 << (bitsPerByte - 1 - w.pos%bitsPerByte)
	}
	w.pos++
}

func (w *bitWriter) bytes() []byte {
	return append([]byte(nil), w.data...)
}
