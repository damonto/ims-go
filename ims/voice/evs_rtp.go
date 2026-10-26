package voice

import (
	"errors"
	"fmt"
)

const (
	evsCMRNoRequestType = 7
	evsCMRNoRequestMode = 15
	evsCompactNoRequest = 7
)

type evsProtectedPayload struct {
	bits      int
	amrwbIO   bool
	frameType int
}

var evsProtectedPayloads = []evsProtectedPayload{
	{48, false, 12},
	{56, false, 0},
	{136, true, 0},
	{144, false, 1},
	{160, false, 2},
	{184, true, 1},
	{192, false, 3},
	{256, true, 2},
	{264, false, 4},
	{288, true, 3},
	{320, true, 4},
	{328, false, 5},
	{368, true, 5},
	{400, true, 6},
	{464, true, 7},
	{480, true, 8},
	{488, false, 6},
	{640, false, 7},
	{960, false, 8},
	{1280, false, 9},
	{1920, false, 10},
	{2560, false, 11},
}

var evsAMRWBIOBits = []int{132, 177, 253, 285, 317, 365, 397, 461, 477, 35, 0, 0, 0, 0, 0, 0}

// Marshal returns one EVS RTP payload.
func (c EVSPayloadCodec) Marshal(payload EVSPayload) ([]byte, error) {
	return c.Append(nil, payload)
}

// Append appends one EVS RTP payload to dst.
func (c EVSPayloadCodec) Append(dst []byte, payload EVSPayload) ([]byte, error) {
	if len(payload.Frames) == 0 {
		return nil, errors.New("marshaling EVS payload: at least one frame is required")
	}
	for _, frame := range payload.Frames {
		if err := validateEVSFrame(frame); err != nil {
			return nil, fmt.Errorf("marshaling EVS payload: %w", err)
		}
	}
	if !c.HeaderFullOnly && !payload.HeaderFull && len(payload.Frames) == 1 {
		compact, ok, err := appendEVSCompact(dst, payload)
		if err != nil {
			return nil, err
		}
		if ok {
			return compact, nil
		}
	}
	return c.appendHeaderFull(dst, payload)
}

// Unmarshal parses one EVS RTP payload.
func (c EVSPayloadCodec) Unmarshal(data []byte) (EVSPayload, error) {
	if len(data) == 0 {
		return EVSPayload{}, errors.New("unmarshaling EVS payload: payload is empty")
	}
	bits := len(data) * bitsPerByte
	specialIOSID := bits == 56 && data[0]&evsHeaderHFlag != 0
	if !c.HeaderFullOnly && !specialIOSID {
		if protected, ok := evsProtectedPayloadForBits(bits); ok {
			return unmarshalEVSCompact(data, protected)
		}
	}
	return unmarshalEVSHeaderFull(data)
}

func appendEVSCompact(dst []byte, payload EVSPayload) ([]byte, bool, error) {
	frame := payload.Frames[0]
	if frame.AMRWBIO {
		if frame.FrameType < 0 || frame.FrameType > 8 {
			return nil, false, nil
		}
		cmr := evsCompactNoRequest
		if payload.CMR != nil {
			if payload.CMR.Type != 0 || payload.CMR.Mode < 0 || payload.CMR.Mode > 7 {
				return nil, false, nil
			}
			cmr = payload.CMR.Mode
		}
		protected, ok := evsProtectedPayloadForFrame(true, frame.FrameType)
		if !ok {
			return nil, false, nil
		}
		start := len(dst)
		dst = append(dst, make([]byte, protected.bits/bitsPerByte)...)
		out := dst[start:]
		setPayloadBits(out, 0, 3, uint64(cmr))
		coreBits := evsAMRWBIOBits[frame.FrameType]
		for bit := 1; bit < coreBits; bit++ {
			setPayloadBit(out, bit+2, payloadBit(frame.Data, bit))
		}
		setPayloadBit(out, coreBits+2, payloadBit(frame.Data, 0))
		return dst, true, nil
	}
	if payload.CMR != nil || frame.FrameType == evsSpeechLostType || frame.FrameType == evsNoDataType {
		return nil, false, nil
	}
	_, ok := evsProtectedPayloadForFrame(false, frame.FrameType)
	if !ok {
		return nil, false, nil
	}
	if frame.FrameType == 0 && frame.Data[0]&evsHeaderHFlag != 0 {
		return nil, false, nil
	}
	return append(dst, frame.Data...), true, nil
}

func (c EVSPayloadCodec) appendHeaderFull(dst []byte, payload EVSPayload) ([]byte, error) {
	start := len(dst)
	cmr := payload.CMR
	if cmr == nil && len(payload.Frames) == 1 && payload.Frames[0].AMRWBIO && payload.Frames[0].FrameType == 9 && !c.HeaderFullOnly {
		cmr = &EVSCMR{Type: evsCMRNoRequestType, Mode: evsCMRNoRequestMode}
	}
	if cmr != nil {
		if cmr.Type < 0 || cmr.Type > 7 || cmr.Mode < 0 || cmr.Mode > 15 {
			return nil, fmt.Errorf("marshaling EVS payload: CMR type/mode %d/%d is outside 0..7/0..15", cmr.Type, cmr.Mode)
		}
		dst = append(dst, evsHeaderHFlag|byte(cmr.Type<<4)|byte(cmr.Mode))
	}
	for i, frame := range payload.Frames {
		toc := byte(frame.FrameType & evsHeaderFrameMask)
		if i < len(payload.Frames)-1 {
			toc |= evsHeaderFFlag
		}
		if frame.AMRWBIO {
			toc |= evsHeaderAMRWBIO
			if frame.Quality {
				toc |= evsHeaderQuality
			}
		}
		dst = append(dst, toc)
	}
	for _, frame := range payload.Frames {
		dst = append(dst, frame.Data...)
	}
	if !c.HeaderFullOnly && (len(dst)-start != 7 || dst[start]&evsHeaderHFlag == 0) {
		for isEVSProtectedPayloadBits((len(dst) - start) * bitsPerByte) {
			dst = append(dst, 0)
		}
	}
	return dst, nil
}

func unmarshalEVSCompact(data []byte, protected evsProtectedPayload) (EVSPayload, error) {
	frameBytes, err := evsFrameDataBytes(protected.amrwbIO, protected.frameType)
	if err != nil {
		return EVSPayload{}, fmt.Errorf("unmarshaling EVS compact payload: %w", err)
	}
	frame := EVSFrame{FrameType: protected.frameType, Quality: true, AMRWBIO: protected.amrwbIO}
	if !protected.amrwbIO {
		frame.Data = append([]byte(nil), data...)
		return EVSPayload{Frames: []EVSFrame{frame}}, nil
	}
	frame.Data = make([]byte, frameBytes)
	coreBits := evsAMRWBIOBits[protected.frameType]
	setPayloadBit(frame.Data, 0, payloadBit(data, coreBits+2))
	for bit := 1; bit < coreBits; bit++ {
		setPayloadBit(frame.Data, bit, payloadBit(data, bit+2))
	}
	return EVSPayload{
		CMR:    &EVSCMR{Mode: int(readPayloadBits(data, 0, 3))},
		Frames: []EVSFrame{frame},
	}, nil
}

func unmarshalEVSHeaderFull(data []byte) (EVSPayload, error) {
	payload := EVSPayload{HeaderFull: true}
	offset := 0
	if data[0]&evsHeaderHFlag != 0 {
		payload.CMR = &EVSCMR{Type: int((data[0] >> 4) & 7), Mode: int(data[0] & 15)}
		offset++
	}
	if offset >= len(data) {
		return EVSPayload{}, errors.New("unmarshaling EVS header-full payload: table of contents is missing")
	}
	for {
		if offset >= len(data) {
			return EVSPayload{}, errors.New("unmarshaling EVS header-full payload: table of contents is truncated")
		}
		toc := data[offset]
		if toc&evsHeaderHFlag != 0 {
			return EVSPayload{}, errors.New("unmarshaling EVS header-full payload: CMR found inside table of contents")
		}
		frame := EVSFrame{
			FrameType: int(toc & evsHeaderFrameMask),
			AMRWBIO:   toc&evsHeaderAMRWBIO != 0,
		}
		if frame.AMRWBIO {
			frame.Quality = toc&evsHeaderQuality != 0
		} else {
			if toc&evsHeaderQuality != 0 {
				return EVSPayload{}, errors.New("unmarshaling EVS header-full payload: native ToC has reserved quality bit set")
			}
			frame.Quality = frame.FrameType != evsSpeechLostType
		}
		if _, err := evsFrameDataBytes(frame.AMRWBIO, frame.FrameType); err != nil {
			return EVSPayload{}, fmt.Errorf("unmarshaling EVS header-full payload: %w", err)
		}
		payload.Frames = append(payload.Frames, frame)
		offset++
		if toc&evsHeaderFFlag == 0 {
			break
		}
	}
	for i := range payload.Frames {
		frameBytes, err := evsFrameDataBytes(payload.Frames[i].AMRWBIO, payload.Frames[i].FrameType)
		if err != nil {
			return EVSPayload{}, fmt.Errorf("unmarshaling EVS header-full payload: frame %d: %w", i, err)
		}
		end := offset + frameBytes
		if end > len(data) {
			return EVSPayload{}, fmt.Errorf("unmarshaling EVS header-full payload: frame %d data is truncated", i)
		}
		payload.Frames[i].Data = append([]byte(nil), data[offset:end]...)
		offset = end
	}
	for _, padding := range data[offset:] {
		if padding != 0 {
			return EVSPayload{}, errors.New("unmarshaling EVS header-full payload: non-zero collision-avoidance padding")
		}
	}
	return payload, nil
}

func validateEVSFrame(frame EVSFrame) error {
	frameBytes, err := evsFrameDataBytes(frame.AMRWBIO, frame.FrameType)
	if err != nil {
		return err
	}
	if len(frame.Data) != frameBytes {
		return fmt.Errorf("frame type %d has %d bytes, want %d", frame.FrameType, len(frame.Data), frameBytes)
	}
	if !frame.AMRWBIO {
		if frame.FrameType == evsSpeechLostType && frame.Quality {
			return errors.New("native speech-lost frame must have bad quality")
		}
		if frame.FrameType != evsSpeechLostType && !frame.Quality {
			return errors.New("native EVS carries no bad-frame quality bit")
		}
	}
	return nil
}

func evsFrameDataBytes(amrwbIO bool, frameType int) (int, error) {
	if amrwbIO {
		if frameType < 0 || frameType >= len(evsAMRWBIOBits) || frameType >= 10 && frameType < 14 {
			return 0, fmt.Errorf("AMR-WB IO frame type %d is invalid", frameType)
		}
		if frameType == 9 {
			return 5, nil
		}
		return (evsAMRWBIOBits[frameType] + 7) / 8, nil
	}
	return evsFrameBytes(frameType)
}

func evsProtectedPayloadForBits(bits int) (evsProtectedPayload, bool) {
	for _, protected := range evsProtectedPayloads {
		if protected.bits == bits {
			return protected, true
		}
	}
	return evsProtectedPayload{}, false
}

func evsProtectedPayloadForFrame(amrwbIO bool, frameType int) (evsProtectedPayload, bool) {
	for _, protected := range evsProtectedPayloads {
		if protected.amrwbIO == amrwbIO && protected.frameType == frameType {
			return protected, true
		}
	}
	return evsProtectedPayload{}, false
}

func isEVSProtectedPayloadBits(bits int) bool {
	_, ok := evsProtectedPayloadForBits(bits)
	return ok
}

func payloadBit(data []byte, bit int) bool {
	return data[bit/bitsPerByte]&(1<<(bitsPerByte-1-bit%bitsPerByte)) != 0
}

func setPayloadBit(data []byte, bit int, value bool) {
	mask := byte(1 << (bitsPerByte - 1 - bit%bitsPerByte))
	if value {
		data[bit/bitsPerByte] |= mask
	} else {
		data[bit/bitsPerByte] &^= mask
	}
}

func setPayloadBits(data []byte, offset, count int, value uint64) {
	for bit := count - 1; bit >= 0; bit-- {
		setPayloadBit(data, offset+count-1-bit, value&(1<<bit) != 0)
	}
}

func readPayloadBits(data []byte, offset, count int) uint64 {
	var value uint64
	for bit := range count {
		value <<= 1
		if payloadBit(data, offset+bit) {
			value++
		}
	}
	return value
}
