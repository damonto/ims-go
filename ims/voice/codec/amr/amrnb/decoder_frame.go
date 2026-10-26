package amrnb

import "fmt"

const (
	amrSIDRxTypeBitOffset = 35
	amrSIDRxModeBitOffset = 36
	numAMRSIDRxModeBits   = 3
)

// RXFrameType identifies the receive-side frame class used by the AMR-NB decoder.
type RXFrameType int

const (
	RXSpeechGood RXFrameType = iota
	RXSpeechDegraded
	RXOnset
	RXSpeechBad
	RXSIDFirst
	RXSIDUpdate
	RXSIDBad
	RXNoData
)

type decoderFrame struct {
	mode   Mode
	rxType RXFrameType
	serial []byte
	params []int16
}

type decodedSpeechFrame struct {
	samples []int16
}

func (s *decoderCoreState) decodeGoodFrame(mode Mode, params []int16, dst []int16) (int, decodedSpeechFrame, error) {
	return s.decodeSpeechFrame(mode, params, dst, speechFrameOptions{})
}

type speechFrameOptions struct {
	badFrame         bool
	potentialDegrade bool
}

func (s *decoderCoreState) decodeSpeechFrame(
	mode Mode,
	params []int16,
	dst []int16,
	options speechFrameOptions,
) (int, decodedSpeechFrame, error) {
	if mode < Mode475 || mode > Mode1220 {
		return 0, decodedSpeechFrame{}, fmt.Errorf("AMR-NB speech mode %d is not supported", mode)
	}

	s.updateBadFrameState(options.badFrame)
	prevLSF := s.lsfState.pastLSFQ
	consumed, err := s.decodeFrameLPC(mode, params, options.badFrame)
	if err != nil {
		return 0, decodedSpeechFrame{}, err
	}

	if cap(dst) < FrameSamples {
		dst = make([]int16, 0, FrameSamples)
	} else {
		dst = dst[:0]
	}

	var subframeSamplesBuf [subframeSamples]int16
	for subframe := range 4 {
		subframeLSF, err := interpolateLSF(prevLSF[:], s.lsfState.pastLSFQ[:], subframe)
		if err != nil {
			return 0, decodedSpeechFrame{}, err
		}
		used, decoded, err := s.decodeGoodSubframe(decodeGoodSubframeInput{
			mode:             mode,
			subframe:         subframe,
			params:           params[consumed:],
			dst:              subframeSamplesBuf[:],
			badFrame:         options.badFrame,
			potentialDegrade: options.potentialDegrade,
			lsfForCBGain:     subframeLSF[:],
		})
		if err != nil {
			return 0, decodedSpeechFrame{}, fmt.Errorf("AMR-NB speech subframe %d: %w", subframe, err)
		}
		consumed += used
		dst = append(dst, decoded.samples...)
	}
	s.inBackgroundNoise, s.voicedHangover = s.background.detect(s.ltpGainHistory[:], dst, s.voicedHangover)
	s.dtx.activityUpdate(s.lsfState.pastLSFQ[:], dst)
	s.lspAvg.update(s.lsfState.pastLSFQ[:])
	s.prevBF = options.badFrame
	s.prevPDF = options.potentialDegrade

	return consumed, decodedSpeechFrame{samples: dst}, nil
}

func (s *decoderCoreState) decodeFrameLPC(mode Mode, params []int16, badFrame bool) (int, error) {
	if mode == Mode1220 {
		return s.decodeMR122LPC(params, badFrame)
	}
	return s.decodeLPC3(mode, params, badFrame)
}

func (s *decoderCoreState) updateBadFrameState(badFrame bool) {
	if badFrame {
		s.state++
	} else if s.state == 6 {
		s.state = 5
	} else {
		s.state = 0
	}
	s.state = min(s.state, 6)
}

func prepareDecoderFrame(
	dstSerial []byte,
	dstParams []int16,
	prevMode Mode,
	frameType Mode,
	speech []byte,
	quality bool,
) (decoderFrame, error) {
	if frameType == ModeNoData {
		return decoderFrame{mode: prevMode, rxType: RXNoData}, nil
	}
	if !validWireFrameType(frameType) {
		return decoderFrame{}, fmt.Errorf("AMR-NB frame type %d is not supported", frameType)
	}

	payload := Speech{Mode: frameType, Serial: dstSerial}
	err := payload.UnmarshalBinary(speech)
	if err != nil {
		return decoderFrame{}, err
	}
	serial := payload.Serial
	mode := frameType
	rxType := RXFrameType(RXSpeechGood)
	if !quality {
		rxType = RXSpeechBad
	}

	if frameType == ModeDTX {
		mode, rxType, err = decodeSIDFrame(serial, quality)
		if err != nil {
			return decoderFrame{}, err
		}
	}

	params, err := decoderFrameParams(dstParams, mode, rxType, serial)
	if err != nil {
		return decoderFrame{}, err
	}
	return decoderFrame{
		mode:   mode,
		rxType: rxType,
		serial: serial,
		params: params,
	}, nil
}

func decodeSIDFrame(serial []byte, quality bool) (Mode, RXFrameType, error) {
	if len(serial) != frameBits[ModeDTX] {
		return 0, 0, fmt.Errorf("AMR-NB SID serial bit count %d, want %d", len(serial), frameBits[ModeDTX])
	}
	mode := 0
	for i := range numAMRSIDRxModeBits {
		bit := serial[amrSIDRxModeBitOffset+i]
		if bit > 1 {
			return 0, 0, fmt.Errorf("AMR-NB SID mode bit %d is %d, want 0 or 1", i, bit)
		}
		mode |= int(bit) << i
	}
	if mode < int(Mode475) || mode > int(Mode1220) {
		return 0, 0, fmt.Errorf("AMR-NB SID mode %d is not a speech mode", mode)
	}
	if !quality {
		return Mode(mode), RXSIDBad, nil
	}
	if serial[amrSIDRxTypeBitOffset] == 0 {
		return Mode(mode), RXSIDFirst, nil
	}
	if serial[amrSIDRxTypeBitOffset] == 1 {
		return Mode(mode), RXSIDUpdate, nil
	}
	return 0, 0, fmt.Errorf("AMR-NB SID RX type bit is %d, want 0 or 1", serial[amrSIDRxTypeBitOffset])
}

func validWireFrameType(mode Mode) bool {
	return ValidMode(mode) || mode == ModeNoData
}

func decoderFrameParams(dst []int16, mode Mode, rxType RXFrameType, serial []byte) ([]int16, error) {
	paramMode := mode
	if rxType == RXSIDBad || rxType == RXSIDUpdate {
		paramMode = ModeDTX
	}
	total, err := ParameterSerialBits(paramMode)
	if err != nil {
		return nil, err
	}
	for i, bit := range serial {
		if bit > 1 {
			return nil, fmt.Errorf("decoding AMR-NB RX type %d: serial bit %d is %d, want 0 or 1", rxType, i, bit)
		}
	}

	// 3GPP COD files carry every frame in a fixed 244-bit ETS buffer. Compact
	// callers may pass only the mode parameters; SID frames additionally carry
	// four control bits that are not consumed by Params.
	switch len(serial) {
	case total:
	case MaxSerialBits:
		serial = serial[:total]
	case 0:
		if rxType != RXNoData {
			return nil, fmt.Errorf(
				"decoding AMR-NB RX type %d: serial bit count 0, want %d or %d",
				rxType,
				total,
				MaxSerialBits,
			)
		}
		serial = make([]byte, total)
	case frameBits[ModeDTX]:
		if rxType != RXSIDFirst && rxType != RXSIDUpdate && rxType != RXSIDBad {
			return nil, fmt.Errorf(
				"decoding AMR-NB RX type %d: serial bit count %d, want %d or %d",
				rxType,
				len(serial),
				total,
				MaxSerialBits,
			)
		}
		if total <= len(serial) {
			serial = serial[:total]
		} else {
			// OpenCORE runs SID_FIRST through the previous speech-mode Bits2prm
			// path, with the unavailable ETS tail behaving as zero-filled bits.
			padded := make([]byte, total)
			copy(padded, serial)
			serial = padded
		}
	default:
		return nil, fmt.Errorf(
			"decoding AMR-NB RX type %d: serial bit count %d, want %d or %d",
			rxType,
			len(serial),
			total,
			MaxSerialBits,
		)
	}

	params := Params{Mode: paramMode, Values: dst}
	if err := params.UnmarshalBinary(serial); err != nil {
		return nil, err
	}
	return params.Values, nil
}
