package amrwb

import (
	"fmt"
	"io"
	"slices"

	amrbitstream "github.com/damonto/ims-go/ims/voice/codec/amr/bitstream"
)

// Speech carries AMR-WB serial bits for speech payload conversion.
type Speech struct {
	Mode   Mode
	Serial []byte
}

var speechSpec = amrbitstream.SpeechSpec{
	Codec: "AMR-WB",
	Order: func(mode int) ([]int, error) {
		return sortBitsForMode(Mode(mode))
	},
	BitLen: func(mode int) (int, error) {
		return FrameBitLen(Mode(mode))
	},
}

// Pack packs AMR-WB serial bits into the speech byte order used after the RTP ToC.
func (s Speech) Pack(dst []byte) ([]byte, error) {
	return speechSpec.Pack(dst, int(s.Mode), s.Serial)
}

// AppendBinary appends AMR-WB speech payload bytes for s.
func (s Speech) AppendBinary(dst []byte) ([]byte, error) {
	return speechSpec.AppendSpeech(dst, int(s.Mode), s.Serial)
}

// MarshalBinary returns AMR-WB speech payload bytes for s.
func (s Speech) MarshalBinary() ([]byte, error) {
	return speechSpec.MarshalSpeech(int(s.Mode), s.Serial)
}

// WriteTo writes AMR-WB speech payload bytes for s to w.
func (s Speech) WriteTo(w io.Writer) (int64, error) {
	return speechSpec.WriteSpeechTo(w, int(s.Mode), s.Serial)
}

// UnmarshalBinary unpacks AMR-WB speech bytes from RTP payload order into serial bits.
func (s *Speech) UnmarshalBinary(speech []byte) error {
	serial, err := speechSpec.UnmarshalSpeech(s.Serial, int(s.Mode), speech)
	if err != nil {
		return err
	}
	s.Serial = serial
	return nil
}

// ReadFrom reads AMR-WB speech payload bytes for s from r.
func (s *Speech) ReadFrom(r io.Reader) (int64, error) {
	serial, n, err := speechSpec.ReadSpeechFrom(r, s.Serial, int(s.Mode))
	if err != nil {
		return n, err
	}
	s.Serial = serial
	return n, nil
}

// SortBits returns the serial-to-speech bit order table for mode.
func SortBits(mode Mode) ([]int, error) {
	sort, err := sortBitsForMode(mode)
	if err != nil {
		return nil, err
	}
	return slices.Clone(sort), nil
}

func sortBitsForMode(mode Mode) ([]int, error) {
	if mode == ModeSpeechLost || mode == ModeNoData {
		return nil, nil
	}
	if !ValidMode(mode) && mode != ModeSID {
		return nil, fmt.Errorf("AMR-WB sort mode %d is not supported", mode)
	}
	return sortBits[mode], nil
}

// FrameBitLen returns the number of AMR-WB speech bits for one frame.
func FrameBitLen(mode Mode) (int, error) {
	if mode == ModeSpeechLost || mode == ModeNoData {
		return 0, nil
	}
	if !ValidMode(mode) && mode != ModeSID {
		return 0, fmt.Errorf("AMR-WB frame mode %d is not supported", mode)
	}
	return frameBits[mode], nil
}
