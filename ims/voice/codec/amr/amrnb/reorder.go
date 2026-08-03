package amrnb

import (
	"fmt"
	"io"
	"slices"

	amrbitstream "github.com/damonto/ims-go/ims/voice/codec/amr/bitstream"
)

// Speech carries AMR-NB ETS serial bits for speech payload conversion.
type Speech struct {
	Mode   Mode
	Serial []byte
}

var speechSpec = amrbitstream.SpeechSpec{
	Codec: "AMR-NB",
	Order: func(mode int) ([]int, error) {
		return reorderBitsForMode(Mode(mode))
	},
	BitLen: func(mode int) (int, error) {
		return FrameBitLen(Mode(mode))
	},
}

// Pack packs ETS serial bits into the AMR-NB speech byte order used after the RTP ToC.
func (s Speech) Pack(dst []byte) ([]byte, error) {
	return speechSpec.Pack(dst, int(s.Mode), s.Serial)
}

// AppendBinary appends AMR-NB speech payload bytes for s.
func (s Speech) AppendBinary(dst []byte) ([]byte, error) {
	return speechSpec.AppendSpeech(dst, int(s.Mode), s.Serial)
}

// MarshalBinary returns AMR-NB speech payload bytes for s.
func (s Speech) MarshalBinary() ([]byte, error) {
	return speechSpec.MarshalSpeech(int(s.Mode), s.Serial)
}

// WriteTo writes AMR-NB speech payload bytes for s to w.
func (s Speech) WriteTo(w io.Writer) (int64, error) {
	return speechSpec.WriteSpeechTo(w, int(s.Mode), s.Serial)
}

// UnmarshalBinary unpacks AMR-NB speech bytes from the RTP payload order into ETS serial bits.
func (s *Speech) UnmarshalBinary(speech []byte) error {
	serial, err := speechSpec.UnmarshalSpeech(s.Serial, int(s.Mode), speech)
	if err != nil {
		return err
	}
	s.Serial = serial
	return nil
}

// ReadSpeechFrom reads one AMR-NB speech payload for s from r.
func (s *Speech) ReadSpeechFrom(r io.Reader) (int64, error) {
	serial, n, err := speechSpec.ReadSpeechFrom(r, s.Serial, int(s.Mode))
	if err != nil {
		return n, err
	}
	s.Serial = serial
	return n, nil
}

// ReorderBits returns the ETS-to-speech bit order table for mode.
func ReorderBits(mode Mode) ([]int, error) {
	reorder, err := reorderBitsForMode(mode)
	if err != nil {
		return nil, err
	}
	return slices.Clone(reorder), nil
}

func reorderBitsForMode(mode Mode) ([]int, error) {
	if mode == ModeNoData {
		return nil, nil
	}
	if !ValidMode(mode) {
		return nil, fmt.Errorf("AMR-NB reorder mode %d is not supported", mode)
	}
	return reorderBits[mode], nil
}

// FrameBitLen returns the number of AMR-NB speech bits for one frame.
func FrameBitLen(mode Mode) (int, error) {
	if mode == ModeNoData {
		return 0, nil
	}
	if !ValidMode(mode) {
		return 0, fmt.Errorf("AMR-NB frame mode %d is not supported", mode)
	}
	return frameBits[mode], nil
}
