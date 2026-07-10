package payload

import (
	"errors"
	"fmt"
	"io"
)

const (
	headerFollowFlag     = 0x80
	headerTypeShift      = 3
	headerTypeMask       = 0x0f
	headerQualityFlag    = 0x04
	headerPaddingBitMask = 0x03
)

// Spec describes the codec-specific parts of one AMR single-frame payload.
type Spec struct {
	Codec      string
	ValidMode  func(mode int) bool
	FrameBytes func(mode int) (int, error)
}

// Header is one AMR ToC byte without the follow bit.
type Header struct {
	Mode    int
	Quality bool
}

// Frame is one AMR access unit without an RTP CMR byte.
type Frame struct {
	Mode    int
	Quality bool
	Data    []byte
}

// AppendHeader appends the AMR ToC byte for h.
func (s Spec) AppendHeader(dst []byte, h Header) ([]byte, error) {
	if err := s.validateHeader("marshaling", h); err != nil {
		return nil, err
	}
	header := byte(h.Mode) << headerTypeShift
	if h.Quality {
		header |= headerQualityFlag
	}
	return append(dst, header), nil
}

// MarshalHeader returns the AMR ToC byte for h.
func (s Spec) MarshalHeader(h Header) ([]byte, error) {
	return s.AppendHeader(nil, h)
}

// WriteHeader writes one AMR ToC byte to w.
func (s Spec) WriteHeader(w io.Writer, h Header) (int64, error) {
	data, err := s.MarshalHeader(h)
	if err != nil {
		return 0, err
	}
	return writeFull(w, data)
}

// UnmarshalHeader decodes one AMR ToC byte into h.
func (s Spec) UnmarshalHeader(h *Header, data []byte) error {
	if h == nil {
		return errors.New("unmarshaling AMR frame header: missing destination")
	}
	if len(data) != 1 {
		return fmt.Errorf("unmarshaling %s frame header: byte count %d, want 1", s.codec(), len(data))
	}
	header := data[0]
	if header&headerFollowFlag != 0 {
		return fmt.Errorf("unmarshaling %s frame header: follow bit is set", s.codec())
	}
	if header&headerPaddingBitMask != 0 {
		return fmt.Errorf("unmarshaling %s frame header: padding bits are set", s.codec())
	}
	out := Header{
		Mode:    int((header >> headerTypeShift) & headerTypeMask),
		Quality: header&headerQualityFlag != 0,
	}
	if err := s.validateHeader("unmarshaling", out); err != nil {
		return err
	}
	*h = out
	return nil
}

// ReadHeader reads one AMR ToC byte from r.
func (s Spec) ReadHeader(r io.Reader, h *Header) (int64, error) {
	var data [1]byte
	n, err := io.ReadFull(r, data[:])
	if err != nil {
		return int64(n), fmt.Errorf("reading %s frame header: %w", s.codec(), err)
	}
	if err := s.UnmarshalHeader(h, data[:]); err != nil {
		return int64(n), err
	}
	return int64(n), nil
}

// AppendFrame appends the AMR ToC byte and speech bytes for f.
func (s Spec) AppendFrame(dst []byte, f Frame) ([]byte, error) {
	if err := s.validateFrame("marshaling", f); err != nil {
		return nil, err
	}
	dst, err := s.AppendHeader(dst, Header{Mode: f.Mode, Quality: f.Quality})
	if err != nil {
		return nil, err
	}
	return append(dst, f.Data...), nil
}

// MarshalFrame returns the AMR ToC byte and speech bytes for f.
func (s Spec) MarshalFrame(f Frame) ([]byte, error) {
	return s.AppendFrame(nil, f)
}

// WriteFrame writes one AMR binary frame to w.
func (s Spec) WriteFrame(w io.Writer, f Frame) (int64, error) {
	if err := s.validateFrame("marshaling", f); err != nil {
		return 0, err
	}
	n, err := s.WriteHeader(w, Header{Mode: f.Mode, Quality: f.Quality})
	if err != nil {
		return n, err
	}
	written, err := writeFull(w, f.Data)
	return n + written, err
}

// UnmarshalFrame decodes one AMR frame encoded as ToC byte plus speech bytes.
func (s Spec) UnmarshalFrame(f *Frame, data []byte) error {
	if f == nil {
		return errors.New("unmarshaling AMR frame: missing destination")
	}
	if len(data) == 0 {
		return fmt.Errorf("unmarshaling %s frame: frame is empty", s.codec())
	}
	var header Header
	if err := s.UnmarshalHeader(&header, data[:1]); err != nil {
		return err
	}
	want, err := s.frameBytes(header.Mode)
	if err != nil {
		return err
	}
	if len(data)-1 != want {
		return fmt.Errorf("unmarshaling %s frame: speech byte count %d, want %d", s.codec(), len(data)-1, want)
	}
	f.Mode = header.Mode
	f.Quality = header.Quality
	f.Data = append(f.Data[:0], data[1:]...)
	return nil
}

// ReadFrame reads one AMR binary frame from r.
func (s Spec) ReadFrame(r io.Reader, f *Frame) (int64, error) {
	if f == nil {
		return 0, errors.New("reading AMR frame: missing destination")
	}
	var header Header
	n, err := s.ReadHeader(r, &header)
	if err != nil {
		return n, err
	}
	size, err := s.frameBytes(header.Mode)
	if err != nil {
		return n, err
	}
	if cap(f.Data) < size {
		f.Data = make([]byte, size)
	} else {
		f.Data = f.Data[:size]
	}
	read, err := io.ReadFull(r, f.Data)
	n += int64(read)
	if err != nil {
		return n, fmt.Errorf("reading %s frame speech: %w", s.codec(), err)
	}
	f.Mode = header.Mode
	f.Quality = header.Quality
	return n, nil
}

func (s Spec) validateFrame(action string, f Frame) error {
	if err := s.validateHeader(action, Header{Mode: f.Mode, Quality: f.Quality}); err != nil {
		return err
	}
	want, err := s.frameBytes(f.Mode)
	if err != nil {
		return err
	}
	if len(f.Data) != want {
		return fmt.Errorf("%s %s frame: speech byte count %d, want %d", action, s.codec(), len(f.Data), want)
	}
	return nil
}

func (s Spec) validateHeader(action string, h Header) error {
	if h.Mode < 0 || h.Mode > headerTypeMask || s.ValidMode == nil || !s.ValidMode(h.Mode) {
		return fmt.Errorf("%s %s frame header: invalid mode %d", action, s.codec(), h.Mode)
	}
	return nil
}

func (s Spec) frameBytes(mode int) (int, error) {
	if s.FrameBytes == nil {
		return 0, fmt.Errorf("%s frame byte table is missing", s.codec())
	}
	return s.FrameBytes(mode)
}

func (s Spec) codec() string {
	if s.Codec == "" {
		return "AMR"
	}
	return s.Codec
}

func writeFull(w io.Writer, data []byte) (int64, error) {
	n, err := w.Write(data)
	if n != len(data) && err == nil {
		err = io.ErrShortWrite
	}
	return int64(n), err
}
