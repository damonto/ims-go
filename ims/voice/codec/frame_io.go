package codec

import (
	"errors"
	"fmt"
	"io"

	"github.com/damonto/ims-go/ims/voice/codec/amr/amrnb"
	"github.com/damonto/ims-go/ims/voice/codec/amr/amrwb"
)

// AppendBinary appends one binary speech frame to dst.
func (f Frame) AppendBinary(dst []byte) ([]byte, error) {
	switch NormalizeName(f.Name) {
	case AMR:
		return (amrnb.Frame{
			Mode:    amrnb.Mode(f.Mode),
			Quality: f.Quality,
			Data:    f.Data,
		}).AppendBinary(dst)
	case AMRWB:
		return (amrwb.Frame{
			Mode:    amrwb.Mode(f.Mode),
			Quality: f.Quality,
			Data:    f.Data,
		}).AppendBinary(dst)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCodec, f.Name)
	}
}

// MarshalBinary returns one binary speech frame.
func (f Frame) MarshalBinary() ([]byte, error) {
	return f.AppendBinary(nil)
}

// UnmarshalBinary fills f from one binary speech frame.
//
// Set f.Name before calling so the decoder can choose AMR-NB or AMR-WB.
func (f *Frame) UnmarshalBinary(data []byte) error {
	switch name := NormalizeName(f.Name); name {
	case AMR:
		var frame amrnb.Frame
		if err := frame.UnmarshalBinary(data); err != nil {
			return err
		}
		f.Name = AMR
		f.Mode = Mode(frame.Mode)
		f.Quality = frame.Quality
		f.Data = append(f.Data[:0], frame.Data...)
		return nil
	case AMRWB:
		var frame amrwb.Frame
		if err := frame.UnmarshalBinary(data); err != nil {
			return err
		}
		f.Name = AMRWB
		f.Mode = Mode(frame.Mode)
		f.Quality = frame.Quality
		f.Data = append(f.Data[:0], frame.Data...)
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedCodec, f.Name)
	}
}

// WriteTo writes one binary speech frame to w.
func (f Frame) WriteTo(w io.Writer) (int64, error) {
	switch NormalizeName(f.Name) {
	case AMR:
		return (amrnb.Frame{
			Mode:    amrnb.Mode(f.Mode),
			Quality: f.Quality,
			Data:    f.Data,
		}).WriteTo(w)
	case AMRWB:
		return (amrwb.Frame{
			Mode:    amrwb.Mode(f.Mode),
			Quality: f.Quality,
			Data:    f.Data,
		}).WriteTo(w)
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedCodec, f.Name)
	}
}

// ReadFrom reads one binary speech frame from r.
//
// Set f.Name before calling so the decoder can choose AMR-NB or AMR-WB.
func (f *Frame) ReadFrom(r io.Reader) (int64, error) {
	switch name := NormalizeName(f.Name); name {
	case AMR:
		var frame amrnb.Frame
		n, err := frame.ReadFrom(r)
		if err != nil {
			return n, err
		}
		f.Name = AMR
		f.Mode = Mode(frame.Mode)
		f.Quality = frame.Quality
		f.Data = append(f.Data[:0], frame.Data...)
		return n, nil
	case AMRWB:
		var frame amrwb.Frame
		n, err := frame.ReadFrom(r)
		if err != nil {
			return n, err
		}
		f.Name = AMRWB
		f.Mode = Mode(frame.Mode)
		f.Quality = frame.Quality
		f.Data = append(f.Data[:0], frame.Data...)
		return n, nil
	default:
		return 0, fmt.Errorf("%w: %q", ErrUnsupportedCodec, f.Name)
	}
}

// FrameReader reads consecutive binary speech frames for one codec family.
type FrameReader struct {
	r    io.Reader
	name Name
}

// NewFrameReader returns a reader for binary frames of name.
func NewFrameReader(r io.Reader, name Name) *FrameReader {
	return &FrameReader{r: r, name: NormalizeName(name)}
}

// ReadFrame reads the next binary speech frame.
func (r *FrameReader) ReadFrame() (Frame, error) {
	if r.r == nil {
		return Frame{}, errors.New("reading codec frame: reader is nil")
	}
	frame := Frame{Name: r.name}
	if _, err := frame.ReadFrom(r.r); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

// FrameWriter writes consecutive binary speech frames.
type FrameWriter struct {
	w io.Writer
}

// NewFrameWriter returns a writer for binary frames.
func NewFrameWriter(w io.Writer) *FrameWriter {
	return &FrameWriter{w: w}
}

// WriteFrame writes one binary speech frame.
func (w *FrameWriter) WriteFrame(frame Frame) (int64, error) {
	if w.w == nil {
		return 0, errors.New("writing codec frame: writer is nil")
	}
	return frame.WriteTo(w.w)
}
