package amrwb

import (
	"io"

	amrpayload "github.com/damonto/ims-go/ims/voice/codec/amr/payload"
)

var frameSpec = amrpayload.Spec{
	Codec: "AMR-WB",
	ValidMode: func(mode int) bool {
		return validWireFrameType(Mode(mode))
	},
	FrameBytes: func(mode int) (int, error) {
		return FrameBytes(Mode(mode))
	},
}

// Frame is one AMR-WB access unit without an RTP CMR byte.
type Frame struct {
	Mode    Mode
	Quality bool
	Data    []byte
}

// FrameHeader is one AMR-WB ToC byte for a single-frame binary payload.
type FrameHeader struct {
	Mode    Mode
	Quality bool
}

// AppendBinary appends the AMR-WB ToC byte for h.
func (h FrameHeader) AppendBinary(dst []byte) ([]byte, error) {
	return frameSpec.AppendHeader(dst, h.payloadHeader())
}

// MarshalBinary returns the AMR-WB ToC byte for h.
func (h FrameHeader) MarshalBinary() ([]byte, error) {
	return frameSpec.MarshalHeader(h.payloadHeader())
}

// WriteTo writes one AMR-WB ToC byte to w.
func (h FrameHeader) WriteTo(w io.Writer) (int64, error) {
	return frameSpec.WriteHeader(w, h.payloadHeader())
}

// UnmarshalBinary decodes one AMR-WB ToC byte into h.
func (h *FrameHeader) UnmarshalBinary(data []byte) error {
	var header amrpayload.Header
	if err := frameSpec.UnmarshalHeader(&header, data); err != nil {
		return err
	}
	h.setPayloadHeader(header)
	return nil
}

// ReadFrom reads one AMR-WB ToC byte from r.
func (h *FrameHeader) ReadFrom(r io.Reader) (int64, error) {
	var header amrpayload.Header
	n, err := frameSpec.ReadHeader(r, &header)
	if err != nil {
		return n, err
	}
	h.setPayloadHeader(header)
	return n, nil
}

// AppendBinary appends the AMR-WB ToC byte and speech bytes for f.
func (f Frame) AppendBinary(dst []byte) ([]byte, error) {
	return frameSpec.AppendFrame(dst, f.payloadFrame())
}

// MarshalBinary returns the AMR-WB ToC byte and speech bytes for f.
func (f Frame) MarshalBinary() ([]byte, error) {
	return frameSpec.MarshalFrame(f.payloadFrame())
}

// UnmarshalBinary decodes one AMR-WB frame encoded as ToC byte plus speech bytes.
func (f *Frame) UnmarshalBinary(data []byte) error {
	frame := amrpayload.Frame{Data: f.Data}
	if err := frameSpec.UnmarshalFrame(&frame, data); err != nil {
		return err
	}
	f.setPayloadFrame(frame)
	return nil
}

// WriteTo writes one AMR-WB binary frame to w.
func (f Frame) WriteTo(w io.Writer) (int64, error) {
	return frameSpec.WriteFrame(w, f.payloadFrame())
}

// ReadFrom reads one AMR-WB binary frame from r.
func (f *Frame) ReadFrom(r io.Reader) (int64, error) {
	frame := amrpayload.Frame{Data: f.Data}
	n, err := frameSpec.ReadFrame(r, &frame)
	if err != nil {
		return n, err
	}
	f.setPayloadFrame(frame)
	return n, nil
}

func (h FrameHeader) payloadHeader() amrpayload.Header {
	return amrpayload.Header{Mode: int(h.Mode), Quality: h.Quality}
}

func (h *FrameHeader) setPayloadHeader(header amrpayload.Header) {
	h.Mode = Mode(header.Mode)
	h.Quality = header.Quality
}

func (f Frame) payloadFrame() amrpayload.Frame {
	return amrpayload.Frame{Mode: int(f.Mode), Quality: f.Quality, Data: f.Data}
}

func (f *Frame) setPayloadFrame(frame amrpayload.Frame) {
	f.Mode = Mode(frame.Mode)
	f.Quality = frame.Quality
	f.Data = frame.Data
}
