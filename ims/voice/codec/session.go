package codec

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/damonto/ims-go/ims/voice/codec/evs"
)

// ErrEngineClosed reports session creation after Engine.Close.
var ErrEngineClosed = errors.New("codec engine is closed")

// ErrUnsupportedReconfiguration reports a codec that cannot change mode
// without resetting its state.
var ErrUnsupportedReconfiguration = errors.New("codec reconfiguration is not supported")

// Session owns the encoder and decoder state for one call leg.
type Session interface {
	Encoder
	Decoder
	Configure(ctx context.Context, cfg Config) error
}

// Engine owns the process-level EVS compilation lifecycle. Create one Engine
// when the media service starts and reuse it for call-scoped Sessions.
type Engine struct {
	mu     sync.Mutex
	evs    *evs.Engine
	closed bool
}

// NewEngine compiles the embedded EVS module once for reuse across Sessions.
func NewEngine(ctx context.Context) (*Engine, error) {
	evsEngine, err := evs.NewEngine(ctx)
	if err != nil {
		return nil, fmt.Errorf("creating codec engine: %w", err)
	}
	return &Engine{evs: evsEngine}, nil
}

// NewSession creates one isolated call-scoped codec session.
func (e *Engine) NewSession(ctx context.Context, cfg Config) (Session, error) {
	if e == nil {
		return nil, ErrEngineClosed
	}
	e.mu.Lock()
	if e.closed || e.evs == nil {
		e.mu.Unlock()
		return nil, ErrEngineClosed
	}
	evsEngine := e.evs
	e.mu.Unlock()
	if NormalizeName(cfg.Name) != EVS {
		return newPureGoSession(ctx, cfg)
	}
	evsConfig, format, err := makeEVSConfig(cfg)
	if err != nil {
		return nil, err
	}
	instance, err := evsEngine.NewCodec(ctx, evsConfig)
	if err != nil {
		return nil, fmt.Errorf("creating EVS session: %w", err)
	}
	return &evsSession{codec: instance, decodeFormat: format}, nil
}

// Close closes all remaining Sessions and the shared EVS runtime.
func (e *Engine) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	evsEngine := e.evs
	e.evs = nil
	e.mu.Unlock()
	if evsEngine == nil {
		return nil
	}
	return evsEngine.Close(ctx)
}

// NewSession creates a self-contained Session for commands, tests and
// low-volume use. EVS services should reuse an Engine instead.
func NewSession(ctx context.Context, cfg Config) (Session, error) {
	if NormalizeName(cfg.Name) != EVS {
		return newPureGoSession(ctx, cfg)
	}
	evsConfig, format, err := makeEVSConfig(cfg)
	if err != nil {
		return nil, err
	}
	instance, err := evs.NewCodec(ctx, evsConfig)
	if err != nil {
		return nil, fmt.Errorf("creating EVS session: %w", err)
	}
	return &evsSession{codec: instance, decodeFormat: format}, nil
}

type pureGoSession struct {
	encoder Encoder
	decoder Decoder
}

func newPureGoSession(ctx context.Context, cfg Config) (Session, error) {
	encoder, err := NewEncoder(ctx, cfg)
	if err != nil {
		return nil, err
	}
	decoder, err := NewDecoder(ctx, cfg.Name)
	if err != nil {
		return nil, errors.Join(err, encoder.Close(ctx))
	}
	return &pureGoSession{encoder: encoder, decoder: decoder}, nil
}

func (s *pureGoSession) Name() Name { return s.encoder.Name() }

func (s *pureGoSession) SampleRate() int { return s.encoder.SampleRate() }

func (s *pureGoSession) FrameSamples() int { return s.encoder.FrameSamples() }

func (s *pureGoSession) Encode(ctx context.Context, dst []byte, pcm []int16) (Frame, error) {
	return s.encoder.Encode(ctx, dst, pcm)
}

func (s *pureGoSession) Decode(ctx context.Context, dst []int16, frame Frame) ([]int16, error) {
	return s.decoder.Decode(ctx, dst, frame)
}

func (s *pureGoSession) DecodeLost(ctx context.Context, dst []int16) ([]int16, error) {
	return s.decoder.DecodeLost(ctx, dst)
}

func (s *pureGoSession) Configure(context.Context, Config) error {
	return fmt.Errorf("%w: %s", ErrUnsupportedReconfiguration, s.Name())
}

func (s *pureGoSession) Reset(ctx context.Context) error {
	return errors.Join(s.encoder.Reset(ctx), s.decoder.Reset(ctx))
}

func (s *pureGoSession) Close(ctx context.Context) error {
	return errors.Join(s.encoder.Close(ctx), s.decoder.Close(ctx))
}
