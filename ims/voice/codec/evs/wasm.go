package evs

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

//go:embed evs.wasm
var wasmBinary []byte

// Engine owns the wazero runtime, WASI host module and compiled EVS module.
// Create one Engine per media service and reuse it for call-scoped Codecs.
type Engine struct {
	mu       sync.Mutex
	creating sync.WaitGroup
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	codecs   map[*Codec]struct{}
	closed   bool
}

// NewEngine initializes the complete WebAssembly environment and compiles EVS
// once. No wazero object escapes this package.
func NewEngine(ctx context.Context) (*Engine, error) {
	runtime := wazero.NewRuntime(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("creating EVS engine: instantiating WASI: %w", err)
	}
	compiled, err := runtime.CompileModule(ctx, wasmBinary)
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("creating EVS engine: compiling module: %w", err)
	}
	return &Engine{
		runtime:  runtime,
		compiled: compiled,
		codecs:   make(map[*Codec]struct{}),
	}, nil
}

// NewCodec creates a self-contained Codec for simple or low-volume use. Its
// Close method also closes the private Engine. Services handling multiple calls
// should create one Engine and call Engine.NewCodec instead.
func NewCodec(ctx context.Context, cfg Config) (*Codec, error) {
	engine, err := NewEngine(ctx)
	if err != nil {
		return nil, err
	}
	codec, err := engine.NewCodec(ctx, cfg)
	if err != nil {
		_ = engine.Close(ctx)
		return nil, err
	}
	codec.ownsEngine = true
	return codec, nil
}

// NewCodec creates one isolated call-scoped codec instance.
func (e *Engine) NewCodec(ctx context.Context, cfg Config) (*Codec, error) {
	if e == nil {
		return nil, ErrEngineClosed
	}
	e.mu.Lock()
	if e.closed || e.runtime == nil || e.compiled == nil {
		e.mu.Unlock()
		return nil, ErrEngineClosed
	}
	runtime := e.runtime
	compiled := e.compiled
	e.creating.Add(1)
	e.mu.Unlock()

	codec, err := newCodec(ctx, runtime, compiled, cfg)
	if err != nil {
		e.creating.Done()
		return nil, err
	}
	e.mu.Lock()
	codec.engine = e
	e.codecs[codec] = struct{}{}
	e.mu.Unlock()
	e.creating.Done()
	return codec, nil
}

// Codec owns one isolated module instance and its encoder/decoder state.
// Codec is not safe for concurrent use.
type Codec struct {
	engine               *Engine
	module               api.Module
	memory               api.Memory
	encoder              uint32
	decoder              uint32
	sampleRate           int
	encConfig            EncoderConfig
	encoderPCMPtr        uint32
	encoderOutputPtr     uint32
	decoderInputPtr      uint32
	decoderInputCapacity int
	decoderOutputPtr     uint32
	pcmBytes             []byte
	functions            wasmFunctions
	ownsEngine           bool
	closed               bool
}

type wasmFunctions struct {
	abiVersion api.Function

	encoderCreate       api.Function
	encoderDestroy      api.Function
	encoderReset        api.Function
	encoderConfigure    api.Function
	encoderPCMPtr       api.Function
	encoderOutputPtr    api.Function
	encoderFrameSamples api.Function
	encoderDelaySamples api.Function
	encoderEncode       api.Function
	encoderResult       api.Function

	decoderCreate        api.Function
	decoderDestroy       api.Function
	decoderReset         api.Function
	decoderInputPtr      api.Function
	decoderInputCapacity api.Function
	decoderOutputPtr     api.Function
	decoderFrameSamples  api.Function
	decoderDelaySamples  api.Function
	decoderDecode        api.Function
}

func newCodec(ctx context.Context, runtime wazero.Runtime, compiled wazero.CompiledModule, cfg Config) (*Codec, error) {
	if runtime == nil {
		return nil, errors.New("creating EVS codec: runtime is nil")
	}
	if compiled == nil {
		return nil, errors.New("creating EVS codec: compiled module is nil")
	}
	if !validSampleRate(cfg.SampleRate) {
		return nil, fmt.Errorf("creating EVS codec: unsupported sample rate %d", cfg.SampleRate)
	}
	if cfg.Encoder.Bitrate == 0 {
		cfg.Encoder.Bitrate = 13200
		cfg.Encoder.Bandwidth = defaultBandwidth(cfg.SampleRate)
	}
	module, err := runtime.InstantiateModule(ctx, compiled, wazero.NewModuleConfig().WithName(""))
	if err != nil {
		return nil, fmt.Errorf("creating EVS codec: instantiating module: %w", err)
	}
	codec := &Codec{module: module, memory: module.Memory(), sampleRate: cfg.SampleRate, encConfig: cfg.Encoder}
	if err := codec.loadFunctions(); err != nil {
		_ = module.Close(ctx)
		return nil, err
	}
	version, err := codec.call(ctx, codec.functions.abiVersion)
	if err != nil {
		_ = module.Close(ctx)
		return nil, fmt.Errorf("creating EVS codec: reading ABI version: %w", err)
	}
	if version != ABIVersion {
		_ = module.Close(ctx)
		return nil, fmt.Errorf("creating EVS codec: ABI version %d, want %d", version, ABIVersion)
	}
	encoder, err := codec.call(ctx, codec.functions.encoderCreate,
		uint64(cfg.SampleRate), uint64(cfg.Encoder.Bitrate), uint64(cfg.Encoder.Bandwidth),
		boolParam(cfg.Encoder.DTX), uint64(cfg.Encoder.RF.Offset), uint64(cfg.Encoder.RF.Indicator))
	if err != nil || encoder == 0 {
		_ = module.Close(ctx)
		if err != nil {
			return nil, fmt.Errorf("creating EVS codec: creating encoder: %w", err)
		}
		return nil, errors.New("creating EVS codec: encoder rejected configuration")
	}
	codec.encoder = uint32(encoder)
	decoder, err := codec.call(ctx, codec.functions.decoderCreate, uint64(cfg.SampleRate))
	if err != nil || decoder == 0 {
		_, _ = codec.functions.encoderDestroy.Call(ctx, uint64(codec.encoder))
		_ = module.Close(ctx)
		if err != nil {
			return nil, fmt.Errorf("creating EVS codec: creating decoder: %w", err)
		}
		return nil, errors.New("creating EVS codec: decoder rejected configuration")
	}
	codec.decoder = uint32(decoder)
	if err := codec.loadMemoryLayout(ctx); err != nil {
		_, _ = codec.functions.encoderDestroy.Call(ctx, uint64(codec.encoder))
		_, _ = codec.functions.decoderDestroy.Call(ctx, uint64(codec.decoder))
		_ = module.Close(ctx)
		return nil, err
	}
	return codec, nil
}

func (c *Codec) loadMemoryLayout(ctx context.Context) error {
	encoderPCMPtr, err := c.call(ctx, c.functions.encoderPCMPtr, uint64(c.encoder))
	if err != nil {
		return fmt.Errorf("creating EVS codec: reading encoder pcm pointer: %w", err)
	}
	encoderOutputPtr, err := c.call(ctx, c.functions.encoderOutputPtr, uint64(c.encoder))
	if err != nil {
		return fmt.Errorf("creating EVS codec: reading encoder output pointer: %w", err)
	}
	decoderInputPtr, err := c.call(ctx, c.functions.decoderInputPtr, uint64(c.decoder))
	if err != nil {
		return fmt.Errorf("creating EVS codec: reading decoder input pointer: %w", err)
	}
	decoderInputCapacity, err := c.callInt(ctx, c.functions.decoderInputCapacity, uint64(c.decoder))
	if err != nil {
		return fmt.Errorf("creating EVS codec: reading decoder input capacity: %w", err)
	}
	decoderOutputPtr, err := c.call(ctx, c.functions.decoderOutputPtr, uint64(c.decoder))
	if err != nil {
		return fmt.Errorf("creating EVS codec: reading decoder output pointer: %w", err)
	}
	if encoderPCMPtr == 0 || encoderOutputPtr == 0 || decoderInputPtr == 0 ||
		decoderInputCapacity <= 0 || decoderOutputPtr == 0 {
		return errors.New("creating EVS codec: module returned an invalid memory layout")
	}
	c.encoderPCMPtr = uint32(encoderPCMPtr)
	c.encoderOutputPtr = uint32(encoderOutputPtr)
	c.decoderInputPtr = uint32(decoderInputPtr)
	c.decoderInputCapacity = decoderInputCapacity
	c.decoderOutputPtr = uint32(decoderOutputPtr)
	c.pcmBytes = make([]byte, c.FrameSamples()*2)
	return nil
}

// SampleRate returns the PCM sample rate in hertz.
func (c *Codec) SampleRate() int { return c.sampleRate }

// FrameSamples returns the number of PCM samples in a 20 ms frame.
func (c *Codec) FrameSamples() int { return c.sampleRate / 50 }

// EncoderDelay returns the reference encoder algorithmic delay in PCM samples.
func (c *Codec) EncoderDelay(ctx context.Context) (int, error) {
	if err := c.ensureOpen(); err != nil {
		return 0, err
	}
	delay, err := c.callInt(ctx, c.functions.encoderDelaySamples, uint64(c.encoder))
	if err != nil {
		return 0, fmt.Errorf("reading EVS encoder delay: %w", err)
	}
	return delay, nil
}

// DecoderDelay returns the reference decoder algorithmic delay in PCM samples.
func (c *Codec) DecoderDelay(ctx context.Context) (int, error) {
	if err := c.ensureOpen(); err != nil {
		return 0, err
	}
	delay, err := c.callInt(ctx, c.functions.decoderDelaySamples, uint64(c.decoder))
	if err != nil {
		return 0, fmt.Errorf("reading EVS decoder delay: %w", err)
	}
	return delay, nil
}

// EncoderConfig returns the current encoder configuration.
func (c *Codec) EncoderConfig() EncoderConfig { return c.encConfig }

// Configure changes encoder mode without resetting codec history. This is how
// an EVS session switches continuously between Native and AMR-WB IO.
func (c *Codec) Configure(ctx context.Context, cfg EncoderConfig) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	result, err := c.callI32(ctx, c.functions.encoderConfigure, uint64(c.encoder),
		uint64(cfg.Bitrate), uint64(cfg.Bandwidth), boolParam(cfg.DTX),
		uint64(cfg.RF.Offset), uint64(cfg.RF.Indicator))
	if err != nil {
		return fmt.Errorf("configuring EVS encoder: %w", err)
	}
	if result != 0 {
		return abiError("configuring EVS encoder", result)
	}
	c.encConfig = cfg
	return nil
}

// Encode encodes exactly one 20 ms PCM16 frame.
func (c *Codec) Encode(ctx context.Context, dst []byte, pcm []int16) (Frame, error) {
	if err := c.ensureOpen(); err != nil {
		return Frame{}, err
	}
	if len(pcm) != c.FrameSamples() {
		return Frame{}, fmt.Errorf("encoding EVS frame: pcm sample count %d, want %d", len(pcm), c.FrameSamples())
	}
	for i, sample := range pcm {
		binary.LittleEndian.PutUint16(c.pcmBytes[i*2:], uint16(sample))
	}
	if !c.memory.Write(c.encoderPCMPtr, c.pcmBytes) {
		return Frame{}, errors.New("encoding EVS frame: pcm memory is outside module")
	}
	result, err := c.callI32(ctx, c.functions.encoderEncode, uint64(c.encoder))
	if err != nil {
		return Frame{}, fmt.Errorf("encoding EVS frame: %w", err)
	}
	if result != 0 {
		return Frame{}, abiError("encoding EVS frame", result)
	}
	metadata, err := c.call(ctx, c.functions.encoderResult, uint64(c.encoder))
	if err != nil {
		return Frame{}, fmt.Errorf("encoding EVS frame: reading result: %w", err)
	}
	frameType := int(metadata & 0xff)
	ioMode := int((metadata >> 8) & 1)
	bits := int((metadata >> 16) & 0xffff)
	byteCount := int((metadata >> 32) & 0xffff)
	data, ok := c.memory.Read(c.encoderOutputPtr, uint32(byteCount))
	if !ok {
		return Frame{}, errors.New("encoding EVS frame: output memory is outside module")
	}
	dst = append(dst, data...)
	format := Native
	if ioMode != 0 {
		format = AMRWBIO
	}
	return Frame{Format: format, FrameType: frameType, Quality: true, Bits: bits, Data: dst}, nil
}

// Decode decodes one access unit. Lost, no-data and partial-copy frames use the
// same stateful path as received speech frames.
func (c *Codec) Decode(ctx context.Context, dst []int16, frame Frame) ([]int16, error) {
	if err := c.ensureOpen(); err != nil {
		return nil, err
	}
	if frame.Bits == 0 {
		bits, err := FrameBits(frame.Format, frame.FrameType)
		if err != nil {
			return nil, err
		}
		frame.Bits = bits
	}
	if err := frame.validate(); err != nil {
		return nil, err
	}
	if len(frame.Data) > c.decoderInputCapacity {
		return nil, fmt.Errorf("decoding EVS frame: byte count %d exceeds module capacity %d", len(frame.Data), c.decoderInputCapacity)
	}
	if len(frame.Data) != 0 && !c.memory.Write(c.decoderInputPtr, frame.Data) {
		return nil, errors.New("decoding EVS frame: input memory is outside module")
	}
	result, err := c.callI32(ctx, c.functions.decoderDecode, uint64(c.decoder), uint64(frame.Bits),
		boolParam(frame.Format == AMRWBIO), uint64(frame.FrameType), boolParam(frame.Quality),
		boolParam(frame.Partial), uint64(frame.NextCoderType))
	if err != nil {
		return nil, fmt.Errorf("decoding EVS frame: %w", err)
	}
	if result != 0 {
		return nil, abiError("decoding EVS frame", result)
	}
	pcmBytes, ok := c.memory.Read(c.decoderOutputPtr, uint32(c.FrameSamples()*2))
	if !ok {
		return nil, errors.New("decoding EVS frame: output memory is outside module")
	}
	dst = growPCM(dst, c.FrameSamples())
	for i := range c.FrameSamples() {
		dst[i] = int16(binary.LittleEndian.Uint16(pcmBytes[i*2:]))
	}
	return dst, nil
}

// DecodeLost performs packet-loss concealment in the current decoder state.
func (c *Codec) DecodeLost(ctx context.Context, dst []int16, format Format) ([]int16, error) {
	return c.Decode(ctx, dst, Frame{Format: format, FrameType: 14, Quality: false})
}

// Reset clears encoder and decoder history while preserving configuration.
func (c *Codec) Reset(ctx context.Context) error {
	if err := c.ensureOpen(); err != nil {
		return err
	}
	encoderResult, encoderErr := c.callI32(ctx, c.functions.encoderReset, uint64(c.encoder))
	decoderResult, decoderErr := c.callI32(ctx, c.functions.decoderReset, uint64(c.decoder))
	if encoderErr != nil || decoderErr != nil {
		return errors.Join(encoderErr, decoderErr)
	}
	if encoderResult != 0 {
		return abiError("resetting EVS encoder", encoderResult)
	}
	if decoderResult != 0 {
		return abiError("resetting EVS decoder", decoderResult)
	}
	return nil
}

// Close destroys C state and closes the module. A Codec created by the package
// NewCodec function also closes its private Engine.
func (c *Codec) Close(ctx context.Context) error {
	if c == nil {
		return nil
	}
	if c.ownsEngine && c.engine != nil {
		return c.engine.Close(ctx)
	}
	if c.engine != nil {
		return c.engine.closeCodec(ctx, c)
	}
	return c.close(ctx)
}

func (c *Codec) close(ctx context.Context) error {
	if c.closed {
		return nil
	}
	c.closed = true
	var errs []error
	if c.encoder != 0 {
		if _, err := c.functions.encoderDestroy.Call(ctx, uint64(c.encoder)); err != nil {
			errs = append(errs, fmt.Errorf("closing EVS encoder: %w", err))
		}
		c.encoder = 0
	}
	if c.decoder != 0 {
		if _, err := c.functions.decoderDestroy.Call(ctx, uint64(c.decoder)); err != nil {
			errs = append(errs, fmt.Errorf("closing EVS decoder: %w", err))
		}
		c.decoder = 0
	}
	if err := c.module.Close(ctx); err != nil {
		errs = append(errs, fmt.Errorf("closing EVS module: %w", err))
	}
	return errors.Join(errs...)
}

// Close closes all call-scoped Codecs and the complete WebAssembly runtime.
// It is safe to call more than once.
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
	e.mu.Unlock()
	e.creating.Wait()
	e.mu.Lock()
	var errs []error
	for codec := range e.codecs {
		if err := codec.close(ctx); err != nil {
			errs = append(errs, err)
		}
		delete(e.codecs, codec)
	}
	runtime := e.runtime
	e.runtime = nil
	e.compiled = nil
	e.mu.Unlock()
	if runtime != nil {
		if err := runtime.Close(ctx); err != nil {
			errs = append(errs, fmt.Errorf("closing EVS engine: %w", err))
		}
	}
	return errors.Join(errs...)
}

func (e *Engine) closeCodec(ctx context.Context, codec *Codec) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.codecs[codec]; !ok {
		return nil
	}
	delete(e.codecs, codec)
	return codec.close(ctx)
}

func (c *Codec) ensureOpen() error {
	if c == nil || c.closed {
		return ErrClosed
	}
	return nil
}

func (c *Codec) loadFunctions() error {
	bindings := []struct {
		name string
		dst  *api.Function
	}{
		{"evs_abi_version", &c.functions.abiVersion},
		{"evs_encoder_create", &c.functions.encoderCreate},
		{"evs_encoder_destroy", &c.functions.encoderDestroy},
		{"evs_encoder_reset", &c.functions.encoderReset},
		{"evs_encoder_configure", &c.functions.encoderConfigure},
		{"evs_encoder_pcm_ptr", &c.functions.encoderPCMPtr},
		{"evs_encoder_output_ptr", &c.functions.encoderOutputPtr},
		{"evs_encoder_frame_samples", &c.functions.encoderFrameSamples},
		{"evs_encoder_delay_samples", &c.functions.encoderDelaySamples},
		{"evs_encoder_encode", &c.functions.encoderEncode},
		{"evs_encoder_result", &c.functions.encoderResult},
		{"evs_decoder_create", &c.functions.decoderCreate},
		{"evs_decoder_destroy", &c.functions.decoderDestroy},
		{"evs_decoder_reset", &c.functions.decoderReset},
		{"evs_decoder_input_ptr", &c.functions.decoderInputPtr},
		{"evs_decoder_input_capacity", &c.functions.decoderInputCapacity},
		{"evs_decoder_output_ptr", &c.functions.decoderOutputPtr},
		{"evs_decoder_frame_samples", &c.functions.decoderFrameSamples},
		{"evs_decoder_delay_samples", &c.functions.decoderDelaySamples},
		{"evs_decoder_decode", &c.functions.decoderDecode},
	}
	for _, binding := range bindings {
		fn := c.module.ExportedFunction(binding.name)
		if fn == nil {
			return fmt.Errorf("creating EVS codec: module export %q is missing", binding.name)
		}
		*binding.dst = fn
	}
	if c.memory == nil {
		return errors.New("creating EVS codec: module memory export is missing")
	}
	return nil
}

func (c *Codec) call(ctx context.Context, fn api.Function, params ...uint64) (uint64, error) {
	results, err := fn.Call(ctx, params...)
	if err != nil {
		return 0, err
	}
	if len(results) == 0 {
		return 0, nil
	}
	return results[0], nil
}

func (c *Codec) callI32(ctx context.Context, fn api.Function, params ...uint64) (int32, error) {
	result, err := c.call(ctx, fn, params...)
	return int32(uint32(result)), err
}

func (c *Codec) callInt(ctx context.Context, fn api.Function, params ...uint64) (int, error) {
	result, err := c.callI32(ctx, fn, params...)
	return int(result), err
}

func boolParam(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func abiError(action string, code int32) error {
	var reason string
	switch code {
	case -1:
		reason = "invalid argument"
	case -2:
		reason = "memory allocation"
	case -3:
		reason = "sample rate"
	case -4:
		reason = "bitrate"
	case -5:
		reason = "bandwidth"
	case -6:
		reason = "frame"
	default:
		reason = "unknown"
	}
	return fmt.Errorf("%s: WASM code %d (%s)", action, code, reason)
}

func growPCM(dst []int16, size int) []int16 {
	if cap(dst) < size {
		return make([]int16, size)
	}
	return dst[:size]
}

func defaultBandwidth(sampleRate int) Bandwidth {
	switch sampleRate {
	case SampleRateNB:
		return BandwidthNB
	case SampleRateWB:
		return BandwidthWB
	case SampleRateSWB:
		return BandwidthSWB
	default:
		return BandwidthFB
	}
}
