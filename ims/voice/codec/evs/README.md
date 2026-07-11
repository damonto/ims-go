# EVS codec

This package runs the 3GPP EVS floating-point C reference implementation inside a wazero WebAssembly sandbox. The checked-in `evs.wasm` supports EVS Native and AMR-WB IO with one continuous encoder/decoder state machine.

Normal `AMR-WB/16000` sessions should continue to use `codec/amr/amrwb`, which is pure Go. Use this package for negotiated EVS sessions, including their AMR-WB IO frames; switching an EVS session to the separate pure-Go AMR-WB codec would lose the EVS state history required for a continuous mode switch.

## Ownership and lifecycle

The embedded WASM binary and all wazero types are private implementation details. The package deliberately has no global runtime, hidden instance pool, finalizer or background goroutine.

Production media services should create one parent-package `codec.Engine` when
the service starts. It compiles EVS once. Each call leg gets one isolated
`Session` containing both encoder and decoder state in a single WebAssembly
module:

```go
engine, err := codec.NewEngine(ctx)
if err != nil {
	return err
}
defer func() { _ = engine.Close(ctx) }()

session, err := engine.NewSession(ctx, codec.Config{
	Name: codec.EVS,
	Mode: codec.EVSMode13200,
})
if err != nil {
	return err
}
defer func() { _ = session.Close(ctx) }()

frame, err := session.Encode(ctx, nil, pcm)
pcm, err = session.Decode(ctx, pcm[:0], frame)
```

The zero-value EVS options select Native mode, 16 kHz PCM and the natural
bandwidth for that sample rate. AMR-WB IO only needs an explicit format and an
AMR-WB mode:

```go
session, err := engine.NewSession(ctx, codec.Config{
	Name: codec.EVS,
	Mode: codec.AMRWBMode1265,
	EVS: codec.EVSConfig{Format: codec.EVSAMRWBIO},
})
```

For a command, test or low-volume tool, `codec.NewSession` is the one-step
constructor. Its `Close` also releases the private Engine:

```go
session, err := codec.NewSession(ctx, cfg)
if err != nil {
	return err
}
defer func() { _ = session.Close(ctx) }()
```

EVS is intentionally not available through `codec.NewEncoder` or
`codec.NewDecoder`. Those lightweight factories remain for AMR and AMR-WB;
using them for EVS would create separate encoder and decoder modules, lose
continuous mode-switching state and repeat the expensive WASM compilation.

Call each `Session` serially. Closing the Engine also closes any Sessions that
were not closed explicitly. Applications do not need to understand WASI,
compiled modules or module naming.

`Configure` changes bitrate, bandwidth, DTX, RF and Native/AMR-WB IO mode without resetting history:

```go
err = session.Configure(ctx, codec.Config{
	Name: codec.EVS,
	Mode: codec.AMRWBMode1265,
	DTX:  true,
	EVS:  codec.EVSConfig{Format: codec.EVSAMRWBIO},
})
```

The Session accepts and produces 20 ms PCM16 frames at 8, 16, 32 or 48 kHz. `Frame` carries the codec format, FT, Q bit, core bit count and access-unit bytes. AMR-WB IO SID is the important exception: it has 35 codec-core bits plus STI and CMI, so `Bits` is 35 while `Data` is five bytes.

## Performance

The shared Engine keeps the roughly half-second compilation step out of call
setup. A call-scoped Session instantiates one module containing both directions;
do not create separate EVS encoders and decoders for a production call.

Run the checked-in benchmarks on the deployment architecture:

```sh
go test ./ims/voice/codec/evs -run '^$' -bench . -benchmem
```

The hot path caches stable WebAssembly memory addresses, reuses its PCM scratch
buffer and reads packed encoder metadata through one ABI call. The linker uses
a 2 MiB stack because the large reference-code states are heap allocated. Keep
the stack size conservative unless every supported rate, mode, DTX and RF path
is exercised on the target build.

## RTP and SDP

`voice.EVSPayloadCodec` implements EVS Compact and Header-Full payloads, CMR, AMR-WB IO bit rotation, frame aggregation and Header-Full collision-avoidance padding. Build it from negotiated media:

```go
payloadCodec := voice.EVSPayloadCodec{HeaderFullOnly: media.HFOnly}
```

Convert a codec frame to `voice.EVSFrame` without adding a storage-format header:

```go
rtpFrame := voice.EVSFrame{
	FrameType: frame.FrameType,
	Quality:   frame.Quality,
	AMRWBIO:   frame.Format == evs.AMRWBIO,
	Data:      frame.Data,
}
```

The SDP configuration supports `br`, `bw`, `mode-set`, `ch-aw-recv` and `hf-only`. `NegotiatedMedia.HFOnly` must be passed to `EVSPayloadCodec`; it is not a decoder option by itself.

Channel-aware RF encoding is enabled only for native 13.2 kbit/s with non-NB input and bandwidth. Received partial-copy frames must set `Frame.Partial` and `Frame.NextCoderType` before `Decode`. Packet loss uses `DecodeLost`; SID and no-data use normal `Decode` frames with FT 12/15 for Native or FT 9/15 for AMR-WB IO.

## Rebuilding `evs.wasm`

Normal `go build` and `go test` use the checked-in module and do not require a C compiler. To rebuild it:

```sh
cd ims/voice/codec/evs/c
make clean
make -j
```

The build requires Clang with the `wasm32-wasip1` target and a WASI sysroot. Override `WASI_SYSROOT` when it is not installed at `/usr/share/wasi-sysroot`. `sources.mk` is intentionally explicit: do not add the reference encoder/decoder CLI, RTP dump, jitter-buffer or file-I/O front ends to the product module. Product-specific changes belong in `evs_shim.c`; keep the reference libraries otherwise unchanged.

After changing Go dependencies, run `go mod tidy`.

## Release gate

The files under `c/lib_com`, `c/lib_enc` and `c/lib_dec` originate from the 3GPP EVS reference package identified in its readme as TS 26.443 version 12.14.0 / 13.10.0 / 14.6.0 / 15.4.0 / 16.3.0. A successful build is not a license or patent grant. Before distributing the source, the WebAssembly binary or a product containing EVS, have counsel verify the reference-code redistribution terms and the required EVS patent licensing for every target market.
