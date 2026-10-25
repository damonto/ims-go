# Working on ims-go

These instructions apply to the whole repository. Make small, readable changes
that preserve protocol behavior, resource ownership, and interoperability.
Explain decisions clearly enough for a developer learning Go to follow them.

## Project and package boundaries

The module is `github.com/damonto/ims-go`; the root package is named `ims`.
Use the Go version required by `go.mod` (currently Go 1.26.3 or newer).

| Location | Responsibility |
| --- | --- |
| Root `*.go` | Public `Client`, configuration, access selection, connection/reconnect lifecycle, state, event subscriptions, and service facades |
| `ims/identity`, `ims/pidf` | Subscriber identities and geolocation payloads |
| `ims/sip` | SIP messages, headers, serialization, and response errors |
| `ims/session` | SIP transports, transactions, dispatch, and attachments |
| `ims/registration`, `ims/security` | REGISTER/subscription flows, AKA authentication, and IMS security negotiation |
| `ims/sms`, `ims/ussd`, `ims/voice` | Service protocols, dialogs, SDP, and RTP/RTCP |
| `ims/voice/codec` | Pure-Go AMR/AMR-WB and PCMU codecs; sandboxed EVS reference codec |
| `swu/ike`, `swu/handshake`, `swu/tunnel` | IKE wire format, handshake state, and the live ePDG tunnel lifecycle |
| `eapaka` | EAP-AKA/AKA' encoding and key derivation |
| `ipsec`, `lte/ipsec`, `ipsec/transport` | Shared packet contracts, ESP data planes, security associations, and userspace TCP/IP integration |
| `lte` | IMS PDN configuration, addresses, routing, and access information |
| `wfcsetup` | Carrier Wi-Fi Calling entitlement and activation flows |
| `examples` | Linux command demonstrating SIM access, VoWiFi registration, SMS, and USSD |
| `ims.json`, `ims_profile.go` | Embedded carrier profiles, matching, and application of defaults |
| `specs` | Local 3GPP/ETSI, GSMA, and RFC specifications |

Keep code in the package that owns its behavior. Lower-level protocol packages
must not import the root client package. Preserve the existing layout; do not
introduce `cmd`, `pkg`, `internal`, or a new architectural layer without a
concrete need in the task. Avoid catch-all packages such as `common`, `shared`,
`utils`, and `base`.

## Before changing code

1. Inspect `git status` and read the affected implementation and nearby tests.
   Preserve existing user changes, including edits to `go.mod` and `go.sum`.
2. Trace the relevant call path across package boundaries. Changes to a wire
   format, timer, state transition, or carrier default can affect both access
   modes and several services.
3. Cross-check protocol behavior against the relevant sections in `specs`.
   Where 3GPP and an RFC differ, prefer the more permissive interoperable
   behavior and record the sections and rationale. This is not a reason to
   bypass authentication, integrity, replay protection, or packet bounds.
4. Verify unfamiliar Go and dependency APIs with Context7. Check the versions
   in `go.mod` and the installed source or `go doc` as well. If Context7 does
   not cover a dependency, use its versioned source and official examples;
   explain any remaining uncertainty instead of inventing an API.

`refs` contains optional, ignored reference implementations and local research.
Use it for comparison when available, but do not make builds or tests depend on
it. Reference implementations supplement the specifications.

## Go style and design

Follow the [Google Go Style Guide](https://google.github.io/styleguide/go/guide)
and the conventions of the surrounding package. Repository-specific rules take
precedence. Format changed Go files with `gofmt`; avoid unrelated style churn.

- Prefer the standard library and the dependencies already in `go.mod`.
  Use `slices` and `maps` when they express the operation clearly; ordinary
  loops are appropriate for protocol parsing and domain-specific comparisons.
- Keep control flow flat, use early returns, and favor explicit data flow over
  reflection, speculative frameworks, or generic abstractions.
- Use concrete types by default. Define small interfaces at the consumer when
  they represent a real transport, SIM, data-plane, or testing boundary.
  Do not add an interface solely to mirror a struct's methods.
- Prefer composition. Embed a type only when its promoted API is intentional.
  Keep configuration and wire types separate when they have different roles.
- Use typed configuration structs for related settings. Avoid constructors with
  long argument lists and functional options for simple configuration.
- Use domain names and conventional initialisms (`SIP`, `IMS`, `IPSec`, `ctx`,
  `err`, `req`, `mu`), following existing exported names. Avoid vague names such
  as `Manager`, `Helper`, and `Base`. Use `Handler` for HTTP handlers only.
- Use import aliases such as `imssession`, `imssms`, `imsvoice`, and `swutunnel`
  where package names collide or their role would otherwise be unclear.
- Use specific types instead of `any` in service and protocol APIs. Type
  parameters are appropriate for actual reusable containers, as in the event
  broadcaster; do not remove working generics just to avoid `any`.
- Follow the existing `encoding.TextMarshaler`, `encoding.BinaryMarshaler`,
  appender, and `io.WriterTo` patterns for wire types where applicable.
- Document exported behavior, ownership, concurrency restrictions, and reasons
  for protocol quirks. Comments should explain constraints and decisions.
  Library files stay in their existing package; only commands use `package main`.

## Errors, concurrency, and ownership

- Use `errors.New` for fixed errors and `%w` when adding useful context.
  Avoid redundant wrapping and prefixes such as "failed to", "unable to", or
  "error". Use `errors.Is` and `errors.AsType` for control flow, not error text.
- Handle cleanup errors deliberately. Use `errors.Join` when both the main
  operation and cleanup fail. Do not discard a resource failure merely because
  a joined error also contains cancellation.
- Pass `ctx context.Context` first. Do not store request contexts in structs.
  Every goroutine needs an exit condition and an owner that waits for it;
  use cancellation or a done channel with a wait group as appropriate.
- Protect shared state with the existing locks. Keep blocking I/O and external
  callbacks outside state locks. Preserve the ownership and lock assumptions
  around `clientState`, `activeConn`, and connection setup rollback.
- `New` takes ownership of the reader, including closing it on construction
  failure. Preserve idempotent shutdown and rollback of partially opened
  resources. Keep context cancellation effective during initial SIM loading.
- Public event subscriptions deliver future events and may drop events for slow
  readers. Preserve nonblocking publication and the separate ordered updates
  of `SMSSubmission`; do not silently change delivery semantics.
- Clone mutable slices, IP addresses, and snapshots when ownership crosses an
  API boundary. Preserve the detached `Client.Registration` snapshot contract.

## Protocol, profile, and platform changes

- Keep parsers bounded and validate lengths before indexing or allocating from
  network input. Preserve SIP framing, retransmission behavior, IKE message IDs,
  cryptographic transform validation, and ESP sequence/replay rules.
- Keep carrier differences in configuration/profile handling where possible.
  Read `withIMSProfile` before changing precedence: some profile fields replace
  settings rather than only filling zero values. Preserve the distinction
  between an omitted setting and an explicit value.
- For `ims.json` changes, add focused profile matching/normalization coverage.
  Avoid reformatting the full dataset or embedding real subscriber information
  in fixtures or logs.
- Respect `//go:build` constraints and OS-specific socket files. The QCOM/MBIM
  adapters and example command are Linux-only; compilation alone does not prove
  modem, carrier, or dedicated voice-bearer support.
- `ipsec/transport/netstack` is a maintained gVisor subset. Preserve upstream
  notices and generated files. Read its README before changes; upstream updates
  require builds for Linux, macOS, and Windows on both amd64 and arm64.
- EVS uses the checked-in `evs.wasm`. Normal Go builds need no C toolchain.
  Keep reference C changes isolated to the shim where possible, preserve source
  notices, and rebuild the WASM asset when its source changes. Check the current
  Go API in `evs/wasm.go` rather than copying an unverified documentation snippet.

## Testing and verification

Use the standard `testing` package, colocate tests with the implementation, and
use table-driven cases with `t.Run` for input/output variants. A stateful
scenario can stay a direct test when a table would obscure the sequence.
Reuse existing fakes and transport hooks; keep their cancellation, error, and
close behavior consistent with the real implementation.

Test observable behavior: valid and malformed packets, protocol error responses,
timeouts, cancellation, reconnect/rollback, and repeated close where relevant.
Use `t.Helper` and `t.Cleanup` for test resources. Prefer explicit synchronization
and bounded waits over timing guesses. Unit tests should not require a real SIM,
modem, or carrier connection; some tests need local loopback sockets.

After a code change, run the affected tests first, then the repository checks:

```sh
go test ./...
go vet ./...
```

For changes to shared state, goroutines, events, or shutdown, also run:

```sh
go test -race ./...
```

For dependency changes, run `go mod tidy`, inspect the diff, and include only
intentional module updates. Do not run it as an unrelated documentation cleanup.
For documentation changes, verify paths, flags, and API examples against the
implementation; compile any new Go example without contacting a carrier.

If permissions, dependency access, or unavailable hardware prevent a check,
report the exact limitation. Do not weaken tests or claim unperformed checks.
In the final response, state what changed, what was verified, and any remaining
limitations. When teaching a Go idiom, explain the practical reason briefly;
use before/after examples when they help the requested change.
