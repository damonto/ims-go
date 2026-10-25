# ims-go

A Go library for connecting to an operator's IP Multimedia Subsystem (IMS)
through Wi-Fi Calling (VoWiFi) or an LTE IMS packet data network (VoLTE).
The module path is `github.com/damonto/ims-go`; its root package is `ims`.

The root client coordinates SIM authentication, access setup, IMS registration,
reconnection, and SMS, USSD, and voice services. Lower-level packages expose the
protocol implementations for applications that need more control.

## Capabilities

- **VoWiFi:** ePDG discovery, SWu IKEv2 with EAP-AKA/AKA', IPsec ESP, NAT-T,
  keepalives, rekeying, and P-CSCF selection/restoration.
- **VoLTE:** LTE IMS PDN access through Linux QCOM and MBIM adapters, interface
  binding, and IMS IPsec security negotiation.
- **IMS:** SIP over TCP/UDP, AKA registration, registration refresh and event
  subscriptions, carrier profiles, and coordinated multiple registrations.
- **SMS:** SMS over SIP MESSAGE, multipart text, incoming messages, submission
  updates, and delivery reports.
- **USSD:** outgoing and incoming sessions with interactive replies.
- **Voice:** outgoing and incoming calls, SDP negotiation, reliable provisional
  responses, session timers, hold/resume, RTP/RTCP transport, and DTMF.
- **Codecs:** pure-Go AMR, AMR-WB, and PCMU, plus a WebAssembly EVS reference
  implementation running in wazero.
- **Wi-Fi Calling setup:** TS.43, NSDS, and carrier-specific entitlement flows,
  including cases that require an activation or emergency-address web page.

Actual service availability depends on the SIM subscription, operator provisioning,
network, modem, and carrier profile. A matching profile is configuration data,
not a guarantee that every service has been tested on that network. Applications
provide their own audio capture/playback and media processing.

## Requirements

- **Go 1.26.3 or newer**, as declared in `go.mod`.
- A SIM/USIM reader capable of the required AKA operations. SIM and modem access
  is supplied by [wwan-go](https://github.com/damonto/wwan-go).
- For VoWiFi, a subscription enabled for Wi-Fi Calling and network access to
  the operator's ePDG and any required entitlement service. IKE/NAT-T normally
  use UDP ports 500 and 4500; profiles can override these settings.
- For the PC/SC example, a working PC/SC service, runtime library, reader driver,
  and permission to access the reader. On Linux the service is typically `pcscd`.
- For VoLTE, a supported Linux modem, IMS PDN addresses and P-CSCF information,
  and host interface/routing configuration. Some socket operations require
  additional OS privileges. IMS PDN readiness alone does not establish that a
  dedicated voice bearer is available.

The example command and QCOM/MBIM adapters are Linux-only. Other packages include
portable implementations and platform-specific socket code; hardware and runtime
support depend on the selected access path.

The userspace IP stack and `evs.wasm` are checked in. Normal Go builds do not
require Bazel, Clang, or a WASI SDK. Rebuilding EVS itself requires a WASI-capable
C toolchain.

## Install and verify

Add the library to an existing Go module:

```sh
go get github.com/damonto/ims-go
go mod tidy
```

To work from this repository:

```sh
git clone https://github.com/damonto/ims-go.git
cd ims-go
go mod download
go test ./...
go vet ./...
```

If a dependency requires repository access, configure your Git/Go credentials
before downloading it. Keep credentials out of the source tree.

Unit tests use simulated peers and local transports; no live SIM or carrier is
required. Some tests start loopback listeners, so the environment must permit
local sockets. Passing these tests does not verify a live carrier connection.

## Run the VoWiFi example

The [example command](examples/main.go) registers over VoWiFi, logs state and SMS
events, and can send an SMS or run an interactive USSD session. Run these commands
from the repository root on Linux.

List PC/SC readers, then use the exact reader name and your terminal's IMEI:

```sh
go run ./examples -list-readers
go run ./examples -driver pcsc -reader 'YOUR PC/SC READER' -imei 'YOUR_IMEI'
```

Send a message:

```sh
go run ./examples -driver pcsc -reader 'YOUR PC/SC READER' -imei 'YOUR_IMEI' \
  -send-to '+15551234567' -send-text 'Hello from ims-go'
```

Start an interactive USSD session:

```sh
go run ./examples -driver pcsc -reader 'YOUR PC/SC READER' -imei 'YOUR_IMEI' \
  -ussd '*100#'
```

Choose either the SMS flags or `-ussd` in one invocation. Registration/SMS mode
stays running to receive events; press Ctrl+C to close the client. In USSD mode,
an empty reply or `/bye`, `/end`, or `/quit` ends the session.

Other SIM access options are:

| Driver | Required options | Purpose |
| --- | --- | --- |
| `pcsc` (default) | `-reader` | Local PC/SC reader |
| `at` | `-device` | Serial modem with AT+CSIM support |
| `qmi` | `-device`, optional `-slot` | Qualcomm modem through QMI |
| `qrtr` | Optional `-slot` | Qualcomm modem through QRTR |
| `ccid-tcp` | `-device host:port` | APDU connection to the example's TCP bridge |

`-slot` defaults to 1. The example always selects `ims.VoWiFi`; choosing QMI or
QRTR changes SIM access, not the IMS access mode. It has no VoLTE or voice-call
command-line mode. Use the library API for those paths.

Use `go run ./examples -h` for all options, including `-epdg`, `-transport`,
identity overrides, terminal metadata, SIP timers, and IKE retransmission delays.

## Use the library

This minimal PC/SC program opens a reader, registers over VoWiFi, and stays
connected until Ctrl+C. Save it as `main.go` in a separate Go module, add ims-go
as above, then run `go run . -reader 'YOUR PC/SC READER' -imei 'YOUR_IMEI'`.

```go
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"

	"github.com/damonto/ims-go"
	"github.com/damonto/wwan-go/ccid"
	"github.com/damonto/wwan-go/sim"
)

func main() {
	if err := run(); err != nil {
		slog.Error("run IMS client", "err", err)
		os.Exit(1)
	}
}

func run() (resultErr error) {
	readerName := flag.String("reader", "", "PC/SC reader name")
	imei := flag.String("imei", "", "terminal IMEI")
	flag.Parse()
	if *readerName == "" || *imei == "" {
		return errors.New("provide -reader and -imei")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	tx, err := ccid.Open(ctx, *readerName)
	if err != nil {
		return fmt.Errorf("open SIM reader: %w", err)
	}
	reader, err := sim.NewReader(tx)
	if err != nil {
		return errors.Join(err, tx.Close())
	}

	// New takes ownership of reader, including on construction failure.
	client, err := ims.New(reader, &ims.Config{
		Terminal: ims.TerminalInfo{ID: *imei},
		Access:   ims.VoWiFi(ims.VoWiFiConfig{}),
	})
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, client.Close())
	}()

	if err := client.Connect(ctx); err != nil {
		return err
	}
	slog.Info("registered to IMS")
	<-ctx.Done()
	return nil
}
```

`Connect(ctx)` loads SIM state, applies configuration, checks VoWiFi entitlement
when applicable, establishes access, registers with IMS, and starts background
processing. Its context bounds connection setup; call `Close` to end the client
lifetime after a successful connection. The client handles reconnection after
recoverable connection failures. An initial connection failure is returned to
the caller. The minimal program returns entitlement errors directly; the full
example also handles pending activation and web-page completion.

### Services and events

| Entry point | Usage |
| --- | --- |
| `client.State()` | Read the current connection state and last error |
| `client.Registration()` | Read a detached snapshot of registered public identities |
| `client.Tunnel()` | Read SWu tunnel information; empty when no SWu tunnel is active |
| `client.Events()` | Subscribe to state, asynchronous errors, and registration changes |
| `client.SMS().Send(ctx, to, text)` | Send text and obtain an `SMSSubmission` with per-segment updates |
| `client.SMS().Events()` | Subscribe to incoming messages and status reports |
| `client.USSD().Start()` | Create a session; use `Send`, `Reply`, and `Close` with a context |
| `client.USSD().Events()` | Subscribe to network-initiated USSD sessions |
| `client.Voice().Dial(ctx, req)` | Dial using a `voice.DialRequest`; the returned call supports hangup, hold/resume, and DTMF |
| `client.Voice().Events()` | Subscribe to incoming calls, call events, and received DTMF |

Subscribe before `Connect` when startup events matter. Close every subscription
when finished and keep consuming its channels: publication is nonblocking, so
slow subscribers can lose events. `RegistrationChanged` coalesces notifications;
subscribe first, read `Registration()`, then refresh the snapshot after each
notification. `State()` provides the current state without requiring event history.

`SMSSubmission.Updates` is ordered per submission. A successful `Send` means the
message was submitted, not delivered to the recipient. Track the updates/reports
and call `SMSSubmission.Close()` when tracking is no longer needed. Multipart
sending can return both a partial submission and an error.

Voice signaling and negotiated packet transports are available through
`ims/voice`. Applications connect those transports to their audio pipeline and
selected codec; the client does not automatically turn RTP into device audio.

### Configuration and carrier profiles

Each client selects exactly one access mode: `ims.VoWiFi(ims.VoWiFiConfig{...})`
or `ims.VoLTE(lte.Config{...})`. For VoLTE, pass an IMS PDN-capable reader adapter
created with `ims.NewQCOMClient` or `ims.NewMBIMClient`. Configure the host network
through the adapter's `PDNNetwork` hook or provide an already configured interface
via `lte.Config.InterfaceName`.

`ims.Config` groups terminal identity, reconnection timing, access settings, and
`ims.ServiceConfig`. Set `Terminal.ID` to the terminal IMEI. Service settings cover
SIP identities and transport, registration/security parameters, SMS/USSD, and
`voice.Config`.

[`ims.json`](ims.json) is embedded at build time, not loaded from a runtime
configuration file. Profiles are selected by MCC/MNC and optional IMSI/ICCID
prefix, SPN, and GID selectors. [`ims_profile.go`](ims_profile.go) defines the schema,
match ranking, and application rules. Most zero-valued settings receive profile
defaults, but some profile-controlled settings replace configured values; check
that code before relying on an override. A SIM without a matching profile needs
explicit IMS IPsec integrity algorithms and any other network-specific settings.
When no ePDG is configured or supplied by a profile, its default address is derived
from the SIM's MCC/MNC.

For clients sharing a SIM and IMS identity, `ims.NewRegistrationGroup()` creates
a group to coordinate registration and AKA access. Assign it to each client's
`IMS.RegistrationGroup`; access-specific default registration IDs and preferences
are supplied by the root package. The group does not share reader ownership.

### Wi-Fi Calling activation

Entitlement may require user action before IMS connection can proceed. Check
`wfcsetup.ErrUserActionRequired`, `wfcsetup.ErrPending`, and `wfcsetup.ErrDenied`
with `errors.Is`. A typed `*wfcsetup.Error` carries the result, retry interval,
and any websheet URL and POST data.

The Linux example prints the required flow and accepts `DONE` or a supported
callback after the page completes, then rechecks entitlement. The
[`VoWiFiWebServiceFlow` adapter](examples/vowifi_service_flow.js) bridges those
callbacks for a host-provided web view. Applications supply their own activation
UI; the library does not open a browser automatically.

## Project layout

| Path | Contents |
| --- | --- |
| Root package | Public client, access adapters, lifecycle, configuration, events, and service facades |
| `ims/` | SIP, transactions, registration, security, identities, SMS, USSD, and voice |
| `ims/voice/codec/` | AMR, AMR-WB, PCMU, and EVS implementations |
| `swu/` | IKE wire types, handshake state, and ePDG tunnel management |
| `eapaka/` | EAP-AKA and AKA' wire messages and key derivation |
| `ipsec/` | ESP, packet codecs, cryptography, and userspace IP transport |
| `lte/` | LTE IMS PDN configuration and IPsec data plane |
| `wfcsetup/` | Wi-Fi Calling entitlement and activation |
| `examples/` | Linux VoWiFi command and web-flow callback adapters |
| `specs/` | 3GPP/ETSI, GSMA, and RFC references used for implementation and review |

`refs/` and `scripts/` may exist in a developer checkout but are ignored and are
not required to build the module.

## Development

Read [AGENTS.md](AGENTS.md) for package boundaries, Go conventions, protocol review,
and verification expectations. Use the local `specs/` documents when changing
protocol behavior. The project follows the
[Google Go Style Guide](https://google.github.io/styleguide/go/guide).

Run focused package tests while developing, followed by `go test ./...` and
`go vet ./...`. For concurrency and lifecycle changes, also run:

```sh
go test -race ./...
```

After changing dependencies, run `go mod tidy` and review the module diff.
Documentation-only changes should not need dependency updates.

The [embedded netstack notes](ipsec/transport/netstack/README.md) describe the
gVisor subset, its upstream revision, and the six-target build requirement for
upstream updates. EVS rebuild requirements and source notices are documented in
the [codec notes](ims/voice/codec/evs/README.md); use
[`evs/wasm.go`](ims/voice/codec/evs/wasm.go) for the current `Engine`/`Codec` API.
Preserve the netstack license and EVS reference-source notices when modifying
or redistributing those components.
