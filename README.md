# ims-go

A Go library for connecting to a carrier's IP Multimedia Subsystem (IMS) over
Wi-Fi Calling (VoWiFi) or LTE (VoLTE). It handles IMS registration and
reconnection and provides APIs for SMS, USSD, and voice calls.

## Installation

Requires Go 1.26.3 or later. From your Go module, run

```sh
go get github.com/damonto/ims-go
```

## Quick start

The [Linux example](examples/main.go) registers over Wi-Fi Calling and supports
SMS and interactive USSD. To use a PC/SC reader, you need a running PC/SC
service, a SIM with Wi-Fi Calling enabled, and your device's IMEI.

Prepare a directory with your carrier's `ims.json` profile and `wfc.json`
discovery settings. From the repository root, run

```sh
go run ./examples -list-readers
go run ./examples -reader 'YOUR PC/SC READER' -imei 'YOUR_IMEI' \
  -carrier-config-dir /path/to/carrier-config
```

Press Ctrl+C to disconnect. Run `go run ./examples -h` for other SIM readers
and the SMS and USSD options.

## Library usage

Set `Config.Access` using `ims.VoWiFi` or `ims.VoLTE`. Provide carrier settings
through `Config.Carriers` and `Config.WFC`. If you configure IMS without a
matching profile, set `Config.IMS.IPSecIntegrityAlgorithms` explicitly.

`ims.New` takes ownership of the SIM reader. Use `Client.Connect` to register
and `Client.Close` to disconnect and release the reader. See the
[Go API reference](https://pkg.go.dev/github.com/damonto/ims-go).

Service availability depends on carrier provisioning and hardware. The QCOM
and MBIM VoLTE adapters require Linux. Voice applications provide their own
audio capture and playback.

## Contributing

Report bugs or request features through [GitHub Issues](https://github.com/damonto/ims-go/issues).

See the [repository guidelines](AGENTS.md) and run the checks below before
submitting changes. Tests use simulated peers and local transports.

```sh
go test ./...
go vet ./...
```

## License

Project code is licensed under the [GNU GPL v3.0](LICENSE). The bundled
[gVisor netstack](ipsec/transport/netstack/LICENSE) and
[EVS reference codec](ims/voice/codec/evs/README.md) retain their own terms.
