package ims

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"testing"

	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

type underlayStub struct {
	localIP   netip.Addr
	addresses []netip.Addr
	err       error
	lookups   int
	network   string
	host      string
	dials     int
	dialErr   error
	dialNet   string
	dialAddr  string
}

func (u *underlayStub) LocalIP() netip.Addr {
	return u.localIP
}

func (u *underlayStub) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	u.lookups++
	u.network = network
	u.host = host
	return append([]netip.Addr(nil), u.addresses...), u.err
}

func (u *underlayStub) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	u.dials++
	u.dialNet = network
	u.dialAddr = address
	return nil, u.dialErr
}

func (*underlayStub) ListenPacket(context.Context, string, string) (net.PacketConn, error) {
	return nil, errors.New("listen is not used")
}

func TestUnderlayHTTPTransport(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "clones default transport and enforces underlay"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := http.DefaultTransport.(*http.Transport)
			underlayDialErr := errors.New("underlay dial")
			underlay := &underlayStub{dialErr: underlayDialErr}

			got := underlayHTTPTransport(underlay)
			if got == base {
				t.Fatal("underlayHTTPTransport() returned default transport")
			}
			if got.MaxIdleConns != base.MaxIdleConns {
				t.Fatalf("MaxIdleConns = %d, want %d", got.MaxIdleConns, base.MaxIdleConns)
			}
			if got.Proxy != nil {
				t.Fatal("Proxy is configured, want nil")
			}
			if got.DialTLSContext != nil {
				t.Fatal("custom TLS dialer was retained")
			}
			if _, err := got.DialContext(t.Context(), "tcp", "carrier.example:443"); !errors.Is(err, underlayDialErr) {
				t.Fatalf("DialContext() error = %v, want %v", err, underlayDialErr)
			}
			if underlay.dials != 1 || underlay.dialNet != "tcp" || underlay.dialAddr != "carrier.example:443" {
				t.Fatalf("underlay DialContext() = calls %d network %q address %q", underlay.dials, underlay.dialNet, underlay.dialAddr)
			}
			if base.Proxy == nil || base.DialTLSContext != nil {
				t.Fatal("default transport was mutated")
			}
		})
	}
}

func TestEPDGRemoteCandidates(t *testing.T) {
	tests := []struct {
		name        string
		remote      string
		initialPort int
		localIP     netip.Addr
		addresses   []netip.Addr
		want        []string
		wantNetwork string
		wantLookup  bool
		wantErr     bool
	}{
		{
			name:        "resolves and deduplicates hostname addresses",
			remote:      "epdg.example",
			addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10"), netip.MustParseAddr("192.0.2.10")},
			want:        []string{"192.0.2.10:500", "[2001:db8::10]:500"},
			wantNetwork: "ip",
			wantLookup:  true,
		},
		{
			name:        "keeps ipv4 addresses for ipv4 underlay",
			remote:      "epdg.example",
			localIP:     netip.MustParseAddr("198.51.100.20"),
			addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
			want:        []string{"192.0.2.10:500"},
			wantNetwork: "ip4",
			wantLookup:  true,
		},
		{
			name:        "keeps ipv6 addresses for ipv6 underlay",
			remote:      "epdg.example",
			localIP:     netip.MustParseAddr("2001:db8::20"),
			addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")},
			want:        []string{"[2001:db8::10]:500"},
			wantNetwork: "ip6",
			wantLookup:  true,
		},
		{
			name:        "rejects addresses from another family",
			remote:      "epdg.example",
			localIP:     netip.MustParseAddr("198.51.100.20"),
			addresses:   []netip.Addr{netip.MustParseAddr("2001:db8::10")},
			wantNetwork: "ip4",
			wantLookup:  true,
			wantErr:     true,
		},
		{
			name:        "preserves explicit port",
			remote:      "epdg.example:4500",
			initialPort: 1234,
			addresses:   []netip.Addr{netip.MustParseAddr("192.0.2.20")},
			want:        []string{"192.0.2.20:4500"},
			wantNetwork: "ip",
			wantLookup:  true,
		},
		{
			name:   "uses literal ipv4 without lookup",
			remote: "192.0.2.30",
			want:   []string{"192.0.2.30:500"},
		},
		{
			name:   "uses bracketed literal ipv6 without lookup",
			remote: "[2001:db8::30]",
			want:   []string{"[2001:db8::30]:500"},
		},
		{
			name:    "rejects literal from another family",
			remote:  "[2001:db8::30]",
			localIP: netip.MustParseAddr("198.51.100.20"),
			wantErr: true,
		},
		{
			name:    "rejects invalid port",
			remote:  "epdg.example:70000",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			underlay := &underlayStub{localIP: tt.localIP, addresses: tt.addresses}
			got, err := epdgRemoteCandidates(t.Context(), underlay, tt.remote, tt.initialPort)
			if (err != nil) != tt.wantErr {
				t.Fatalf("epdgRemoteCandidates() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("epdgRemoteCandidates() = %v, want %v", got, tt.want)
			}
			if gotLookup := underlay.lookups > 0; gotLookup != tt.wantLookup {
				t.Fatalf("LookupNetIP called = %v, want %v", gotLookup, tt.wantLookup)
			}
			if tt.wantLookup && (underlay.network != tt.wantNetwork || underlay.host != "epdg.example") {
				t.Fatalf("LookupNetIP() = network %q host %q", underlay.network, underlay.host)
			}
		})
	}
}

func TestShouldTryNextEPDG(t *testing.T) {
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	tests := []struct {
		name string
		ctx  context.Context
		err  error
		want bool
	}{
		{name: "ike sa init received no response", ctx: t.Context(), err: swutunnel.ErrIKESAInitNoResponse, want: true},
		{name: "wrapped no response", ctx: t.Context(), err: errors.Join(errors.New("connecting swu"), swutunnel.ErrIKESAInitNoResponse), want: true},
		{name: "ordinary network error", ctx: t.Context(), err: errors.New("network unreachable")},
		{name: "access rejection", ctx: t.Context(), err: swutunnel.ErrAccessRejected},
		{name: "canceled attempt", ctx: canceled, err: swutunnel.ErrIKESAInitNoResponse},
		{name: "deadline error", ctx: t.Context(), err: context.DeadlineExceeded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldTryNextEPDG(tt.ctx, tt.err); got != tt.want {
				t.Fatalf("shouldTryNextEPDG() = %v, want %v", got, tt.want)
			}
		})
	}
}
