package voice

import (
	"bytes"
	"context"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"net"
	"slices"
	"strconv"
	"testing"
	"time"
)

func TestAddInviteSessionTimer(t *testing.T) {
	tests := []struct {
		name                string
		cfg                 Config
		wantSupported       string
		wantSessionExpires  string
		wantMinSE           string
		wantNoSessionHeader bool
	}{
		{
			name:               "disabled",
			cfg:                Config{},
			wantSupported:      sip.DefaultClientSupported,
			wantSessionExpires: "",
		},
		{
			name: "timer support only",
			cfg: Config{
				SessionTimer: true,
			},
			wantSupported:       sip.DefaultClientSupported + ",timer",
			wantNoSessionHeader: true,
		},
		{
			name: "configured interval is capped to IR92 initial invite value",
			cfg: Config{
				SessionTimer:      true,
				SessionExpires:    3600 * time.Second,
				MinSessionExpires: 600 * time.Second,
			},
			wantSupported:      sip.DefaultClientSupported + ",timer",
			wantSessionExpires: "1800",
			wantMinSE:          "600",
		},
		{
			name: "configured uac refresher included in initial invite",
			cfg: Config{
				SessionTimer:     true,
				SessionExpires:   3600 * time.Second,
				SessionRefresher: sessionRefresherUAC,
			},
			wantSupported:      sip.DefaultClientSupported + ",timer",
			wantSessionExpires: "1800;refresher=uac",
		},
		{
			name: "configured uas refresher is omitted in initial invite",
			cfg: Config{
				SessionTimer:     true,
				SessionExpires:   3600 * time.Second,
				SessionRefresher: sessionRefresherUAS,
			},
			wantSupported:      sip.DefaultClientSupported + ",timer",
			wantSessionExpires: "1800",
		},
		{
			name: "min se above IR92 initial invite value omits session expires",
			cfg: Config{
				SessionTimer:      true,
				SessionExpires:    3600 * time.Second,
				MinSessionExpires: 3600 * time.Second,
			},
			wantSupported:       sip.DefaultClientSupported + ",timer",
			wantMinSE:           "3600",
			wantNoSessionHeader: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewRequest("INVITE", "sip:remote@example.com")
			msg.Headers.Add("Supported", sip.DefaultClientSupported)

			addInviteSessionTimer(&msg, tt.cfg)

			if got := msg.Header("Supported"); got != tt.wantSupported {
				t.Fatalf("Supported = %q, want %q", got, tt.wantSupported)
			}
			if got := msg.Header("Min-SE"); got != tt.wantMinSE {
				t.Fatalf("Min-SE = %q, want %q", got, tt.wantMinSE)
			}
			if got := msg.Header("Session-Expires"); got != tt.wantSessionExpires {
				t.Fatalf("Session-Expires = %q, want %q", got, tt.wantSessionExpires)
			}
			if tt.wantNoSessionHeader && msg.Header("Session-Expires") != "" {
				t.Fatalf("Session-Expires = %q, want omitted", msg.Header("Session-Expires"))
			}
		})
	}
}

func TestConfigNormalizesSessionExpiresAgainstMinSE(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want time.Duration
	}{
		{
			name: "session expires raised to configured minimum",
			cfg:  Config{SessionExpires: 300 * time.Second, MinSessionExpires: 600 * time.Second},
			want: 600 * time.Second,
		},
		{
			name: "session expires keeps configured interval above minimum",
			cfg:  Config{SessionExpires: 900 * time.Second, MinSessionExpires: 600 * time.Second},
			want: 900 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got.SessionExpires != tt.want {
				t.Fatalf("SessionExpires = %s, want %s", got.SessionExpires, tt.want)
			}
		})
	}
}

func TestConfigNormalizesSessionRefresher(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		want    string
		wantErr bool
	}{
		{name: "default", want: sessionRefresherNone},
		{name: "none lower-case normalized", cfg: Config{SessionRefresher: " NONE "}, want: sessionRefresherNone},
		{name: "uac lower-case normalized", cfg: Config{SessionRefresher: " UAC "}, want: sessionRefresherUAC},
		{name: "uas lower-case normalized", cfg: Config{SessionRefresher: " UAS "}, want: sessionRefresherUAS},
		{name: "invalid rejected", cfg: Config{SessionRefresher: "proxy"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Normalized() error = nil, want non-nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got.SessionRefresher != tt.want {
				t.Fatalf("SessionRefresher = %q, want %q", got.SessionRefresher, tt.want)
			}
		})
	}
}

func TestSessionTimerHeaderCodecs(t *testing.T) {
	t.Run("Session-Expires", func(t *testing.T) {
		tests := []struct {
			name     string
			value    string
			want     sessionExpiresHeader
			wantText string
			wantErr  bool
		}{
			{
				name:     "plain interval",
				value:    "1800",
				want:     sessionExpiresHeader{seconds: 1800},
				wantText: "1800",
			},
			{
				name:     "refresher and generic param",
				value:    `600;foo=bar;refresher="uac"`,
				want:     sessionExpiresHeader{seconds: 600, refresher: sessionRefresherUAC, params: []string{"foo=bar"}},
				wantText: "600;foo=bar;refresher=uac",
			},
			{name: "empty", wantErr: true},
			{name: "zero", value: "0", wantErr: true},
			{name: "invalid refresher", value: "1800;refresher=server", wantErr: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var got sessionExpiresHeader
				err := got.UnmarshalText([]byte(tt.value))
				if tt.wantErr {
					if err == nil {
						t.Fatal("UnmarshalText() error = nil, want error")
					}
					return
				}
				if err != nil {
					t.Fatalf("UnmarshalText() error = %v", err)
				}
				if got.seconds != tt.want.seconds || got.refresher != tt.want.refresher || !slices.Equal(got.params, tt.want.params) {
					t.Fatalf("UnmarshalText() = %+v, want %+v", got, tt.want)
				}
				text, err := got.MarshalText()
				if err != nil {
					t.Fatalf("MarshalText() error = %v", err)
				}
				if string(text) != tt.wantText {
					t.Fatalf("MarshalText() = %q, want %q", text, tt.wantText)
				}
			})
		}
	})

	t.Run("Min-SE", func(t *testing.T) {
		tests := []struct {
			name     string
			value    string
			want     minSEHeader
			wantText string
			wantErr  bool
		}{
			{
				name:     "absolute minimum",
				value:    "90",
				want:     minSEHeader{seconds: 90},
				wantText: "90",
			},
			{
				name:     "generic param preserved",
				value:    "600;foo=bar",
				want:     minSEHeader{seconds: 600, params: []string{"foo=bar"}},
				wantText: "600;foo=bar",
			},
			{name: "empty", wantErr: true},
			{name: "below absolute minimum", value: "89", wantErr: true},
			{name: "not decimal", value: "soon", wantErr: true},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				var got minSEHeader
				err := got.UnmarshalText([]byte(tt.value))
				if tt.wantErr {
					if err == nil {
						t.Fatal("UnmarshalText() error = nil, want error")
					}
					return
				}
				if err != nil {
					t.Fatalf("UnmarshalText() error = %v", err)
				}
				if got.seconds != tt.want.seconds || !slices.Equal(got.params, tt.want.params) {
					t.Fatalf("UnmarshalText() = %+v, want %+v", got, tt.want)
				}
				text, err := got.MarshalText()
				if err != nil {
					t.Fatalf("MarshalText() error = %v", err)
				}
				if string(text) != tt.wantText {
					t.Fatalf("MarshalText() = %q, want %q", text, tt.wantText)
				}
			})
		}
	})
}

func TestAddInviteOKSessionTimerUsesIR92Default(t *testing.T) {
	tests := []struct {
		name        string
		cfg         Config
		min         string
		session     string
		want        string
		wantRequire string
		supported   bool
	}{
		{
			name:        "supported invite without session expires uses IR92 default",
			cfg:         Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			want:        "1800;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "configured uas refresher ignored when UE fills missing timer",
			cfg:         Config{SessionTimer: true, SessionExpires: 600 * time.Second, SessionRefresher: sessionRefresherUAS},
			want:        "1800;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "local min se does not change IR92 default",
			cfg:         Config{SessionTimer: true, MinSessionExpires: 3600 * time.Second},
			want:        "1800;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "min se above default",
			cfg:         Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			min:         "3600",
			want:        "3600;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "uac refresher copied from request requires timer",
			cfg:         Config{SessionTimer: true},
			session:     "120;refresher=uac",
			want:        "120;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "uas refresher copied from supported request requires timer",
			cfg:         Config{SessionTimer: true},
			session:     "120;refresher=uas",
			want:        "120;refresher=uas",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:        "missing request refresher filled with uac",
			cfg:         Config{SessionTimer: true, SessionRefresher: sessionRefresherUAS},
			session:     "120",
			want:        "120;refresher=uac",
			wantRequire: "timer",
			supported:   true,
		},
		{
			name:    "proxy inserted session expires without uac timer support",
			cfg:     Config{SessionTimer: true},
			session: "300",
			want:    "300;refresher=uas",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invite := sip.NewRequest("INVITE", "sip:local@example.com")
			if tt.supported {
				invite.Headers.Add("Supported", "timer")
			}
			if tt.min != "" {
				invite.Headers.Add("Min-SE", tt.min)
			}
			if tt.session != "" {
				invite.Headers.Add("Session-Expires", tt.session)
			}
			resp := sip.NewResponse(200, "OK")

			addInviteOKSessionTimer(&resp, invite, tt.cfg)

			if got := resp.Header("Session-Expires"); got != tt.want {
				t.Fatalf("Session-Expires = %q, want %q", got, tt.want)
			}
			if got := resp.Header("Require"); got != tt.wantRequire {
				t.Fatalf("Require = %q, want %q", got, tt.wantRequire)
			}
		})
	}
}

func TestInvalidSessionTimerRefresher(t *testing.T) {
	tests := []struct {
		name      string
		supported bool
		session   string
		want      bool
	}{
		{name: "absent", supported: false},
		{name: "proxy inserted interval without refresher", session: "300"},
		{name: "unsupported uac refresher", session: "300;refresher=uac", want: true},
		{name: "unsupported uas refresher", session: "300;refresher=uas", want: true},
		{name: "supported uac refresher", supported: true, session: "300;refresher=uac"},
		{name: "malformed handled by header parser", session: "bad;refresher=uac"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := sip.NewRequest("INVITE", "sip:local@example.com")
			if tt.supported {
				msg.Headers.Add("Supported", "timer")
			}
			if tt.session != "" {
				msg.Headers.Add("Session-Expires", tt.session)
			}

			if got := invalidSessionTimerRefresher(msg); got != tt.want {
				t.Fatalf("invalidSessionTimerRefresher() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestApplySessionTimerResponseKeepsUACRequestedTimerWithoutResponseHeader(t *testing.T) {
	tests := []struct {
		name               string
		cfg                Config
		currentMinSE       int
		wantInterval       time.Duration
		wantMinSE          int
		wantLocalRefresher bool
	}{
		{
			name:               "configured session expires",
			cfg:                Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			wantInterval:       600 * time.Second,
			wantMinSE:          durationSeconds(defaultMinSessionExpires),
			wantLocalRefresher: true,
		},
		{
			name:               "stored Min-SE raises fallback interval",
			cfg:                Config{SessionTimer: true, SessionExpires: 600 * time.Second},
			currentMinSE:       900,
			wantInterval:       900 * time.Second,
			wantMinSE:          900,
			wantLocalRefresher: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{
				service:       &Service{cfg: tt.cfg},
				inviteRequest: sip.NewRequest("INVITE", "sip:remote@example.com"),
				sessionTimer: sessionTimerState{
					minSE: tt.currentMinSE,
				},
			}
			call.inviteRequest.Headers.Set("Session-Expires", strconv.Itoa(durationSeconds(tt.cfg.SessionExpires)))
			defer call.stopSessionTimer()

			if err := call.applySessionTimerUACResponse(sip.NewResponse(sipStatusOK, "OK"), true); err != nil {
				t.Fatalf("applySessionTimerUACResponse() error = %v", err)
			}
			call.mu.Lock()
			got := call.sessionTimer
			call.mu.Unlock()
			if !got.active {
				t.Fatal("session timer active = false, want true")
			}
			if got.interval != tt.wantInterval {
				t.Fatalf("session timer interval = %s, want %s", got.interval, tt.wantInterval)
			}
			if got.minSE != tt.wantMinSE {
				t.Fatalf("session timer minSE = %d, want %d", got.minSE, tt.wantMinSE)
			}
			if got.localRefresher != tt.wantLocalRefresher {
				t.Fatalf("session timer localRefresher = %t, want %t", got.localRefresher, tt.wantLocalRefresher)
			}
		})
	}
}

func TestApplySessionTimerResponseWithoutHeaderStopsSubsequentRefreshTimer(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "subsequent UAC refresh can turn off timer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{
				service: &Service{cfg: Config{SessionTimer: true}},
				sessionTimer: sessionTimerState{
					active:         true,
					interval:       600 * time.Second,
					minSE:          durationSeconds(defaultMinSessionExpires),
					localRefresher: true,
				},
			}

			if err := call.applySessionTimerUACResponse(sip.NewResponse(sipStatusOK, "OK"), false); err != nil {
				t.Fatalf("applySessionTimerUACResponse() error = %v", err)
			}
			call.mu.Lock()
			got := call.sessionTimer
			call.mu.Unlock()
			if got.active {
				t.Fatalf("session timer active = true, want false after 2xx without Session-Expires")
			}
		})
	}
}

func TestDialSessionTimerRefreshesWithUPDATE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "local refresher sends UPDATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				SessionTimer: true,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					resp := callOK(msg)
					resp.Headers.Add("Allow", sip.DefaultClientAllow)
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "180;refresher=uac")
					transport.queue(resp)
				case "UPDATE":
					resp := okForRequest(msg)
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "180;refresher=uac")
					transport.queue(resp)
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.refreshSession()

			updates := transport.messagesByMethod("UPDATE")
			if len(updates) != 1 {
				t.Fatalf("UPDATE count = %d, want 1", len(updates))
			}
			if got := updates[0].Header("Session-Expires"); got != "180;refresher=uac" {
				t.Fatalf("UPDATE Session-Expires = %q, want 180;refresher=uac", got)
			}
			if got := updates[0].Header("Supported"); !sip.TokenListContains(got, "timer") {
				t.Fatalf("UPDATE Supported = %q, want timer", got)
			}
		})
	}
}

func TestDialSessionTimerRefreshRetriesIncreasingMinSE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "UPDATE refresh retries with largest Min-SE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				SessionTimer: true,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			updates := 0
			transport.onWrite = func(msg sip.Message) {
				switch msg.Method() {
				case "INVITE":
					resp := callOK(msg)
					resp.Headers.Add("Allow", sip.DefaultClientAllow)
					resp.Headers.Add("Require", "timer")
					resp.Headers.Add("Session-Expires", "180;refresher=uac")
					transport.queue(resp)
				case "UPDATE":
					updates++
					switch updates {
					case 1:
						resp := callStatus(msg, sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
						resp.Headers.Add("Min-SE", "600")
						transport.queue(resp)
					case 2:
						if got := msg.Header("Min-SE"); got != "600" {
							t.Fatalf("retry UPDATE Min-SE = %q, want 600", got)
						}
						if got := msg.Header("Session-Expires"); got != "600;refresher=uac" {
							t.Fatalf("retry UPDATE Session-Expires = %q, want 600;refresher=uac", got)
						}
						resp := callStatus(msg, sipStatusSessionIntervalTooSmall, "Session Interval Too Small")
						resp.Headers.Add("Min-SE", "900")
						transport.queue(resp)
					case 3:
						if got := msg.Header("Min-SE"); got != "900" {
							t.Fatalf("second retry UPDATE Min-SE = %q, want 900", got)
						}
						if got := msg.Header("Session-Expires"); got != "900;refresher=uac" {
							t.Fatalf("second retry UPDATE Session-Expires = %q, want 900;refresher=uac", got)
						}
						resp := okForRequest(msg)
						resp.Headers.Add("Require", "timer")
						resp.Headers.Add("Session-Expires", "900;refresher=uac")
						transport.queue(resp)
					default:
						t.Fatalf("UPDATE count = %d, want 3", updates)
					}
				}
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.refreshSession()

			if updates != 3 {
				t.Fatalf("UPDATE count = %d, want 3", updates)
			}
			call.mu.Lock()
			timer := call.sessionTimer
			call.mu.Unlock()
			if !timer.active || !timer.localRefresher || timer.minSE != 900 || timer.interval != 900*time.Second {
				t.Fatalf("session timer = %+v, want active local refresher 900s/min-se 900", timer)
			}
			if got := transport.countMethod("BYE"); got != 0 {
				t.Fatalf("BYE count = %d, want 0 after successful retry", got)
			}
		})
	}
}

func TestSessionTimerRefreshNon2xxTerminatesDialog(t *testing.T) {
	transport := newVoiceStubTransport()
	sess, err := session.Open(session.Config{}, transport)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	reg, err := registration.New(registration.Config{Logger: testLogger(),
		PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
		HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
		IMEI:            "123456789012345",
	}, sess, voiceStubCard{})
	if err != nil {
		t.Fatalf("registration.New() error = %v", err)
	}
	media := &voiceMediaTransport{}
	svc, err := New(Config{Logger: testLogger(),
		SessionTimer: true,
		OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
			media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
			media.onPacket = cfg.OnPacket
			return media, nil
		},
	}, sess, reg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- sess.Run(ctx)
	}()
	if err := sess.WaitStarted(ctx); err != nil {
		t.Fatalf("WaitStarted() error = %v", err)
	}
	defer func() {
		cancel()
		_ = svc.Close()
		_ = sess.Close()
		<-runErr
	}()

	transport.onWrite = func(msg sip.Message) {
		switch msg.Method() {
		case "INVITE":
			resp := callOK(msg)
			resp.Headers.Add("Allow", sip.DefaultClientAllow)
			resp.Headers.Add("Require", "timer")
			resp.Headers.Add("Session-Expires", "180;refresher=uac")
			transport.queue(resp)
		case "UPDATE":
			transport.queue(callStatus(msg, sipStatusServerInternalError, "Server Internal Error"))
		case "BYE":
			transport.queue(okForRequest(msg))
		}
	}

	call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	call.refreshSession()

	if !waitForCallTest(func() bool { return transport.countMethod("BYE") == 1 }) {
		t.Fatalf("BYE count = %d, want 1 after failed session refresh", transport.countMethod("BYE"))
	}
	if got := call.State(); got != CallStateEnded {
		t.Fatalf("call state = %s, want %s", got, CallStateEnded)
	}
}

func TestDialSessionTimerRefreshFallsBackToReINVITEWithoutRemoteUPDATE(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "remote Allow does not advertise UPDATE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := newVoiceStubTransport()
			sess, err := session.Open(session.Config{}, transport)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			reg, err := registration.New(registration.Config{Logger: testLogger(),
				PrivateIdentity: "001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				PublicIdentity:  "sip:001010123456789@ims.mnc001.mcc001.3gppnetwork.org",
				HomeDomain:      "ims.mnc001.mcc001.3gppnetwork.org",
				IMEI:            "123456789012345",
			}, sess, voiceStubCard{})
			if err != nil {
				t.Fatalf("registration.New() error = %v", err)
			}
			media := &voiceMediaTransport{}
			svc, err := New(Config{Logger: testLogger(),
				SessionTimer: true,
				OpenMedia: func(ctx context.Context, cfg MediaConfig) (MediaTransport, error) {
					media.local = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: cfg.LocalPort}
					media.onPacket = cfg.OnPacket
					return media, nil
				},
			}, sess, reg)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			runErr := make(chan error, 1)
			go func() {
				runErr <- sess.Run(ctx)
			}()
			if err := sess.WaitStarted(ctx); err != nil {
				t.Fatalf("WaitStarted() error = %v", err)
			}
			defer func() {
				cancel()
				_ = svc.Close()
				_ = sess.Close()
				<-runErr
			}()

			invites := 0
			transport.onWrite = func(msg sip.Message) {
				if msg.Method() != "INVITE" {
					return
				}
				invites++
				resp := callOK(msg)
				resp.Headers.Add("Require", "timer")
				resp.Headers.Add("Session-Expires", "180;refresher=uac")
				if invites == 1 {
					resp.Headers.Add("Allow", "ACK,BYE,CANCEL,INVITE,PRACK")
				} else {
					resp.Headers.Set("Contact", "<sip:remote-refresh@192.0.2.11:5060>")
					resp.Body = bytes.Replace(resp.Body, []byte("m=audio 50000 RTP/AVP 104 110\r\n"), []byte("m=audio 51000 RTP/AVP 104 110\r\n"), 1)
				}
				transport.queue(resp)
			}

			call, err := svc.Dial(context.Background(), DialRequest{To: "sip:remote@example.com"})
			if err != nil {
				t.Fatalf("Dial() error = %v", err)
			}
			call.refreshSession()

			if got := transport.countMethod("UPDATE"); got != 0 {
				t.Fatalf("UPDATE count = %d, want 0", got)
			}
			refreshes := transport.messagesByMethod("INVITE")
			if len(refreshes) != 2 {
				t.Fatalf("INVITE count = %d, want initial plus refresh", len(refreshes))
			}
			refresh := refreshes[1]
			if got := refresh.Header("Session-Expires"); got != "180;refresher=uac" {
				t.Fatalf("re-INVITE Session-Expires = %q, want 180;refresher=uac", got)
			}
			if got := refresh.Header("Supported"); !sip.TokenListContains(got, "timer") {
				t.Fatalf("re-INVITE Supported = %q, want timer", got)
			}
			if got := refresh.Header("Content-Type"); got != "application/sdp" {
				t.Fatalf("re-INVITE Content-Type = %q, want application/sdp", got)
			}
			if got := transport.countMethod("ACK"); got != 2 {
				t.Fatalf("ACK count = %d, want initial ACK plus re-INVITE ACK", got)
			}
			call.mu.Lock()
			target := call.targetURI
			call.mu.Unlock()
			if target != "sip:remote-refresh@192.0.2.11:5060" {
				t.Fatalf("targetURI = %q, want refreshed Contact", target)
			}
			remote, ok := media.RemoteAddr().(*net.UDPAddr)
			if !ok {
				t.Fatalf("media remote = %T, want *net.UDPAddr", media.RemoteAddr())
			}
			if remote.Port != 51000 {
				t.Fatalf("media remote port = %d, want refreshed SDP answer port 51000", remote.Port)
			}
		})
	}
}

func TestSessionRefreshReINVITEUsesLocalSDP(t *testing.T) {
	const remoteSDP = "v=0\r\no=- 10 10 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\n"
	const localSDP = "v=0\r\no=- 20 20 IN IP4 192.0.2.20\r\ns=-\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\nm=audio 40000 RTP/AVP 104\r\n"

	tests := []struct {
		name string
	}{
		{name: "incoming dialog refresh reuses local answer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			invite := sip.NewRequest("INVITE", "sip:local@example.com")
			invite.Headers.Set("Content-Type", "application/sdp")
			invite.Body = []byte(remoteSDP)
			snap := dialogSnapshot{
				id:            "call-id",
				localURI:      "sip:local@example.com",
				localTag:      "local-tag",
				remoteTo:      "<sip:remote@example.com>;tag=remote-tag",
				targetURI:     "sip:remote@192.0.2.10:5060",
				inviteSeq:     1,
				inviteRequest: invite,
				localSDP:      []byte(localSDP),
				transport:     "TCP",
				contactHost:   "192.0.2.20",
				messagePort:   5060,
				contact:       "<sip:local@192.0.2.20:5060>",
			}
			msg := snap.buildSessionRefreshRequest(2, sessionTimerState{
				active:         true,
				interval:       180 * time.Second,
				minSE:          durationSeconds(defaultMinSessionExpires),
				localRefresher: true,
			})

			if got := msg.Method(); got != "INVITE" {
				t.Fatalf("refresh method = %q, want INVITE", got)
			}
			if got := msg.Header("Content-Type"); got != "application/sdp" {
				t.Fatalf("Content-Type = %q, want application/sdp", got)
			}
			if string(msg.Body) != localSDP {
				t.Fatalf("refresh SDP = %q, want local SDP %q", string(msg.Body), localSDP)
			}
		})
	}
}
