package voice

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBuildSDPOffer(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}

	body, media, err := buildSDPOffer(cfg, net.IPv4(10, 0, 0, 2), 40000, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPOffer() error = %v", err)
	}

	text := string(body)
	for _, want := range []string{
		"m=audio 40000 RTP/AVP 104 102 0 101 110",
		"b=AS:14",
		"b=RS:0",
		"b=RR:2500",
		"a=rtpmap:104 AMR-WB/16000",
		"a=fmtp:104 mode-change-capability=2;max-red=220",
		"a=rtpmap:102 AMR/8000",
		"a=fmtp:102 mode-change-capability=2;max-red=220",
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:101 telephone-event/8000",
		"a=fmtp:101 0-15",
		"a=rtpmap:110 telephone-event/16000",
		"a=fmtp:110 0-15",
		"a=ptime:20",
		"a=maxptime:240",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SDP offer missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "mode-set=0,2,4,7") {
		t.Fatalf("SDP offer contains AMR mode-set, want initial offer without mode-set:\n%s", text)
	}
	if strings.Contains(text, "octet-align=1") {
		t.Fatalf("SDP offer requests octet-aligned AMR, want bandwidth-efficient by default:\n%s", text)
	}
	if media.Codec != CodecAMRWB || media.PayloadType != 104 || media.PTime != 20*time.Millisecond {
		t.Fatalf("NegotiatedMedia = %+v, want AMR-WB payload 104 ptime 20ms", media)
	}
	if media.OctetAlign {
		t.Fatalf("NegotiatedMedia.OctetAlign = true, want false")
	}
	if !media.HasDTMF || media.DTMFPayloadType != 110 || media.DTMFClockRate != 16000 {
		t.Fatalf("NegotiatedMedia DTMF = %t %d/%d, want telephone-event 110/16000", media.HasDTMF, media.DTMFPayloadType, media.DTMFClockRate)
	}
}

func TestBuildSDPOfferCanRequestOctetAlignedAMR(t *testing.T) {
	cfg, err := (Config{
		Codecs: []AudioCodecConfig{
			{Name: CodecAMRWB, PayloadTypes: []int{104}, ClockRate: 16000, OctetAlign: true},
			{Name: CodecTelephoneEvent, PayloadTypes: []int{101}, ClockRate: 8000},
		},
	}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}

	body, _, err := buildSDPOffer(cfg, net.IPv4(10, 0, 0, 2), 40000, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPOffer() error = %v", err)
	}
	if text := string(body); !strings.Contains(text, "a=fmtp:104 octet-align=1;mode-change-capability=2;max-red=220") {
		t.Fatalf("SDP offer missing octet-align fmtp:\n%s", text)
	}
}

func TestBuildSDPOfferUsesConfiguredEVSProfile(t *testing.T) {
	chAwRecv := 2
	cfg, err := (Config{
		AudioASBandwidthKbps: 49,
		Codecs: []AudioCodecConfig{
			{Name: CodecEVS, PayloadTypes: []int{127}, ClockRate: 16000, Bitrate: "5.9-13.2", Bandwidth: "nb-swb", ModeSet: "0,1,2", ChAwRecv: &chAwRecv},
			{Name: CodecTelephoneEvent, PayloadTypes: []int{96}, ClockRate: 16000},
		},
	}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}

	body, media, err := buildSDPOffer(cfg, net.IPv4(10, 0, 0, 2), 40000, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPOffer() error = %v", err)
	}

	text := string(body)
	for _, want := range []string{
		"m=audio 40000 RTP/AVP 127 96",
		"b=AS:49",
		"a=rtpmap:127 EVS/16000",
		"a=fmtp:127 br=5.9-13.2;bw=nb-swb;ch-aw-recv=2",
		"a=rtpmap:96 telephone-event/16000",
		"a=fmtp:96 0-15",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SDP offer missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "mode-set=0,1,2") {
		t.Fatalf("SDP offer contains EVS mode-set, want initial offer limited to Pixel EVS payload description:\n%s", text)
	}
	if media.Codec != CodecEVS || media.PayloadType != 127 {
		t.Fatalf("NegotiatedMedia = %+v, want EVS payload 127", media)
	}
}

func TestParseSDPInfersStaticRTPPayloads(t *testing.T) {
	tests := []struct {
		name string
		sdp  string
		want AudioCodecConfig
	}{
		{
			name: "pcmu payload zero without rtpmap",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 0 101\r\na=rtpmap:101 telephone-event/8000\r\n",
			want: AudioCodecConfig{Name: CodecPCMU, PayloadTypes: []int{0}, ClockRate: 8000},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offer, err := parseSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}
			got := offer.Codecs[0]
			if got.Name != tt.want.Name || got.ClockRate != tt.want.ClockRate || len(got.PayloadTypes) != 1 || got.PayloadTypes[0] != tt.want.PayloadTypes[0] {
				t.Fatalf("offer.Codecs[0] = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseSDPReadsRTCPBandwidth(t *testing.T) {
	tests := []struct {
		name         string
		sdp          string
		wantRS       int
		wantRR       int
		wantDisabled bool
	}{
		{
			name:         "rtcp disabled",
			sdp:          "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\nb=RS:0\r\nb=RR:0\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantRS:       0,
			wantRR:       0,
			wantDisabled: true,
		},
		{
			name:   "rtcp enabled with bandwidth",
			sdp:    "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\nb=RS:120\r\nb=RR:240\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantRS: 120,
			wantRR: 240,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offer, err := parseSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}
			if offer.RTCPSenderBandwidth == nil || *offer.RTCPSenderBandwidth != tt.wantRS {
				t.Fatalf("RTCP sender bandwidth = %v, want %d", offer.RTCPSenderBandwidth, tt.wantRS)
			}
			if offer.RTCPReceiverBandwidth == nil || *offer.RTCPReceiverBandwidth != tt.wantRR {
				t.Fatalf("RTCP receiver bandwidth = %v, want %d", offer.RTCPReceiverBandwidth, tt.wantRR)
			}
			if got := rtcpDisabled(offer); got != tt.wantDisabled {
				t.Fatalf("rtcpDisabled() = %v, want %v", got, tt.wantDisabled)
			}
		})
	}
}

func TestParseSDPReadsRTCPTransportAttributes(t *testing.T) {
	tests := []struct {
		name         string
		sdp          string
		wantRTCPIP   net.IP
		wantRTCPPort int
		wantMux      bool
	}{
		{
			name:         "explicit rtcp port",
			sdp:          "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtcp:50005\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantRTCPPort: 50005,
		},
		{
			name:         "explicit rtcp address",
			sdp:          "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtcp:50007 IN IP4 192.0.2.20\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantRTCPIP:   net.IPv4(192, 0, 2, 20),
			wantRTCPPort: 50007,
		},
		{
			name:         "rtcp mux",
			sdp:          "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtcp-mux\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantMux:      true,
			wantRTCPPort: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offer, err := parseSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}
			if got := offer.RemoteRTCPPort; got != tt.wantRTCPPort {
				t.Fatalf("RemoteRTCPPort = %d, want %d", got, tt.wantRTCPPort)
			}
			if got := offer.RTCPMux; got != tt.wantMux {
				t.Fatalf("RTCPMux = %v, want %v", got, tt.wantMux)
			}
			if tt.wantRTCPIP != nil && !offer.RemoteRTCPIP.Equal(tt.wantRTCPIP) {
				t.Fatalf("RemoteRTCPIP = %v, want %v", offer.RemoteRTCPIP, tt.wantRTCPIP)
			}
		})
	}
}

func TestParseSDPRejectsInvalidNumbers(t *testing.T) {
	tests := []struct {
		name    string
		sdp     string
		wantErr string
	}{
		{
			name:    "audio port out of range",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 65536 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "invalid audio port",
		},
		{
			name:    "payload type out of range",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 128\r\n",
			wantErr: "invalid payload type",
		},
		{
			name:    "rtpmap payload out of range",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:128 AMR-WB/16000\r\n",
			wantErr: "invalid rtpmap payload",
		},
		{
			name:    "rtpmap clock must be positive",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/0\r\n",
			wantErr: "invalid rtpmap clock",
		},
		{
			name:    "rtpmap channels must be positive",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000/0\r\n",
			wantErr: "invalid rtpmap channels",
		},
		{
			name:    "rtcp bandwidth must be non-negative",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\nb=RR:-1\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "invalid RR bandwidth",
		},
		{
			name:    "connection IP4 must carry IPv4 address",
			sdp:     "v=0\r\nc=IN IP4 2001:db8::10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "invalid connection IP4 address",
		},
		{
			name:    "connection IP6 must carry IPv6 address",
			sdp:     "v=0\r\nc=IN IP6 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "invalid connection IP6 address",
		},
		{
			name:    "connection address type must be IP4 or IP6",
			sdp:     "v=0\r\nc=IN E.164 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "invalid connection address type",
		},
		{
			name:    "rtcp port out of range",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtcp:65536\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "invalid rtcp port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseSDP([]byte(tt.sdp))
			if err == nil {
				t.Fatal("parseSDP() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("parseSDP() error = %q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestBuildSDPAnswerNegotiatesRTCPTransport(t *testing.T) {
	tests := []struct {
		name         string
		sdp          string
		wantAnswer   []string
		rejectAnswer []string
		wantRTCPIP   net.IP
		wantRTCPPort int
		wantMux      bool
	}{
		{
			name:         "explicit rtcp port",
			sdp:          "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtcp:50005\r\na=rtpmap:104 AMR-WB/16000\r\n",
			rejectAnswer: []string{"a=rtcp-mux"},
			wantRTCPIP:   net.IPv4(192, 0, 2, 10),
			wantRTCPPort: 50005,
		},
		{
			name:         "rtcp mux",
			sdp:          "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtcp:50005\r\na=rtcp-mux\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantAnswer:   []string{"a=rtcp-mux"},
			wantRTCPIP:   net.IPv4(192, 0, 2, 10),
			wantRTCPPort: 50000,
			wantMux:      true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			remote, err := parseSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}

			body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			text := string(body)
			for _, want := range tt.wantAnswer {
				if !strings.Contains(text, want) {
					t.Fatalf("SDP answer missing %q:\n%s", want, text)
				}
			}
			for _, reject := range tt.rejectAnswer {
				if strings.Contains(text, reject) {
					t.Fatalf("SDP answer contains %q:\n%s", reject, text)
				}
			}
			if got := media.RTCPMux; got != tt.wantMux {
				t.Fatalf("NegotiatedMedia.RTCPMux = %v, want %v", got, tt.wantMux)
			}
			if got := media.RemoteRTCPPort; got != tt.wantRTCPPort {
				t.Fatalf("NegotiatedMedia.RemoteRTCPPort = %d, want %d", got, tt.wantRTCPPort)
			}
			if !media.RemoteRTCPIP.Equal(tt.wantRTCPIP) {
				t.Fatalf("NegotiatedMedia.RemoteRTCPIP = %v, want %v", media.RemoteRTCPIP, tt.wantRTCPIP)
			}
		})
	}
}

func TestBuildSDPAnswerReflectsDisabledRTCP(t *testing.T) {
	tests := []struct {
		name         string
		sdp          string
		want         []string
		wantDisabled bool
	}{
		{
			name:         "both rtcp bandwidth directions disabled",
			sdp:          "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\nb=RS:0\r\nb=RR:0\r\na=rtpmap:104 AMR-WB/16000\r\n",
			want:         []string{"b=RS:0", "b=RR:0"},
			wantDisabled: true,
		},
		{
			name:         "only receiver bandwidth disabled",
			sdp:          "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\nb=RR:0\r\na=rtpmap:104 AMR-WB/16000\r\n",
			want:         []string{"b=RS:0", "b=RR:0"},
			wantDisabled: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			remote, err := parseSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}

			body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			text := string(body)
			for _, want := range tt.want {
				if !strings.Contains(text, want) {
					t.Fatalf("SDP answer missing %q:\n%s", want, text)
				}
			}
			if got := media.RTCPDisabled; got != tt.wantDisabled {
				t.Fatalf("NegotiatedMedia.RTCPDisabled = %v, want %v", got, tt.wantDisabled)
			}
		})
	}
}

func TestBuildSDPAnswerEchoesEVSChannelAwareReceive(t *testing.T) {
	cfg, err := (Config{
		AudioASBandwidthKbps: 49,
		Codecs: []AudioCodecConfig{
			{Name: CodecEVS, PayloadTypes: []int{127}, ClockRate: 16000, Bitrate: "5.9-13.2", Bandwidth: "nb-swb"},
			{Name: CodecTelephoneEvent, PayloadTypes: []int{96}, ClockRate: 16000},
		},
	}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 127 96\r\na=rtpmap:127 EVS/16000\r\na=fmtp:127 br=5.9-13.2;bw=nb-swb;ch-aw-recv=2\r\na=rtpmap:96 telephone-event/16000\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}

	body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"m=audio 40000 RTP/AVP 127 96",
		"b=AS:49",
		"a=fmtp:127 br=5.9-13.2;bw=nb-swb;ch-aw-recv=2",
		"a=fmtp:96 0-15",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SDP answer missing %q:\n%s", want, text)
		}
	}
	if media.Codec != CodecEVS || media.PayloadType != 127 || !media.HasDTMF || media.DTMFPayloadType != 96 || media.DTMFClockRate != 16000 {
		t.Fatalf("NegotiatedMedia = %+v, want EVS payload 127 DTMF 96/16000", media)
	}
}

func TestBuildSDPAnswerSelectsCompatibleCodec(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 102 101 110\r\na=rtpmap:104 AMR-WB/16000\r\na=fmtp:104 octet-align=1\r\na=rtpmap:102 AMR/8000\r\na=rtpmap:101 telephone-event/8000\r\na=rtpmap:110 telephone-event/16000\r\na=ptime:20\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}

	body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"m=audio 40000 RTP/AVP 104 110",
		"b=AS:14",
		"b=RS:0",
		"b=RR:2500",
		"a=fmtp:104 octet-align=1;mode-change-capability=2;max-red=220",
		"a=rtpmap:110 telephone-event/16000",
		"a=fmtp:110 0-15",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SDP answer missing %q:\n%s", want, text)
		}
	}
	if media.Codec != CodecAMRWB || media.PayloadType != 104 || media.RemotePort != 50000 || !media.HasDTMF || media.DTMFPayloadType != 110 || media.DTMFClockRate != 16000 {
		t.Fatalf("NegotiatedMedia = %+v, want AMR-WB payload 104 remote port 50000 DTMF 110/16000", media)
	}
	if !media.OctetAlign {
		t.Fatalf("NegotiatedMedia.OctetAlign = false, want true")
	}
}

func TestBuildSDPAnswerPreservesTelephoneEventMask(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 110\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:110 telephone-event/16000\r\na=fmtp:110 0-9\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}
	body, media, err := buildSDPAnswer(cfg, net.IPv4(192, 0, 2, 20), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	want := uint16(0x03ff)
	if media.DTMFEventMask != want {
		t.Fatalf("DTMFEventMask = %#04x, want %#04x", media.DTMFEventMask, want)
	}
	text := string(body)
	if !strings.Contains(text, "a=fmtp:110 0-9\r\n") {
		t.Fatalf("SDP answer missing negotiated telephone-event mask:\n%s", text)
	}
	if strings.Contains(text, "a=fmtp:110 0-15\r\n") {
		t.Fatalf("SDP answer advertised unnegotiated telephone-event mask:\n%s", text)
	}
}

func TestBuildSDPAnswerRejectsTelephoneEventWithoutDTMFDigits(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 110\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:110 telephone-event/16000\r\na=fmtp:110 16-31\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}
	body, media, err := buildSDPAnswer(cfg, net.IPv4(192, 0, 2, 20), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	if media.HasDTMF || strings.Contains(string(body), "telephone-event") {
		t.Fatalf("DTMF negotiated for unsupported event range: media=%+v\n%s", media, body)
	}
}

func TestParseTelephoneEventMask(t *testing.T) {
	tests := []struct {
		name string
		fmtp string
		want uint16
	}{
		{name: "full range", fmtp: "0-15", want: 0xffff},
		{name: "list and range", fmtp: "0-2,10,12-15", want: 0xf407},
		{name: "out of DTMF range", fmtp: "16-31", want: 0},
		{name: "partial invalid", fmtp: "0-1,broken,15", want: 0x8003},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseTelephoneEventMask(tt.fmtp); got != tt.want {
				t.Fatalf("parseTelephoneEventMask() = %#04x, want %#04x", got, tt.want)
			}
		})
	}
}

func TestFormatTelephoneEventMask(t *testing.T) {
	tests := []struct {
		name string
		mask uint16
		want string
	}{
		{name: "default full range", mask: 0, want: "0-15"},
		{name: "full range", mask: 0xffff, want: "0-15"},
		{name: "single event", mask: 1 << 10, want: "10"},
		{name: "ranges", mask: 0xf407, want: "0-2,10,12-15"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatTelephoneEventMask(tt.mask); got != tt.want {
				t.Fatalf("formatTelephoneEventMask() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildSDPAnswerKeepsBandwidthEfficientAMR(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}

	body, _, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	if text := string(body); strings.Contains(text, "octet-align=1") {
		t.Fatalf("SDP answer forced octet-aligned AMR, want bandwidth-efficient:\n%s", text)
	}
	if text := string(body); !strings.Contains(text, "a=fmtp:104 mode-change-capability=2;max-red=220") {
		t.Fatalf("SDP answer missing AMR mode-change/max-red fmtp:\n%s", text)
	}
}

func TestBuildSDPAnswerSelectsPCMU(t *testing.T) {
	cfg, err := (Config{
		Codecs: []AudioCodecConfig{
			{Name: CodecAMR, PayloadTypes: []int{102}, ClockRate: 8000},
			{Name: CodecPCMU, PayloadTypes: []int{0}, ClockRate: 8000},
			{Name: CodecTelephoneEvent, PayloadTypes: []int{101}, ClockRate: 8000},
		},
	}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 0 100 101\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:100 AMR/8000\r\na=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}

	body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{Codecs: []AudioCodec{CodecAMR, CodecPCMU}})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"m=audio 40000 RTP/AVP 0 101",
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:101 telephone-event/8000",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SDP answer missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "a=fmtp:0") {
		t.Fatalf("SDP answer contains PCMU fmtp:\n%s", text)
	}
	if media.Codec != CodecPCMU || media.PayloadType != 0 || media.RemotePort != 50000 || !media.HasDTMF || media.DTMFPayloadType != 101 {
		t.Fatalf("NegotiatedMedia = %+v, want PCMU payload 0 remote port 50000 DTMF 101", media)
	}
}

func TestBuildSDPAnswerRejectsIncompatibleCodec(t *testing.T) {
	cfg, err := (Config{
		Codecs: []AudioCodecConfig{
			{Name: CodecAMR, PayloadTypes: []int{102}, ClockRate: 8000},
		},
	}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}

	if _, _, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{}); err == nil {
		t.Fatal("buildSDPAnswer() error = nil, want incompatible codec error")
	}
}

func TestConfigNormalizedRejectsDuplicatePayloadType(t *testing.T) {
	_, err := (Config{
		Codecs: []AudioCodecConfig{
			{Name: CodecAMR, PayloadTypes: []int{102}, ClockRate: 8000},
			{Name: CodecAMRWB, PayloadTypes: []int{102}, ClockRate: 16000},
		},
	}).Normalized()
	if err == nil {
		t.Fatal("Normalized() error = nil, want duplicate payload type error")
	}
}

func TestConfigNormalizedAllowsPreconditions(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want Config
	}{
		{
			name: "preconditions enable reliable provisional",
			cfg:  Config{Preconditions: true},
			want: Config{Preconditions: true, ReliableProvisional: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if got.Preconditions != tt.want.Preconditions || got.ReliableProvisional != tt.want.ReliableProvisional {
				t.Fatalf("Normalized() preconditions/reliable = %t/%t, want %t/%t",
					got.Preconditions, got.ReliableProvisional, tt.want.Preconditions, tt.want.ReliableProvisional)
			}
		})
	}
}

func TestBuildSDPOfferIncludesQoSPreconditions(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want []string
	}{
		{
			name: "preconditions enabled",
			cfg: Config{
				Preconditions: true,
			},
			want: []string{
				"a=curr:qos local none",
				"a=curr:qos remote none",
				"a=des:qos mandatory local sendrecv",
				"a=des:qos optional remote sendrecv",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := tt.cfg.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			body, _, err := buildSDPOffer(cfg, net.IPv4(10, 0, 0, 1), 40000, MediaOffer{})
			if err != nil {
				t.Fatalf("buildSDPOffer() error = %v", err)
			}
			text := string(body)
			for _, want := range tt.want {
				if !strings.Contains(text, want+"\r\n") {
					t.Fatalf("SDP offer missing %q:\n%s", want, text)
				}
			}
			if strings.Contains(text, "a=conf:qos") {
				t.Fatalf("SDP offer requested remote resource confirmation:\n%s", text)
			}
		})
	}
}

func TestBuildSDPPreconditionUpdateSelectsCodecAndMarksLocalQoSMet(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "selected codec only"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{Preconditions: true}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			answer, err := parseSDP([]byte("v=0\r\n" +
				"o=- 1 1 IN IP4 192.0.2.10\r\n" +
				"s=-\r\n" +
				"c=IN IP4 192.0.2.10\r\n" +
				"t=0 0\r\n" +
				"m=audio 50000 RTP/AVP 104 110\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				"a=rtpmap:110 telephone-event/16000\r\n" +
				"a=ptime:20\r\n" +
				"a=curr:qos local none\r\n" +
				"a=curr:qos remote none\r\n" +
				"a=des:qos mandatory local sendrecv\r\n" +
				"a=des:qos optional remote sendrecv\r\n"))
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}

			body, err := buildSDPPreconditionUpdate(cfg, net.IPv4(10, 0, 0, 1), 40000, answer, NegotiatedMedia{PTime: 20 * time.Millisecond})
			if err != nil {
				t.Fatalf("buildSDPPreconditionUpdate() error = %v", err)
			}
			text := string(body)
			for _, want := range []string{
				"m=audio 40000 RTP/AVP 104 110",
				"a=rtpmap:104 AMR-WB/16000",
				"a=rtpmap:110 telephone-event/16000",
				"a=fmtp:110 0-15",
				"a=curr:qos local sendrecv",
				"a=curr:qos remote none",
				"a=des:qos mandatory local sendrecv",
				"a=des:qos optional remote sendrecv",
			} {
				if !strings.Contains(text, want+"\r\n") {
					t.Fatalf("SDP update missing %q:\n%s", want, text)
				}
			}
			if strings.Contains(text, " 102 ") || strings.Contains(text, "a=rtpmap:102") {
				t.Fatalf("SDP update included unselected AMR codec:\n%s", text)
			}
		})
	}
}

func TestBuildSDPAnswerPreconditionConfirmation(t *testing.T) {
	tests := []struct {
		name     string
		qosLocal string
		wantConf bool
	}{
		{name: "originating local resources not met", qosLocal: "none", wantConf: true},
		{name: "originating local resources already met", qosLocal: "sendrecv"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{Preconditions: true}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			remote, err := parseSDP([]byte("v=0\r\n" +
				"o=- 1 1 IN IP4 192.0.2.10\r\n" +
				"s=-\r\n" +
				"c=IN IP4 192.0.2.10\r\n" +
				"t=0 0\r\n" +
				"m=audio 50000 RTP/AVP 104 110\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				"a=rtpmap:110 telephone-event/16000\r\n" +
				"a=curr:qos local " + tt.qosLocal + "\r\n" +
				"a=curr:qos remote none\r\n" +
				"a=des:qos mandatory local sendrecv\r\n" +
				"a=des:qos optional remote sendrecv\r\n"))
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}

			body, _, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 1), 40000, remote, MediaOffer{})
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			gotConf := strings.Contains(string(body), "a=conf:qos remote sendrecv\r\n")
			if gotConf != tt.wantConf {
				t.Fatalf("SDP answer conf:qos present = %t, want %t:\n%s", gotConf, tt.wantConf, string(body))
			}
		})
	}
}

func TestSDPAudioLineTextRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		text string
		want sdpAudioLine
	}{
		{
			name: "audio payload list",
			text: "m=audio 49170 RTP/AVP 104 102 101",
			want: sdpAudioLine{
				Port:     49170,
				Protocol: "RTP/AVP",
				Payloads: []int{104, 102, 101},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got sdpAudioLine
			if err := got.UnmarshalText([]byte(tt.text)); err != nil {
				t.Fatalf("UnmarshalText() error = %v", err)
			}
			if got.Port != tt.want.Port || got.Protocol != tt.want.Protocol || !slices.Equal(got.Payloads, tt.want.Payloads) {
				t.Fatalf("UnmarshalText() = %+v, want %+v", got, tt.want)
			}
			text, err := got.MarshalText()
			if err != nil {
				t.Fatalf("MarshalText() error = %v", err)
			}
			if string(text) != tt.text {
				t.Fatalf("MarshalText() = %q, want %q", string(text), tt.text)
			}
		})
	}
}

func TestConfigNormalizedAudioInactivityCallEndReasons(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		want    []AudioInactivityCallEndReason
		wantErr bool
	}{
		{
			name: "default matches carrier config default",
			want: []AudioInactivityCallEndReason{
				AudioInactivityRTCPOnHold,
				AudioInactivityRTPOnConnected,
				AudioInactivityE911RTP,
			},
		},
		{
			name: "explicit empty disables call end reasons",
			cfg:  Config{AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{}},
			want: []AudioInactivityCallEndReason{},
		},
		{
			name:    "reject unsupported reason",
			cfg:     Config{AudioInactivityCallEndReasons: []AudioInactivityCallEndReason{5}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if tt.wantErr {
				if err == nil {
					t.Fatal("Normalized() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if !slices.Equal(got.AudioInactivityCallEndReasons, tt.want) {
				t.Fatalf("AudioInactivityCallEndReasons = %v, want %v", got.AudioInactivityCallEndReasons, tt.want)
			}
		})
	}
}

func TestConfigNormalizedMediaInactivityTimers(t *testing.T) {
	tests := []struct {
		name     string
		cfg      Config
		wantRTP  time.Duration
		wantRTCP time.Duration
		wantSend time.Duration
	}{
		{
			name:     "zero values use carrier defaults",
			wantRTP:  10 * time.Second,
			wantRTCP: 30 * time.Second,
			wantSend: defaultRTCPSend,
		},
		{
			name:     "explicit zero disables timers",
			cfg:      Config{RTPInactivityTimeout: Duration(0), RTCPInactivityTimeout: Duration(0), RTCPSendInterval: Duration(0)},
			wantRTP:  0,
			wantRTCP: 0,
			wantSend: 0,
		},
		{
			name:     "explicit non-zero timers",
			cfg:      Config{RTPInactivityTimeout: Duration(10 * time.Second), RTCPInactivityTimeout: Duration(11 * time.Second), RTCPSendInterval: Duration(3 * time.Second)},
			wantRTP:  10 * time.Second,
			wantRTCP: 11 * time.Second,
			wantSend: 3 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if *got.RTPInactivityTimeout != tt.wantRTP || *got.RTCPInactivityTimeout != tt.wantRTCP || *got.RTCPSendInterval != tt.wantSend {
				t.Fatalf("media timers = %v/%v/%v, want %v/%v/%v",
					*got.RTPInactivityTimeout, *got.RTCPInactivityTimeout, *got.RTCPSendInterval,
					tt.wantRTP, tt.wantRTCP, tt.wantSend)
			}
		})
	}
}

func TestBuildSDPAnswerRejectsUnsupportedMediaLines(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\n" +
		"o=- 1 1 IN IP4 192.0.2.10\r\n" +
		"s=-\r\n" +
		"c=IN IP4 192.0.2.10\r\n" +
		"t=0 0\r\n" +
		"m=audio 50000 RTP/AVP 104 110\r\n" +
		"a=rtpmap:104 AMR-WB/16000\r\n" +
		"a=rtpmap:110 telephone-event/16000\r\n" +
		"m=video 50002 RTP/AVP 96\r\n" +
		"a=rtpmap:96 H264/90000\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}
	answer, _, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	if !strings.Contains(string(answer), "m=video 0 RTP/AVP 96\r\n") {
		t.Fatalf("SDP answer = %q, want rejected video m-line", string(answer))
	}
}

func TestParseSDPMediaDirection(t *testing.T) {
	tests := []struct {
		name string
		line string
		want mediaDirection
	}{
		{name: "missing direction defaults sendrecv", want: mediaDirectionSendRecv},
		{name: "sendrecv", line: "a=sendrecv\r\n", want: mediaDirectionSendRecv},
		{name: "sendonly", line: "a=sendonly\r\n", want: mediaDirectionSendOnly},
		{name: "recvonly", line: "a=recvonly\r\n", want: mediaDirectionRecvOnly},
		{name: "inactive", line: "a=inactive\r\n", want: mediaDirectionInactive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("v=0\r\n" +
				"o=- 1 1 IN IP4 192.0.2.10\r\n" +
				"s=-\r\n" +
				"c=IN IP4 192.0.2.10\r\n" +
				"t=0 0\r\n" +
				"m=audio 50000 RTP/AVP 104\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				tt.line)
			offer, err := parseSDP(body)
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}
			if offer.Direction != tt.want {
				t.Fatalf("direction = %s, want %s", offer.Direction, tt.want)
			}
		})
	}
}

func TestBuildSDPOfferWithDirection(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}

	tests := []struct {
		name      string
		direction mediaDirection
		want      string
	}{
		{name: "local hold", direction: mediaDirectionInactive, want: "a=inactive\r\n"},
		{name: "resume", direction: mediaDirectionSendRecv, want: "a=sendrecv\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, _, err := buildSDPOfferWithDirection(cfg, net.IPv4(10, 0, 0, 2), 40000, MediaOffer{}, tt.direction)
			if err != nil {
				t.Fatalf("buildSDPOfferWithDirection() error = %v", err)
			}
			if !strings.Contains(string(body), tt.want) {
				t.Fatalf("SDP offer missing %q:\n%s", tt.want, string(body))
			}
		})
	}
}

func TestSDPWithDirectionMarksSessionModificationQoSMet(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		direction mediaDirection
		want      []string
	}{
		{
			name:      "hold keeps preconditions met",
			direction: mediaDirectionInactive,
			body: "v=0\r\n" +
				"o=- 1 1 IN IP4 10.0.0.1\r\n" +
				"s=-\r\n" +
				"c=IN IP4 10.0.0.1\r\n" +
				"t=0 0\r\n" +
				"m=audio 40000 RTP/AVP 104\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				"a=sendrecv\r\n" +
				"a=curr:qos local none\r\n" +
				"a=curr:qos remote none\r\n" +
				"a=des:qos mandatory local sendrecv\r\n" +
				"a=des:qos optional remote sendrecv\r\n",
			want: []string{
				"a=inactive\r\n",
				"a=curr:qos local sendrecv\r\n",
				"a=curr:qos remote sendrecv\r\n",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(sdpWithDirection([]byte(tt.body), tt.direction, true))
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Fatalf("SDP missing %q:\n%s", want, got)
				}
			}
		})
	}
}

func TestBuildSDPAnswerWithHoldDirections(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}

	tests := []struct {
		name      string
		remote    mediaDirection
		localHold bool
		want      string
	}{
		{name: "remote sendonly answer", remote: mediaDirectionSendOnly, want: "a=recvonly\r\n"},
		{name: "remote hold answer", remote: mediaDirectionRecvOnly, want: "a=sendonly\r\n"},
		{name: "both sides held answer", remote: mediaDirectionRecvOnly, localHold: true, want: "a=inactive\r\n"},
		{name: "remote inactive answer", remote: mediaDirectionInactive, want: "a=inactive\r\n"},
		{name: "local hold answer", remote: mediaDirectionSendRecv, localHold: true, want: "a=inactive\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remote, err := parseSDP([]byte("v=0\r\n" +
				"o=- 1 1 IN IP4 192.0.2.10\r\n" +
				"s=-\r\n" +
				"c=IN IP4 192.0.2.10\r\n" +
				"t=0 0\r\n" +
				"m=audio 50000 RTP/AVP 104 110\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				"a=rtpmap:110 telephone-event/16000\r\n" +
				"a=" + string(tt.remote) + "\r\n"))
			if err != nil {
				t.Fatalf("parseSDP() error = %v", err)
			}
			answer, _, err := buildSDPAnswerWithLocalHold(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{}, tt.localHold)
			if err != nil {
				t.Fatalf("buildSDPAnswerWithLocalHold() error = %v", err)
			}
			if !strings.Contains(string(answer), tt.want) {
				t.Fatalf("SDP answer missing %q:\n%s", tt.want, string(answer))
			}
		})
	}
}
