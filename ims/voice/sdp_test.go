package voice

import (
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func unmarshalSDP(data []byte) (sdpOffer, error) {
	var offer sdpOffer
	if err := offer.UnmarshalBinary(data); err != nil {
		return sdpOffer{}, err
	}
	return offer, nil
}

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
		"b=AS:80",
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
	if media.DTMF == nil || media.DTMF.PayloadType != 110 || media.DTMF.ClockRate != 16000 {
		t.Fatalf("NegotiatedMedia DTMF = %+v, want telephone-event 110/16000", media.DTMF)
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
			offer, err := unmarshalSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			got := offer.Codecs[0]
			if got.Name != tt.want.Name || got.ClockRate != tt.want.ClockRate || len(got.PayloadTypes) != 1 || got.PayloadTypes[0] != tt.want.PayloadTypes[0] {
				t.Fatalf("offer.Codecs[0] = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMediaDescriptionUnmarshalBinaryPreservesFormats(t *testing.T) {
	tests := []struct {
		name          string
		sdp           string
		wantCodec     AudioCodec
		wantPayload   int
		wantFMTP      string
		wantPTime     time.Duration
		wantMaxPTime  time.Duration
		wantDirection MediaDirection
	}{
		{
			name:          "EVS format and packetization",
			sdp:           "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 127 96\r\na=fmtp:127 br=5.9-13.2;bw=nb-swb;ch-aw-recv=2;vendor-mode=x\r\na=rtpmap:127 EVS/16000\r\na=rtpmap:96 telephone-event/16000\r\na=fmtp:96 0-15\r\na=ptime:20\r\na=maxptime:60\r\na=recvonly\r\n",
			wantCodec:     CodecEVS,
			wantPayload:   127,
			wantFMTP:      "br=5.9-13.2;bw=nb-swb;ch-aw-recv=2;vendor-mode=x",
			wantPTime:     20 * time.Millisecond,
			wantMaxPTime:  60 * time.Millisecond,
			wantDirection: MediaDirectionRecvOnly,
		},
		{
			name:          "static PCMU format",
			sdp:           "v=0\r\nc=IN IP4 192.0.2.20\r\nt=0 0\r\nm=audio 51000 RTP/AVP 0\r\na=ptime:12.5\r\na=maxptime:25.5\r\n",
			wantCodec:     CodecPCMU,
			wantPayload:   0,
			wantPTime:     12500 * time.Microsecond,
			wantMaxPTime:  25500 * time.Microsecond,
			wantDirection: MediaDirectionSendRecv,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var description MediaDescription
			if err := description.UnmarshalBinary([]byte(tt.sdp)); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if description.Profile != defaultRTPProfile || description.PTime != tt.wantPTime || description.MaxPTime != tt.wantMaxPTime || description.Direction != tt.wantDirection {
				t.Fatalf("MediaDescription = %+v, want profile %s ptime/maxptime %s/%s direction %s", description, defaultRTPProfile, tt.wantPTime, tt.wantMaxPTime, tt.wantDirection)
			}
			if len(description.Formats) == 0 {
				t.Fatal("MediaDescription.Formats is empty")
			}
			format := description.Formats[0]
			if format.Codec != tt.wantCodec || format.PayloadType != tt.wantPayload || format.FMTP != tt.wantFMTP {
				t.Fatalf("AudioFormat = %+v, want %s payload %d fmtp %q", format, tt.wantCodec, tt.wantPayload, tt.wantFMTP)
			}
			if !slices.Equal(description.RawSDP, []byte(tt.sdp)) {
				t.Fatal("MediaDescription.RawSDP did not preserve the SDP body")
			}
		})
	}
}

func TestFormatSDPDuration(t *testing.T) {
	tests := []struct {
		name  string
		value time.Duration
		want  string
	}{
		{name: "integer milliseconds", value: 20 * time.Millisecond, want: "20"},
		{name: "fractional milliseconds", value: 12500 * time.Microsecond, want: "12.5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatSDPDuration(tt.value); got != tt.want {
				t.Fatalf("formatSDPDuration(%s) = %q, want %q", tt.value, got, tt.want)
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
			offer, err := unmarshalSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
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
			offer, err := unmarshalSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
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
			name:    "audio port count must be positive",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000/0 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "invalid audio port",
		},
		{
			name:    "media port count must be numeric",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=video 50002/two RTP/AVP 96\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "invalid media port",
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
		{
			name:    "ptime must be numeric",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\na=ptime:twenty\r\n",
			wantErr: "invalid ptime",
		},
		{
			name:    "maxptime must be non-negative",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\na=maxptime:-1\r\n",
			wantErr: "invalid maxptime",
		},
		{
			name:    "ptime cannot exceed maxptime",
			sdp:     "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\na=ptime:80\r\na=maxptime:40\r\n",
			wantErr: "ptime exceeds maxptime",
		},
		{
			name:    "connection from another media section does not apply",
			sdp:     "v=0\r\nt=0 0\r\nm=video 50002 RTP/AVP 96\r\nc=IN IP4 192.0.2.20\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n",
			wantErr: "connection line is missing",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := unmarshalSDP([]byte(tt.sdp))
			if err == nil {
				t.Fatal("unmarshalSDP() error = nil, want non-nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("unmarshalSDP() error = %q, want containing %q", err.Error(), tt.wantErr)
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
			remote, err := unmarshalSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
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
			remote, err := unmarshalSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
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
	remote, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 127 96\r\na=rtpmap:127 EVS/16000\r\na=fmtp:127 br=5.9-13.2;bw=nb-swb;ch-aw-recv=2\r\na=rtpmap:96 telephone-event/16000\r\n"))
	if err != nil {
		t.Fatalf("unmarshalSDP() error = %v", err)
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
	if media.Codec != CodecEVS || media.PayloadType != 127 || media.DTMF == nil || media.DTMF.PayloadType != 96 || media.DTMF.ClockRate != 16000 {
		t.Fatalf("NegotiatedMedia = %+v, want EVS payload 127 DTMF 96/16000", media)
	}
	if !media.Negotiated || media.Bitrate != "5.9-13.2" || media.Bandwidth != "nb-swb" || media.ChAwRecv == nil || *media.ChAwRecv != 2 {
		t.Fatalf("NegotiatedMedia format = %+v, want EVS br/bw/ch-aw-recv", media.AudioFormat)
	}
	if media.RemoteFormat.FMTP != "br=5.9-13.2;bw=nb-swb;ch-aw-recv=2" {
		t.Fatalf("RemoteFormat.FMTP = %q", media.RemoteFormat.FMTP)
	}
}

func TestEVSHeaderFullOnlyNegotiation(t *testing.T) {
	tests := []struct {
		name        string
		localHFOnly bool
		remoteFMTP  string
	}{
		{"local requires header-full", true, "br=5.9-13.2;bw=nb-swb"},
		{"remote requires header-full", false, "br=5.9-13.2;bw=nb-swb;hf-only=1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{Codecs: []AudioCodecConfig{
				{Name: CodecEVS, PayloadTypes: []int{127}, ClockRate: 16000, Bitrate: "5.9-13.2", Bandwidth: "nb-swb", HFOnly: tt.localHFOnly},
			}}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			remote, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 127\r\na=rtpmap:127 EVS/16000\r\na=fmtp:127 " + tt.remoteFMTP + "\r\n"))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			if !strings.Contains(string(body), "hf-only=1") {
				t.Fatalf("SDP answer missing hf-only=1:\n%s", body)
			}
			if !media.HFOnly {
				t.Fatal("NegotiatedMedia.HFOnly = false, want true")
			}
		})
	}
}

func TestBuildSDPAnswerSelectsCompatibleCodec(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 102 101 110\r\na=rtpmap:104 AMR-WB/16000\r\na=fmtp:104 octet-align=1\r\na=rtpmap:102 AMR/8000\r\na=rtpmap:101 telephone-event/8000\r\na=rtpmap:110 telephone-event/16000\r\na=ptime:20\r\n"))
	if err != nil {
		t.Fatalf("unmarshalSDP() error = %v", err)
	}

	body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"m=audio 40000 RTP/AVP 104 110",
		"b=AS:42",
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
	if media.Codec != CodecAMRWB || media.PayloadType != 104 || media.RemotePort != 50000 || media.DTMF == nil || media.DTMF.PayloadType != 110 || media.DTMF.ClockRate != 16000 {
		t.Fatalf("NegotiatedMedia = %+v, want AMR-WB payload 104 remote port 50000 DTMF 110/16000", media)
	}
	if !media.OctetAlign {
		t.Fatalf("NegotiatedMedia.OctetAlign = false, want true")
	}
}

func TestAudioFormatCompatibleNegotiatesFMTP(t *testing.T) {
	tests := []struct {
		name   string
		local  AudioCodecConfig
		remote AudioFormat
		want   bool
	}{
		{
			name:   "EVS overlapping bitrate and bandwidth",
			local:  AudioCodecConfig{Name: CodecEVS, ClockRate: 16000, Bitrate: "5.9-13.2", Bandwidth: "nb-wb"},
			remote: AudioFormat{Codec: CodecEVS, ClockRate: 16000, Channels: 1, Bitrate: "13.2-24.4", Bandwidth: "wb-swb"},
			want:   true,
		},
		{
			name:   "EVS disjoint bitrate",
			local:  AudioCodecConfig{Name: CodecEVS, ClockRate: 16000, Bitrate: "5.9-13.2", Bandwidth: "nb-wb"},
			remote: AudioFormat{Codec: CodecEVS, ClockRate: 16000, Channels: 1, Bitrate: "24.4", Bandwidth: "swb"},
			want:   false,
		},
		{
			name:   "AMR mode-set overlap",
			local:  AudioCodecConfig{Name: CodecAMR, ClockRate: 8000, ModeSet: "0,2,4,7"},
			remote: AudioFormat{Codec: CodecAMR, ClockRate: 8000, Channels: 1, ModeSet: "1,2,3"},
			want:   true,
		},
		{
			name:   "AMR disjoint mode-set",
			local:  AudioCodecConfig{Name: CodecAMR, ClockRate: 8000, ModeSet: "0,2,4,7"},
			remote: AudioFormat{Codec: CodecAMR, ClockRate: 8000, Channels: 1, ModeSet: "1,3,5,6"},
			want:   false,
		},
		{
			name:   "different clock rate",
			local:  AudioCodecConfig{Name: CodecAMR, ClockRate: 8000},
			remote: AudioFormat{Codec: CodecAMR, ClockRate: 16000, Channels: 1},
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := AudioFormatCompatible(tt.local, tt.remote); got != tt.want {
				t.Fatalf("AudioFormatCompatible() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildSDPAnswerIntersectsCodecFMTP(t *testing.T) {
	tests := []struct {
		name     string
		local    AudioCodecConfig
		rtpmap   string
		fmtp     string
		wantFMTP string
		wantErr  bool
	}{
		{
			name:     "EVS intersection",
			local:    AudioCodecConfig{Name: CodecEVS, PayloadTypes: []int{127}, ClockRate: 16000, Bitrate: "5.9-13.2", Bandwidth: "nb-wb", ModeSet: "0,1,2"},
			rtpmap:   "EVS/16000",
			fmtp:     "br=9.6-24.4;bw=wb-swb;mode-set=1,2,3",
			wantFMTP: "br=9.6-13.2;bw=wb;mode-set=1,2",
		},
		{
			name:    "EVS disjoint range",
			local:   AudioCodecConfig{Name: CodecEVS, PayloadTypes: []int{127}, ClockRate: 16000, Bitrate: "5.9-13.2", Bandwidth: "nb-wb"},
			rtpmap:  "EVS/16000",
			fmtp:    "br=24.4;bw=swb",
			wantErr: true,
		},
		{
			name:     "AMR mode-set intersection",
			local:    AudioCodecConfig{Name: CodecAMR, PayloadTypes: []int{102}, ClockRate: 8000, ModeSet: "0,2,4,7"},
			rtpmap:   "AMR/8000",
			fmtp:     "mode-set=1,2,4",
			wantFMTP: "mode-set=2,4",
		},
		{
			name:    "AMR disjoint mode-set",
			local:   AudioCodecConfig{Name: CodecAMR, PayloadTypes: []int{102}, ClockRate: 8000, ModeSet: "0,2,4,7"},
			rtpmap:  "AMR/8000",
			fmtp:    "mode-set=1,3,5,6",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{Codecs: []AudioCodecConfig{tt.local}}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			body := "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP " + strconv.Itoa(tt.local.PayloadTypes[0]) + "\r\n" +
				"a=rtpmap:" + strconv.Itoa(tt.local.PayloadTypes[0]) + " " + tt.rtpmap + "\r\na=fmtp:" + strconv.Itoa(tt.local.PayloadTypes[0]) + " " + tt.fmtp + "\r\n"
			remote, err := unmarshalSDP([]byte(body))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			answer, _, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
			if tt.wantErr {
				if err == nil {
					t.Fatal("buildSDPAnswer() error = nil, want incompatible codec error")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			if !strings.Contains(string(answer), tt.wantFMTP) {
				t.Fatalf("SDP answer missing %q:\n%s", tt.wantFMTP, answer)
			}
		})
	}
}

func TestBuildSDPAnswerSelectsRequestedPayloadType(t *testing.T) {
	cfg, err := (Config{Codecs: []AudioCodecConfig{
		{Name: CodecEVS, PayloadTypes: []int{126}, ClockRate: 16000, Bitrate: "5.9-13.2"},
		{Name: CodecEVS, PayloadTypes: []int{127}, ClockRate: 16000, Bitrate: "13.2-24.4"},
	}}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 126 127\r\na=rtpmap:126 EVS/16000\r\na=fmtp:126 br=5.9-13.2\r\na=rtpmap:127 EVS/16000\r\na=fmtp:127 br=13.2-24.4\r\n"))
	if err != nil {
		t.Fatalf("unmarshalSDP() error = %v", err)
	}
	tests := []struct {
		name        string
		payloadType int
		wantBitrate string
	}{
		{name: "first EVS configuration", payloadType: 126, wantBitrate: "5.9-13.2"},
		{name: "second EVS configuration", payloadType: 127, wantBitrate: "13.2-24.4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{PayloadTypes: []int{tt.payloadType}})
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			if media.PayloadType != tt.payloadType || media.Bitrate != tt.wantBitrate {
				t.Fatalf("NegotiatedMedia = %+v, want payload %d bitrate %s", media.AudioFormat, tt.payloadType, tt.wantBitrate)
			}
		})
	}
}

func TestBuildSDPAnswerPreservesTelephoneEventMask(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 110\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:110 telephone-event/16000\r\na=fmtp:110 0-9\r\n"))
	if err != nil {
		t.Fatalf("unmarshalSDP() error = %v", err)
	}
	body, media, err := buildSDPAnswer(cfg, net.IPv4(192, 0, 2, 20), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	want := uint16(0x03ff)
	if media.DTMF == nil || media.DTMF.DTMFEventMask != want {
		t.Fatalf("DTMF = %+v, want event mask %#04x", media.DTMF, want)
	}
	text := string(body)
	if !strings.Contains(text, "a=fmtp:110 0-9\r\n") {
		t.Fatalf("SDP answer missing negotiated telephone-event mask:\n%s", text)
	}
	if strings.Contains(text, "a=fmtp:110 0-15\r\n") {
		t.Fatalf("SDP answer advertised unnegotiated telephone-event mask:\n%s", text)
	}
}

func TestBuildSDPAnswerDefaultsTelephoneEventWithoutFMTP(t *testing.T) {
	tests := []struct {
		name string
		sdp  string
	}{
		{
			name: "missing fmtp defaults to events zero through fifteen",
			sdp:  "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 110\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:110 telephone-event/16000\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			remote, err := unmarshalSDP([]byte(tt.sdp))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			if media.DTMF == nil || media.DTMF.DTMFEventMask != dtmfAllEventsMask {
				t.Fatalf("DTMF = %+v, want default events 0-15", media.DTMF)
			}
			if !strings.Contains(string(body), "a=fmtp:110 0-15\r\n") {
				t.Fatalf("SDP answer missing default telephone-event range:\n%s", body)
			}
		})
	}
}

func TestBuildSDPAnswerRejectsTelephoneEventWithoutDTMFDigits(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 110\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:110 telephone-event/16000\r\na=fmtp:110 16-31\r\n"))
	if err != nil {
		t.Fatalf("unmarshalSDP() error = %v", err)
	}
	body, media, err := buildSDPAnswer(cfg, net.IPv4(192, 0, 2, 20), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	if media.DTMF != nil || strings.Contains(string(body), "telephone-event") {
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

func TestValidTelephoneEventFMTP(t *testing.T) {
	tests := []struct {
		name string
		fmtp string
		want bool
	}{
		{name: "empty uses default", fmtp: "", want: true},
		{name: "all events", fmtp: "0-15", want: true},
		{name: "list and ranges", fmtp: "0-2,10,12-15", want: true},
		{name: "invalid token", fmtp: "digits", want: false},
		{name: "out of range", fmtp: "0-16", want: false},
		{name: "reversed range", fmtp: "8-2", want: false},
		{name: "empty item", fmtp: "0,,1", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validTelephoneEventFMTP(tt.fmtp); got != tt.want {
				t.Fatalf("validTelephoneEventFMTP(%q) = %t, want %t", tt.fmtp, got, tt.want)
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
	remote, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n"))
	if err != nil {
		t.Fatalf("unmarshalSDP() error = %v", err)
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
	remote, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 0 100 101\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:100 AMR/8000\r\na=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n"))
	if err != nil {
		t.Fatalf("unmarshalSDP() error = %v", err)
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
	if media.Codec != CodecPCMU || media.PayloadType != 0 || media.RemotePort != 50000 || media.DTMF == nil || media.DTMF.PayloadType != 101 {
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
	tests := []struct {
		name    string
		profile string
		rtpmap  string
	}{
		{name: "different codec", profile: "RTP/AVP", rtpmap: "AMR-WB/16000"},
		{name: "wrong clock rate", profile: "RTP/AVP", rtpmap: "AMR/16000"},
		{name: "wrong channel count", profile: "RTP/AVP", rtpmap: "AMR/8000/2"},
		{name: "WebRTC secure profile", profile: "UDP/TLS/RTP/SAVPF", rtpmap: "AMR/8000"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 " + tt.profile + " 104\r\na=rtpmap:104 " + tt.rtpmap + "\r\n"
			remote, err := unmarshalSDP([]byte(body))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			if _, _, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{}); err == nil {
				t.Fatal("buildSDPAnswer() error = nil, want incompatible media error")
			}
		})
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
			answer, err := unmarshalSDP([]byte("v=0\r\n" +
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
				t.Fatalf("unmarshalSDP() error = %v", err)
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
			remote, err := unmarshalSDP([]byte("v=0\r\n" +
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
				t.Fatalf("unmarshalSDP() error = %v", err)
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

func TestParseQoSConfirmationRemote(t *testing.T) {
	tests := []struct {
		name string
		line string
		want bool
	}{
		{name: "remote sendrecv", line: "a=conf:qos remote sendrecv", want: true},
		{name: "case insensitive", line: "a=conf:qos REMOTE SENDRECV", want: true},
		{name: "none is not confirmation", line: "a=conf:qos remote none"},
		{name: "local confirmation", line: "a=conf:qos local sendrecv"},
		{name: "missing status", line: "a=conf:qos remote"},
		{name: "extra field", line: "a=conf:qos remote sendrecv extra"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseQoSConfirmationRemote(tt.line); got != tt.want {
				t.Fatalf("parseQoSConfirmationRemote(%q) = %v, want %v", tt.line, got, tt.want)
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
	}{
		{
			name:     "zero values use carrier defaults",
			wantRTP:  10 * time.Second,
			wantRTCP: 30 * time.Second,
		},
		{
			name:     "explicit zero disables timers",
			cfg:      Config{RTPInactivityTimeout: Duration(0), RTCPInactivityTimeout: Duration(0)},
			wantRTP:  0,
			wantRTCP: 0,
		},
		{
			name:     "explicit non-zero timers",
			cfg:      Config{RTPInactivityTimeout: Duration(10 * time.Second), RTCPInactivityTimeout: Duration(11 * time.Second)},
			wantRTP:  10 * time.Second,
			wantRTCP: 11 * time.Second,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.cfg.Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			if *got.RTPInactivityTimeout != tt.wantRTP || *got.RTCPInactivityTimeout != tt.wantRTCP {
				t.Fatalf("inactivity timers = %v/%v, want %v/%v",
					*got.RTPInactivityTimeout, *got.RTCPInactivityTimeout, tt.wantRTP, tt.wantRTCP)
			}
		})
	}
}

func TestBuildSDPAnswerRejectsUnsupportedMediaLines(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	const audio = "m=audio 50000 RTP/AVP 104 110\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:110 telephone-event/16000\r\n"
	tests := []struct {
		name       string
		timing     string
		media      string
		wantTiming string
		wantMedia  []string
	}{
		{
			name:       "video after audio",
			timing:     "0 0",
			media:      audio + "m=video 50002/2 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n",
			wantTiming: "t=0 0",
			wantMedia:  []string{"m=audio 40000 RTP/AVP 104 110", "m=video 0 RTP/AVP 96"},
		},
		{
			name:       "video before audio",
			timing:     "10 20",
			media:      "m=video 50002/2 RTP/AVP 96\r\na=rtpmap:96 H264/90000\r\n" + audio,
			wantTiming: "t=10 20",
			wantMedia:  []string{"m=video 0 RTP/AVP 96", "m=audio 40000 RTP/AVP 104 110"},
		},
		{
			name:       "second audio stream",
			timing:     "0 0",
			media:      audio + "m=audio 50002 RTP/AVP 0\r\n",
			wantTiming: "t=0 0",
			wantMedia:  []string{"m=audio 40000 RTP/AVP 104 110", "m=audio 0 RTP/AVP 0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\nt=" + tt.timing + "\r\n" + tt.media
			remote, err := unmarshalSDP([]byte(body))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			answer, _, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			lines := strings.FieldsFunc(string(answer), func(r rune) bool { return r == '\r' || r == '\n' })
			var mediaLines []string
			for _, line := range lines {
				if strings.HasPrefix(line, "m=") {
					mediaLines = append(mediaLines, line)
				}
			}
			if !slices.Equal(mediaLines, tt.wantMedia) || !slices.Contains(lines, tt.wantTiming) {
				t.Fatalf("SDP answer media/timing = %v/%q, want %v/%q", mediaLines, string(answer), tt.wantMedia, tt.wantTiming)
			}
		})
	}
}

func TestBuildSDPAnswerPreservesTimeDescriptions(t *testing.T) {
	tests := []struct {
		name string
		time string
		want []string
	}{
		{
			name: "multiple times with repeats and zones",
			time: "t=3724394400 3724398000\r\nr=7d 1h 0 25h\r\nt=3724484400 3724488000\r\nr=7d 1h 0 25h\r\nz=2882844526 -1h 2898848070 0\r\n",
			want: []string{
				"t=3724394400 3724398000",
				"r=7d 1h 0 25h",
				"t=3724484400 3724488000",
				"r=7d 1h 0 25h",
				"z=2882844526 -1h 2898848070 0",
			},
		},
		{
			name: "missing time falls back to permanent session",
			want: []string{"t=0 0"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := (Config{}).Normalized()
			if err != nil {
				t.Fatalf("Normalized() error = %v", err)
			}
			body := "v=0\r\no=- 1 1 IN IP4 192.0.2.10\r\ns=-\r\nc=IN IP4 192.0.2.10\r\n" + tt.time +
				"m=audio 50000 RTP/AVP 104\r\na=rtpmap:104 AMR-WB/16000\r\n"
			remote, err := unmarshalSDP([]byte(body))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			answer, _, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
			if err != nil {
				t.Fatalf("buildSDPAnswer() error = %v", err)
			}
			var got []string
			for line := range strings.FieldsFuncSeq(string(answer), func(r rune) bool { return r == '\r' || r == '\n' }) {
				if strings.HasPrefix(line, "t=") || strings.HasPrefix(line, "r=") || strings.HasPrefix(line, "z=") {
					got = append(got, line)
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Fatalf("SDP answer time descriptions = %v, want %v\n%s", got, tt.want, answer)
			}
		})
	}
}

func TestParseSDPSupportsMediaPortCount(t *testing.T) {
	tests := []struct {
		name      string
		media     string
		wantCount int
	}{
		{name: "audio RTP sessions", media: "m=audio 50000/2 RTP/AVP 104", wantCount: 2},
		{name: "single audio port", media: "m=audio 50000 RTP/AVP 104"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n" + tt.media + "\r\na=rtpmap:104 AMR-WB/16000\r\n")
			offer, err := unmarshalSDP(body)
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			if len(offer.Media) != 1 || offer.Media[0].Port != 50000 || offer.Media[0].PortCount != tt.wantCount {
				t.Fatalf("media line = %+v, want port 50000 count %d", offer.Media, tt.wantCount)
			}
		})
	}
}

func TestParseSDPMediaDirection(t *testing.T) {
	tests := []struct {
		name    string
		session string
		media   string
		want    MediaDirection
	}{
		{name: "missing direction defaults sendrecv", want: MediaDirectionSendRecv},
		{name: "media sendrecv", media: "a=sendrecv\r\n", want: MediaDirectionSendRecv},
		{name: "media sendonly", media: "a=sendonly\r\n", want: MediaDirectionSendOnly},
		{name: "session recvonly", session: "a=recvonly\r\n", want: MediaDirectionRecvOnly},
		{name: "media overrides session", session: "a=sendonly\r\n", media: "a=inactive\r\n", want: MediaDirectionInactive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte("v=0\r\n" +
				"o=- 1 1 IN IP4 192.0.2.10\r\n" +
				"s=-\r\n" +
				"c=IN IP4 192.0.2.10\r\n" +
				"t=0 0\r\n" +
				tt.session +
				"m=audio 50000 RTP/AVP 104\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				tt.media)
			offer, err := unmarshalSDP(body)
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
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
		direction MediaDirection
		want      string
	}{
		{name: "local hold", direction: MediaDirectionSendOnly, want: "a=sendonly\r\n"},
		{name: "resume", direction: MediaDirectionSendRecv, want: "a=sendrecv\r\n"},
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
		direction MediaDirection
		want      []string
	}{
		{
			name:      "hold keeps preconditions met",
			direction: MediaDirectionSendOnly,
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
				"a=sendonly\r\n",
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

func TestSDPWithDirectionKeepsRTCPBandwidthScopedToAudio(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "zero modifiers split across video and audio",
			body: "v=0\r\nb=RR:0\r\nm=video 50002 RTP/AVP 96\r\nb=RS:0\r\nm=audio 50000 RTP/AVP 104\r\nb=RR:0\r\na=sendrecv\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := string(sdpWithDirection([]byte(tt.body), MediaDirectionSendOnly, true))
			if strings.Contains(got, "b=RR:2500") {
				t.Fatalf("bandwidth from different SDP scopes disabled audio RTCP:\n%s", got)
			}
			if strings.Count(got, "b=RR:0") != 2 {
				t.Fatalf("session/audio b=RR:0 was modified:\n%s", got)
			}
		})
	}
}

func TestLocalSDPWithDirectionRestoresDisabledRTCP(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "resume disables RTCP enabled only for hold",
			body: "v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104\r\nb=RS:0\r\nb=RR:2500\r\na=sendonly\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{
				endpoint:         &Endpoint{},
				localSDP:         []byte(tt.body),
				localHoldRTCPOff: true,
			}
			got, err := call.localSDPWithDirection(MediaDirectionSendRecv)
			if err != nil {
				t.Fatalf("localSDPWithDirection() error = %v", err)
			}
			body := string(got)
			for _, want := range []string{"b=RS:0\r\n", "b=RR:0\r\n", "a=sendrecv\r\n"} {
				if !strings.Contains(body, want) {
					t.Fatalf("resumed SDP missing %q:\n%s", want, body)
				}
			}
			if strings.Contains(body, "b=RR:2500") {
				t.Fatalf("resumed SDP kept temporary hold RTCP bandwidth:\n%s", body)
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
		remote    MediaDirection
		localHold bool
		want      string
	}{
		{name: "remote sendonly answer", remote: MediaDirectionSendOnly, want: "a=recvonly\r\n"},
		{name: "remote hold answer", remote: MediaDirectionRecvOnly, want: "a=sendonly\r\n"},
		{name: "both sides held answer", remote: MediaDirectionRecvOnly, localHold: true, want: "a=inactive\r\n"},
		{name: "remote inactive answer", remote: MediaDirectionInactive, want: "a=inactive\r\n"},
		{name: "local hold answer", remote: MediaDirectionSendRecv, localHold: true, want: "a=inactive\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			remote, err := unmarshalSDP([]byte("v=0\r\n" +
				"o=- 1 1 IN IP4 192.0.2.10\r\n" +
				"s=-\r\n" +
				"c=IN IP4 192.0.2.10\r\n" +
				"t=0 0\r\n" +
				"m=audio 50000 RTP/AVP 104 110\r\n" +
				"a=rtpmap:104 AMR-WB/16000\r\n" +
				"a=rtpmap:110 telephone-event/16000\r\n" +
				"a=" + string(tt.remote) + "\r\n"))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
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
