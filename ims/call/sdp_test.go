package call

import (
	"net"
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
		"m=audio 40000 RTP/AVP 104 102 0 101",
		"b=AS:14",
		"b=RS:0",
		"b=RR:2500",
		"a=rtpmap:104 AMR-WB/16000",
		"a=rtpmap:102 AMR/8000",
		"a=fmtp:102 octet-align=1",
		"a=rtpmap:0 PCMU/8000",
		"a=rtpmap:101 telephone-event/8000",
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
	if media.Codec != CodecAMRWB || media.PayloadType != 104 || media.PTime != 20*time.Millisecond {
		t.Fatalf("NegotiatedMedia = %+v, want AMR-WB payload 104 ptime 20ms", media)
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

func TestBuildSDPAnswerSelectsCompatibleCodec(t *testing.T) {
	cfg, err := (Config{}).Normalized()
	if err != nil {
		t.Fatalf("Normalized() error = %v", err)
	}
	remote, err := parseSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 104 102 101\r\na=rtpmap:104 AMR-WB/16000\r\na=rtpmap:102 AMR/8000\r\na=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\n"))
	if err != nil {
		t.Fatalf("parseSDP() error = %v", err)
	}

	body, media, err := buildSDPAnswer(cfg, net.IPv4(10, 0, 0, 2), 40000, remote, MediaOffer{})
	if err != nil {
		t.Fatalf("buildSDPAnswer() error = %v", err)
	}
	text := string(body)
	for _, want := range []string{
		"m=audio 40000 RTP/AVP 104 101",
		"b=AS:14",
		"b=RS:0",
		"b=RR:2500",
		"a=fmtp:104 octet-align=1",
		"a=rtpmap:101 telephone-event/8000",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("SDP answer missing %q:\n%s", want, text)
		}
	}
	if media.Codec != CodecAMRWB || media.PayloadType != 104 || media.RemotePort != 50000 || media.DTMFPayloadType != 101 {
		t.Fatalf("NegotiatedMedia = %+v, want AMR-WB payload 104 remote port 50000 DTMF 101", media)
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
	if media.Codec != CodecPCMU || media.PayloadType != 0 || media.RemotePort != 50000 || media.DTMFPayloadType != 101 {
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

func TestConfigNormalizedRejectsUnsupportedPreconditions(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "preconditions", cfg: Config{Preconditions: true}},
		{name: "reliable provisional", cfg: Config{ReliableProvisional: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.cfg.Normalized(); err == nil {
				t.Fatal("Normalized() error = nil, want unsupported feature error")
			}
		})
	}
}
