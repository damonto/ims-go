package voice

import (
	"strings"
	"testing"
)

func TestValidateRemotePayloadMappings(t *testing.T) {
	previous := map[int]rtpPayloadMapping{
		96: {encoding: "amr", clockRate: 8000, channels: 1},
	}
	tests := []struct {
		name    string
		media   string
		wantErr string
	}{
		{
			name:  "unchanged mapping",
			media: "m=audio 50000 RTP/AVP 96\r\na=rtpmap:96 AMR/8000\r\n",
		},
		{
			name:  "new payload for same codec",
			media: "m=audio 50000 RTP/AVP 96 97\r\na=rtpmap:96 AMR/8000\r\na=rtpmap:97 AMR/8000\r\n",
		},
		{
			name:    "codec remapped",
			media:   "m=audio 50000 RTP/AVP 96\r\na=rtpmap:96 EVS/16000\r\n",
			wantErr: "payload type 96 changed",
		},
		{
			name:    "clock remapped",
			media:   "m=audio 50000 RTP/AVP 96\r\na=rtpmap:96 AMR/16000\r\n",
			wantErr: "payload type 96 changed",
		},
		{
			name:  "static payload is not tracked",
			media: "m=audio 50000 RTP/AVP 0\r\na=rtpmap:0 EVS/16000\r\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			description, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\n" + tt.media))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			err = validateRemotePayloadMappings(previous, description)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRemotePayloadMappings() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("validateRemotePayloadMappings() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestMergeRemotePayloadMappingsKeepsHistory(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "removed payload remains reserved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			previous := map[int]rtpPayloadMapping{96: {encoding: "amr", clockRate: 8000, channels: 1}}
			description, err := unmarshalSDP([]byte("v=0\r\nc=IN IP4 192.0.2.10\r\nt=0 0\r\nm=audio 50000 RTP/AVP 97\r\na=rtpmap:97 AMR/8000\r\n"))
			if err != nil {
				t.Fatalf("unmarshalSDP() error = %v", err)
			}
			got := mergeRemotePayloadMappings(previous, description)
			if len(got) != 2 || got[96].encoding != "amr" || got[97].encoding != "amr" {
				t.Fatalf("mergeRemotePayloadMappings() = %+v, want payloads 96 and 97", got)
			}
		})
	}
}
