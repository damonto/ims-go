package usim

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	"github.com/damonto/ims-client/apdu"
)

type scriptTransmitter struct {
	steps []scriptStep
	idx   int
}

type scriptStep struct {
	wantAPDU string
	resp     apdu.Response
}

func (s *scriptTransmitter) Close() error { return nil }

func (s *scriptTransmitter) Transmit(_ context.Context, req *apdu.Request) (apdu.Response, error) {
	step := s.steps[s.idx]
	s.idx++
	if got := req.String(); got != step.wantAPDU {
		return nil, apdu.StatusError{SW: 0x6F00}
	}
	return step.resp, nil
}

func TestCardAKA(t *testing.T) {
	rand := bytes.Repeat([]byte{0x01}, 16)
	autn := bytes.Repeat([]byte{0x02}, 16)
	res := []byte{0x11, 0x22, 0x33, 0x44}
	ck := bytes.Repeat([]byte{0xAA}, 16)
	ik := bytes.Repeat([]byte{0xBB}, 16)
	auts := bytes.Repeat([]byte{0xAA}, 14)

	tests := []struct {
		name  string
		body  []byte
		check func(t *testing.T, got AKAResult)
	}{
		{
			name: "success",
			body: append(append(append(append([]byte{0xDB, byte(len(res))}, res...), byte(len(ck))), ck...), append([]byte{byte(len(ik))}, ik...)...),
			check: func(t *testing.T, got AKAResult) {
				t.Helper()
				if !bytes.Equal(got.RES, res) || !bytes.Equal(got.CK, ck) || !bytes.Equal(got.IK, ik) {
					t.Fatalf("AKA() = %+v, want RES=%X CK=%X IK=%X", got, res, ck, ik)
				}
			},
		},
		{
			name: "synchronization failure",
			body: append([]byte{0xDC, byte(len(auts))}, auts...),
			check: func(t *testing.T, got AKAResult) {
				t.Helper()
				if !got.IsSynchronizationFailure() {
					t.Fatalf("AKA() = %+v, want synchronization failure", got)
				}
				if !bytes.Equal(got.AUTS, auts) {
					t.Fatalf("AKA().AUTS = %X, want %X", got.AUTS, auts)
				}
			},
		},
		{
			name: "authentication reject",
			body: []byte{0xDC, 0x00},
			check: func(t *testing.T, got AKAResult) {
				t.Helper()
				if !got.IsAuthenticationReject() {
					t.Fatalf("AKA() = %+v, want authentication reject", got)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := &Card{tx: &scriptTransmitter{steps: []scriptStep{
				{wantAPDU: apdu.Authenticate3G(rand, autn).String(), resp: apdu.Response{0x61, byte(len(tt.body))}},
				{wantAPDU: apdu.GetResponse(byte(len(tt.body))).String(), resp: append(append(apdu.Response{}, tt.body...), 0x90, 0x00)},
			}}, logger: slog.Default()}

			got, err := card.AKA(context.Background(), rand, autn)
			if err != nil {
				t.Fatalf("AKA() error = %v", err)
			}
			tt.check(t, got)
		})
	}
}
