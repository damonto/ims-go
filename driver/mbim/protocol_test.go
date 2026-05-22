package mbim

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestRequestMarshalBinary(t *testing.T) {
	tests := []struct {
		name string
		req  *Request
		want []byte
	}{
		{
			name: "open",
			req:  (&OpenDeviceRequest{TransactionID: 1}).Request(),
			want: []byte{
				0x01, 0x00, 0x00, 0x00,
				0x10, 0x00, 0x00, 0x00,
				0x01, 0x00, 0x00, 0x00,
				0x00, 0x10, 0x00, 0x00,
			},
		},
		{
			name: "subscriber ready status",
			req:  (&SubscriberReadyStatusRequest{TransactionID: 6}).Request(),
			want: mustDecodeHex(t, "0300000030000000060000000100000000000000A289CC33BCBB8B4FB6B0133EC2AAE6DF020000000000000000000000"),
		},
		{
			name: "auth aka",
			req: (&AuthAKARequest{
				TransactionID: 7,
				Rand:          []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
				AUTN:          []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0},
			}).Request(),
			want: mustDecodeHex(t, "03000000500000000700000001000000000000001D2B5FF70AA148B2AA5250F15767174E010000000000000020000000000102030405060708090A0B0C0D0E0FFFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.req.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("MarshalBinary() = %X, want %X", got, tt.want)
			}
		})
	}
}

func TestDeviceSlotMappingsResponseUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    []SlotMapping
		wantErr bool
	}{
		{
			name: "empty",
			data: []byte{0, 0, 0, 0},
			want: nil,
		},
		{
			name: "single mapping",
			data: slotMappingsPayload(2),
			want: []SlotMapping{{Slot: 2}},
		},
		{
			name:    "truncated table",
			data:    []byte{1, 0, 0, 0},
			wantErr: true,
		},
		{
			name:    "bad slot size",
			data:    []byte{1, 0, 0, 0, 12, 0, 0, 0, 2, 0, 0, 0, 0, 0},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got DeviceSlotMappingsResponse
			err := got.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if len(got.SlotMappings) != len(tt.want) {
				t.Fatalf("SlotMappings length = %d, want %d", len(got.SlotMappings), len(tt.want))
			}
			for i := range tt.want {
				if got.SlotMappings[i] != tt.want[i] {
					t.Fatalf("SlotMappings[%d] = %+v, want %+v", i, got.SlotMappings[i], tt.want[i])
				}
			}
		})
	}
}

func TestApplicationListResponseUnmarshalBinary(t *testing.T) {
	payload := mustDecodeHex(t,
		"0100000001000000000000003C000000"+
			"180000003C000000"+
			"0400000020000000100000003000000008000000020000003800000002000000"+
			"A0000000871002FF34FF0789312E30FF"+
			"4D6F766973746172"+
			"01810000",
	)
	var got ApplicationListResponse
	if err := got.UnmarshalBinary(payload); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if got.Version != 1 || got.ActiveApplicationIndex != 0 || len(got.Applications) != 1 {
		t.Fatalf("response = %+v", got)
	}
	app := got.Applications[0]
	if app.Type != UiccApplicationTypeUSIM {
		t.Fatalf("Application Type = %d, want %d", app.Type, UiccApplicationTypeUSIM)
	}
	if !bytes.Equal(app.AID, mustDecodeHex(t, "A0000000871002FF34FF0789312E30FF")) {
		t.Fatalf("Application AID = %X", app.AID)
	}
	if app.Label != "Movistar" {
		t.Fatalf("Application Label = %q, want Movistar", app.Label)
	}
}

func TestReadBinaryRequestData(t *testing.T) {
	req := (&ReadBinaryRequest{
		TransactionID: 1,
		ApplicationID: []byte{0xA0, 0x00},
		FilePath:      []byte{0x6F, 0xAD},
		Size:          4,
	}).Request()
	command := req.Command.(*Command)
	if command.CommandID != CIDUiccReadBinary {
		t.Fatalf("CommandID = %#x, want %#x", command.CommandID, CIDUiccReadBinary)
	}
	want := mustDecodeHex(t, "010000002C000000020000003000000002000000000000000400000000000000000000000000000000000000A00000006FAD0000")
	if !bytes.Equal(command.Data, want) {
		t.Fatalf("Data = %X, want %X", command.Data, want)
	}
}

func TestFileStatusRequestData(t *testing.T) {
	req := (&FileStatusRequest{
		TransactionID: 1,
		ApplicationID: []byte{0xA0, 0x00},
		FilePath:      []byte{0x6F, 0xAD},
	}).Request()
	command := req.Command.(*Command)
	if command.CommandID != CIDUiccFileStatus {
		t.Fatalf("CommandID = %#x, want %#x", command.CommandID, CIDUiccFileStatus)
	}
	want := mustDecodeHex(t, "0100000014000000020000001800000002000000A00000006FAD0000")
	if !bytes.Equal(command.Data, want) {
		t.Fatalf("Data = %X, want %X", command.Data, want)
	}
}

func TestReadBinaryResponseUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		sw1     uint32
		sw2     uint32
		resp    []byte
		wantErr bool
	}{
		{
			name: "response",
			data: mustDecodeHex(t, "0100000090000000000000001400000002000000AABB"),
			sw1:  0x90,
			sw2:  0x00,
			resp: []byte{0xAA, 0xBB},
		},
		{
			name:    "truncated",
			data:    []byte{0x90},
			wantErr: true,
		},
		{
			name:    "truncated response",
			data:    mustDecodeHex(t, "0100000090000000000000001400000002000000AA"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ReadBinaryResponse
			err := got.UnmarshalBinary(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if got.StatusWord1 != tt.sw1 || got.StatusWord2 != tt.sw2 {
				t.Fatalf("StatusWord = %#x%#x, want %#x%#x", got.StatusWord1, got.StatusWord2, tt.sw1, tt.sw2)
			}
			if !bytes.Equal(got.Data, tt.resp) {
				t.Fatalf("Data = %X, want %X", got.Data, tt.resp)
			}
		})
	}
}

func TestAKAPayload(t *testing.T) {
	tests := []struct {
		name string
		resp *AuthAKAResponse
		want []byte
	}{
		{
			name: "success",
			resp: &AuthAKAResponse{
				RES: []byte{1, 2, 3},
				CK:  []byte{4, 5},
				IK:  []byte{6, 7},
			},
			want: []byte{0xDB, 3, 1, 2, 3, 2, 4, 5, 2, 6, 7},
		},
		{
			name: "sync failure",
			resp: &AuthAKAResponse{
				AUTS: []byte{1, 2, 3, 4},
			},
			want: []byte{0xDC, 4, 1, 2, 3, 4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := akaPayload(tt.resp)
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("akaPayload() = %X, want %X", got, tt.want)
			}
		})
	}
}

func slotMappingsPayload(slot uint32) []byte {
	var data []byte
	data = binary.LittleEndian.AppendUint32(data, 1)
	data = binary.LittleEndian.AppendUint32(data, 12)
	data = binary.LittleEndian.AppendUint32(data, 4)
	data = binary.LittleEndian.AppendUint32(data, slot)
	return data
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("DecodeString() error = %v", err)
	}
	return data
}
