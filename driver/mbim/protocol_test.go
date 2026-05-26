package mbim

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	usimcommand "github.com/damonto/ims-client/usim/command"
	usimreader "github.com/damonto/ims-client/usim/reader"
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

func TestSTKEnvelopeRequest(t *testing.T) {
	req := (&STKEnvelopeRequest{
		TransactionID: 7,
		Data:          []byte{0xD1, 0x09, 0x82, 0x02, 0x83, 0x81, 0x8B, 0x03, 0x00, 0x7F, 0xF6},
	}).Request()

	cmd, ok := req.Command.(*Command)
	if !ok {
		t.Fatalf("Command type = %T, want *Command", req.Command)
	}
	if cmd.ServiceID != ServiceSTK {
		t.Fatalf("ServiceID = % X, want STK", cmd.ServiceID)
	}
	if cmd.CommandID != CIDSTKEnvelope || cmd.CommandType != CommandTypeSet {
		t.Fatalf("command = cid %d type %d, want STK envelope set", cmd.CommandID, cmd.CommandType)
	}

	want := []byte{0x0B, 0x00, 0x00, 0x00, 0xD1, 0x09, 0x82, 0x02, 0x83, 0x81, 0x8B, 0x03, 0x00, 0x7F, 0xF6}
	if !bytes.Equal(cmd.Data, want) {
		t.Fatalf("Data = % X, want % X", cmd.Data, want)
	}
}

func TestUICCChannelRequestData(t *testing.T) {
	tests := []struct {
		name      string
		req       *Request
		commandID uint32
		want      []byte
	}{
		{
			name: "open channel",
			req: (&OpenChannelRequest{
				TransactionID: 1,
				ApplicationID: []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04},
				ChannelGroup:  uiccChannelGroupDefault,
			}).Request(),
			commandID: CIDUiccOpenChannel,
			want:      mustDecodeHex(t, "07000000100000000000000001000000A0000000871004"),
		},
		{
			name: "apdu",
			req: (&APDURequest{
				TransactionID:   1,
				Channel:         3,
				SecureMessaging: uiccSecureMessagingNone,
				ClassByteType:   uiccClassByteTypeInterIndustry,
				Command:         []byte{0x00, 0x88, 0x00, 0x81},
			}).Request(),
			commandID: CIDUiccAPDU,
			want:      mustDecodeHex(t, "030000000000000000000000040000001400000000880081"),
		},
		{
			name: "close channel",
			req: (&CloseChannelRequest{
				TransactionID: 1,
				Channel:       3,
				ChannelGroup:  uiccChannelGroupDefault,
			}).Request(),
			commandID: CIDUiccCloseChannel,
			want:      mustDecodeHex(t, "0300000001000000"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := tt.req.Command.(*Command)
			if command.ServiceID != ServiceMsUiccLowLevelAccess {
				t.Fatalf("ServiceID = % X, want MS UICC low level access", command.ServiceID)
			}
			if command.CommandID != tt.commandID || command.CommandType != CommandTypeSet {
				t.Fatalf("command = cid %d type %d, want cid %d set", command.CommandID, command.CommandType, tt.commandID)
			}
			if !bytes.Equal(command.Data, tt.want) {
				t.Fatalf("Data = %X, want %X", command.Data, tt.want)
			}
		})
	}
}

func TestUICCChannelResponseUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name    string
		parse   func([]byte) ([]byte, uint32, error)
		data    []byte
		want    []byte
		status  uint32
		wantErr bool
	}{
		{
			name: "open channel",
			parse: func(data []byte) ([]byte, uint32, error) {
				var got OpenChannelResponse
				err := got.UnmarshalBinary(data)
				if got.Channel != 3 {
					return nil, 0, errors.New("channel mismatch")
				}
				return got.Response, got.Status, err
			},
			data:   mustDecodeHex(t, "900000000300000002000000100000009000"),
			want:   []byte{0x90, 0x00},
			status: 0x90,
		},
		{
			name: "apdu",
			parse: func(data []byte) ([]byte, uint32, error) {
				var got APDUResponse
				err := got.UnmarshalBinary(data)
				return got.Response, got.Status, err
			},
			data:   mustDecodeHex(t, "90000000020000000C000000DB00"),
			want:   []byte{0xDB, 0x00},
			status: 0x90,
		},
		{
			name: "close channel",
			parse: func(data []byte) ([]byte, uint32, error) {
				var got CloseChannelResponse
				err := got.UnmarshalBinary(data)
				return nil, got.Status, err
			},
			data:   mustDecodeHex(t, "90000000"),
			status: 0x90,
		},
		{
			name: "truncated apdu",
			parse: func(data []byte) ([]byte, uint32, error) {
				var got APDUResponse
				err := got.UnmarshalBinary(data)
				return got.Response, got.Status, err
			},
			data:    []byte{0x00},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, status, err := tt.parse(tt.data)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalBinary() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
			}
			if status != tt.status {
				t.Fatalf("Status = %d, want %d", status, tt.status)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("Response = %X, want %X", got, tt.want)
			}
		})
	}
}

func TestReaderAuthenticate3GWithAIDUsesUICCChannel(t *testing.T) {
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })

	aid := []byte{0xA0, 0x00, 0x00, 0x00, 0x87, 0x10, 0x04}
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := bytes.Repeat([]byte{0x22}, 16)
	apduResponse := []byte{0xDB, 0x01, 0xAA, 0x02, 0xBB, 0xCC, 0x03, 0xDD, 0xEE, 0xFF}

	errc := make(chan error, 1)
	go func() {
		defer close(errc)
		defer server.Close()

		if err := expectMBIMCommand(server, 1, CIDUiccOpenChannel, mustDecodeHex(t, "07000000100000000000000001000000A0000000871004")); err != nil {
			errc <- err
			return
		}
		if _, err := server.Write(mbimCommandDone(1, ServiceMsUiccLowLevelAccess, CIDUiccOpenChannel, mbimUICCOpenChannelResponseData(0x90, 3, nil))); err != nil {
			errc <- err
			return
		}

		wantAPDU := usimcommand.Authenticate3G{Rand: rand, AUTN: autn}.APDU()
		wantAPDUData := binary.LittleEndian.AppendUint32(nil, 3)
		wantAPDUData = binary.LittleEndian.AppendUint32(wantAPDUData, uiccSecureMessagingNone)
		wantAPDUData = binary.LittleEndian.AppendUint32(wantAPDUData, uiccClassByteTypeInterIndustry)
		wantAPDUData = binary.LittleEndian.AppendUint32(wantAPDUData, uint32(len(wantAPDU)))
		wantAPDUData = binary.LittleEndian.AppendUint32(wantAPDUData, 20)
		wantAPDUData = append(wantAPDUData, wantAPDU...)
		if err := expectMBIMCommand(server, 2, CIDUiccAPDU, wantAPDUData); err != nil {
			errc <- err
			return
		}
		if _, err := server.Write(mbimCommandDone(2, ServiceMsUiccLowLevelAccess, CIDUiccAPDU, mbimUICCResponseData(0x90, apduResponse))); err != nil {
			errc <- err
			return
		}

		if err := expectMBIMCommand(server, 3, CIDUiccCloseChannel, mustDecodeHex(t, "0300000001000000")); err != nil {
			errc <- err
			return
		}
		if _, err := server.Write(mbimCommandDone(3, ServiceMsUiccLowLevelAccess, CIDUiccCloseChannel, mustDecodeHex(t, "90000000"))); err != nil {
			errc <- err
			return
		}
	}()

	reader := &Reader{conn: client}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := reader.Authenticate3G(ctx, usimreader.AuthenticateRequest{
		AID:  aid,
		Rand: rand,
		AUTN: autn,
	})
	if err != nil {
		t.Fatalf("Authenticate3G() error = %v", err)
	}
	if want := apduResponse; !bytes.Equal(got, want) {
		t.Fatalf("Authenticate3G() = %X, want %X", got, want)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
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

func expectMBIMCommand(conn net.Conn, transactionID, commandID uint32, wantData []byte) error {
	frame, err := readFrame(conn)
	if err != nil {
		return err
	}
	if got := binary.LittleEndian.Uint32(frame[8:12]); got != transactionID {
		return fmt.Errorf("transaction ID = %d, want %d", got, transactionID)
	}
	var service [16]byte
	copy(service[:], frame[20:36])
	if service != ServiceMsUiccLowLevelAccess {
		return fmt.Errorf("service = % X, want MS UICC low level access", service)
	}
	if got := binary.LittleEndian.Uint32(frame[36:40]); got != commandID {
		return fmt.Errorf("command ID = %d, want %d", got, commandID)
	}
	if got := binary.LittleEndian.Uint32(frame[40:44]); got != CommandTypeSet {
		return fmt.Errorf("command type = %d, want set", got)
	}
	dataLength := binary.LittleEndian.Uint32(frame[44:48])
	if dataLength > uint32(len(frame)-48) {
		return errors.New("request data is truncated")
	}
	gotData := frame[48 : 48+dataLength]
	if !bytes.Equal(gotData, wantData) {
		return fmt.Errorf("request data = %X, want %X", gotData, wantData)
	}
	return nil
}

func mbimCommandDone(transactionID uint32, service [16]byte, commandID uint32, data []byte) []byte {
	messageLength := uint32(48 + len(data))
	buf := binary.LittleEndian.AppendUint32(nil, uint32(MessageTypeCommandDone))
	buf = binary.LittleEndian.AppendUint32(buf, messageLength)
	buf = binary.LittleEndian.AppendUint32(buf, transactionID)
	buf = binary.LittleEndian.AppendUint32(buf, 1)
	buf = binary.LittleEndian.AppendUint32(buf, 0)
	buf = append(buf, service[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, commandID)
	buf = binary.LittleEndian.AppendUint32(buf, uint32(StatusNone))
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(data)))
	return append(buf, data...)
}

func mbimUICCResponseData(status uint32, response []byte) []byte {
	data := binary.LittleEndian.AppendUint32(nil, status)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(response)))
	data = binary.LittleEndian.AppendUint32(data, 12)
	return append(data, response...)
}

func mbimUICCOpenChannelResponseData(status, channel uint32, response []byte) []byte {
	data := binary.LittleEndian.AppendUint32(nil, status)
	data = binary.LittleEndian.AppendUint32(data, channel)
	data = binary.LittleEndian.AppendUint32(data, uint32(len(response)))
	data = binary.LittleEndian.AppendUint32(data, 16)
	return append(data, response...)
}
