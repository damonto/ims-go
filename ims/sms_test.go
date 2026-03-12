package ims

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeDecodeSMS(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{"gsm7", "hello"},
		{"gsm7 newline", "hello\nworld"},
		{"ucs2", "你好"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpdu, err := encodeSMSSubmit(7, "+12345", tt.text)
			if err != nil {
				t.Fatalf("encodeSMSSubmit() error = %v", err)
			}
			if len(tpdu) == 0 {
				t.Fatal("encodeSMSSubmit() returned empty TPDU")
			}

			encoded, dcs, udl, err := encodeUserData(tt.text)
			if err != nil {
				t.Fatalf("encodeUserData() error = %v", err)
			}
			deliver := []byte{0x00}
			deliver = append(deliver, encodeTPAddress("+12345")...)
			deliver = append(deliver, 0x00, dcs)
			deliver = append(deliver, bytes.Repeat([]byte{0x00}, 7)...)
			deliver = append(deliver, udl)
			deliver = append(deliver, encoded...)

			msg, err := decodeSMSDeliver(deliver)
			if err != nil {
				t.Fatalf("decodeSMSDeliver() error = %v", err)
			}
			if msg.Text != tt.text {
				t.Fatalf("decodeSMSDeliver() text = %q, want %q", msg.Text, tt.text)
			}
		})
	}
}

func TestRPEncodeDecode(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want rpMessage
	}{
		{
			name: "rp-data",
			raw: func() []byte {
				raw := append([]byte{rpDataNetworkToMS, 5, 0x00}, encodeRPAddress("+8613800000000")...)
				raw = append(raw, 0x03, 0x01, 0x02, 0x03)
				return raw
			}(),
			want: rpMessage{Type: rpDataNetworkToMS, Reference: 5, Destination: "8613800000000", TPDU: []byte{0x01, 0x02, 0x03}},
		},
		{
			name: "rp-error",
			raw:  []byte{rpErrorNetworkToMS, 7, 0x01, rpCauseInvalidMandatoryInformation},
			want: rpMessage{Type: rpErrorNetworkToMS, Reference: 7, Cause: rpCauseInvalidMandatoryInformation, HasCause: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got rpMessage
			if err := got.UnmarshalBinary(tt.raw); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Type != tt.want.Type || got.Reference != tt.want.Reference || got.Destination != tt.want.Destination || got.Cause != tt.want.Cause || got.HasCause != tt.want.HasCause || !bytes.Equal(got.TPDU, tt.want.TPDU) {
				t.Fatalf("UnmarshalBinary() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestEncodeDecodeMultipartSMS(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{name: "gsm7 multipart", text: strings.Repeat("A", 200)},
		{name: "ucs2 multipart", text: strings.Repeat("你", 80)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := buildSMSUserDataParts(tt.text)
			if err != nil {
				t.Fatalf("buildSMSUserDataParts() error = %v", err)
			}
			if len(parts) < 2 {
				t.Fatalf("len(parts) = %d, want >= 2", len(parts))
			}
			var assembled strings.Builder
			var reference uint16
			var sixteenBit bool
			for i, part := range parts {
				var deliver smsDeliverTPDU
				if err := deliver.UnmarshalBinary(part.marshalDeliver("+12345")); err != nil {
					t.Fatalf("UnmarshalBinary(part %d) error = %v", i, err)
				}
				if deliver.Concat == nil {
					t.Fatalf("deliver.Concat(part %d) = nil", i)
				}
				if i == 0 {
					reference = deliver.Concat.Reference
					sixteenBit = deliver.Concat.SixteenBit
				} else if deliver.Concat.Reference != reference || deliver.Concat.SixteenBit != sixteenBit {
					t.Fatalf("concat reference mismatch at part %d: %+v", i, deliver.Concat)
				}
				assembled.WriteString(deliver.Message.Text)
			}
			if assembled.String() != tt.text {
				t.Fatalf("assembled text length = %d, want %d", len(assembled.String()), len(tt.text))
			}
		})
	}
}

func TestDecodeMultipartSMS16BitReference(t *testing.T) {
	text := strings.Repeat("你", 66)
	header := []byte{0x06, smsConcatIEI16Bit, 0x04, 0x12, 0x34, 0x02, 0x01}
	userData := append(header, encodeUCS2(text)...)
	part := smsUserDataPart{udhi: true, dcs: 0x08, udl: len(userData), userData: userData}
	var deliver smsDeliverTPDU
	if err := deliver.UnmarshalBinary(part.marshalDeliver("+12345")); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if deliver.Concat == nil || !deliver.Concat.SixteenBit || deliver.Concat.Reference != 0x1234 || deliver.Concat.Total != 2 || deliver.Concat.Sequence != 1 {
		t.Fatalf("deliver.Concat = %+v", deliver.Concat)
	}
	if deliver.Message.Text != text {
		t.Fatalf("deliver.Message.Text = %q, want %q", deliver.Message.Text, text)
	}
}

func TestRPMessageMarshalBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		msg  rpMessage
	}{
		{
			name: "rp-data",
			msg:  newRPDataMessage(7, "+8613800000000", []byte{0x01, 0x02, 0x03}),
		},
		{
			name: "rp-ack",
			msg:  newRPAckMessage(5),
		},
		{
			name: "rp-error",
			msg:  newRPErrorMessage(9, rpCauseInvalidMandatoryInformation),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.msg.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if tt.msg.Type == rpDataMSToNetwork {
				return
			}
			var got rpMessage
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Type != tt.msg.Type || got.Reference != tt.msg.Reference || got.Cause != tt.msg.Cause {
				t.Fatalf("round trip = %+v, want %+v", got, tt.msg)
			}
		})
	}
}

func TestSMSSubmitTPDUMarshalBinary(t *testing.T) {
	parts, err := buildSMSUserDataParts("hello")
	if err != nil {
		t.Fatalf("buildSMSUserDataParts() error = %v", err)
	}
	tests := []struct {
		name string
		tpdu smsSubmitTPDU
	}{
		{
			name: "single-part gsm7",
			tpdu: newSMSSubmitTPDU(7, "+12345", parts[0]),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.tpdu.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if len(data) == 0 {
				t.Fatal("MarshalBinary() returned empty TPDU")
			}
		})
	}
}

func TestSMSDeliverTPDURoundTrip(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{name: "gsm7", text: "hello"},
		{name: "ucs2", text: "你好"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := buildSMSUserDataParts(tt.text)
			if err != nil {
				t.Fatalf("buildSMSUserDataParts() error = %v", err)
			}
			data, err := newSMSDeliverTPDU("+12345", parts[0]).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var deliver smsDeliverTPDU
			if err := deliver.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if deliver.Message.From != "12345" {
				t.Fatalf("Message.From = %q, want %q", deliver.Message.From, "12345")
			}
			if deliver.Message.Text != tt.text {
				t.Fatalf("Message.Text = %q, want %q", deliver.Message.Text, tt.text)
			}
		})
	}
}
