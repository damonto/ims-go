package sms

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestSMSDeliver8BitUserData(t *testing.T) {
	tests := []struct {
		name       string
		part       userDataPart
		wantHeader []byte
	}{
		{name: "plain", part: userDataPart{dcs: 0x04, udl: 3, userData: []byte{0x01, 0x02, 0x03}}},
		{name: "with UDH", part: userDataPart{udhi: true, dcs: 0x04, udl: 6, userData: []byte{0x02, 0x70, 0x00, 0x01, 0x02, 0x03}}, wantHeader: []byte{0x02, 0x70, 0x00}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := newDeliverTPDU("+15551234567", tt.part).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got deliverTPDU
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got.Message.UserData, tt.part.userData) {
				t.Fatalf("UserData = %x, want %x", got.Message.UserData, tt.part.userData)
			}
			if !bytes.Equal(got.Message.UserDataHeader, tt.wantHeader) {
				t.Fatalf("UserDataHeader = %x, want %x", got.Message.UserDataHeader, tt.wantHeader)
			}
		})
	}
}

func TestEncodeDecodeSMS(t *testing.T) {
	tests := []struct {
		name string
		text string
		dcs  byte
	}{
		{"gsm7", "hello", 0x00},
		{"gsm7 newline", "hello\nworld", 0x00},
		{"gsm7 class 1", "hello", 0xF1},
		{"ucs2", "你好", 0x08},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tpdu, err := encodeSubmit(7, "+12345", tt.text)
			if err != nil {
				t.Fatalf("encodeSubmit() error = %v", err)
			}
			if len(tpdu) == 0 {
				t.Fatal("encodeSubmit() returned empty TPDU")
			}

			encoded, _, udl, err := encodeUserData(tt.text)
			if err != nil {
				t.Fatalf("encodeUserData() error = %v", err)
			}
			deliver := []byte{0x00}
			deliver = append(deliver, mustEncodeTPAddress(t, "+12345")...)
			deliver = append(deliver, 0x00, tt.dcs)
			deliver = append(deliver, bytes.Repeat([]byte{0x00}, 7)...)
			deliver = append(deliver, udl)
			deliver = append(deliver, encoded...)

			msg, err := decodeDeliver(deliver)
			if err != nil {
				t.Fatalf("decodeDeliver() error = %v", err)
			}
			if msg.Text != tt.text {
				t.Fatalf("decodeDeliver() text = %q, want %q", msg.Text, tt.text)
			}
		})
	}
}

func TestGSM7BinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{name: "plain", text: "hello"},
		{name: "extension", text: "{hello}^€"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := NewGSM7(tt.text)
			if err != nil {
				t.Fatalf("NewGSM7() error = %v", err)
			}

			data, err := value.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var got GSM7
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.String() != tt.text {
				t.Fatalf("String() = %q, want %q", got.String(), tt.text)
			}
		})
	}
}

func TestUCS2BinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		text string
	}{
		{name: "bmp", text: "你好"},
		{name: "surrogate pair", text: "你好🙂世界"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value := UCS2(tt.text)

			data, err := value.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var got UCS2
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if string(got) != tt.text {
				t.Fatalf("string(got) = %q, want %q", string(got), tt.text)
			}
		})
	}
}

func TestUCS2UnmarshalBinaryRejectsOddLength(t *testing.T) {
	var got UCS2
	if err := got.UnmarshalBinary([]byte{0x00}); err == nil {
		t.Fatal("UnmarshalBinary() error = nil, want odd length error")
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
				raw := append([]byte{rpDataNetworkToMS, 5}, encodeRPAddress("+15550000000")...)
				raw = append(raw, encodeRPAddress("+8613800000000")...)
				raw = append(raw, 0x03, 0x01, 0x02, 0x03)
				return raw
			}(),
			want: rpMessage{Type: rpDataNetworkToMS, Reference: 5, Originator: "+15550000000", Destination: "+8613800000000", TPDU: []byte{0x01, 0x02, 0x03}},
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
			if got.Type != tt.want.Type || got.Reference != tt.want.Reference || got.Originator != tt.want.Originator || got.Destination != tt.want.Destination || got.Cause != tt.want.Cause || got.HasCause != tt.want.HasCause || !bytes.Equal(got.TPDU, tt.want.TPDU) {
				t.Fatalf("UnmarshalBinary() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestRPErrorIncludesCauseText(t *testing.T) {
	tests := []struct {
		name  string
		cause byte
		want  string
	}{
		{
			name:  "known cause",
			cause: 28,
			want:  "rp-error cause 28 (unidentified subscriber)",
		},
		{
			name:  "unknown cause",
			cause: 2,
			want:  "rp-error cause 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &RPError{Cause: tt.cause}
			if got := err.Error(); got != tt.want {
				t.Fatalf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEncodeRPAddressEmptyUsesZeroLengthOnly(t *testing.T) {
	got := encodeRPAddress("")

	if !bytes.Equal(got, []byte{0x00}) {
		t.Fatalf("encodeRPAddress(\"\") = % X, want 00", got)
	}
}

func TestDecodeTPAddressAddsInternationalPrefix(t *testing.T) {
	got, _, err := decodeTPAddress(mustEncodeTPAddress(t, "+15551234567"))
	if err != nil {
		t.Fatalf("decodeTPAddress() error = %v", err)
	}
	if got != "+15551234567" {
		t.Fatalf("decodeTPAddress() = %q, want %q", got, "+15551234567")
	}
}

func TestDecodeTPAddressAlphanumeric(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "short code", raw: "777", want: "777"},
		{name: "brand name", raw: "One NZ", want: "One NZ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, _, err := decodeTPAddress(encodeAlphanumericTPAddress(t, tt.raw))
			if err != nil {
				t.Fatalf("decodeTPAddress() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("decodeTPAddress() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDecodeTPAddressSemiOctetSpecialDigits(t *testing.T) {
	got, _, err := decodeTPAddress(mustEncodeTPAddress(t, "123#45*"))
	if err != nil {
		t.Fatalf("decodeTPAddress() error = %v", err)
	}
	if got != "123#45*" {
		t.Fatalf("decodeTPAddress() = %q, want %q", got, "123#45*")
	}
}

func TestDecodeTPAddressRejectsInvalidLength(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "full address over twelve octets",
			raw:  append([]byte{22, tpTOAInternationalISDN}, bytes.Repeat([]byte{0x21}, 11)...),
		},
		{
			name: "alphanumeric full address over twelve octets",
			raw:  append([]byte{22, 0xD0}, bytes.Repeat([]byte{0x00}, 11)...),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := decodeTPAddress(tt.raw); err == nil {
				t.Fatal("decodeTPAddress() error = nil, want invalid length error")
			}
		})
	}
}

func TestEncodeTPAddressShortCodeUsesUnknownTypeOfNumber(t *testing.T) {
	got := mustEncodeTPAddress(t, "777")

	if len(got) < 2 {
		t.Fatalf("len(encodeTPAddress()) = %d, want at least 2", len(got))
	}
	if got[1] != 0x81 {
		t.Fatalf("ToA = 0x%02X, want 0x81", got[1])
	}
}

func TestEncodeTPAddressRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name    string
		address string
	}{
		{name: "empty", address: ""},
		{name: "plus only", address: "+"},
		{name: "letter outside called BCD", address: "123d"},
		{name: "fill digit from input", address: "123f"},
		{name: "too long", address: "+123456789012345678901"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := encodeTPAddress(tt.address); err == nil {
				t.Fatal("encodeTPAddress() error = nil, want non-nil")
			}
		})
	}
}

func TestSplitUCS2WordsKeepsSurrogatePairsTogether(t *testing.T) {
	words := encodeUCS2("你好🙂世界")
	decoded := make([]uint16, len(words)/2)
	for i := range decoded {
		decoded[i] = uint16(words[i*2])<<8 | uint16(words[i*2+1])
	}
	parts := splitUCS2Words(decoded, 3)
	if len(parts) != 3 {
		t.Fatalf("len(parts) = %d, want 3", len(parts))
	}
	last := parts[0][len(parts[0])-1]
	if last >= 0xD800 && last <= 0xDBFF {
		t.Fatalf("splitUCS2Words() split after high surrogate: %x", last)
	}
	first := parts[1][0]
	if first >= 0xDC00 && first <= 0xDFFF {
		t.Fatalf("splitUCS2Words() split before low surrogate: %x", first)
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
			parts, err := buildUserDataParts(tt.text)
			if err != nil {
				t.Fatalf("buildUserDataParts() error = %v", err)
			}
			if len(parts) < 2 {
				t.Fatalf("len(parts) = %d, want >= 2", len(parts))
			}
			var assembled strings.Builder
			var reference uint16
			var sixteenBit bool
			for i, part := range parts {
				payload, err := newDeliverTPDU("+12345", part).MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary(part %d) error = %v", i, err)
				}
				var deliver deliverTPDU
				if err := deliver.UnmarshalBinary(payload); err != nil {
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
	header := []byte{0x06, concatIEI16Bit, 0x04, 0x12, 0x34, 0x02, 0x01}
	userData := append(header, encodeUCS2(text)...)
	part := userDataPart{udhi: true, dcs: 0x08, udl: len(userData), userData: userData}
	payload, err := newDeliverTPDU("+12345", part).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	var deliver deliverTPDU
	if err := deliver.UnmarshalBinary(payload); err != nil {
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
		{
			name: "rp-error with SMS-DELIVER-REPORT",
			msg:  newRPErrorDeliverReportMessage(9, rpCauseMemoryCapacityExceeded, tpFailureCauseMemoryCapacityExceeded),
		},
		{
			name: "rp-smma",
			msg:  newRPSMMAMessage(11),
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
			if got.Type != tt.msg.Type || got.Reference != tt.msg.Reference || got.Cause != tt.msg.Cause || !bytes.Equal(got.UserData, tt.msg.UserData) {
				t.Fatalf("round trip = %+v, want %+v", got, tt.msg)
			}
		})
	}
}

func TestSMSSubmitTPDUMarshalBinary(t *testing.T) {
	parts, err := buildUserDataParts("hello")
	if err != nil {
		t.Fatalf("buildUserDataParts() error = %v", err)
	}
	tests := []struct {
		name           string
		tpdu           submitTPDU
		wantFirstOctet byte
	}{
		{
			name: "single-part gsm7",
			tpdu: newSubmitTPDU(submitTPDUConfig{
				Reference:   7,
				Destination: "+12345",
				Part:        parts[0],
			}),
			wantFirstOctet: tpduMTISubmit,
		},
		{
			name: "status report requested",
			tpdu: newSubmitTPDU(submitTPDUConfig{
				Reference:           7,
				Destination:         "+12345",
				Part:                parts[0],
				RequestStatusReport: true,
			}),
			wantFirstOctet: tpduMTISubmit | tpduStatusReportRequestFlag,
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
			if data[0] != tt.wantFirstOctet {
				t.Fatalf("first octet = 0x%02X, want 0x%02X", data[0], tt.wantFirstOctet)
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
			parts, err := buildUserDataParts(tt.text)
			if err != nil {
				t.Fatalf("buildUserDataParts() error = %v", err)
			}
			data, err := newDeliverTPDU("+12345", parts[0]).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var deliver deliverTPDU
			if err := deliver.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if deliver.Message.From != "+12345" {
				t.Fatalf("Message.From = %q, want %q", deliver.Message.From, "+12345")
			}
			if deliver.Message.Text != tt.text {
				t.Fatalf("Message.Text = %q, want %q", deliver.Message.Text, tt.text)
			}
			if !bytes.Equal(deliver.Message.RawTPDU, data) {
				t.Fatalf("Message.RawTPDU = % X, want original % X", deliver.Message.RawTPDU, data)
			}
			if deliver.Message.ReservedMTI {
				t.Fatal("Message.ReservedMTI = true, want false")
			}
		})
	}
}

func TestSMSDeliverTPDUPreservesReservedMTIRawTPDU(t *testing.T) {
	parts, err := buildUserDataParts("hello")
	if err != nil {
		t.Fatalf("buildUserDataParts() error = %v", err)
	}
	data, err := newDeliverTPDU("+12345", parts[0]).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	data[0] = data[0]&^tpduMTIMask | tpduMTIReserved

	var deliver deliverTPDU
	if err := deliver.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if deliver.Message.Text != "hello" || deliver.Message.From != "+12345" {
		t.Fatalf("Message = %+v, want decoded deliver fields", deliver.Message)
	}
	if !deliver.Message.ReservedMTI {
		t.Fatal("Message.ReservedMTI = false, want true")
	}
	if !bytes.Equal(deliver.Message.RawTPDU, data) {
		t.Fatalf("Message.RawTPDU = % X, want original % X", deliver.Message.RawTPDU, data)
	}
}

func TestSMSDeliverTPDURejectsTrailingData(t *testing.T) {
	parts, err := buildUserDataParts("hello")
	if err != nil {
		t.Fatalf("buildUserDataParts() error = %v", err)
	}
	data, err := newDeliverTPDU("+12345", parts[0]).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	data = append(data, 0xFF)

	var deliver deliverTPDU
	if err := deliver.UnmarshalBinary(data); err == nil {
		t.Fatal("UnmarshalBinary() error = nil, want trailing data error")
	}
}

func TestSMSDeliverTPDURejectsOverlongOriginatorAddress(t *testing.T) {
	overlongAddress := append([]byte{22, tpTOAInternationalISDN}, bytes.Repeat([]byte{0x21}, 11)...)
	raw := append([]byte{byte(tpduMTIDeliver)}, overlongAddress...)
	raw = append(raw, 0x00, 0x00)
	raw = append(raw, tpduZeroTimestamp[:]...)
	raw = append(raw, 0x00)

	var deliver deliverTPDU
	if err := deliver.UnmarshalBinary(raw); err == nil {
		t.Fatal("UnmarshalBinary() error = nil, want overlong TP-OA error")
	}
}

func TestSMSStatusReportTPDURoundTrip(t *testing.T) {
	serviceCenterTime := time.Date(2026, time.March, 13, 10, 20, 30, 0, time.FixedZone("", 8*60*60))
	dischargeTime := time.Date(2026, time.March, 13, 10, 21, 5, 0, time.FixedZone("", 8*60*60))
	want := StatusReport{
		Recipient:         "+12345",
		MessageReference:  7,
		Status:            0x00,
		ServiceCenterTime: serviceCenterTime,
		DischargeTime:     dischargeTime,
	}

	data, err := (statusReportTPDU{Message: want}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	got, err := decodeStatusReport(data)
	if err != nil {
		t.Fatalf("decodeStatusReport() error = %v", err)
	}
	if got.Recipient != want.Recipient {
		t.Fatalf("Recipient = %q, want %q", got.Recipient, want.Recipient)
	}
	if got.MessageReference != want.MessageReference {
		t.Fatalf("MessageReference = %d, want %d", got.MessageReference, want.MessageReference)
	}
	if got.Status != want.Status {
		t.Fatalf("Status = 0x%02X, want 0x%02X", got.Status, want.Status)
	}
	if got.ServiceCenterTime.Format(time.RFC3339) != want.ServiceCenterTime.Format(time.RFC3339) {
		t.Fatalf("ServiceCenterTime = %q, want %q", got.ServiceCenterTime.Format(time.RFC3339), want.ServiceCenterTime.Format(time.RFC3339))
	}
	if got.DischargeTime.Format(time.RFC3339) != want.DischargeTime.Format(time.RFC3339) {
		t.Fatalf("DischargeTime = %q, want %q", got.DischargeTime.Format(time.RFC3339), want.DischargeTime.Format(time.RFC3339))
	}
}

func TestSMSStatusReportTPDURejectsOverlongRecipientAddress(t *testing.T) {
	serviceCenterTime := time.Date(2026, time.March, 13, 10, 20, 30, 0, time.FixedZone("", 8*60*60))
	dischargeTime := time.Date(2026, time.March, 13, 10, 21, 5, 0, time.FixedZone("", 8*60*60))
	overlongAddress := append([]byte{22, tpTOAInternationalISDN}, bytes.Repeat([]byte{0x21}, 11)...)
	raw := []byte{byte(tpduMTIStatusReport), 0x07}
	raw = append(raw, overlongAddress...)
	raw = append(raw, encodeTimestamp(serviceCenterTime)...)
	raw = append(raw, encodeTimestamp(dischargeTime)...)
	raw = append(raw, 0x00)

	if _, err := decodeStatusReport(raw); err == nil {
		t.Fatal("decodeStatusReport() error = nil, want overlong TP-RA error")
	}
}

func TestSMSStatusReportTPDUParsesExtendedFields(t *testing.T) {
	serviceCenterTime := time.Date(2026, time.March, 13, 10, 20, 30, 0, time.FixedZone("", 8*60*60))
	dischargeTime := time.Date(2026, time.March, 13, 10, 21, 5, 0, time.FixedZone("", 8*60*60))

	raw := []byte{0x6E, 0x07}
	raw = append(raw, mustEncodeTPAddress(t, "+12345")...)
	raw = append(raw, encodeTimestamp(serviceCenterTime)...)
	raw = append(raw, encodeTimestamp(dischargeTime)...)
	raw = append(raw, 0x20)
	raw = append(raw, 0x87, 0x00, 0x7F, 0xF6, 0x03, 0xAA, 0xBB, 0xCC)

	got, err := decodeStatusReport(raw)
	if err != nil {
		t.Fatalf("decodeStatusReport() error = %v", err)
	}
	if got.Recipient != "+12345" {
		t.Fatalf("Recipient = %q, want %q", got.Recipient, "+12345")
	}
	if got.MessageReference != 7 {
		t.Fatalf("MessageReference = %d, want 7", got.MessageReference)
	}
	if got.Status != 0x20 {
		t.Fatalf("Status = 0x%02X, want 0x20", got.Status)
	}
	if got.MoreMessagesWaiting {
		t.Fatal("MoreMessagesWaiting = true, want false")
	}
	if !got.LoopPrevention {
		t.Fatal("LoopPrevention = false, want true")
	}
	if !got.FromCommand {
		t.Fatal("FromCommand = false, want true")
	}
	if !got.HasUserDataHeader {
		t.Fatal("HasUserDataHeader = false, want true")
	}
	if !got.HasProtocolIdentifier || got.ProtocolIdentifier != 0x7F {
		t.Fatalf("ProtocolIdentifier = 0x%02X, has = %t, want 0x7F/true", got.ProtocolIdentifier, got.HasProtocolIdentifier)
	}
	if !got.HasDataCodingScheme || got.DataCodingScheme != 0xF6 {
		t.Fatalf("DataCodingScheme = 0x%02X, has = %t, want 0xF6/true", got.DataCodingScheme, got.HasDataCodingScheme)
	}
	if got.UserDataLength != 3 {
		t.Fatalf("UserDataLength = %d, want 3", got.UserDataLength)
	}
	if !bytes.Equal(got.UserData, []byte{0xAA, 0xBB, 0xCC}) {
		t.Fatalf("UserData = % X, want AA BB CC", got.UserData)
	}
}

func TestSMSStatusReportTPDURejectsTrailingData(t *testing.T) {
	report := StatusReport{
		Recipient:         "+12345",
		MessageReference:  7,
		Status:            0x00,
		ServiceCenterTime: time.Date(2026, time.March, 13, 10, 20, 30, 0, time.FixedZone("", 8*60*60)),
		DischargeTime:     time.Date(2026, time.March, 13, 10, 21, 5, 0, time.FixedZone("", 8*60*60)),
	}
	data, err := (statusReportTPDU{Message: report}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	data = append(data, 0xFF)

	if _, err := decodeStatusReport(data); err == nil {
		t.Fatal("decodeStatusReport() error = nil, want trailing data error")
	}
}

func TestDecodeSMSStatusReportNormalizesNonIntegerTimestampDigits(t *testing.T) {
	serviceCenterTime := time.Date(2026, time.March, 13, 10, 20, 30, 0, time.FixedZone("", 8*60*60))
	dischargeTime := time.Date(2026, time.March, 13, 10, 21, 5, 0, time.FixedZone("", 8*60*60))

	raw := []byte{byte(tpduMTIStatusReport), 0x07}
	raw = append(raw, mustEncodeTPAddress(t, "+12345")...)
	raw = append(raw, encodeTimestamp(serviceCenterTime)...)
	raw = append(raw, encodeTimestamp(dischargeTime)...)
	raw = append(raw, 0x00)

	addrLen := len(mustEncodeTPAddress(t, "+12345"))
	sctsOffset := 2 + addrLen
	raw[sctsOffset+1] = 0x3A

	got, err := decodeStatusReport(raw)
	if err != nil {
		t.Fatalf("decodeStatusReport() error = %v", err)
	}
	if got.ServiceCenterTime.Format(time.RFC3339) != serviceCenterTime.Format(time.RFC3339) {
		t.Fatalf("ServiceCenterTime = %q, want %q", got.ServiceCenterTime.Format(time.RFC3339), serviceCenterTime.Format(time.RFC3339))
	}
}

func encodeAlphanumericTPAddress(t *testing.T, value string) []byte {
	t.Helper()
	septets, err := encodeGSM7(value)
	if err != nil {
		t.Fatalf("encodeGSM7(%q) error = %v", value, err)
	}
	lengthSemiOctets := (len(septets)*7 + 3) / 4
	return append([]byte{byte(lengthSemiOctets), 0xD0}, packSeptets(septets)...)
}

func mustEncodeTPAddress(t *testing.T, value string) []byte {
	t.Helper()
	data, err := encodeTPAddress(value)
	if err != nil {
		t.Fatalf("encodeTPAddress(%q) error = %v", value, err)
	}
	return data
}
