package apdu

func GetResponse(length byte) *Request {
	return &Request{CLA: 0x00, INS: 0xC0, P1: 0x00, P2: 0x00, Le: &length}
}

func ReadBinary(length byte, offset uint16) *Request {
	return &Request{
		CLA: 0x00,
		INS: 0xB0,
		P1:  byte(offset >> 8),
		P2:  byte(offset),
		Le:  &length,
	}
}

func ReadRecord(record byte, length byte) *Request {
	return &Request{
		CLA: 0x00,
		INS: 0xB2,
		P1:  record,
		P2:  0x04,
		Le:  &length,
	}
}

func SelectID(id []byte, fci bool) *Request {
	return selectRequest(0x00, id, fci)
}

func SelectName(name []byte, fci bool) *Request {
	return selectRequest(0x04, name, fci)
}

func SelectPath(path []byte, fci bool) *Request {
	return selectRequest(0x08, path, fci)
}

func Authenticate3G(rand, autn []byte) *Request {
	data := make([]byte, 0, len(rand)+len(autn)+2)
	data = append(data, byte(len(rand)))
	data = append(data, rand...)
	data = append(data, byte(len(autn)))
	data = append(data, autn...)

	return &Request{
		CLA:  0x00,
		INS:  0x88,
		P1:   0x00,
		P2:   0x81,
		Data: data,
	}
}

func selectRequest(p1 byte, value []byte, fci bool) *Request {
	p2 := byte(0x00)
	if fci {
		p2 = 0x04
	}
	return &Request{CLA: 0x00, INS: 0xA4, P1: p1, P2: p2, Data: value}
}
