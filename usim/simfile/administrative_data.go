package simfile

import "errors"

func DecodeMNCLength(data []byte) (int, error) {
	if len(data) < 4 {
		return 0, errors.New("parsing EF_AD: truncated payload")
	}

	switch data[3] & 0x0F {
	case 0x02, 0x03:
		return int(data[3] & 0x0F), nil
	case 0x00:
		return 0, errors.New("parsing EF_AD: MNC length is unavailable")
	default:
		return 0, errors.New("parsing EF_AD: invalid MNC length")
	}
}
