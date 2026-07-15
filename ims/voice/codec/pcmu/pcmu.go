// Package pcmu implements the G.711 mu-law audio codec.
package pcmu

const (
	// SampleRate is the PCMU clock rate in hertz.
	SampleRate = 8000
	// Silence is the PCMU representation of a zero PCM sample.
	Silence byte = 0xff

	bias = 0x84
)

// AppendEncode appends the PCMU encoding of pcm to dst.
func AppendEncode(dst []byte, pcm []int16) []byte {
	start := len(dst)
	dst = append(dst, make([]byte, len(pcm))...)
	for i, sample := range pcm {
		dst[start+i] = encodeSample(sample)
	}
	return dst
}

// AppendDecode appends the signed 16-bit PCM decoding of payload to dst.
func AppendDecode(dst []int16, payload []byte) []int16 {
	start := len(dst)
	dst = append(dst, make([]int16, len(payload))...)
	for i, encoded := range payload {
		value := ^encoded
		sign := value & 0x80
		exponent := (value >> 4) & 0x07
		mantissa := value & 0x0f
		sample := int16((((int(mantissa) << 3) + bias) << exponent) - bias)
		if sign != 0 {
			sample = -sample
		}
		dst[start+i] = sample
	}
	return dst
}

func encodeSample(sample int16) byte {
	value := int(sample)
	sign := 0
	if value < 0 {
		sign = 0x80
		value = -value - 1
	}
	if value > 32635 {
		value = 32635
	}
	value += bias

	exponent := 7
	for mask := 0x4000; exponent > 0 && value&mask == 0; mask >>= 1 {
		exponent--
	}
	mantissa := (value >> (exponent + 3)) & 0x0f
	return byte(^(sign | (exponent << 4) | mantissa))
}
