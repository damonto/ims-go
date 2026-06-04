package voice

import (
	"fmt"
	"strconv"
	"strings"
)

type rseqHeader int64

const (
	rseqInitialMax = 1<<31 - 1
	sipSequenceMax = 1<<32 - 1
)

func (h rseqHeader) MarshalText() ([]byte, error) {
	if h <= 0 || h > sipSequenceMax {
		return nil, fmt.Errorf("building PRACK: invalid RSeq %d", h)
	}
	return []byte(strconv.FormatInt(int64(h), 10)), nil
}

func (h *rseqHeader) UnmarshalText(text []byte) error {
	value := string(text)
	rseq, err := strconv.ParseUint(strings.TrimSpace(value), 10, 32)
	if err != nil || rseq == 0 {
		return fmt.Errorf("building PRACK: invalid RSeq %q", value)
	}
	*h = rseqHeader(rseq)
	return nil
}

func (h rackHeader) MarshalText() ([]byte, error) {
	if h.rseq <= 0 || h.rseq > sipSequenceMax {
		return nil, fmt.Errorf("building PRACK: invalid RAck RSeq %d", h.rseq)
	}
	if h.cseq <= 0 || h.cseq > sipSequenceMax {
		return nil, fmt.Errorf("building PRACK: invalid RAck CSeq %d", h.cseq)
	}
	method := strings.TrimSpace(h.method)
	if method == "" {
		return nil, fmt.Errorf("building PRACK: invalid RAck method %q", h.method)
	}
	return []byte(fmt.Sprintf("%d %d %s", h.rseq, h.cseq, method)), nil
}

func (h *rackHeader) UnmarshalText(text []byte) error {
	value := string(text)
	fields := strings.Fields(value)
	if len(fields) != 3 {
		return fmt.Errorf("handling PRACK: invalid RAck %q", value)
	}
	rseq, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil || rseq == 0 {
		return fmt.Errorf("handling PRACK: invalid RAck RSeq %q", value)
	}
	cseq, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil || cseq == 0 {
		return fmt.Errorf("handling PRACK: invalid RAck CSeq %q", value)
	}
	method := strings.TrimSpace(fields[2])
	if method == "" {
		return fmt.Errorf("handling PRACK: invalid RAck method %q", value)
	}
	*h = rackHeader{rseq: int64(rseq), cseq: int64(cseq), method: method}
	return nil
}

func (p reliableProvisional) matches(rack rackHeader) bool {
	return p.rseq == rack.rseq && p.cseq == rack.cseq && p.method == rack.method
}
