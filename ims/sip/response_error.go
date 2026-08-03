package sip

import (
	"encoding"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var (
	_ encoding.TextAppender    = WarningValue{}
	_ encoding.TextMarshaler   = WarningValue{}
	_ encoding.TextUnmarshaler = (*WarningValue)(nil)
)

type WarningValue struct {
	Code  int
	Agent string
	Text  string
}

type ResponseError struct {
	StatusCode   int
	ReasonPhrase string
	Warnings     []WarningValue
}

func NewResponseError(resp Message) *ResponseError {
	return &ResponseError{
		StatusCode:   resp.StatusCode(),
		ReasonPhrase: resp.ReasonPhrase(),
		Warnings:     ParseWarningValues(resp.HeadersByName("Warning")),
	}
}

func (e *ResponseError) Error() string {
	if e == nil {
		return ""
	}
	var b strings.Builder
	if e.StatusCode != 0 {
		b.WriteString(strconv.Itoa(e.StatusCode))
	}
	if e.ReasonPhrase != "" {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(e.ReasonPhrase)
	}
	if b.Len() == 0 {
		b.WriteString("SIP response")
	}
	if text := e.WarningText(); text != "" {
		b.WriteString(": ")
		b.WriteString(text)
	}
	return b.String()
}

func (e *ResponseError) WarningText() string {
	if e == nil || len(e.Warnings) == 0 {
		return ""
	}
	texts := make([]string, 0, len(e.Warnings))
	for _, warning := range e.Warnings {
		if warning.Text != "" {
			texts = append(texts, warning.Text)
		}
	}
	return strings.Join(texts, "; ")
}

func ParseWarningValues(values []string) []WarningValue {
	warnings := make([]WarningValue, 0, len(values))
	for _, value := range values {
		for _, part := range SplitHeaderList(value) {
			var warning WarningValue
			if err := warning.UnmarshalText([]byte(part)); err == nil {
				warnings = append(warnings, warning)
			}
		}
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

func (w WarningValue) MarshalText() ([]byte, error) {
	return w.AppendText(nil)
}

func (w WarningValue) AppendText(dst []byte) ([]byte, error) {
	if w.Code < 100 || w.Code > 999 {
		return nil, fmt.Errorf("marshaling SIP Warning: code %d is not three digits", w.Code)
	}
	agent := strings.TrimSpace(w.Agent)
	if agent == "" {
		return nil, errors.New("marshaling SIP Warning: agent is empty")
	}
	if strings.ContainsAny(agent, " \t\r\n,\"") {
		return nil, fmt.Errorf("marshaling SIP Warning: invalid agent %q", w.Agent)
	}
	if !validSIPQuotedText(w.Text) {
		return nil, errors.New("marshaling SIP Warning: text contains an invalid control character")
	}
	return fmt.Appendf(dst, `%03d %s "%s"`, w.Code, agent, quoteSIPString(w.Text)), nil
}

func (w *WarningValue) UnmarshalText(text []byte) error {
	value := strings.TrimSpace(string(text))
	codeText, rest, ok := strings.Cut(value, " ")
	if !ok {
		return errors.New("parsing SIP Warning: expected code, agent, and text")
	}
	if len(codeText) != 3 {
		return fmt.Errorf("parsing SIP Warning code %q: expected three digits", codeText)
	}
	code, err := strconv.Atoi(codeText)
	if err != nil {
		return fmt.Errorf("parsing SIP Warning code %q: %w", codeText, err)
	}
	rest = strings.TrimLeft(rest, " \t")
	agent, rawText, ok := strings.Cut(rest, " ")
	if !ok || agent == "" || strings.ContainsAny(agent, "\t\r\n,\"") {
		return errors.New("parsing SIP Warning: invalid agent")
	}
	rawText = strings.TrimSpace(rawText)
	if !validSIPQuotedString(rawText) {
		return errors.New("parsing SIP Warning: text must be quoted")
	}
	*w = WarningValue{
		Code:  code,
		Agent: agent,
		Text:  unquoteSIPString(rawText),
	}
	return nil
}

func validSIPQuotedString(value string) bool {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return false
	}
	escaped := false
	for i := 1; i < len(value)-1; i++ {
		b := value[i]
		if escaped {
			if b == '\r' || b == '\n' || b >= 0x80 {
				return false
			}
			escaped = false
			continue
		}
		if b == '\\' {
			escaped = true
			continue
		}
		if b == '"' || b == '\r' || b == '\n' || (b < 0x20 && b != '\t') {
			return false
		}
	}
	return !escaped
}

func validSIPQuotedText(value string) bool {
	for i := range len(value) {
		b := value[i]
		if b == '\r' || b == '\n' || (b < 0x20 && b != '\t') {
			return false
		}
	}
	return true
}

func unquoteSIPString(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	value = value[1 : len(value)-1]
	var b strings.Builder
	b.Grow(len(value))
	escaped := false
	for i := range len(value) {
		if escaped {
			b.WriteByte(value[i])
			escaped = false
			continue
		}
		if value[i] == '\\' {
			escaped = true
			continue
		}
		b.WriteByte(value[i])
	}
	if escaped {
		b.WriteByte('\\')
	}
	return b.String()
}

func quoteSIPString(value string) string {
	var b strings.Builder
	b.Grow(len(value))
	for i := range len(value) {
		switch value[i] {
		case '\\', '"':
			b.WriteByte('\\')
		}
		b.WriteByte(value[i])
	}
	return b.String()
}
