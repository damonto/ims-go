package sip

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	if w.Code < 100 || w.Code > 999 {
		return nil, fmt.Errorf("marshaling SIP Warning: code %d is not three digits", w.Code)
	}
	if strings.TrimSpace(w.Agent) == "" {
		return nil, errors.New("marshaling SIP Warning: agent is empty")
	}
	return []byte(fmt.Sprintf(`%03d %s "%s"`, w.Code, strings.TrimSpace(w.Agent), quoteSIPString(w.Text))), nil
}

func (w *WarningValue) UnmarshalText(text []byte) error {
	value := strings.TrimSpace(string(text))
	fields := strings.Fields(value)
	if len(fields) < 3 {
		return errors.New("parsing SIP Warning: expected code, agent, and text")
	}
	if len(fields[0]) != 3 {
		return fmt.Errorf("parsing SIP Warning code %q: expected three digits", fields[0])
	}
	code, err := strconv.Atoi(fields[0])
	if err != nil {
		return fmt.Errorf("parsing SIP Warning code %q: %w", fields[0], err)
	}
	textStart := strings.Index(value, fields[2])
	if textStart < 0 {
		return errors.New("parsing SIP Warning: missing text")
	}
	rawText := strings.TrimSpace(value[textStart:])
	if len(rawText) < 2 || rawText[0] != '"' || rawText[len(rawText)-1] != '"' {
		return errors.New("parsing SIP Warning: text must be quoted")
	}
	*w = WarningValue{
		Code:  code,
		Agent: fields[1],
		Text:  unquoteSIPString(rawText),
	}
	return nil
}

func unquoteSIPString(value string) string {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return value
	}
	value = value[1 : len(value)-1]
	var b strings.Builder
	b.Grow(len(value))
	escaped := false
	for i := 0; i < len(value); i++ {
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
	for i := 0; i < len(value); i++ {
		switch value[i] {
		case '\\', '"':
			b.WriteByte('\\')
		}
		b.WriteByte(value[i])
	}
	return b.String()
}
