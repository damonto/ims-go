package sip

import (
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
			warning, ok := parseWarningValue(part)
			if ok {
				warnings = append(warnings, warning)
			}
		}
	}
	if len(warnings) == 0 {
		return nil
	}
	return warnings
}

func parseWarningValue(value string) (WarningValue, bool) {
	value = strings.TrimSpace(value)
	fields := strings.Fields(value)
	if len(fields) < 3 {
		return WarningValue{}, false
	}
	code, err := strconv.Atoi(fields[0])
	if err != nil {
		return WarningValue{}, false
	}
	textStart := strings.Index(value, fields[2])
	if textStart < 0 {
		return WarningValue{}, false
	}
	return WarningValue{
		Code:  code,
		Agent: fields[1],
		Text:  unquoteSIPString(strings.TrimSpace(value[textStart:])),
	}, true
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
